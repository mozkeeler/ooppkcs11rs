#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

use libc::getenv;
use serde_json::{from_str, to_string};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::ops::DerefMut;
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;
use timeout_readwrite::{TimeoutReader, TimeoutWriter};
use ooppkcs11rs_types::*;

use ipc::*;
use pkcs11::*;

type State = (
    IpcSender<TimeoutWriter<ChildStdin>>,
    IpcReceiver<TimeoutReader<ChildStdout>>,
);

lazy_static! {
    static ref STATE: Mutex<Option<State>> = Mutex::new(None);
}

fn get_library_to_load_path(init_args: *const CK_C_INITIALIZE_ARGS) -> Result<String, CK_RV> {
    let ooppkcs11rs_load_this_env_var = CString::new("OOPPKCS11RS_LOAD_THIS").unwrap();
    unsafe {
        let library_path = getenv(ooppkcs11rs_load_this_env_var.as_ptr());
        if !library_path.is_null() {
            return Ok(CStr::from_ptr(library_path).to_string_lossy().into_owned());
        }
    }
    if init_args.is_null() {
        return Err(CKR_GENERAL_ERROR);
    }
    unsafe {
        let library_path = (*init_args).pReserved as *const i8;
        if library_path.is_null() {
            return Err(CKR_GENERAL_ERROR);
        }
        Ok(CStr::from_ptr(library_path).to_string_lossy().into_owned())
    }
}

fn get_ooppkcs11rs_binary_path() -> Result<String, CK_RV> {
    let ooppkcs11rs_binary_path_env_var = CString::new("OOPPKCS11RS_BINARY_PATH").unwrap();
    unsafe {
        let binary_path = getenv(ooppkcs11rs_binary_path_env_var.as_ptr());
        if !binary_path.is_null() {
            return Ok(CStr::from_ptr(binary_path).to_string_lossy().into_owned());
        }
    }
    Err(CKR_GENERAL_ERROR)
}

extern "C" fn C_Initialize(pInitArgs: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV {
    eprintln!("parent: C_Initialize");
    let mut state_guard = STATE.lock().unwrap();
    let ooppkcs11rs_binary_path = match get_ooppkcs11rs_binary_path() {
        Ok(path) => path,
        Err(e) => return e,
    };
    let mut child = match Command::new(ooppkcs11rs_binary_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("failed to start ooppkcs11rs: {}", e);
            return CKR_GENERAL_ERROR;
        }
    };
    let write_to_child = match child.stdin {
        Some(stdin) => stdin,
        None => return CKR_GENERAL_ERROR,
    };
    let read_from_child = match child.stdout {
        Some(stdout) => stdout,
        None => return CKR_GENERAL_ERROR,
    };
    let timeout = Some(Duration::new(7, 0));
    let mut tx = IpcSender::new(TimeoutWriter::new(write_to_child, timeout));
    let timeout = Some(Duration::new(7, 0));
    let mut rx = IpcReceiver::new(TimeoutReader::new(read_from_child, timeout));
    let args = match get_library_to_load_path(pInitArgs) {
        Ok(args) => args,
        Err(e) => return e,
    };
    let msg = Request::new("C_Initialize", args);
    if tx.send(msg).is_err() {
        return CKR_GENERAL_ERROR;
    }
    eprintln!("parent sent C_Initialize");
    let msg_back: Response = match rx.recv() {
        Ok(msg_back) => msg_back,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    eprintln!("parent received {:?}", msg_back);
    *state_guard = Some((tx, rx));
    msg_back.status()
}

macro_rules! send {
    ($state_guard:ident, $to_send:expr) => {{
        let result = {
            let state = match $state_guard.as_mut() {
                Some(state) => state,
                None => return CKR_GENERAL_ERROR,
            };
            state.0.send($to_send)
        };
        match result {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error sending to child: {}", e);
                let _ = $state_guard.take();
                return CKR_GENERAL_ERROR;
            }
        }
    }};
}

macro_rules! recv {
    ($state_guard:ident) => {{
        let result = {
            let state = match $state_guard.as_mut() {
                Some(state) => state,
                None => return CKR_GENERAL_ERROR,
            };
            state.1.recv()
        };
        match result {
            Ok(result) => result,
            Err(e) => {
                eprintln!("error reading from child: {}", e);
                let _ = $state_guard.take();
                return CKR_GENERAL_ERROR;
            }
        }
    }};
}

extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    eprintln!("parent: C_Finalize");
    let mut state_guard = STATE.lock().unwrap();
    send!(state_guard, Request::new("C_Finalize", String::new()));
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    response.status()
}

macro_rules! deserialize_or_return_error {
    ($response_args:expr) => {
        match from_str($response_args) {
            Ok(args) => args,
            Err(e) => {
                eprintln!("failed to deserialize response: {}", e);
                return CKR_GENERAL_ERROR;
            }
        }
    };
}

macro_rules! serialize_or_return_error {
    ($request_args:expr) => {
        match to_string($request_args) {
            Ok(serialized) => serialized,
            Err(e) => {
                eprintln!("failed to serialize request: {}", e);
                return CKR_GENERAL_ERROR;
            }
        }
    };
}

macro_rules! fill_struct_pkcs11_function {
    ($pkcs11_function:ident, $out_arg_type:ty) => {
        extern "C" fn $pkcs11_function(out_arg: $out_arg_type) -> CK_RV {
            eprintln!("parent: {}", stringify!($pkcs11_function));
            let mut state_guard = STATE.lock().unwrap();
            send!(
                state_guard,
                Request::new(stringify!($pkcs11_function), String::new())
            );
            let response: Response = recv!(state_guard);
            eprintln!("parent received {:?}", response);
            if response.status() == CKR_OK {
                let arg = deserialize_or_return_error!(response.args());
                unsafe {
                    *out_arg = arg;
                }
                CKR_OK
            } else {
                response.status()
            }
        }
    };
    ($pkcs11_function:ident, $in_arg_type:ty, $out_arg_type:ty) => {
        extern "C" fn $pkcs11_function(in_arg: $in_arg_type, out_arg: $out_arg_type) -> CK_RV {
            eprintln!("parent: {}", stringify!($pkcs11_function));
            let mut state_guard = STATE.lock().unwrap();
            let msg = Request::new(
                stringify!($pkcs11_function),
                serialize_or_return_error!(&in_arg),
            );
            send!(state_guard, msg);
            let response: Response = recv!(state_guard);
            eprintln!("parent received {:?}", response);
            if response.status() == CKR_OK {
                let arg = deserialize_or_return_error!(response.args());
                unsafe {
                    *out_arg = arg;
                }
                CKR_OK
            } else {
                response.status()
            }
        }
    };
}

fill_struct_pkcs11_function!(C_GetInfo, CK_INFO_PTR);

extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("parent: C_GetSlotList");
    let mut state_guard = STATE.lock().unwrap();
    let slot_list = if pSlotList.is_null() {
        None
    } else {
        Some(Vec::new())
    };
    // Right now we use the same struct in both directions, so we fill this out with
    // not-entirely-meaningful data. Maybe this isn't the best and we should have e.g.
    // `CGetSlotListArgsIn`/`CGetSlotListArgsOut` or something.
    let slot_count = if pSlotList.is_null() {
        0
    } else {
        unsafe { *pulCount }
    };
    let args = CGetSlotListArgs {
        token_present: tokenPresent,
        slot_list,
        slot_count,
    };
    let msg = Request::new("C_GetSlotList", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let mut result: CGetSlotListArgs = deserialize_or_return_error!(response.args());
        unsafe {
            *pulCount = result.slot_count;
            if !pSlotList.is_null() {
                let ids = match result.slot_list.take() {
                    Some(ids) => ids,
                    None => return CKR_GENERAL_ERROR,
                };
                for i in 0..result.slot_count {
                    *pSlotList.offset(i as isize) = ids[i as usize];
                }
            }
        }
        CKR_OK
    } else {
        response.status()
    }
}

fill_struct_pkcs11_function!(C_GetSlotInfo, CK_SLOT_ID, CK_SLOT_INFO_PTR);
fill_struct_pkcs11_function!(C_GetTokenInfo, CK_SLOT_ID, CK_TOKEN_INFO_PTR);

extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("parent: C_GetMechanismList");
    let mut state_guard = STATE.lock().unwrap();
    let mechanism_list = if pMechanismList.is_null() {
        None
    } else {
        Some(Vec::new())
    };
    let mechanism_count = if pMechanismList.is_null() {
        0
    } else {
        unsafe { *pulCount }
    };
    let args = CGetMechanismListArgs {
        slot_id: slotID,
        mechanism_list,
        mechanism_count,
    };
    let msg = Request::new("C_GetMechanismList", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let mut result: CGetMechanismListArgs = deserialize_or_return_error!(response.args());
        unsafe {
            *pulCount = result.mechanism_count as u64;
            if !pMechanismList.is_null() {
                let ids = match result.mechanism_list.take() {
                    Some(ids) => ids,
                    None => return CKR_GENERAL_ERROR,
                };
                for i in 0..result.mechanism_count {
                    *pMechanismList.offset(i as isize) = ids[i as usize];
                }
            }
        }
        CKR_OK
    } else {
        response.status()
    }
}

extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: CK_MECHANISM_INFO_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GetMechanismInfo");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_InitToken");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_InitPIN(
    hSession: CK_SESSION_HANDLE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_InitPIN");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SetPIN(
    hSession: CK_SESSION_HANDLE,
    pOldPin: CK_UTF8CHAR_PTR,
    ulOldLen: CK_ULONG,
    pNewPin: CK_UTF8CHAR_PTR,
    ulNewLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SetPIN");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    pApplication: CK_VOID_PTR,
    Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    eprintln!("parent: C_OpenSession");
    let mut state_guard = STATE.lock().unwrap();
    let args = COpenSessionArgs {
        slot_id: slotID,
        flags,
        session_handle: 0,
    };
    let msg = Request::new("C_OpenSession", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let args: COpenSessionArgs = deserialize_or_return_error!(response.args());
        unsafe {
            *phSession = args.session_handle;
        }
        CKR_OK
    } else {
        response.status()
    }
}

macro_rules! simple_pkcs11_function {
    ($pkcs11_function:ident, $arg_type:ty) => {
        extern "C" fn $pkcs11_function(arg: $arg_type) -> CK_RV {
            eprintln!("parent: {}", stringify!($pkcs11_function));
            let mut state_guard = STATE.lock().unwrap();
            let msg = Request::new(
                stringify!($pkcs11_function),
                serialize_or_return_error!(&arg),
            );
            send!(state_guard, msg);
            let response: Response = recv!(state_guard);
            eprintln!("parent received {:?}", response);
            response.status()
        }
    };
}

simple_pkcs11_function!(C_CloseSession, CK_SESSION_HANDLE);
simple_pkcs11_function!(C_CloseAllSessions, CK_SLOT_ID);

fill_struct_pkcs11_function!(C_GetSessionInfo, CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);

extern "C" fn C_GetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GetOperationState");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SetOperationState");
    CKR_FUNCTION_NOT_SUPPORTED
}

macro_rules! simple_pkcs11_vector_function {
    ($pkcs11_function:ident, $arg_type:ty, $type_in_vector:ty) => {
        extern "C" fn $pkcs11_function(
            arg: $arg_type,
            data: *mut $type_in_vector,
            len: CK_ULONG,
        ) -> CK_RV {
            eprintln!("parent: {}", stringify!($pkcs11_function));
            let mut state_guard = STATE.lock().unwrap();
            let mut vector = Vec::with_capacity(len as usize);
            unsafe {
                for i in 0..len {
                    vector.push(*data.offset(i as isize));
                }
            }
            let args = (arg, vector);
            let msg = Request::new(
                stringify!($pkcs11_function),
                serialize_or_return_error!(&args),
            );
            send!(state_guard, msg);
            let response: Response = recv!(state_guard);
            eprintln!("parent received {:?}", response);
            response.status()
        }
    };
    ($pkcs11_function:ident, $arg_type_1:ty, $arg_type_2:ty, $type_in_vector:ty) => {
        extern "C" fn $pkcs11_function(
            arg1: $arg_type_1,
            arg2: $arg_type_2,
            data: *mut $type_in_vector,
            len: CK_ULONG,
        ) -> CK_RV {
            eprintln!("parent: {}", stringify!($pkcs11_function));
            let mut state_guard = STATE.lock().unwrap();
            // TODO: data can be null (e.g. protected auth C_Login), so that needs to be handled
            let mut vector = Vec::with_capacity(len as usize);
            unsafe {
                for i in 0..len {
                    vector.push(*data.offset(i as isize));
                }
            }
            let args = (arg1, arg2, vector);
            let msg = Request::new(
                stringify!($pkcs11_function),
                serialize_or_return_error!(&args),
            );
            send!(state_guard, msg);
            let response: Response = recv!(state_guard);
            eprintln!("parent received {:?}", response);
            response.status()
        }
    };
}

simple_pkcs11_vector_function!(C_Login, CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR);
simple_pkcs11_vector_function!(C_SeedRandom, CK_SESSION_HANDLE, CK_BYTE);

simple_pkcs11_function!(C_Logout, CK_SESSION_HANDLE);

extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_CreateObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CopyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_CopyObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DestroyObject");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GetObjectSize");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    eprintln!("parent: C_GetAttributeValue");
    let mut state_guard = STATE.lock().unwrap();
    let mut args = CGetAttributeValueArgs {
        session_handle: hSession,
        object_handle: hObject,
        template: Vec::new(),
    };
    unsafe {
        for i in 0..ulCount {
            args.template
                .push(Attribute::from_raw(*pTemplate.offset(i as isize)));
        }
    }
    let msg = Request::new("C_GetAttributeValue", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let args: CGetAttributeValueArgs = deserialize_or_return_error!(response.args());
        unsafe {
            for i in 0..ulCount {
                args.template[i as usize].into_raw(pTemplate.offset(i as isize));
            }
        }
    }
    response.status()
}

extern "C" fn C_SetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SetAttributeValue");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    eprintln!("parent: C_FindObjectsInit");
    let mut state_guard = STATE.lock().unwrap();
    let mut args = CFindObjectsInitArgs {
        session_handle: hSession,
        template: Vec::new(),
    };
    unsafe {
        for i in 0..ulCount {
            args.template
                .push(Attribute::from_raw(*pTemplate.offset(i as isize)));
        }
    }
    let msg = Request::new("C_FindObjectsInit", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    response.status()
}

extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("parent: C_FindObjects");
    let mut state_guard = STATE.lock().unwrap();
    let mut args = CFindObjectsArgs {
        session_handle: hSession,
        objects: Vec::new(),
        max_objects: ulMaxObjectCount,
    };
    let msg = Request::new("C_FindObjects", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    let args: CFindObjectsArgs = deserialize_or_return_error!(response.args());
    if response.status() == CKR_OK {
        unsafe {
            for i in 0..args.objects.len() {
                *phObject.offset(i as isize) = args.objects[i];
            }
            *pulObjectCount = args.objects.len() as CK_ULONG;
        }
    }
    response.status()
}

simple_pkcs11_function!(C_FindObjectsFinal, CK_SESSION_HANDLE);

extern "C" fn C_EncryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_EncryptInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Encrypt(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_Encrypt");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_EncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_EncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_EncryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_EncryptFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DecryptInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: CK_BYTE_PTR,
    ulEncryptedDataLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_Decrypt");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DecryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptFinal(
    hSession: CK_SESSION_HANDLE,
    pLastPart: CK_BYTE_PTR,
    pulLastPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DecryptFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestInit(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DigestInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_Digest");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DigestUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DigestKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DigestFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("parent: C_SignInit");
    let mut state_guard = STATE.lock().unwrap();
    let mechanism = unsafe { *pMechanism };
    let args = (hSession, Mechanism::from_raw(mechanism), hKey);
    let msg = Request::new("C_SignInit", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    response.status()
}

fn copy_bytes_in(bytes: CK_BYTE_PTR, len: CK_ULONG) -> Vec<CK_BYTE> {
    let mut copy = Vec::with_capacity(len as usize);
    for i in 0..len as isize {
        unsafe {
            copy.push(*bytes.offset(i));
        }
    }
    copy
}

fn copy_bytes_out(
    bytes_in: Vec<CK_BYTE>,
    bytes_out: CK_BYTE_PTR,
    bytes_out_capacity: CK_ULONG,
    bytes_out_len: CK_ULONG_PTR,
) -> Result<(), CK_RV> {
    if bytes_in.len() > bytes_out_capacity as usize {
        return Err(CKR_BUFFER_TOO_SMALL);
    }
    for i in 0..bytes_in.len() as isize {
        unsafe {
            *(bytes_out.offset(i)) = bytes_in[i as usize];
        }
    }
    unsafe {
        *bytes_out_len = bytes_in.len() as CK_ULONG;
    }
    Ok(())
}

extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("parent: C_Sign");
    let mut state_guard = STATE.lock().unwrap();
    let data = copy_bytes_in(pData, ulDataLen);
    let signature_capacity = unsafe { *pulSignatureLen };
    let mut signature = Vec::with_capacity(signature_capacity as usize);
    signature.resize(signature_capacity as usize, 0);
    let args = (hSession, data, signature);
    let msg = Request::new("C_Sign", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let signature: Vec<CK_BYTE> = deserialize_or_return_error!(response.args());
        match copy_bytes_out(signature, pSignature, signature_capacity, pulSignatureLen) {
            Ok(()) => {}
            Err(result) => return result,
        }
    }
    response.status()
}

extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SignUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SignFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SignRecoverInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignRecover(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SignRecover");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_VerifyInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_Verify(
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_Verify");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_VerifyUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_VerifyFinal");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyRecoverInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_VerifyRecoverInit");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_VerifyRecover(
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_VerifyRecover");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DigestEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DigestEncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptDigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DecryptDigestUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_SignEncryptUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_SignEncryptUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DecryptVerifyUpdate(
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DecryptVerifyUpdate");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GenerateKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GenerateKeyPair");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_WrapKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_UnwrapKey");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_DeriveKey");
    CKR_FUNCTION_NOT_SUPPORTED
}

extern "C" fn C_GenerateRandom(
    hSession: CK_SESSION_HANDLE,
    RandomData: CK_BYTE_PTR,
    ulRandomLen: CK_ULONG,
) -> CK_RV {
    eprintln!("parent: C_GenerateRandom");
    let mut state_guard = STATE.lock().unwrap();
    let mut args = CGenerateRandomArgs {
        session_handle: hSession,
        data: Vec::new(),
        length: ulRandomLen,
    };
    let msg = Request::new("C_GenerateRandom", serialize_or_return_error!(&args));
    send!(state_guard, msg);
    let response: Response = recv!(state_guard);
    eprintln!("parent received {:?}", response);
    if response.status() == CKR_OK {
        let mut result: CGenerateRandomArgs = deserialize_or_return_error!(response.args());
        unsafe {
            for i in 0..ulRandomLen {
                *RandomData.offset(i as isize) = result.data[i as usize];
            }
        }
        CKR_OK
    } else {
        response.status()
    }
}

extern "C" fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("NOT SUPPORTED C_GetFunctionStatus");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_CancelFunction(hSession: CK_SESSION_HANDLE) -> CK_RV {
    eprintln!("NOT SUPPORTED C_CancelFunction");
    CKR_FUNCTION_NOT_SUPPORTED
}
extern "C" fn C_WaitForSlotEvent(
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pRserved: CK_VOID_PTR,
) -> CK_RV {
    eprintln!("NOT SUPPORTED C_WaitForSlotEvent");
    CKR_FUNCTION_NOT_SUPPORTED
}

pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 2 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: None,
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};
