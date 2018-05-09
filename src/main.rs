#[macro_use]
extern crate dlopen_derive;
extern crate dlopen;
extern crate ipc_channel;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use dlopen::wrapper::{Container, WrapperApi};
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use serde_json::{from_str, to_string};
use std::io::{self, Error, ErrorKind, Read};

mod pkcs11;
mod pkcs11types;

use pkcs11::*;
use pkcs11types::*;

// The ChildStdin in the parent process is supposed to close our stdin after sending the name of the
// ipc server. For some reason this isn't happening correctly, so reading until we're closed doesn't
// work. As a workaround, read until we hit a null byte.
fn read_string_from_stdin() -> Result<String, Error> {
    let mut total_buf = Vec::new();
    loop {
        let mut buf = Vec::with_capacity(100);
        buf.resize(100, 0);
        io::stdin().read(&mut buf)?;
        for b in buf {
            if b == 0 {
                return String::from_utf8(total_buf).map_err(|e| Error::new(ErrorKind::Other, e));
            }
            total_buf.push(b);
        }
    }
}

#[derive(WrapperApi)]
struct Pkcs11Module {
    C_GetFunctionList: extern "C" fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV,
}

fn main() {
    println!("ooppkcs11rs main");
    let server_name = read_string_from_stdin().expect("couldn't read server name");
    println!("server_name: '{}'", server_name);
    let tx: IpcSender<Response> = IpcSender::connect(server_name).unwrap();
    let (server, name): (IpcOneShotServer<Request>, String) = IpcOneShotServer::new().unwrap();
    println!("sending server name to parent");
    tx.send(Response::new(CKR_OK, name))
        .expect("couldn't send server name to parent");
    println!("waiting for parent to connect");
    let (rx, msg): (IpcReceiver<Request>, Request) = server.accept().unwrap();
    println!("{:?}", msg);
    if msg.function() != "C_Initialize" {
        panic!("unexpected first message from parent");
    }
    println!("loading library at '{}'", msg.args());
    let module: Container<Pkcs11Module> = unsafe { Container::load(msg.args()) }.unwrap();
    let mut function_list_ptr: CK_FUNCTION_LIST_PTR = std::ptr::null();
    module.C_GetFunctionList(&mut function_list_ptr);
    let result = unsafe {
        let null_args = std::ptr::null::<CK_C_INITIALIZE_ARGS>();
        (*function_list_ptr).C_Initialize.unwrap()(null_args as *mut CK_C_INITIALIZE_ARGS)
    };
    println!("result from C_Initialize was {}", result);
    tx.send(Response::new(result, String::new())).unwrap();
    if result != CKR_OK {
        return;
    }

    let mut keep_going = true;
    while keep_going {
        let msg = match rx.recv() {
            Ok(msg) => msg,
            Err(e) => {
                println!("error receiving request from parent: {}", e);
                return;
            }
        };
        println!("child received {:?}", msg);
        let response = match msg.function() {
            "C_Finalize" => {
                keep_going = false;
                c_finalize(function_list_ptr)
            }
            "C_GetInfo" => c_get_info(function_list_ptr),
            "C_GetSlotList" => c_get_slot_list(msg, function_list_ptr),
            "C_GetSlotInfo" => c_get_slot_info(msg, function_list_ptr),
            "C_GetTokenInfo" => c_get_token_info(msg, function_list_ptr),
            "C_GetMechanismList" => c_get_mechanism_list(msg, function_list_ptr),
            "C_OpenSession" => c_open_session(msg, function_list_ptr),
            "C_GetSessionInfo" => c_get_session_info(msg, function_list_ptr),
            "C_FindObjectsInit" => c_find_objects_init(msg, function_list_ptr),
            "C_FindObjects" => c_find_objects(msg, function_list_ptr),
            "C_FindObjectsFinal" => c_find_objects_final(msg, function_list_ptr),
            "C_CloseSession" => c_close_session(msg, function_list_ptr),
            "C_CloseAllSessions" => c_close_all_sessions(msg, function_list_ptr),
            "C_GetAttributeValue" => c_get_attribute_value(msg, function_list_ptr),
            "C_Logout" => c_logout(msg, function_list_ptr),
            _ => Ok(Response::new(CKR_FUNCTION_NOT_SUPPORTED, String::new())),
        };
        match response {
            Ok(response) => match tx.send(response) {
                Ok(()) => {}
                Err(e) => {
                    println!("error sending response to parent: '{}'", e);
                    keep_going = false;
                }
            },
            Err(e) => {
                println!("error performing operation: '{}'", e);
                keep_going = false;
            }
        }
    }
}

fn c_finalize(fs: CK_FUNCTION_LIST_PTR) -> Result<Response, serde_json::Error> {
    let result = unsafe {
        (*fs).C_Finalize.unwrap()(std::ptr::null::<std::os::raw::c_void>() as CK_VOID_PTR)
    };
    println!("C_Finalize: {}", result);
    Ok(Response::new(result, String::new()))
}

macro_rules! fill_struct_pkcs11_function {
    ($function_name:ident, $out_arg_type:ty, $pkcs11_function:ident) => {
        fn $function_name(fs: CK_FUNCTION_LIST_PTR) -> Result<Response, serde_json::Error> {
            let mut out_arg: $out_arg_type = Default::default();
            let result = unsafe { (*fs).$pkcs11_function.unwrap()(&mut out_arg) };
            println!("{}: {}", stringify!($pkcs11_function), result);
            let payload = if result == CKR_OK {
                to_string(&out_arg)?
            } else {
                String::new()
            };
            Ok(Response::new(result, payload))
        }
    };
    ($function_name:ident, $in_arg_type:ty, $out_arg_type:ty, $pkcs11_function:ident) => {
        fn $function_name(
            msg: Request,
            fs: CK_FUNCTION_LIST_PTR,
        ) -> Result<Response, serde_json::Error> {
            let in_arg: $in_arg_type = from_str(msg.args())?;
            let mut out_arg: $out_arg_type = Default::default();
            let result = unsafe { (*fs).$pkcs11_function.unwrap()(in_arg, &mut out_arg) };
            println!("{}: {}", stringify!($pkcs11_function), result);
            let payload = if result == CKR_OK {
                to_string(&out_arg)?
            } else {
                String::new()
            };
            Ok(Response::new(result, payload))
        }
    };
}

fill_struct_pkcs11_function!(c_get_info, CK_INFO, C_GetInfo);

fn c_get_slot_list(msg: Request, fs: CK_FUNCTION_LIST_PTR) -> Result<Response, serde_json::Error> {
    let mut args: CGetSlotListArgs = from_str(msg.args())?;
    let slot_list = match &mut args.slot_list {
        &mut Some(ref mut slot_list) => {
            slot_list.reserve(args.slot_count as usize);
            slot_list.as_mut_ptr()
        }
        &mut None => std::ptr::null(),
    };
    let result = unsafe {
        (*fs).C_GetSlotList.unwrap()(
            args.token_present,
            slot_list as *mut CK_SLOT_ID,
            &mut args.slot_count,
        )
    };
    println!("C_GetSlotList: {}", result);
    let msg_back = if result == CKR_OK {
        match &mut args.slot_list {
            &mut Some(ref mut slot_list) => unsafe { slot_list.set_len(args.slot_count as usize) },
            &mut None => {}
        }
        Response::new(CKR_OK, to_string(&args)?)
    } else {
        Response::new(result, String::new())
    };
    Ok(msg_back)
}

fill_struct_pkcs11_function!(c_get_slot_info, CK_SLOT_ID, CK_SLOT_INFO, C_GetSlotInfo);
fill_struct_pkcs11_function!(c_get_token_info, CK_SLOT_ID, CK_TOKEN_INFO, C_GetTokenInfo);

fn c_get_mechanism_list(
    msg: Request,
    fs: CK_FUNCTION_LIST_PTR,
) -> Result<Response, serde_json::Error> {
    let mut args: CGetMechanismListArgs = from_str(msg.args())?;
    let mechanism_list = match &mut args.mechanism_list {
        &mut Some(ref mut mechanism_list) => {
            mechanism_list.reserve(args.mechanism_count as usize);
            mechanism_list.as_mut_ptr()
        }
        &mut None => std::ptr::null(),
    };
    let result = unsafe {
        (*fs).C_GetMechanismList.unwrap()(
            args.slot_id,
            mechanism_list as *mut CK_MECHANISM_TYPE,
            &mut args.mechanism_count,
        )
    };
    println!("C_GetMechanismList: {}", result);
    let msg_back = if result == CKR_OK {
        match &mut args.mechanism_list {
            &mut Some(ref mut mechanism_list) => unsafe {
                mechanism_list.set_len(args.mechanism_count as usize);
            },
            &mut None => {}
        }
        Response::new(CKR_OK, to_string(&args)?)
    } else {
        Response::new(result, String::new())
    };
    Ok(msg_back)
}

fn c_open_session(msg: Request, fs: CK_FUNCTION_LIST_PTR) -> Result<Response, serde_json::Error> {
    let mut args: COpenSessionArgs = from_str(msg.args())?;
    let result = unsafe {
        (*fs).C_OpenSession.unwrap()(
            args.slot_id,
            args.flags,
            std::ptr::null::<std::os::raw::c_void>() as CK_VOID_PTR,
            None,
            &mut args.session_handle,
        )
    };
    println!("C_OpenSession: {}", result);
    let msg_back = if result == CKR_OK {
        Response::new(CKR_OK, to_string(&args)?)
    } else {
        Response::new(result, String::new())
    };
    Ok(msg_back)
}

fill_struct_pkcs11_function!(
    c_get_session_info,
    CK_SESSION_HANDLE,
    CK_SESSION_INFO,
    C_GetSessionInfo
);

fn c_find_objects_init(
    msg: Request,
    fs: CK_FUNCTION_LIST_PTR,
) -> Result<Response, serde_json::Error> {
    let args: CFindObjectsInitArgs = from_str(msg.args())?;
    // NB: currently args must outlive template here (things in template point to data in args).
    let mut template = Vec::with_capacity(args.template.len());
    for t in args.template {
        template.push(t.to_raw());
    }
    // So here's a fun question: does the API require that the memory referred to in template be
    // valid for the lifetime of the find operation? The spec doesn't seem to specify this.
    let result = unsafe {
        (*fs).C_FindObjectsInit.unwrap()(
            args.session_handle,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        )
    };
    Ok(Response::new(result, String::new()))
}

fn c_find_objects(msg: Request, fs: CK_FUNCTION_LIST_PTR) -> Result<Response, serde_json::Error> {
    let mut args: CFindObjectsArgs = from_str(msg.args())?;
    args.objects.reserve(args.max_objects as usize);
    let mut object_count = 0;
    let result = unsafe {
        (*fs).C_FindObjects.unwrap()(
            args.session_handle,
            args.objects.as_mut_ptr(),
            args.max_objects,
            &mut object_count,
        )
    };
    let msg_back = if result == CKR_OK {
        unsafe {
            args.objects.set_len(object_count as usize);
        }
        Response::new(CKR_OK, to_string(&args)?)
    } else {
        Response::new(result, String::new())
    };
    Ok(msg_back)
}

macro_rules! simple_pkcs11_function {
    ($function_name:ident, $arg_type:ty, $pkcs11_function:ident) => {
        fn $function_name(
            msg: Request,
            fs: CK_FUNCTION_LIST_PTR,
        ) -> Result<Response, serde_json::Error> {
            let arg: $arg_type = from_str(msg.args())?;
            let result = unsafe { (*fs).$pkcs11_function.unwrap()(arg) };
            println!("{}: {}", stringify!($pkcs11_function), result);
            Ok(Response::new(result, String::new()))
        }
    };
}

simple_pkcs11_function!(c_find_objects_final, CK_SESSION_HANDLE, C_FindObjectsFinal);
simple_pkcs11_function!(c_close_session, CK_SESSION_HANDLE, C_CloseSession);
simple_pkcs11_function!(c_close_all_sessions, CK_SLOT_ID, C_CloseAllSessions);
simple_pkcs11_function!(c_logout, CK_SESSION_HANDLE, C_Logout);

fn c_get_attribute_value(
    msg: Request,
    fs: CK_FUNCTION_LIST_PTR,
) -> Result<Response, serde_json::Error> {
    let mut args: CGetAttributeValueArgs = from_str(msg.args())?;
    // NB: currently args must outlive template here (things in template point to data in args).
    let mut template = Vec::with_capacity(args.template.len());
    for t in args.template {
        template.push(t.to_raw());
    }
    let result = unsafe {
        (*fs).C_GetAttributeValue.unwrap()(
            args.session_handle,
            args.object_handle,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        )
    };
    let msg_back = if result == CKR_OK {
        args.template = Vec::new();
        for attribute in template {
            args.template.push(Attribute::from_raw(attribute));
        }
        Response::new(CKR_OK, to_string(&args)?)
    } else {
        Response::new(result, String::new())
    };
    Ok(msg_back)
}
