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

    loop {
        let msg = match rx.recv() {
            Ok(msg) => msg,
            Err(e) => {
                println!("error receiving request from parent: {}", e);
                return;
            }
        };
        println!("child received {:?}", msg);
        match msg.function() {
            "C_Finalize" => {
                c_finalize(&tx, function_list_ptr);
                break;
            }
            "C_GetInfo" => c_get_info(&tx, function_list_ptr),
            "C_GetSlotList" => c_get_slot_list(&tx, msg, function_list_ptr),
            "C_GetSlotInfo" => c_get_slot_info(&tx, msg, function_list_ptr),
            "C_GetTokenInfo" => c_get_token_info(&tx, msg, function_list_ptr),
            "C_GetMechanismList" => c_get_mechanism_list(&tx, msg, function_list_ptr),
            "C_OpenSession" => c_open_session(&tx, msg, function_list_ptr),
            "C_FindObjectsInit" => c_find_objects_init(&tx, msg, function_list_ptr),
            "C_FindObjects" => c_find_objects(&tx, msg, function_list_ptr),
            "C_FindObjectsFinal" => c_find_objects_final(&tx, msg, function_list_ptr),
            "C_CloseAllSessions" => c_close_all_sessions(&tx, msg, function_list_ptr),
            "C_GetAttributeValue" => c_get_attribute_value(&tx, msg, function_list_ptr),
            _ => {
                let msg_back = Response::new(CKR_FUNCTION_NOT_SUPPORTED, String::new());
                tx.send(msg_back).unwrap();
            }
        }
    }
}

fn c_finalize(tx: &IpcSender<Response>, fs: CK_FUNCTION_LIST_PTR) {
    let result = unsafe {
        (*fs).C_Finalize.unwrap()(std::ptr::null::<std::os::raw::c_void>() as CK_VOID_PTR)
    };
    tx.send(Response::new(result, String::new())).unwrap();
}

fn c_get_info(tx: &IpcSender<Response>, fs: CK_FUNCTION_LIST_PTR) {
    let mut ck_info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32usize],
        flags: 0,
        libraryDescription: [0; 32usize],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    let result = unsafe { (*fs).C_GetInfo.unwrap()(&mut ck_info) };
    println!("C_GetInfo: {}", result);
    let msg_back = if result == CKR_OK {
        Response::new(CKR_OK, to_string(&ck_info).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_get_slot_list(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let mut args: CGetSlotListArgs = from_str(msg.args()).unwrap();
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
        Response::new(CKR_OK, to_string(&args).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_get_slot_info(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let slot_id: CK_SLOT_ID = from_str(msg.args()).unwrap();
    let mut slot_info = CK_SLOT_INFO {
        slotDescription1: [0; 32usize],
        slotDescription2: [0; 32usize],
        manufacturerID: [0; 32usize],
        flags: 0,
        hardwareVersion: CK_VERSION { major: 0, minor: 0 },
        firmwareVersion: CK_VERSION { major: 0, minor: 0 },
    };
    let result = unsafe { (*fs).C_GetSlotInfo.unwrap()(slot_id, &mut slot_info) };
    println!("C_GetSlotInfo: {}", result);
    let msg_back = if result == CKR_OK {
        Response::new(CKR_OK, to_string(&slot_info).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_get_token_info(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let slot_id: CK_SLOT_ID = from_str(msg.args()).unwrap();
    let mut token_info = CK_TOKEN_INFO {
        label: [0; 32usize],
        manufacturerID: [0; 32usize],
        model: [0; 16usize],
        serialNumber: [0; 16usize],
        flags: 0,
        ulMaxSessionCount: 0,
        ulSessionCount: 0,
        ulMaxRwSessionCount: 0,
        ulRwSessionCount: 0,
        ulMaxPinLen: 0,
        ulMinPinLen: 0,
        ulTotalPublicMemory: 0,
        ulFreePublicMemory: 0,
        ulTotalPrivateMemory: 0,
        ulFreePrivateMemory: 0,
        hardwareVersion: CK_VERSION { major: 0, minor: 0 },
        firmwareVersion: CK_VERSION { major: 0, minor: 0 },
        utcTime: [0; 16usize],
    };
    let result = unsafe { (*fs).C_GetTokenInfo.unwrap()(slot_id, &mut token_info) };
    println!("C_GetTokenInfo: {}", result);
    let msg_back = if result == CKR_OK {
        Response::new(CKR_OK, to_string(&token_info).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_get_mechanism_list(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let mut args: CGetMechanismListArgs = from_str(msg.args()).unwrap();
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
        Response::new(CKR_OK, to_string(&args).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_open_session(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let mut args: COpenSessionArgs = from_str(msg.args()).unwrap();
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
        Response::new(CKR_OK, to_string(&args).unwrap())
    } else {
        Response::new(result, String::new())
    };
    tx.send(msg_back).unwrap();
}

fn c_find_objects_init(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let args: CFindObjectsInitArgs = from_str(msg.args()).unwrap();
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
    tx.send(Response::new(result, String::new())).unwrap();
}

fn c_find_objects(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let mut args: CFindObjectsArgs = from_str(msg.args()).unwrap();
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
    if result == CKR_OK {
        unsafe {
            args.objects.set_len(object_count as usize);
        }
        tx.send(Response::new(CKR_OK, to_string(&args).unwrap()))
            .unwrap();
    } else {
        tx.send(Response::new(result, String::new())).unwrap();
    }
}

fn c_find_objects_final(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let session_handle: CK_SESSION_HANDLE = from_str(msg.args()).unwrap();
    let result = unsafe { (*fs).C_FindObjectsFinal.unwrap()(session_handle) };
    tx.send(Response::new(result, String::new())).unwrap();
}

fn c_close_all_sessions(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let slot_id: CK_SLOT_ID = from_str(msg.args()).unwrap();
    let result = unsafe { (*fs).C_CloseAllSessions.unwrap()(slot_id) };
    tx.send(Response::new(result, String::new())).unwrap();
}

fn c_get_attribute_value(tx: &IpcSender<Response>, msg: Request, fs: CK_FUNCTION_LIST_PTR) {
    let mut args: CGetAttributeValueArgs = from_str(msg.args()).unwrap();
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
    if result == CKR_OK {
        args.template = Vec::new();
        for attribute in template {
            args.template.push(Attribute::from_raw(attribute));
        }
        tx.send(Response::new(CKR_OK, to_string(&args).unwrap()))
            .unwrap();
    } else {
        tx.send(Response::new(result, String::new())).unwrap();
    }
}
