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
use serde_json::to_string;
use std::io::{self, Error, ErrorKind, Read};


mod pkcs11;

mod pkcs11types;
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
    let tx: IpcSender<pkcs11::Message> = IpcSender::connect(server_name).unwrap();
    let (server, name): (IpcOneShotServer<pkcs11::Message>, String) =
        IpcOneShotServer::new().unwrap();
    println!("sending server name to parent");
    tx.send(pkcs11::Message::new_from_string(name))
        .expect("couldn't send server name to parent");
    println!("waiting for parent to connect");
    let (rx, msg): (IpcReceiver<pkcs11::Message>, pkcs11::Message) = server.accept().unwrap();
    println!("{:?}", msg);
    if msg.name() != "C_Initialize" {
        panic!("unexpected first message from parent");
    }
    let mut module: Container<Pkcs11Module> = unsafe {
        //Container::load("/usr/lib64/libykcs11.so.1") // YKCS11 is failing?
        Container::load("/usr/lib64/libnssckbi.so")
    }.unwrap();
    let mut function_list_ptr: CK_FUNCTION_LIST_PTR = std::ptr::null();
    module.C_GetFunctionList(&mut function_list_ptr);
    let result = unsafe {
        let null_args = std::ptr::null::<CK_C_INITIALIZE_ARGS>();
        (*function_list_ptr).C_Initialize.unwrap()(null_args as *mut CK_C_INITIALIZE_ARGS)
    };
    println!("result from C_Initialize was {}", result);
    let msg_back = if result == CKR_OK {
        pkcs11::Message::new("ACK")
    } else {
        pkcs11::Message::new("NAK")
    };
    tx.send(msg_back).unwrap();

    loop {
        let msg = rx.recv().unwrap();
        println!("need to dispatch to {}", msg.name());
        if msg.name() == "C_GetInfo" {
            c_get_info(&tx, function_list_ptr);
        } else {
            let msg_back = pkcs11::Message::new("ACK");
            tx.send(msg_back).unwrap();
        }
        if msg.name() == "C_Finalize" {
            break;
        }
    }
}

fn c_get_info(tx: &IpcSender<pkcs11::Message>, fs: CK_FUNCTION_LIST_PTR) {
    let mut ck_info = CK_INFO {
        cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
        manufacturerID: [0; 32usize],
        flags: 0,
        libraryDescription: [0; 32usize],
        libraryVersion: CK_VERSION { major: 0, minor: 0 },
    };
    let result = unsafe {
        (*fs).C_GetInfo.unwrap()(&mut ck_info)
    };
    println!("C_GetInfo: {}", result);
    let msg_back = if result == CKR_OK {
        pkcs11::Message::new_with_payload("ACK", to_string(&ck_info).unwrap())
    } else {
        pkcs11::Message::new("NAK")
    };
    tx.send(msg_back).unwrap();
}
