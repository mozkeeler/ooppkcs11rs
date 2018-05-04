#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate ipc_channel;

use ipc_channel::ipc::{self, IpcOneShotServer, IpcReceiver, IpcSender};
use std::io::{self, Error, ErrorKind, Read, Result};

mod pkcs11;

// The ChildStdin in the parent process is supposed to close our stdin after sending the name of the
// ipc server. For some reason this isn't happening correctly, so reading until we're closed doesn't
// work. As a workaround, read until we hit a null byte.
fn read_string_from_stdin() -> Result<String> {
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
    let msg_back = pkcs11::Message::new("ACK");
    tx.send(msg_back).unwrap();
}
