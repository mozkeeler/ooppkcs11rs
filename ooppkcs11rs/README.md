ooppkcs11rs
-----
This is a rust implementation of a PKCS#11 module that will load another PKCS#11 module in a separate process
("out-of-process PKCS#11 in Rust"). The eventual goal is that this provides a safe\(r\) way of providing PKCS#11
support. If a 3rd party module hangs or crashes, the incorporating application should be able to recover.

The PKCS#11 specification can currently be found at <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html>

The API defined in C can be found at <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/csprd01/include/pkcs11-v2.40/>

(these files are not included here directly because their license may not be compatible with this one)

HOWTO
-----
First install or build the ooppkcs11rs binary and module with `cargo build`. Then set the environment variable
`OOPPKCS11RS_BINARY_PATH` to the location of the binary (`ooppkcs11rs` on Linux). Instruct the application wishing to
load a PKCS#11 module (referred to as the "target module" for simplicity) to load the ooppkcs11rs module
(`libooppkcs11rs.so` on Linux). If possible, point the `pReserved` argument to `C_Initialize` to the path to the target
module. Otherwise, set the environment variable `OOPPKCS11RS_LOAD_THIS` to the location of the target module. If
everything goes according to plan, the incorporating application will load the ooppkcs11rs module, which will spawn a
child process to run the ooppkcs11rs binary, which will load the target module.
