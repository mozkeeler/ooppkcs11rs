extern crate byteorder;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate ooppkcs11rs_types;
extern crate serde_json;
extern crate timeout_readwrite;

mod ipc;
mod pkcs11;
mod pkcs11parent;

use ooppkcs11rs_types::*;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *ppFunctionList = &pkcs11parent::FUNCTION_LIST;
    }
    CKR_OK
}
