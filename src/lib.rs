extern crate ipc_channel;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

mod pkcs11;
mod pkcs11parent;
mod pkcs11types;

use pkcs11types::*;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    unsafe {
        *ppFunctionList = &pkcs11parent::FUNCTION_LIST;
    }
    CKR_OK
}
