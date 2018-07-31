// Why do I need these here when I don't need them elsewhere?
use std::os;
use std::ptr;
use ooppkcs11rs_types::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    function: String,
    args: String,
}

impl Request {
    // This is used in the parent but not the child.
    #[allow(dead_code)]
    pub fn new(function: &'static str, args: String) -> Request {
        Request {
            function: String::from(function),
            args,
        }
    }

    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn function(&self) -> &str {
        &self.function
    }

    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn args(&self) -> &str {
        &self.args
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    status: CK_RV,
    args: String,
}

impl Response {
    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn new(status: CK_RV, args: String) -> Response {
        Response { status, args }
    }

    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn status(&self) -> CK_RV {
        self.status
    }

    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn args(&self) -> &str {
        &self.args
    }
}

#[derive(Deserialize, Serialize)]
pub struct CGetSlotListArgs {
    pub token_present: CK_BBOOL,
    pub slot_list: Option<Vec<CK_SLOT_ID>>,
    pub slot_count: CK_ULONG,
}

#[derive(Deserialize, Serialize)]
pub struct CGetMechanismListArgs {
    pub slot_id: CK_SLOT_ID,
    pub mechanism_list: Option<Vec<CK_MECHANISM_TYPE>>,
    pub mechanism_count: CK_ULONG,
}

#[derive(Deserialize, Serialize)]
pub struct COpenSessionArgs {
    pub slot_id: CK_SLOT_ID,
    pub flags: CK_FLAGS,
    pub session_handle: CK_SESSION_HANDLE,
}

#[derive(Deserialize, Serialize)]
pub struct Attribute {
    pub type_: CK_ATTRIBUTE_TYPE,
    pub value: Option<Vec<u8>>,
    pub len: CK_ULONG,
}

impl Attribute {
    pub fn from_raw(attribute: CK_ATTRIBUTE) -> Attribute {
        let value = if !attribute.pValue.is_null() {
            let byte_ptr = attribute.pValue as *const u8;
            let mut value = Vec::with_capacity(attribute.ulValueLen as usize);
            unsafe {
                for i in 0..attribute.ulValueLen {
                    value.push(*byte_ptr.offset(i as isize));
                }
            }
            Some(value)
        } else {
            None
        };
        Attribute {
            type_: attribute.type_,
            value,
            len: attribute.ulValueLen,
        }
    }

    // TODO: really we want to enforce that self lives longer than the value returned. I think we
    // could do this by adding a lifetime parameter to CK_ATTRIBUTE, but I don't want to change that
    // type since it's part of the PKCS#11 API. Could we use a helper/wrapper in some way?
    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn to_raw(&self) -> CK_ATTRIBUTE {
        let ptr = match self.value {
            Some(ref value) => value.as_ptr() as CK_VOID_PTR,
            None => ptr::null::<os::raw::c_void>() as CK_VOID_PTR,
        };
        CK_ATTRIBUTE {
            type_: self.type_,
            pValue: ptr,
            ulValueLen: self.len,
        }
    }

    // This is used in the parent but not the child.
    #[allow(dead_code)]
    pub fn into_raw(&self, attribute: *mut CK_ATTRIBUTE) {
        match self.value {
            Some(ref value) => unsafe {
                let ptr = (*attribute).pValue as *mut u8;
                if !ptr.is_null() {
                    for i in 0..self.len {
                        (*ptr.offset(i as isize)) = value[i as usize];
                    }
                }
            },
            None => {}
        }
        unsafe {
            (*attribute).type_ = self.type_;
            (*attribute).ulValueLen = self.len;
        }
    }
}

// This is silly - we should be able to parameterize/macro this.
#[derive(Deserialize, Serialize)]
pub struct Mechanism {
    pub mechanism: CK_MECHANISM_TYPE,
    pub parameter: Option<Vec<u8>>,
    pub len: CK_ULONG,
}

impl Mechanism {
    // This is used in the parent but not the child.
    #[allow(dead_code)]
    pub fn from_raw(mechanism: CK_MECHANISM) -> Mechanism {
        let parameter = if !mechanism.pParameter.is_null() {
            let byte_ptr = mechanism.pParameter as *const u8;
            let mut parameter = Vec::with_capacity(mechanism.ulParameterLen as usize);
            unsafe {
                for i in 0..mechanism.ulParameterLen {
                    parameter.push(*byte_ptr.offset(i as isize));
                }
            }
            Some(parameter)
        } else {
            None
        };
        Mechanism {
            mechanism: mechanism.mechanism,
            parameter,
            len: mechanism.ulParameterLen,
        }
    }

    // This is used in the child but not the parent.
    #[allow(dead_code)]
    pub fn to_raw(&self) -> CK_MECHANISM {
        let ptr = match self.parameter {
            Some(ref parameter) => parameter.as_ptr() as CK_VOID_PTR,
            None => ptr::null::<os::raw::c_void>() as CK_VOID_PTR,
        };
        CK_MECHANISM {
            mechanism: self.mechanism,
            pParameter: ptr,
            ulParameterLen: self.len,
        }
    }

    // This is used in the parent but not the child.
    #[allow(dead_code)]
    pub fn into_raw(&self, mechanism: *mut CK_MECHANISM) {
        match self.parameter {
            Some(ref parameter) => unsafe {
                let ptr = (*mechanism).pParameter as *mut u8;
                if !ptr.is_null() {
                    for i in 0..self.len {
                        (*ptr.offset(i as isize)) = parameter[i as usize];
                    }
                }
            },
            None => {}
        }
        unsafe {
            (*mechanism).mechanism = self.mechanism;
            (*mechanism).ulParameterLen = self.len;
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct CFindObjectsInitArgs {
    pub session_handle: CK_SESSION_HANDLE,
    pub template: Vec<Attribute>,
}

#[derive(Deserialize, Serialize)]
pub struct CFindObjectsArgs {
    pub session_handle: CK_SESSION_HANDLE,
    pub objects: Vec<CK_OBJECT_HANDLE>,
    pub max_objects: CK_ULONG,
}

#[derive(Deserialize, Serialize)]
pub struct CGetAttributeValueArgs {
    pub session_handle: CK_SESSION_HANDLE,
    pub object_handle: CK_OBJECT_HANDLE,
    pub template: Vec<Attribute>,
}

#[derive(Deserialize, Serialize)]
pub struct CGenerateRandomArgs {
    pub session_handle: CK_SESSION_HANDLE,
    pub data: Vec<CK_BYTE>,
    pub length: CK_ULONG,
}
