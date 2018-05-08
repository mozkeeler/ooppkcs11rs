use pkcs11types::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    function: String,
    args: String,
}

impl Request {
    pub fn new(function: &'static str, args: String) -> Request {
        Request {
            function: String::from(function),
            args,
        }
    }

    pub fn function(&self) -> &str {
        &self.function
    }

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
    pub fn new(status: CK_RV, args: String) -> Response {
        Response { status, args }
    }

    pub fn status(&self) -> CK_RV {
        self.status
    }

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
    pub value: Vec<u8>,
}

impl Attribute {
    pub fn from_raw(attribute: CK_ATTRIBUTE) -> Attribute {
        let mut value = Vec::with_capacity(attribute.ulValueLen as usize);
        let byte_ptr = attribute.pValue as *const u8;
        unsafe {
            for i in 0..attribute.ulValueLen {
                value.push(*byte_ptr.offset(i as isize));
            }
        }
        Attribute {
            type_: attribute.type_,
            value,
        }
    }

    // TODO: really we want to enforce that self lives longer than the value returned. I think we
    // could do this by adding a lifetime parameter to CK_ATTRIBUTE, but I don't want to change that
    // type since it's part of the PKCS#11 API. Could we use a helper/wrapper in some way?
    pub fn to_raw(&self) -> CK_ATTRIBUTE {
        CK_ATTRIBUTE {
            type_: self.type_,
            pValue: self.value.as_ptr() as CK_VOID_PTR,
            ulValueLen: self.value.len() as CK_ULONG,
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
