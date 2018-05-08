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
    pub token_present: bool,
    pub slot_list: Option<Vec<CK_SLOT_ID>>,
    pub slot_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct CGetMechanismListArgs {
    pub slot_id: CK_SLOT_ID,
    pub mechanism_list: Option<Vec<CK_MECHANISM_TYPE>>,
    pub mechanism_count: usize,
}
