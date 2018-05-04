#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    name: String,
    payload: String,
}

impl Message {
    pub fn new(function_name: &'static str) -> Message {
        Message {
            name: String::from(function_name),
            payload: String::new(),
        }
    }

    pub fn new_from_string(name: String) -> Message {
        Message { name, payload: String::new() }
    }

    pub fn new_with_payload(name: &'static str, payload: String) -> Message {
        Message { name: String::from(name), payload }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn payload(&self) -> &str {
        &self.payload
    }
}
