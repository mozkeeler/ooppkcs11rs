#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    name: String,
}

impl Message {
    pub fn new(function_name: &'static str) -> Message {
        Message {
            name: String::from(function_name),
        }
    }

    pub fn new_from_string(name: String) -> Message {
        Message { name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}
