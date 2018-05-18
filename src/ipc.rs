use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{from_str, to_string};
use std::io::{Error, ErrorKind, Read, Write};

pub struct IpcSender<W: Write> {
    writer: W,
}

impl<W: Write> IpcSender<W> {
    pub fn new(writer: W) -> IpcSender<W> {
        IpcSender { writer }
    }

    pub fn send<T: Serialize>(&mut self, object: T) -> Result<(), Error> {
        let serialized = to_string(&object).map_err(|e| Error::new(ErrorKind::Other, e))?;
        let len = serialized.len();
        if len > <u32>::max_value() as usize {
            return Err(Error::new(
                ErrorKind::Other,
                format!("couldn't send serialized object of length {}", len),
            ));
        }
        self.writer.write_u32::<NetworkEndian>(len as u32)?;
        self.writer.write_all(serialized.as_bytes())?;
        self.writer.flush()
    }
}

pub struct IpcReceiver<R: Read> {
    reader: R,
}

impl<R: Read> IpcReceiver<R> {
    pub fn new(reader: R) -> IpcReceiver<R> {
        IpcReceiver { reader }
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> Result<T, Error> {
        let len = self.reader.read_u32::<NetworkEndian>()? as usize;
        let mut buf = Vec::with_capacity(len);
        buf.resize(len, 0);
        self.reader.read_exact(&mut buf)?;
        let string = String::from_utf8(buf).map_err(|e| Error::new(ErrorKind::Other, e))?;
        from_str(&string).map_err(|e| Error::new(ErrorKind::Other, e))
    }
}
