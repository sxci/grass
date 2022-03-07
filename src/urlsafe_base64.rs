
pub type DecodeError = base64::DecodeError;

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::encode_config(input, base64::URL_SAFE)
}

pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, DecodeError> {
    base64::decode_config(input, base64::URL_SAFE)
}
