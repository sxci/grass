use crate::{urlsafe_base64, PutPolicy};
use ring::hmac;

use thiserror::Error;

pub const NONE_CONTENT_TYPE: Option<&str> = None;
pub const NONE_BODY: Option<&[u8]> = None;

#[derive(Error, Debug)]
pub enum SignError {
    #[error("Infallible")]
    _Infallible(#[from] core::convert::Infallible),
    #[error("invalid content-type")]
    InvalidContentType(#[from] http::header::InvalidHeaderValue),
    #[error("invalid method")]
    InvalidMethod(#[from] http::method::InvalidMethod),
    #[error("invalid url")]
    InvalidUrl(#[from] url::ParseError),
    // #[error("other error")]
    // Other(#[from] Box<dyn std::error::Error>),

    // #[error("the data for key `{0}` is not available")]
    // Redaction(String),
    // #[error("invalid header (expected {expected:?}, found {found:?})")]
    // InvalidHeader {
    //     expected: String,
    //     found: String,
    // },
    // #[error("unknown data store error")]
    // Unknown,
}

pub struct Auth {
    sk: hmac::Key,
    ak: String,
}

impl Auth {
    pub fn new(ak: &str, sk: &str) -> Self {
        let ak: String = String::from(ak);
        let sk: hmac::Key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, sk.as_bytes());
        Auth { sk, ak }
    }

    pub fn sign_raw<T: AsRef<[u8]>>(&self, data: T) -> String {
        let tag = hmac::sign(&self.sk, data.as_ref());
        let sign = urlsafe_base64::encode(tag.as_ref());
        sign
    }

    pub fn sign_qiniu_token<M, U, T, B>(
        &self,
        method: M,
        url: U,
        content_type: Option<T>,
        body: Option<B>,
    ) -> Result<String, SignError>
    where
        M: TryInto<http::Method>,
        M::Error: Into<SignError>,
        U: TryInto<url::Url>,
        U::Error: Into<SignError>,
        T: TryInto<http::HeaderValue>,
        T::Error: Into<SignError>,
        B: AsRef<[u8]>,
    {
        let buf = self.qiniu_token_data(method, url, content_type, body)?;

        let mut token = String::with_capacity(69);
        token.push_str("Qiniu ");
        token.push_str(&self.ak);
        token.push(':');
        token.push_str(&self.sign_raw(buf));
        Ok(token)
    }

    fn qiniu_token_data<M, U, T, B>(
        &self,
        method: M,
        url: U,
        content_type: Option<T>,
        body: Option<B>,
    ) -> Result<Vec<u8>, SignError>
    where
        M: TryInto<http::Method>,
        M::Error: Into<SignError>,
        U: TryInto<url::Url>,
        U::Error: Into<SignError>,
        T: TryInto<http::HeaderValue>,
        T::Error: Into<SignError>,
        B: AsRef<[u8]>,
    {
        let method: http::Method = method.try_into().map_err(Into::into)?;
        let url: url::Url = url.try_into().map_err(Into::into)?;
        let content_type = if let Some(content_type) = content_type {
            Some(content_type.try_into().map_err(Into::into)?)
        } else {
            None
        };
        let mut buf = vec![];
        buf.extend(method.as_str().as_bytes());
        buf.push(b' ');
        buf.extend(url.path().as_bytes());
        if let Some(query) = url.query() {
            buf.push(b'?');
            buf.extend(query.as_bytes());
        }
        buf.extend(b"\nHost: ");
        if let Some(host) = url.host_str() {
            buf.extend(host.as_bytes())
        } else {
            return Err(url::ParseError::EmptyHost.into());
        }
        if let Some(content_type) = &content_type {
            buf.extend(b"\nContent-Type: ");
            buf.extend(content_type.as_bytes())
        }
        buf.push(b'\n');
        buf.push(b'\n');
        if let (Some(body), Some(content_type)) = (body, content_type) {
            if content_type.as_bytes() != b"application/octet-stream" {
                buf.extend(body.as_ref())
            }
        }
        Ok(buf)
    }

    pub fn sing_upload_token_with_policy(&self, policy:&PutPolicy) -> String{
        let json = policy.to_json();
        let sign = self.sign_raw(&json);
        let mut token = String::from(&self.ak);
        token.push(':');
        token.push_str(&sign);
        token.push(':');
        token.push_str(&json);
        token
    }

    pub fn sing_upload_token_with_deadline<N, K, T>(&self, bucket: N, key:Option<K>, deadline: T) -> String 
    where N:AsRef<str>, K:AsRef<str>, T: Into<u64>{
        let policy = PutPolicy::with_deadline(bucket, key, deadline);
        self.sing_upload_token_with_policy(&policy)
    }

    pub fn sing_upload_token<N, K, T>(&self, bucket: N, key:Option<K>) -> String 
    where N:AsRef<str>, K:AsRef<str>, T: Into<u64>{
        let policy = PutPolicy::new(bucket, key);
        self.sing_upload_token_with_policy(&policy)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sign_as_ref<CType>(content_type: CType) -> Result<String, SignError>
    where
        CType: AsRef<[u8]>,
    {
        let ctype = http::HeaderValue::from_bytes(content_type.as_ref())?;
        Ok(ctype.to_str().unwrap().to_string())
    }

    fn sign_try_into<CType>(content_type: CType) -> Result<String, SignError>
    where
        CType: TryInto<http::HeaderValue>,
        CType::Error: Into<SignError>,
    {
        let ctype: http::HeaderValue = content_type.try_into().map_err(Into::into)?;
        Ok(ctype.to_str().unwrap().to_string())
    }

    #[allow(dead_code)]
    fn a() -> Result<String, SignError> {
        let header0 = "text/html";
        let header1 = http::HeaderValue::from_str(header0).unwrap();
        let header2 = b"text/html";
        sign_as_ref(&header0)?;
        sign_as_ref(header0)?;
        sign_as_ref(&header1)?;
        sign_as_ref(header1)?;
        sign_as_ref(&header2)?;
        sign_as_ref(header2)?;

        let header1: http::HeaderValue = header0.parse().unwrap();
        sign_try_into(header0)?;
        sign_try_into(&header1)?;
        sign_try_into(header1)?;
        sign_try_into(&header2[..])?;
        sign_try_into(header2.as_ref())?;

        Ok("".to_string())
    }

    #[test]
    fn muti_sign() {
        let ak = "test_ak";
        let sk = "test_sk";
        let auth = Auth::new(ak, sk);
        let data = b"cnudfhjeuHuef3& jsdife(ske2dlggtowkJDKSWE";
        let s1 = auth.sign_raw(data);
        let s2 = auth.sign_raw(data);
        let s3 = auth.sign_raw(data.as_ref());
        assert_eq!(s1, s2);
        assert_eq!(s1, s3);
    }

    #[test]
    fn sign1() {
        let dummy_access_key = "abcdefghklmnopq";
        let dummy_secret_key = "1234567890";
        let auth = Auth::new(dummy_access_key, dummy_secret_key);
        let token = auth.sign_raw(b"test");
        println!("{token}");
        assert_eq!("mSNBTR7uS2crJsyFr2Amwv1LaYg=", token);

        let method = http::Method::POST;
        let url = "http://sdfd.api.qiniu.com/sdfe/hubs/hhxd/f?start=1234556";
        let content_type = "application/json";
        let body = b"{\"sdfjefdkmkfjgkdsdfevfd984594\": \"dfj832cmad2923\"}";
        let token = auth.sign_qiniu_token(&method, url, Some(content_type), Some(body));
        println!("{:?}", token);
        assert_eq!(
            "Qiniu abcdefghklmnopq:0sCQ2yz6nsQeVT2E7Rk0qxWp8Y8=",
            token.unwrap()
        );

        let content_type = "application/octet-stream";
        let token = auth.sign_qiniu_token("POST", url, Some(content_type), Some(body));
        println!("{:?}", token);
        assert!(token.is_ok());
        if let Ok(t) = token {
            assert_eq!("Qiniu abcdefghklmnopq:VSnCW9LpK1xhuxdKMr4fE_SJHuU=", t);
        }

        let url = url::Url::parse(url).unwrap();
        let token = auth.sign_qiniu_token(method, url, Some(content_type), NONE_BODY);
        println!("{:?}", token);
        assert!(token.is_ok());
        if let Ok(t) = token {
            assert_eq!("Qiniu abcdefghklmnopq:VSnCW9LpK1xhuxdKMr4fE_SJHuU=", t);
        }
    }
}
