use std::collections::HashMap;
use std::time::SystemTime;

use self::Inner::*;

pub const NONE_KEY: Option<&str> = None;

pub struct PutPolicy {
    inner: HashMap<Name, Value>
}

impl PutPolicy {
    pub fn with_deadline<N, K, T>(bucket: N, key:Option<K>, deadline: T) -> Self 
    where N:AsRef<str>, K:AsRef<str>, T: Into<u64>{
        let mut policy = PutPolicy{
            inner: HashMap::new(),
        };
        let mut scope = String::from(bucket.as_ref());
        if let Some(key) = key {
            scope.push(':');
            scope.push_str(key.as_ref());
        }
        policy.inner.insert(Name::SCOPE, scope.into());
        policy.inner.insert(Name::DEADLINE, Value::Number(deadline.into()));
        policy
    }

    pub fn new<N,K>(bucket: N, key:Option<K>) -> Self 
    where N:AsRef<str>, K:AsRef<str>{
        let now = SystemTime::now();
        let t = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        let deadline = t.as_secs() + 3600;
        Self::with_deadline(bucket, key, deadline)
    }

    pub fn put<N, V>(&mut self, name:N, value:V) -> &mut Self 
    where N: Into<Name>, V: Into<Value>{
        self.inner.insert(name.into(), value.into());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(PartialEq, Eq, std::hash::Hash)]
pub struct Name(Inner);

#[derive(PartialEq, Eq, std::hash::Hash)]
enum Inner {
    Scope,
    IsPrefixalScope,
    Deadline,
    InsertOnly,
    EndUser,
    ReturnUrl,
    ReturnBody,
    CallbackUrl,
    CallbackHost,
    CallbackBody,
    CallbackBodyType,
    PersistentOps,
    PersistentNotifyUrl,
    PersistentPipeline,
    ForcesaveKey,
    SaveKey,
    FsizeMin,
    FsizeLimit,
    DetectMime,
    MimeLimit,
    FileType,
    ExtensionAllocated(AllocatedExtension),
}

impl Name {
    pub const SCOPE: Name = Name(Scope);
    pub const IS_PREFIXAL_SCOPE: Name = Name(IsPrefixalScope);
    pub const DEADLINE: Name = Name(Deadline);
    pub const INSERT_ONLY: Name = Name(InsertOnly);
    pub const END_USER: Name = Name(EndUser);
    pub const RETURN_URL: Name = Name(ReturnUrl);
    pub const RETURN_BODY: Name = Name(ReturnBody);
    pub const CALLBACK_URL: Name = Name(CallbackUrl);
    pub const CALLBACK_HOST: Name = Name(CallbackHost);
    pub const CALLBACK_BODY: Name = Name(CallbackBody);
    pub const CALLBACK_BODY_TYPE: Name = Name(CallbackBodyType);
    pub const PERSISTENT_OPS: Name = Name(PersistentOps);
    pub const PERSISTENT_NOTIFY_URL: Name = Name(PersistentNotifyUrl);
    pub const PERSISTENT_PIPELINE: Name = Name(PersistentPipeline);
    pub const FORCESAVE_KEY: Name = Name(ForcesaveKey);
    pub const SAVE_KEY: Name = Name(SaveKey);
    pub const FSIZE_MIN: Name = Name(FsizeMin);
    pub const FSIZE_LIMIT: Name = Name(FsizeLimit);
    pub const DETECT_MIME: Name = Name(DetectMime);
    pub const MIME_LIMIT: Name = Name(MimeLimit);
    pub const FILE_TYPE: Name = Name(FileType);

    pub fn as_str(&self) -> &str {
        match self.0 {
            Scope => "scope",
            IsPrefixalScope => "isPrefixalScope",
            Deadline => "deadline",
            InsertOnly => "insertOnly",
            EndUser => "endUser",
            ReturnUrl => "returnUrl",
            ReturnBody => "returnBody",
            CallbackUrl => "callbackUrl",
            CallbackHost => "callbackHost",
            CallbackBody => "callbackBody",
            CallbackBodyType => "callbackBodyType",
            PersistentOps => "persistentOps",
            PersistentNotifyUrl => "persistentNotifyUrl",
            PersistentPipeline => "persistentPipeline",
            ForcesaveKey => "forcesaveKey",
            SaveKey => "saveKey",
            FsizeMin => "fsizeMin",
            FsizeLimit => "fsizeLimit",
            DetectMime => "detectMime",
            MimeLimit => "mimeLimit",
            FileType => "fileType",
            ExtensionAllocated(ref allocated) => allocated.as_str(),
        }
    }
}

impl<'a> From<&'a str> for Name {
    fn from(name: &str) -> Self {
        match name {
            "scope" => Name::SCOPE,
            "isPrefixalScope" => Name::IS_PREFIXAL_SCOPE,
            "deadline" => Name::DEADLINE,
            "insertOnly" => Name::INSERT_ONLY,
            "endUser" => Name::END_USER,
            "returnUrl" => Name::RETURN_URL,
            "returnBody" => Name::RETURN_BODY,
            "callbackUrl" => Name::CALLBACK_URL,
            "callbackHost" => Name::CALLBACK_HOST,
            "callbackBody" => Name::CALLBACK_BODY,
            "callbackBodyType" => Name::CALLBACK_BODY_TYPE,
            "persistentOps" => Name::PERSISTENT_OPS,
            "persistentNotifyUrl" => Name::PERSISTENT_NOTIFY_URL,
            "persistentPipeline" => Name::PERSISTENT_PIPELINE,
            "forcesaveKey" => Name::FORCESAVE_KEY,
            "saveKey" => Name::SAVE_KEY,
            "fsizeMin" => Name::FSIZE_MIN,
            "fsizeLimit" => Name::FSIZE_LIMIT,
            "detectMime" => Name::DETECT_MIME,
            "mimeLimit" => Name::MIME_LIMIT,
            "fileType" => Name::FILE_TYPE,
            _ => {
                let allocated = name.into();
                Name(ExtensionAllocated(allocated))
            }
        }
    }
}

impl From<String> for Name {
    fn from(f: String) -> Self {
        Self::from(f.as_ref())
    }
}


impl<'a> From<std::borrow::Cow<'a, str>> for Name {
    fn from(f: std::borrow::Cow<'a, str>) -> Self {
        Name::from(f.as_ref())
    }
}

#[derive(PartialEq, Eq, std::hash::Hash)]
struct AllocatedExtension(String);

impl From<&str> for AllocatedExtension {
    fn from(name: &str) -> Self {
        Self(name.to_string())
    }
}



impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for AllocatedExtension {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AllocatedExtension {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}


pub enum Value {
    String(String),
    Number(u64),
}

macro_rules! from_integer {
    ($($ty:ident)*) => {
        $(
            impl From<$ty> for Value {
                fn from(n: $ty) -> Self {
                    Value::Number(n as u64)
                }
            }
        )*
    };
}

from_integer! {
    i8 i16 i32 i64 isize
    u8 u16 u32 u64 usize
}


impl From<String> for Value {
    fn from(f: String) -> Self {
        Value::String(f)
    }
}

impl<'a> From<&'a str> for Value {
    fn from(f: &str) -> Self {
        Value::String(f.to_string())
    }
}

impl<'a> From<std::borrow::Cow<'a, str>> for Value {
    fn from(f: std::borrow::Cow<'a, str>) -> Self {
        Value::String(f.into_owned())
    }
}

impl serde::Serialize for PutPolicy{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.inner.len()))?;
        for (k, v) in &self.inner {
            serde::ser::SerializeMap::serialize_entry(&mut map, k, v)?;
        }
        serde::ser::SerializeMap::end(map)
    }
}


impl serde::Serialize for Name{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl serde::Serialize for Value{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::String(v) => serializer.serialize_str(v.as_str()),
            Value::Number(v) => serializer.serialize_u64(*v),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let mut policy = PutPolicy::new("litic", Some("key"));
        policy.put("xxxx", 1).put(Name::PERSISTENT_PIPELINE, "sjfiede");
        let json = policy.to_json();
        println!("{json}");


        let mut policy = PutPolicy::new("litic", NONE_KEY);
        policy.put(Name::PERSISTENT_PIPELINE, "sjfiede");
        let json = policy.to_json();
        println!("{json}");
    }
}
