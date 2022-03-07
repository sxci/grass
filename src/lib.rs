pub mod urlsafe_base64;
pub mod auth;
pub use auth::*;
pub mod put_policy;
pub use put_policy::*;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
        urlsafe_base64::encode("result");
    }
}
