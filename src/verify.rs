use hmac::{Hmac, Mac};
use sha2::Sha256;

type HS256 = Hmac<Sha256>;

fn verify(secret: &str, message: &str, signature: &str) -> Result<(), hmac::digest::MacError> {
    let mut mac = HS256::new_from_slice(secret.as_bytes()).expect("Failed to make HMAC");

    mac.update(message.as_bytes());

    mac.verify_slice(signature.as_bytes())
}

fn sign(secret: &str, message: &str) {
    let mut mac = HS256::new_from_slice(secret.as_bytes()).expect("Failed to make HMAC");

    mac.update(message.as_bytes());

    let result = mac.finalize();
    println!("{:?}", result.clone().into_bytes());
    // let res_string = std::str::from_utf8(&result).unwrap();
    let res_string = String::from_utf8((&result.into_bytes()).to_vec()).unwrap();
    println!("{:?}", res_string);
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;

    #[test]
    fn test_verify() -> Result<()> {
        let message = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        let signature = "hi1kB39QtSPbzifU9ZreDAB-5fnmO54Vcd4PY1UQCpE";

        let secret = "iamawesome";

        assert!(verify(secret, &message, signature).is_ok());

        Ok(())
    }

    #[test]
    fn test_sign() -> Result<()> {
        let secret = "secretkey";

        let message = "secretmessage";

        let expected = "b7d022bab260d05e9be02fcde4a0f6832a64e6c626e5b8bd2e7ce818107edee7";

        sign(secret, message);
        assert!(1 == 2);

        // assert!(verify(secret, &message, signature).is_ok());

        Ok(())
    }
}
