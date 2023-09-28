use anyhow::{bail, Result};
use chrono::{DateTime, Local};
use serde_json::{json, Value};

fn get_parts(jwt: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = jwt.split('.').map(|s| s.to_string()).collect();
    if parts.len() != 3 {
        bail!("JWT has invalid length")
    }
    Ok(parts)
}

fn decode_part(part: &str) -> Result<Value> {
    let part_utf8 = base64::decode(part)?;
    let part_str = std::str::from_utf8(&part_utf8)?.to_string();
    let part_json = serde_json::from_str(&part_str)?;
    Ok(part_json)
}

pub fn read_jwt(jwt: &str) -> Result<Value> {
    let parts = get_parts(jwt)?;
    let header = decode_part(&parts[0])?;
    let mut payload = decode_part(&parts[1])?;

    convert_unix_time(&mut payload, "iat");
    convert_unix_time(&mut payload, "exp");
    convert_unix_time(&mut payload, "nbf");

    let jwt_decoded = json!({
        "header": header,
        "payload": payload,
    });
    Ok(jwt_decoded)
}

/// Converts the given `key` field from a unix timestamp to a local date string
fn convert_unix_time(payload: &mut Value, key: &str) {
    if let Some(iat) = payload.get_mut(key) {
        if let Some(iat_i64) = iat.as_i64() {
            if let Some(dt) = DateTime::from_timestamp(iat_i64, 0) {
                let localtime: DateTime<Local> = dt.into();
                *iat = serde_json::json!(localtime.to_string())
            }
        }
    }
}

pub fn print_colored(jwt: Value) {
    let output = colored_json::to_colored_json_auto(&jwt).unwrap_or_else(|_| "".into());

    println!("{}", output);
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use serde_json::json;

    static JWT_HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    static JWT_PAYLOAD: &str =
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
    static JWT_SIGNATURE: &str = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn test_get_parts() -> Result<()> {
        let good_jwt = [JWT_HEADER, JWT_PAYLOAD, JWT_SIGNATURE].join(".");

        let parts = get_parts(&good_jwt)?;

        assert_eq!(parts[0], JWT_HEADER);
        assert_eq!(parts[1], JWT_PAYLOAD);
        assert_eq!(parts[2], JWT_SIGNATURE);

        assert!(get_parts("notjwt").is_err());

        Ok(())
    }

    #[test]
    fn test_decode_part() -> Result<()> {
        let header = json!({
            "alg": "HS256",
            "typ": "JWT",
        });

        let payload = json!(
            {
                "sub" : "1234567890",
                "name" : "John Doe",
                "iat" : 1516239022
            }
        );

        assert_eq!(decode_part(JWT_HEADER).unwrap(), header);
        assert_eq!(decode_part(JWT_PAYLOAD).unwrap(), payload);

        Ok(())
    }
}
