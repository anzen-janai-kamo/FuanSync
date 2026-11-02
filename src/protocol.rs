use crate::Result;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

pub fn validate_input(mut input: impl BufRead) -> Result<()> {
    let mut protocol = None;
    let mut host = None;
    let mut total = 0usize;
    loop {
        let mut line = Zeroizing::new(Vec::new());
        let length = input
            .by_ref()
            .take(64 * 1024 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "cannot read Git credential input")?;
        total += length;
        if total > 64 * 1024 {
            return Err("Git credential input exceeds limit");
        }
        if length == 0 {
            break;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            break;
        }
        let split = line
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or("malformed Git credential input")?;
        let (key, rest) = line.split_at(split);
        let value = &rest[1..];
        match key {
            b"protocol" => {
                if protocol.replace(value == b"https").is_some() {
                    return Err("duplicate protocol field");
                }
            }
            b"host" if host.replace(value == b"github.com").is_some() => {
                return Err("duplicate host field");
            }
            _ => {}
        }
    }
    if protocol != Some(true) || host != Some(true) {
        return Err("only protocol=https and host=github.com are supported");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_origin_and_no_echo() {
        for good in [
            "protocol=https\nhost=github.com\n\n",
            "host=github.com\r\nprotocol=https\r\npath=ignored\r\npassword=secret\r\n\r\n",
        ] {
            assert!(validate_input(good.as_bytes()).is_ok());
        }
        for bad in [
            "protocol=http\nhost=github.com\n",
            "protocol=https\nhost=github.com:443\n",
            "protocol=https\nhost=evil.com\n",
            "host=github.com\n",
            "protocol=https\nhost=github.com\nhost=github.com\n",
            "secret malformed\n",
        ] {
            let error = validate_input(bad.as_bytes()).unwrap_err();
            assert!(!error.contains("secret"));
        }
        assert!(validate_input(vec![b'x'; 65 * 1024].as_slice()).is_err());
    }
}
