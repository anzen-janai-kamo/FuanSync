use crate::Result;
use zeroize::Zeroizing;

pub const CAPACITY: usize = 1024 * 1024;
pub const MAX_PEM: usize = 64 * 1024;
const HEADER: usize = 32;
const MAGIC: &[u8; 8] = b"FUANSYNC";

pub struct Credentials {
    pub app: u64,
    pub installation: u64,
    pub pem: Zeroizing<Vec<u8>>,
}

// Little endian fields. CRC32C covers header + PEM, excluding CRC and padding.
pub fn encode(credentials: &Credentials) -> Result<Zeroizing<Vec<u8>>> {
    validate(credentials)?;
    let mut bytes = Zeroizing::new(vec![0; CAPACITY]);
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[12..20].copy_from_slice(&credentials.app.to_le_bytes());
    bytes[20..28].copy_from_slice(&credentials.installation.to_le_bytes());
    bytes[28..32].copy_from_slice(&(credentials.pem.len() as u32).to_le_bytes());
    let end = HEADER + credentials.pem.len();
    bytes[HEADER..end].copy_from_slice(&credentials.pem);
    let crc = crc32c(&bytes[..end]);
    bytes[end..end + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Option<Credentials> {
    if bytes.len() != CAPACITY || &bytes[..8] != MAGIC {
        return None;
    }
    if bytes[8..10] != 1u16.to_le_bytes() || bytes[10..12] != [0, 0] {
        return None;
    }
    let length = u32::from_le_bytes(bytes[28..32].try_into().ok()?) as usize;
    if length == 0 || length > MAX_PEM {
        return None;
    }
    let end = HEADER.checked_add(length)?;
    if crc32c(&bytes[..end]) != u32::from_le_bytes(bytes[end..end + 4].try_into().ok()?)
        || bytes[end + 4..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let credentials = Credentials {
        app: u64::from_le_bytes(bytes[12..20].try_into().ok()?),
        installation: u64::from_le_bytes(bytes[20..28].try_into().ok()?),
        pem: Zeroizing::new(bytes[HEADER..end].to_vec()),
    };
    validate(&credentials).ok()?;
    Some(credentials)
}

pub fn validate(credentials: &Credentials) -> Result<()> {
    if credentials.app == 0 || credentials.installation == 0 {
        return Err("App ID and Installation ID must be positive integers");
    }
    if credentials.pem.is_empty() || credentials.pem.len() > MAX_PEM {
        return Err("PEM must contain between 1 byte and 64 KiB");
    }
    Ok(())
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f63b78 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_roundtrip_and_corruption() {
        let credentials = Credentials {
            app: u64::MAX,
            installation: 2,
            pem: Zeroizing::new(b"secret pem".to_vec()),
        };
        let bytes = encode(&credentials).unwrap();
        assert_eq!(bytes.len(), CAPACITY);
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded.app, u64::MAX);
        assert_eq!(*decoded.pem, *credentials.pem);
        for offset in [0, 8, 10, 12, 20, 28, 32, 42, CAPACITY - 1] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(decode(&bad).is_none(), "offset {offset}");
        }
        assert!(decode(&vec![0; CAPACITY]).is_none());
    }
    #[test]
    fn pem_bounds_and_known_crc() {
        assert_eq!(crc32c(b"123456789"), 0xe3069283);
        let mut credentials = Credentials {
            app: 1,
            installation: 1,
            pem: Zeroizing::new(vec![1; MAX_PEM]),
        };
        assert!(decode(&encode(&credentials).unwrap()).is_some());
        credentials.pem.push(1);
        assert!(encode(&credentials).is_err());
    }
}
