use crate::{Result, record::Credentials};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Proxy, blocking::Client, redirect::Policy};
use rsa::{
    RsaPrivateKey,
    pkcs1::DecodeRsaPrivateKey,
    pkcs1v15::SigningKey,
    pkcs8::DecodePrivateKey,
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding},
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn private_key(pem: &[u8]) -> Result<RsaPrivateKey> {
    let text = std::str::from_utf8(pem).map_err(|_| "invalid RSA PEM private key")?;
    let key = RsaPrivateKey::from_pkcs8_pem(text)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
        .map_err(|_| "invalid RSA PEM private key")?;
    key.validate().map_err(|_| "invalid RSA PEM private key")?;
    Ok(key)
}

pub fn validate_pem(pem: &[u8]) -> Result<()> {
    private_key(pem).map(|_| ())
}

#[derive(Serialize)]
struct Claims {
    iat: u64,
    exp: u64,
    iss: String,
}

pub fn jwt(credentials: &Credentials, now: u64) -> Result<Zeroizing<String>> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::to_vec(&Claims {
        iat: now.saturating_sub(60),
        exp: now.checked_add(540).ok_or("system clock is out of range")?,
        iss: credentials.app.to_string(),
    })
    .map_err(|_| "cannot encode JWT claims")?;
    let mut token = Zeroizing::new(format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims)));
    let key = SigningKey::<Sha256>::new(private_key(&credentials.pem)?);
    let signature = key.sign_with_rng(&mut rsa::rand_core::OsRng, token.as_bytes());
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature.to_bytes()));
    Ok(token)
}

fn variable(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            env::var(name.to_ascii_lowercase())
                .ok()
                .filter(|value| !value.is_empty())
        })
}

// Explicit environment selection prevents platform proxy discovery from changing
// HTTPS_PROXY precedence. No-proxy matching is delegated to reqwest.
pub fn client() -> Result<Client> {
    let mut builder = Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .no_proxy()
        .user_agent(concat!("FuanSync/", env!("CARGO_PKG_VERSION")));
    if let Some(proxy) = variable("HTTPS_PROXY").or_else(|| variable("HTTP_PROXY")) {
        let proxy = Proxy::https(proxy)
            .map_err(|_| "invalid proxy configuration")?
            .no_proxy(reqwest::NoProxy::from_env());
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|_| "cannot initialize HTTPS client")
}

#[derive(Deserialize)]
struct TokenResponse {
    token: String,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.token);
    }
}

pub fn parse_token(bytes: &[u8]) -> Result<Zeroizing<String>> {
    let mut response: TokenResponse =
        serde_json::from_slice(bytes).map_err(|_| "invalid GitHub token response")?;
    if response.token.is_empty()
        || response.token.len() > 16 * 1024
        || !response
            .token
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err("invalid GitHub token response");
    }
    Ok(Zeroizing::new(std::mem::take(&mut response.token)))
}

pub fn installation_token(credentials: &Credentials) -> Result<Zeroizing<String>> {
    request_token(&client()?, credentials)
}

fn request_token(client: &Client, credentials: &Credentials) -> Result<Zeroizing<String>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is out of range")?
        .as_secs();
    let jwt = jwt(credentials, now)?;
    let bearer = Zeroizing::new(format!("Bearer {}", *jwt));
    let mut authorization = reqwest::header::HeaderValue::from_str(&bearer)
        .map_err(|_| "cannot create authentication header")?;
    authorization.set_sensitive(true);
    let response = client
        .post(format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            credentials.installation
        ))
        .header(reqwest::header::AUTHORIZATION, authorization)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .body("{}")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .map_err(|_| "GitHub token request failed")?;
    if !response.status().is_success() {
        return Err("GitHub rejected the token request");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read GitHub token response")?;
    if bytes.len() > 1024 * 1024 {
        return Err("GitHub token response exceeds limit");
    }
    parse_token(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::{
        pkcs1v15::{Signature, VerifyingKey},
        pkcs8::EncodePrivateKey,
        pkcs8::LineEnding,
        signature::Verifier,
    };

    #[test]
    fn jwt_signature_claims_and_redacted_errors() {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let credentials = Credentials {
            app: u64::MAX,
            installation: 2,
            pem: Zeroizing::new(pem.as_bytes().to_vec()),
        };
        let token = jwt(&credentials, 1700000000).unwrap();
        let parts: Vec<_> = token.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iat"], 1699999940u64);
        assert_eq!(claims["exp"], 1700000540u64);
        assert_eq!(claims["iss"], u64::MAX.to_string());
        VerifyingKey::<Sha256>::new(key.to_public_key())
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            validate_pem(b"private-secret").unwrap_err(),
            "invalid RSA PEM private key"
        );
    }

    #[test]
    fn token_response_rejects_protocol_injection() {
        assert_eq!(
            &*parse_token(br#"{"token":"ghs_valid_123"}"#).unwrap(),
            "ghs_valid_123"
        );
        for bytes in [
            br#"{"token":"secret\nhost=evil.com"}"#.as_slice(),
            br#"{"token":""}"#,
            b"SECRET",
        ] {
            assert_eq!(
                parse_token(bytes).unwrap_err(),
                "invalid GitHub token response"
            );
        }
    }

    #[test]
    fn https_request_success_errors_and_redirects() {
        use rcgen::generate_simple_self_signed;
        use rustls::{
            ServerConfig, ServerConnection, StreamOwned,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            sync::Arc,
            thread,
        };

        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let credentials = Credentials {
            app: 123,
            installation: 456,
            pem: Zeroizing::new(pem.as_bytes().to_vec()),
        };
        let certificate = generate_simple_self_signed(vec!["api.github.com".to_owned()]).unwrap();
        let der = certificate.cert.der().clone();
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        certificate.signing_key.serialize_der(),
                    )),
                )
                .unwrap(),
        );
        for (status, body, location, expected) in [
            (
                "201 Created",
                r#"{"token":"ghs_mock_token"}"#,
                "",
                Ok("ghs_mock_token"),
            ),
            (
                "403 Forbidden",
                "PEM JWT TOKEN SECRET",
                "",
                Err("GitHub rejected the token request"),
            ),
            (
                "302 Found",
                "",
                "Location: https://evil.example/leak\r\n",
                Err("GitHub rejected the token request"),
            ),
            (
                "302 Found",
                "",
                "Location: https://api.github.com/other\r\n",
                Err("GitHub rejected the token request"),
            ),
            (
                "201 Created",
                "SECRET INVALID JSON",
                "",
                Err("invalid GitHub token response"),
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let config = config.clone();
            let server = thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let tls = StreamOwned::new(ServerConnection::new(config).unwrap(), socket);
                let mut stream = BufReader::new(tls);
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).unwrap();
                    request.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body_input = [0; 2];
                stream.read_exact(&mut body_input).unwrap();
                assert_eq!(&body_input, b"{}");
                stream.get_mut().write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{location}Connection: close\r\n\r\n{body}", body.len()).as_bytes()).unwrap();
                stream.get_mut().flush().unwrap();
                request
            });
            let client = Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(5))
                .add_root_certificate(reqwest::Certificate::from_der(&der).unwrap())
                .resolve("api.github.com", address)
                .build()
                .unwrap();
            let result = request_token(&client, &credentials);
            assert_eq!(
                result
                    .as_ref()
                    .map(|value| value.as_str())
                    .map_err(|error| *error),
                expected
            );
            let request = server.join().unwrap();
            assert!(request.starts_with("POST /app/installations/456/access_tokens HTTP/1.1\r\n"));
            assert!(request.to_lowercase().contains("host: api.github.com\r\n"));
            let bearer = request
                .lines()
                .find_map(|line| line.strip_prefix("authorization: Bearer "))
                .unwrap();
            let parts: Vec<_> = bearer.split('.').collect();
            VerifyingKey::<Sha256>::new(key.to_public_key())
                .verify(
                    format!("{}.{}", parts[0], parts[1]).as_bytes(),
                    &Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice())
                        .unwrap(),
                )
                .unwrap();
            let claims: serde_json::Value =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
            assert_eq!(claims["iss"], "123");
        }
    }
}
