//! ECDSA P-256 signing keys (`--key-file`).
//!
//! Keys are read from PEM files in SEC1 (`EC PRIVATE KEY`, as written by `nrfutil keys generate`
//! and `openssl ecparam -genkey`) or PKCS#8 (`PRIVATE KEY`) format. Signatures use SHA-256 with
//! deterministic nonces (RFC 6979), so signed packages are reproducible. nrfutil uses random
//! nonces instead; both kinds of signature verify the same way.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use p256::ecdsa::signature::Signer;

/// The public key of the well-known default key shipped with nrfutil (`keys_default_pem` in
/// `nordicsemi/dfu/signing.py`), as an uncompressed SEC1 point.
const NRFUTIL_DEFAULT_PUBLIC_KEY: &str = "0468762b52efe814a217378e7b187fbc20ebafe8e20f0512eaa078da10a334c08c\
                                          c96749617cefc0e7784a1a32848d84f754d4d0dd9ab5601de8e5049030ffcb46";

#[derive(Debug)]
pub struct SigningKey(p256::ecdsa::SigningKey);

/// An ECDSA signature with `r` and `s` as big-endian integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

impl Signature {
    /// `r || s`, both big-endian, as used by legacy init packets.
    pub fn to_be_bytes(self) -> [u8; 64] {
        let mut out = [0; 64];
        out[..32].copy_from_slice(&self.r);
        out[32..].copy_from_slice(&self.s);
        out
    }

    /// `r || s`, both little-endian, as expected by the nRF5 SDK (12+) bootloader.
    pub fn to_le_bytes(self) -> [u8; 64] {
        let mut out = self.to_be_bytes();
        out[..32].reverse();
        out[32..].reverse();
        out
    }
}

impl SigningKey {
    pub fn from_pem_file(path: &Path) -> Result<Self> {
        let pem = fs::read_to_string(path)
            .with_context(|| format!("cannot read '{}'", path.display()))?;
        Self::from_pem(&pem)
            .with_context(|| format!("cannot use '{}' as a signing key", path.display()))
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        if pem.contains("ENCRYPTED") {
            bail!(
                "encrypted keys are not supported; decrypt it first, e.g. with `openssl ec -in KEY -out KEY.plain`"
            );
        }
        // The file may hold other blocks too, e.g. the "EC PARAMETERS" block that
        // `openssl ecparam -genkey` writes first, so pick out the private key.
        let block = ["EC PRIVATE KEY", "PRIVATE KEY"]
            .into_iter()
            .find_map(|label| pem_block(pem, label))
            .context("no \"EC PRIVATE KEY\" or \"PRIVATE KEY\" PEM block found")?;
        let secret = p256::SecretKey::from_pem(block)
            .map_err(|err| anyhow!("not a valid NIST P-256 (prime256v1) private key: {err}"))?;
        Ok(SigningKey(secret.into()))
    }

    /// Signs `message` with ECDSA P-256 over its SHA-256 digest.
    pub fn sign(&self, message: &[u8]) -> Result<Signature> {
        let signature: p256::ecdsa::Signature = self
            .0
            .try_sign(message)
            .map_err(|err| anyhow!("signing failed: {err}"))?;
        let (r, s) = signature.split_bytes();
        Ok(Signature {
            r: r.into(),
            s: s.into(),
        })
    }

    /// Whether this is nrfutil's publicly known default key, which offers no protection.
    pub fn is_nrfutil_default(&self) -> bool {
        let point = self.0.verifying_key().to_sec1_point(false);
        hex(point.as_bytes()) == NRFUTIL_DEFAULT_PUBLIC_KEY
    }
}

/// Finds `-----BEGIN <label>----- ... -----END <label>-----` in `text`.
fn pem_block<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text.find(&begin)?;
    let stop = start + text[start..].find(&end)? + end.len();
    Some(&text[start..stop])
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier;

    use super::*;

    // A throwaway key for tests, generated with `openssl ecparam -name prime256v1 -genkey`.
    const KEY_WITH_PARAMS: &str = "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n\
        -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILZXLzospkSJmP5YIp1qqKsA2j7mC6557RRugp750QeloAoGCCqGSM49\n\
        AwEHoUQDQgAE48UCpmZQoxT2lkwO/pDyckXkCA7raNnfVQBSCXCxQKXd9Mf5IBkR\nlw+g2HQn423zAOggaMGpX6xdckF3NRljeA==\n\
        -----END EC PRIVATE KEY-----\n";

    #[test]
    fn signs_verifiably_in_both_byte_orders() {
        let key = SigningKey::from_pem(KEY_WITH_PARAMS).unwrap();
        let signature = key.sign(b"init packet").unwrap();

        let be = signature.to_be_bytes();
        let le = signature.to_le_bytes();
        assert_eq!(le[..32].iter().rev().copied().collect::<Vec<_>>(), be[..32]);
        assert_eq!(le[32..].iter().rev().copied().collect::<Vec<_>>(), be[32..]);

        let parsed = p256::ecdsa::Signature::from_slice(&be).unwrap();
        key.0
            .verifying_key()
            .verify(b"init packet", &parsed)
            .unwrap();
        assert!(key.0.verifying_key().verify(b"other", &parsed).is_err());
        assert!(!key.is_nrfutil_default());
    }

    #[test]
    fn deterministic_signatures() {
        let key = SigningKey::from_pem(KEY_WITH_PARAMS).unwrap();
        assert_eq!(key.sign(b"x").unwrap(), key.sign(b"x").unwrap());
    }

    #[test]
    fn detects_nrfutil_default_key() {
        // The private scalar of nrfutil's published default key (see NRFUTIL_DEFAULT_PUBLIC_KEY).
        let scalar = "6becae95e1f26fc4f5b8f576aff4a356813d054014943a3f3bacc7af39511134";
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&scalar[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let key = SigningKey(p256::ecdsa::SigningKey::from_slice(&bytes).unwrap());
        assert!(key.is_nrfutil_default());
    }

    #[test]
    fn rejects_unusable_pem() {
        let err = SigningKey::from_pem("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n")
            .unwrap_err();
        assert!(err.to_string().contains("no \"EC PRIVATE KEY\""), "{err}");
        let encrypted =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        assert!(
            SigningKey::from_pem(encrypted)
                .unwrap_err()
                .to_string()
                .contains("encrypted")
        );
    }
}
