use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub shadowtls: String,
    pub shadowsocks: String,
    pub vmess: String,
    pub trojan: String,
    pub naive: String,
    pub tuic: String,
    pub hysteria2: String,
    pub anytls: String,
}

pub fn derive_credentials(token: &str, uuid: Uuid, master_secret: Option<&str>) -> Credentials {
    let master_secret = master_secret.filter(|value| !value.is_empty());

    Credentials {
        shadowtls: derive_text_password(token, uuid, "shadowtls", master_secret),
        shadowsocks: derive_ss2022_password(token, uuid, master_secret),
        vmess: derive_text_password(token, uuid, "vmess", master_secret),
        trojan: derive_text_password(token, uuid, "trojan", master_secret),
        naive: derive_text_password(token, uuid, "naive", master_secret),
        tuic: derive_text_password(token, uuid, "tuic", master_secret),
        hysteria2: derive_text_password(token, uuid, "hysteria2", master_secret),
        anytls: derive_text_password(token, uuid, "anytls", master_secret),
    }
}

fn derive_text_password(
    token: &str,
    uuid: Uuid,
    protocol: &str,
    master_secret: Option<&str>,
) -> String {
    let digest = hmac_digest(token, uuid, protocol, master_secret);
    general_purpose::URL_SAFE_NO_PAD.encode(&digest[..24])
}

fn derive_ss2022_password(token: &str, uuid: Uuid, master_secret: Option<&str>) -> String {
    let digest = hmac_digest(token, uuid, "shadowsocks-2022-aes-128-gcm", master_secret);
    general_purpose::STANDARD.encode(&digest[..16])
}

fn hmac_digest(token: &str, uuid: Uuid, protocol: &str, master_secret: Option<&str>) -> [u8; 32] {
    let (key, message) = match master_secret {
        Some(secret) => (
            secret.as_bytes(),
            format!("sing-box-proxy:v2:{uuid}:{token}:{protocol}"),
        ),
        None => (
            token.as_bytes(),
            format!("sing-box-proxy:v1:{uuid}:{protocol}"),
        ),
    };

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_master_secret_matches_token_only_derivation() {
        let uuid = Uuid::parse_str("a03faa38-dea9-4c15-9d56-71c4757b572c").unwrap();

        let token_only = derive_credentials("token", uuid, None);
        let empty_secret = derive_credentials("token", uuid, Some(""));

        assert_eq!(token_only, empty_secret);
    }

    #[test]
    fn master_secret_changes_derived_credentials() {
        let uuid = Uuid::parse_str("a03faa38-dea9-4c15-9d56-71c4757b572c").unwrap();

        let token_only = derive_credentials("token", uuid, None);
        let with_secret = derive_credentials("token", uuid, Some("master-secret"));

        assert_ne!(token_only.shadowsocks, with_secret.shadowsocks);
        assert_ne!(token_only.shadowtls, with_secret.shadowtls);
        assert_ne!(token_only.vmess, with_secret.vmess);
        assert_ne!(token_only.trojan, with_secret.trojan);
    }
}
