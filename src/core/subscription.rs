use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::core::{config as server_config, derive_credentials, normalize_path, Credentials, User};

#[derive(Debug, Clone, Copy)]
pub enum SubscriptionFormat {
    Clash,
    SingBox,
    Shadowrocket,
}

impl SubscriptionFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "clash" | "mihomo" => Some(Self::Clash),
            "sing-box" | "singbox" | "json" => Some(Self::SingBox),
            "shadowrocket" | "shadow-rocket" => Some(Self::Shadowrocket),
            _ => None,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Clash => "yaml",
            Self::SingBox => "json",
            Self::Shadowrocket => "conf",
        }
    }

    pub fn template_name(self) -> &'static str {
        match self {
            Self::Clash => "clash/config.yaml",
            Self::SingBox => "sing-box/config.json",
            Self::Shadowrocket => "shadowrocket/config.conf",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubscriptionConfig {
    pub server_host: String,
    node_name_base: String,
    outbounds: Vec<OutboundConfig>,
}

#[derive(Debug, Clone)]
struct OutboundConfig {
    protocol: ProxyProtocol,
    name: String,
    port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyProtocol {
    Shadowsocks,
    Vmess,
    Trojan,
    Naive,
    Tuic,
    Hysteria2,
    AnyTls,
}

impl ProxyProtocol {
    fn all() -> &'static [Self] {
        &[
            Self::Shadowsocks,
            Self::Vmess,
            Self::Trojan,
            Self::Naive,
            Self::Tuic,
            Self::Hysteria2,
            Self::AnyTls,
        ]
    }

    fn as_inbound_type(self) -> &'static str {
        match self {
            Self::Shadowsocks => "shadowsocks",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Naive => "naive",
            Self::Tuic => "tuic",
            Self::Hysteria2 => "hysteria2",
            Self::AnyTls => "anytls",
        }
    }
}

impl SubscriptionConfig {
    pub fn from_env() -> Result<Self> {
        let path = server_config::config_path_from_env();
        Self::from_path_with_node_name_base(&path, &node_name_base_from_env())
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_path_with_node_name_base(path, "🌐 Unknown")
    }

    pub fn from_path_with_node_name_base(path: &Path, node_name_base: &str) -> Result<Self> {
        let document = fs::read_to_string(path)
            .with_context(|| format!("read sing-box config {}", path.display()))?;
        let document: Value = serde_json::from_str(&document).context("parse sing-box config")?;
        Self::from_document_with_node_name_base(&document, node_name_base)
    }

    pub fn from_document(document: &Value) -> Result<Self> {
        Self::from_document_with_node_name_base(document, "🌐 Unknown")
    }

    pub fn from_document_with_node_name_base(
        document: &Value,
        node_name_base: &str,
    ) -> Result<Self> {
        let server_host =
            infer_server_host(document).context("infer public proxy host from sing-box config")?;
        let inbounds = document
            .get("inbounds")
            .and_then(Value::as_array)
            .context("sing-box config inbounds must be an array")?;

        let outbounds = collect_outbounds_from_inbounds(inbounds, node_name_base)?;

        if outbounds.is_empty() {
            bail!("sing-box config does not contain supported proxy inbounds");
        }

        Ok(Self {
            server_host,
            node_name_base: node_name_base.to_owned(),
            outbounds,
        })
    }
}

pub fn render(
    format: SubscriptionFormat,
    config: &SubscriptionConfig,
    user: &User,
    master_secret: Option<&str>,
) -> Result<String> {
    let template = load_template(format)?;
    let credentials = derive_credentials(&user.token, user.uuid, master_secret);
    match format {
        SubscriptionFormat::Clash => Ok(append_fragment(
            &template,
            &render_clash_section(config, user, &credentials)?,
        )),
        SubscriptionFormat::SingBox => {
            merge_sing_box_template(&template, config, user, &credentials)
        }
        SubscriptionFormat::Shadowrocket => {
            merge_shadowrocket_template(&template, config, user, &credentials)
        }
    }
}

pub fn render_sing_box_subscription(
    config: &SubscriptionConfig,
    user: &User,
    master_secret: Option<&str>,
) -> Result<String> {
    render(SubscriptionFormat::SingBox, config, user, master_secret)
}

fn render_clash_section(
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Result<String> {
    Ok(format!(
        r#"proxies:
{proxies}
"#,
        proxies = render_clash_proxies(config, user, credentials)?.trim_end(),
    ))
}

fn render_clash_proxies(
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Result<String> {
    let proxies = config
        .outbounds
        .iter()
        .filter(|outbound| is_clash_compatible(outbound.protocol))
        .enumerate()
        .filter_map(|(index, outbound)| {
            render_clash_proxy(config, outbound, index, user, credentials)
        })
        .collect::<Vec<_>>();

    if proxies.is_empty() {
        bail!("sing-box config does not contain Clash-compatible proxy inbounds");
    }

    Ok(proxies.join(""))
}

fn render_clash_proxy(
    config: &SubscriptionConfig,
    outbound: &OutboundConfig,
    index: usize,
    user: &User,
    credentials: &Credentials,
) -> Option<String> {
    let server = &config.server_host;
    let name = compact_node_name(config, index);
    let proxy = match outbound.protocol {
        ProxyProtocol::Shadowsocks => format!(
            "  - name: \"{name}\"
    type: \"ss\"
    server: \"{server}\"
    port: {port}
    password: \"{password}\"
    cipher: \"2022-blake3-aes-128-gcm\"
",
            name = name,
            port = outbound.port,
            password = credentials.shadowsocks,
        ),
        ProxyProtocol::Vmess => format!(
            "  - name: \"{name}\"
    type: \"vmess\"
    server: \"{server}\"
    port: {port}
    uuid: \"{uuid}\"
    alterId: 0
    cipher: \"auto\"
    network: \"ws\"
    ws-opts:
      path: \"{path}\"
      headers:
        Host: \"{server}\"
",
            name = name,
            port = outbound.port,
            uuid = user.uuid,
            path = vmess_ws_path(credentials),
        ),
        ProxyProtocol::Trojan => format!(
            "  - name: \"{name}\"
    type: \"trojan\"
    server: \"{server}\"
    port: {port}
    password: \"{password}\"
    sni: \"{server}\"
",
            name = name,
            port = outbound.port,
            password = credentials.trojan,
        ),
        ProxyProtocol::Tuic => format!(
            "  - name: \"{name}\"
    type: \"tuic\"
    server: \"{server}\"
    port: {port}
    uuid: \"{uuid}\"
    password: \"{password}\"
    congestion-controller: \"bbr\"
    sni: \"{server}\"
    alpn:
      - h3
",
            name = name,
            port = outbound.port,
            uuid = user.uuid,
            password = credentials.tuic,
        ),
        ProxyProtocol::Hysteria2 => format!(
            "  - name: \"{name}\"
    type: \"hysteria2\"
    server: \"{server}\"
    port: {port}
    password: \"{password}\"
    sni: \"{server}\"
",
            name = name,
            port = outbound.port,
            password = credentials.hysteria2,
        ),
        ProxyProtocol::Naive | ProxyProtocol::AnyTls => return None,
    };

    Some(proxy)
}

fn is_clash_compatible(protocol: ProxyProtocol) -> bool {
    matches!(
        protocol,
        ProxyProtocol::Shadowsocks
            | ProxyProtocol::Vmess
            | ProxyProtocol::Trojan
            | ProxyProtocol::Tuic
            | ProxyProtocol::Hysteria2
    )
}

fn merge_sing_box_template(
    template: &str,
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Result<String> {
    let mut document: Value = serde_json::from_str(template).context("parse sing-box template")?;
    let outbounds = document
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .context("sing-box template outbounds must be an array")?;
    let mut fragment = render_sing_box_outbounds(config, user, credentials);
    outbounds.append(&mut fragment);
    serde_json::to_string_pretty(&document).context("serialize sing-box subscription")
}

fn render_sing_box_outbounds(
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Vec<Value> {
    config
        .outbounds
        .iter()
        .map(|outbound| match outbound.protocol {
            ProxyProtocol::Shadowsocks => serde_json::json!({
                "type": "shadowsocks",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "method": "2022-blake3-aes-128-gcm",
                "password": credentials.shadowsocks
            }),
            ProxyProtocol::Vmess => serde_json::json!({
                "type": "vmess",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "uuid": user.uuid,
                "security": "auto",
                "transport": {
                    "type": "ws",
                    "path": vmess_ws_path(credentials),
                    "headers": {
                        "Host": config.server_host
                    }
                }
            }),
            ProxyProtocol::Trojan => serde_json::json!({
                "type": "trojan",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "password": credentials.trojan,
                "tls": {
                    "enabled": true,
                    "server_name": config.server_host
                }
            }),
            ProxyProtocol::Naive => serde_json::json!({
                "type": "naive",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "username": user.name,
                "password": credentials.naive,
                "tls": {
                    "enabled": true,
                    "server_name": config.server_host
                }
            }),
            ProxyProtocol::Tuic => serde_json::json!({
                "type": "tuic",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "uuid": user.uuid,
                "password": credentials.tuic,
                "congestion_control": "bbr",
                "zero_rtt_handshake": true,
                "tls": {
                    "enabled": true,
                    "server_name": config.server_host,
                    "alpn": ["h3"]
                }
            }),
            ProxyProtocol::Hysteria2 => serde_json::json!({
                "type": "hysteria2",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "password": credentials.hysteria2,
                "tls": {
                    "enabled": true,
                    "server_name": config.server_host
                }
            }),
            ProxyProtocol::AnyTls => serde_json::json!({
                "type": "anytls",
                "tag": outbound.name,
                "server": config.server_host,
                "server_port": outbound.port,
                "password": credentials.anytls,
                "tls": {
                    "enabled": true,
                    "server_name": config.server_host
                }
            }),
        })
        .collect()
}

fn merge_shadowrocket_template(
    template: &str,
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Result<String> {
    let proxy_lines = render_shadowrocket_proxy_lines(config, user, credentials)?;
    Ok(insert_into_ini_section(template, "Proxy", &proxy_lines))
}

fn render_shadowrocket_proxy_lines(
    config: &SubscriptionConfig,
    user: &User,
    credentials: &Credentials,
) -> Result<String> {
    let proxies = config
        .outbounds
        .iter()
        .filter(|outbound| is_shadowrocket_compatible(outbound.protocol))
        .enumerate()
        .filter_map(|(index, outbound)| {
            render_shadowrocket_proxy(config, outbound, index, user, credentials)
        })
        .collect::<Vec<_>>();

    if proxies.is_empty() {
        bail!("sing-box config does not contain Shadowrocket-compatible proxy inbounds");
    }

    Ok(proxies.join(""))
}

fn render_shadowrocket_proxy(
    config: &SubscriptionConfig,
    outbound: &OutboundConfig,
    index: usize,
    user: &User,
    credentials: &Credentials,
) -> Option<String> {
    let server = &config.server_host;
    let name = compact_node_name(config, index);
    let proxy = match outbound.protocol {
        ProxyProtocol::Shadowsocks => format!(
            "{name} = ss, {server}, {port}, encrypt-method=2022-blake3-aes-128-gcm, password={password}\n",
            name = name,
            port = outbound.port,
            password = credentials.shadowsocks,
        ),
        ProxyProtocol::Vmess => format!(
            "{name} = vmess, {server}, {port}, username={uuid}, ws=true, ws-path={path}, ws-headers=Host:\"{server}\", vmess-aead=true, tfo=true, sni={server}\n",
            name = name,
            port = outbound.port,
            uuid = user.uuid,
            path = vmess_ws_path(credentials),
        ),
        ProxyProtocol::Trojan => format!(
            "{name} = trojan, {server}, {port}, username={username}, password={password}, sni={server}\n",
            name = name,
            port = outbound.port,
            username = user.name,
            password = credentials.trojan,
        ),
        ProxyProtocol::Tuic => format!(
            "{name} = tuic-v5, {server}, {port}, password={password}, uuid={uuid}, sni={server}\n",
            name = name,
            port = outbound.port,
            password = credentials.tuic,
            uuid = user.uuid.to_string().to_ascii_uppercase(),
        ),
        ProxyProtocol::Hysteria2 => format!(
            "{name} = hysteria2, {server}, {port}, password={password}, sni={server}\n",
            name = name,
            port = outbound.port,
            password = credentials.hysteria2,
        ),
        ProxyProtocol::AnyTls => format!(
            "{name} = anytls, {server}, {port}, password={password}\n",
            name = name,
            port = outbound.port,
            password = credentials.anytls,
        ),
        ProxyProtocol::Naive => return None,
    };

    Some(proxy)
}

fn is_shadowrocket_compatible(protocol: ProxyProtocol) -> bool {
    matches!(
        protocol,
        ProxyProtocol::Shadowsocks
            | ProxyProtocol::Vmess
            | ProxyProtocol::Trojan
            | ProxyProtocol::Tuic
            | ProxyProtocol::Hysteria2
            | ProxyProtocol::AnyTls
    )
}

fn compact_node_name(config: &SubscriptionConfig, index: usize) -> String {
    format!("{} {:02}", config.node_name_base, index + 1)
}

fn infer_server_host(document: &Value) -> Option<String> {
    let inbounds = document.get("inbounds")?.as_array()?;
    for inbound in inbounds {
        if let Some(host) = inbound
            .pointer("/handshake/server")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Some(host.to_owned());
        }

        if let Some(host) = inbound
            .pointer("/tls/server_name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Some(host.to_owned());
        }
    }
    None
}

fn collect_outbounds_from_inbounds(
    inbounds: &[Value],
    node_name_base: &str,
) -> Result<Vec<OutboundConfig>> {
    let mut outbounds = Vec::new();

    for inbound in inbounds {
        let Some(protocol) = inbound_protocol(inbound) else {
            continue;
        };
        let port = inbound
            .get("listen_port")
            .and_then(Value::as_u64)
            .with_context(|| {
                format!(
                    "{}.listen_port must be an integer",
                    protocol.as_inbound_type()
                )
            })?;
        let port = u16::try_from(port).with_context(|| {
            format!("{}.listen_port is out of range", protocol.as_inbound_type())
        })?;
        let index = outbounds.len() + 1;

        outbounds.push(OutboundConfig {
            protocol,
            name: format!("{node_name_base} {index:02}"),
            port,
        });
    }

    Ok(outbounds)
}

fn inbound_protocol(inbound: &Value) -> Option<ProxyProtocol> {
    let inbound_type = inbound.get("type").and_then(Value::as_str)?;
    ProxyProtocol::all()
        .iter()
        .copied()
        .find(|protocol| protocol.as_inbound_type() == inbound_type)
}

fn node_name_base_from_env() -> String {
    if let Ok(value) = env::var("NODE_NAME_BASE") {
        if !value.is_empty() {
            return value;
        }
    }

    env::var("NODE_LOCATION")
        .ok()
        .filter(|value| !value.is_empty())
        .as_deref()
        .and_then(location_from_code)
        .unwrap_or("🌐 Unknown")
        .to_owned()
}

fn location_from_code(code: &str) -> Option<&'static str> {
    match code.to_ascii_uppercase().as_str() {
        "JP" => Some("🇯🇵 Japan"),
        "KR" => Some("🇰🇷 South Korea"),
        "SG" => Some("🇸🇬 Singapore"),
        "HK" => Some("🇭🇰 Hong Kong"),
        "TW" => Some("🇹🇼 Taiwan"),
        "US" => Some("🇺🇸 United States"),
        "CA" => Some("🇨🇦 Canada"),
        "GB" | "UK" => Some("🇬🇧 United Kingdom"),
        "DE" => Some("🇩🇪 Germany"),
        "FR" => Some("🇫🇷 France"),
        "NL" => Some("🇳🇱 Netherlands"),
        "SE" => Some("🇸🇪 Sweden"),
        "CH" => Some("🇨🇭 Switzerland"),
        "IT" => Some("🇮🇹 Italy"),
        "ES" => Some("🇪🇸 Spain"),
        "AU" => Some("🇦🇺 Australia"),
        "IN" => Some("🇮🇳 India"),
        "BR" => Some("🇧🇷 Brazil"),
        "AE" => Some("🇦🇪 United Arab Emirates"),
        "BH" => Some("🇧🇭 Bahrain"),
        "ZA" => Some("🇿🇦 South Africa"),
        _ => None,
    }
}

fn load_template(format: SubscriptionFormat) -> Result<String> {
    let path = template_dir().join(format.template_name());
    fs::read_to_string(&path)
        .with_context(|| format!("read subscription template {}", path.display()))
}

fn append_fragment(template: &str, fragment: &str) -> String {
    let mut rendered = template.to_owned();
    if !rendered.is_empty() && !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered.push_str(fragment);
    rendered
}

fn insert_into_ini_section(template: &str, section: &str, lines: &str) -> String {
    let section_header = format!("[{section}]");
    let mut output = String::new();
    let mut inserted = false;
    let mut in_target_section = false;

    for line in template.split_inclusive('\n') {
        let trimmed = line.trim();
        let is_section_header =
            trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2;

        if is_section_header && in_target_section && !inserted {
            push_generated_lines(&mut output, lines);
            inserted = true;
            in_target_section = false;
        }

        output.push_str(line);

        if is_section_header {
            in_target_section = trimmed == section_header;
        }
    }

    if in_target_section && !inserted {
        push_generated_lines(&mut output, lines);
        inserted = true;
    }

    if !inserted {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(&section_header);
        output.push('\n');
        push_generated_lines(&mut output, lines);
    }

    output
}

fn push_generated_lines(output: &mut String, lines: &str) {
    if !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(lines);
    if !output.ends_with('\n') {
        output.push('\n');
    }
}

fn template_dir() -> PathBuf {
    env::var("SUBSCRIPTION_TEMPLATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("templates"))
}

fn vmess_ws_path(credentials: &Credentials) -> String {
    normalize_path(&credentials.vmess)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn subscription_config_reads_host_ports_and_names_from_sing_box_config() {
        let config = sample_subscription_config();

        assert_eq!(config.server_host, "proxy.example.com");
        assert_eq!(config.outbounds[0].protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(config.outbounds[0].port, 2008);
        assert_eq!(config.outbounds[1].protocol, ProxyProtocol::Vmess);
        assert_eq!(config.outbounds[1].port, 2009);
        assert_eq!(config.outbounds[2].protocol, ProxyProtocol::Trojan);
        assert_eq!(config.outbounds[2].name, "🇯🇵 Japan 03");
    }

    #[test]
    fn sing_box_template_merges_generated_outbounds() {
        let config = sample_subscription_config();
        let user = sample_user();

        let template: Value =
            serde_json::from_str(&load_template(SubscriptionFormat::SingBox).unwrap()).unwrap();
        let before = template["outbounds"].as_array().unwrap().len();
        let rendered = render(SubscriptionFormat::SingBox, &config, &user, None).unwrap();
        let rendered: Value = serde_json::from_str(&rendered).unwrap();
        let after = rendered["outbounds"].as_array().unwrap().len();

        assert_eq!(before + 6, after);
    }

    #[test]
    fn clash_subscription_uses_compatible_nodes_from_sing_box_config() {
        let config = sample_subscription_config();
        let user = sample_user();

        let rendered = render(SubscriptionFormat::Clash, &config, &user, None).unwrap();

        assert!(rendered.contains("name: \"🇯🇵 Japan 01\""));
        assert!(rendered.contains("name: \"🇯🇵 Japan 02\""));
        assert!(rendered.contains("name: \"🇯🇵 Japan 03\""));
        assert!(rendered.contains("name: \"🇯🇵 Japan 04\""));
        assert!(rendered.contains("name: \"🇯🇵 Japan 05\""));
        assert!(!rendered.contains("name: \"🇯🇵 Japan 06\""));
    }

    #[test]
    fn shadowrocket_subscription_uses_compatible_nodes_from_sing_box_config() {
        let config = sample_subscription_config();
        let user = sample_user();

        let rendered = render(SubscriptionFormat::Shadowrocket, &config, &user, None).unwrap();

        assert_eq!(rendered.matches("[Proxy]").count(), 1);
        assert!(rendered.contains("🇯🇵 Japan 01 = ss"));
        assert!(rendered.contains("🇯🇵 Japan 02 = vmess"));
        assert!(rendered.contains("🇯🇵 Japan 03 = trojan"));
        assert!(rendered.contains("🇯🇵 Japan 04 = tuic-v5"));
        assert!(rendered.contains("🇯🇵 Japan 05 = hysteria2"));
        assert!(!rendered.contains("snell"));
        assert!(!rendered.contains("🇯🇵 Japan 06 ="));
    }

    #[test]
    fn shadowrocket_merges_generated_lines_into_existing_proxy_section() {
        let config = sample_subscription_config();
        let user = sample_user();
        let credentials = derive_credentials(&user.token, user.uuid, None);
        let template =
            "[General]\nloglevel = notify\n[Proxy]\n🟢 Direct = direct\n[Rule]\nFINAL,🐟 Final\n";

        let rendered =
            merge_shadowrocket_template(&template, &config, &user, &credentials).unwrap();
        let proxy_index = rendered.find("[Proxy]").unwrap();
        let generated_index = rendered.find("🇯🇵 Japan 01 = ss").unwrap();
        let rule_index = rendered.find("[Rule]").unwrap();

        assert_eq!(rendered.matches("[Proxy]").count(), 1);
        assert!(proxy_index < generated_index);
        assert!(generated_index < rule_index);
    }

    #[test]
    fn shadowrocket_creates_proxy_section_when_template_has_none() {
        let config = sample_subscription_config();
        let user = sample_user();
        let credentials = derive_credentials(&user.token, user.uuid, None);
        let template = "[General]\nloglevel = notify\n";

        let rendered =
            merge_shadowrocket_template(&template, &config, &user, &credentials).unwrap();

        assert_eq!(rendered.matches("[Proxy]").count(), 1);
        assert!(rendered.contains("[Proxy]\n🇯🇵 Japan 01 = ss"));
    }

    fn sample_subscription_config() -> SubscriptionConfig {
        let document = serde_json::json!({
            "inbounds": [
                {
                    "type": "shadowtls",
                    "handshake": {
                        "server": "proxy.example.com",
                        "server_port": 443
                    }
                },
                {
                    "tag": "ss-in",
                    "type": "shadowsocks",
                    "listen_port": 2008
                },
                {
                    "tag": "vmess-in",
                    "type": "vmess",
                    "listen_port": 2009
                },
                {
                    "tag": "trojan-in",
                    "type": "trojan",
                    "listen_port": 2010
                },
                {
                    "tag": "naive-in",
                    "type": "naive",
                    "listen_port": 2012
                },
                {
                    "tag": "tuic-in",
                    "type": "tuic",
                    "listen_port": 2013
                },
                {
                    "tag": "hy2-in",
                    "type": "hysteria2",
                    "listen_port": 2014
                }
            ]
        });
        SubscriptionConfig::from_document_with_node_name_base(&document, "🇯🇵 Japan").unwrap()
    }

    fn sample_user() -> User {
        User {
            uuid: Uuid::parse_str("5946ceeb-0363-42d5-8d23-ceae21da428f").unwrap(),
            name: "chao".to_owned(),
            token: "token".to_owned(),
        }
    }
}
