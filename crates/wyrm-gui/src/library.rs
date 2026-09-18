//! The catalog the inspector offers: transport tags and mitigation templates,
//! each mapped to the WYRM rules it addresses so a click both records the control
//! and downgrades the matching findings.

/// Selectable dataflow tags (id, human label). The transport ones satisfy the
/// engine's encryption predicate; the rest are documentary.
pub const TAGS: &[(&str, &str)] = &[
    ("tls", "TLS (transport encrypted)"),
    ("mtls", "mutual TLS"),
    ("https", "HTTPS"),
    ("encrypted", "encrypted tunnel (IPSec/VPN)"),
    ("authenticated", "caller authenticated"),
    ("source-range-allowlist", "source-IP allowlist"),
];

/// A mitigation the user can drop onto the selected element. `addresses` are the
/// rule ids it neutralises; `risk` is its `riskReduction` (100 resolves).
pub struct MitTemplate {
    pub id: &'static str,
    pub name: &'static str,
    pub risk: u8,
    pub addresses: &'static [&'static str],
    pub desc: &'static str,
}

pub const MITIGATIONS: &[MitTemplate] = &[
    MitTemplate {
        id: "tls",
        name: "TLS / mTLS on the flow",
        risk: 100,
        addresses: &["WYRM-T001", "WYRM-T002"],
        desc: "Terminate the flow over TLS and verify peer identity.",
    },
    MitTemplate {
        id: "waf",
        name: "Web Application Firewall",
        risk: 50,
        addresses: &["WYRM-T003"],
        desc: "WAF (Cloudflare / Cloud Armor / AWS WAF) filtering the ingress.",
    },
    MitTemplate {
        id: "iap",
        name: "Identity-Aware Proxy (auth gate)",
        risk: 80,
        addresses: &["WYRM-T003", "WYRM-T005"],
        desc: "Managed auth+authz wall; verify the binding is not allUsers.",
    },
    MitTemplate {
        id: "sso",
        name: "OAuth2 / SSO authentication",
        risk: 70,
        addresses: &["WYRM-T005", "WYRM-T003"],
        desc: "Authenticate the caller (OIDC / oauth2-proxy / Keycloak).",
    },
    MitTemplate {
        id: "private-zone",
        name: "Private zone / network policy",
        risk: 60,
        addresses: &["WYRM-T004"],
        desc: "Move the datastore private; least-privilege network access only.",
    },
    MitTemplate {
        id: "allowlist",
        name: "Source-IP allowlist",
        risk: 40,
        addresses: &["WYRM-T003"],
        desc: "Restrict ingress to known source ranges.",
    },
];
