//! Authenticated operator control plane built from Proxima's HTTP pipe path.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use proxima::middlewares::auth::Auth;
use proxima::pipe::{PipeHandle, into_handle};
use proxima::{ProximaError, Request, Response, SendPipe};

use crate::{
    ClientGroupConfig, CountryPolicyConfig, Mode, Policy, RegexRuleConfig, RewriteConfig,
    RuleConfig, ServiceProfileConfig,
};

const MAX_POLICY_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, serde::Deserialize)]
struct ProfileReload {
    profiles: Vec<ServiceProfileConfig>,
    #[serde(default)]
    client_groups: Vec<ClientGroupConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct ClientGroupUpsert {
    client_groups: Vec<ClientGroupConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct ProfileUpsert {
    profiles: Vec<ServiceProfileConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct RewriteUpsert {
    rewrites: Vec<RewriteConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct PolicyBundle {
    /// Optional legacy fallback mode; omitted fields retain their live value.
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    domains: Option<Vec<String>>,
    #[serde(default)]
    default_action: Option<crate::Action>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
    #[serde(default)]
    regex_rules: Vec<RegexRuleConfig>,
    #[serde(default)]
    profiles: Vec<ServiceProfileConfig>,
    #[serde(default)]
    client_groups: Vec<ClientGroupConfig>,
    #[serde(default)]
    rewrites: Vec<RewriteConfig>,
    #[serde(default)]
    country_policy: CountryPolicyConfig,
    /// Omitted/null retains the currently loaded blocklist snapshot.
    #[serde(default)]
    blocklists: Option<Vec<String>>,
}
const ADMIN_UI: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>Blackhole DNS</title>
<style>body{font:15px system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}pre{background:#f3f3f3;padding:1rem;overflow:auto}button{padding:.4rem .7rem}</style>
<h1>Blackhole DNS</h1>
<p>Authenticated operator control plane. DNS names and packet payloads are not shown here.</p>
<p><button id="clear-logs">Clear privacy log</button> <button id="reload-blocklists">Reload blocklists</button></p>
<h2>Status</h2><pre id="status">loading…</pre>
<h2>Admission limits</h2><pre id="admission-status">loading…</pre>
<h2>Country policy</h2><pre id="country-status">loading…</pre>
<h2>Privacy status</h2><pre id="privacy-status">loading…</pre>
<h2>Rules</h2><pre id="rules">loading…</pre>
<h2>Service profiles</h2><pre id="profiles">loading…</pre>
<h2>Client groups</h2><pre id="groups">loading…</pre>
<h2>Local rewrites</h2><pre id="rewrites">loading…</pre>
<h2>Privacy log</h2><pre id="logs">loading…</pre>
<script>
const load = (path, target) => fetch(path).then(response => response.json()).then(value => {
  document.querySelector(target).textContent = JSON.stringify(value, null, 2);
});
const refresh = () => Promise.all([load('/status','#status'), load('/admission/status','#admission-status'), load('/country/status','#country-status'), load('/privacy/status','#privacy-status'), load('/rules','#rules'), load('/profiles','#profiles'), load('/client-groups','#groups'), load('/rewrites','#rewrites'), load('/logs','#logs')]);
document.querySelector('#clear-logs').onclick = () => fetch('/logs/clear', {method:'POST'}).then(refresh);
document.querySelector('#reload-blocklists').onclick = () => fetch('/reload/blocklists', {method:'POST'}).then(refresh);
refresh();
</script>
"#;

/// The current control plane is HTTP bearer auth without TLS. Keep credentials
/// on the local host until a TLS listener is added to the admin surface.
pub fn validate_bind(bind: SocketAddr) -> Result<(), ProximaError> {
    if bind.ip().is_loopback() {
        Ok(())
    } else {
        Err(ProximaError::Config(
            "admin.listen must be a loopback address until admin TLS is available".into(),
        ))
    }
}

/// The authenticated control surface exposes only health and bounded
/// non-sensitive status; reload routes rebuild already configured snapshots.
/// It deliberately exposes no query data or configuration secrets.
pub struct AdminHandler {
    policy: Arc<Policy>,
}

impl AdminHandler {
    #[must_use]
    pub fn new(policy: Arc<Policy>) -> Self {
        Self { policy }
    }
}

impl SendPipe for AdminHandler {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        let method = request.method.as_str().unwrap_or("");
        let path = std::str::from_utf8(&request.path).unwrap_or("");
        match (method, path) {
            ("GET", "/") => {
                Ok(Response::ok(ADMIN_UI).with_header("content-type", "text/html; charset=utf-8"))
            }
            ("GET", "/health") => Ok(Response::ok("{\"status\":\"ok\"}")),
            ("GET", "/status") => Ok(Response::ok(self.policy.admin_status())),
            ("GET", "/admission/status") => Ok(Response::ok(self.policy.admin_admission_status())),
            ("GET", "/country/status") => Ok(Response::ok(self.policy.admin_country_status())),
            ("GET", "/policy/status") => Ok(Response::ok(self.policy.admin_policy_status())),
            ("GET", "/privacy/status") => Ok(Response::ok(self.policy.admin_privacy_status())),
            ("GET", "/rules") => Ok(Response::ok(self.policy.admin_rules())),
            ("GET", "/profiles") => Ok(Response::ok(self.policy.admin_profiles())),
            ("GET", "/client-groups") => Ok(Response::ok(self.policy.admin_client_groups())),
            ("GET", "/rewrites") => Ok(Response::ok(self.policy.admin_rewrites())),
            ("POST", "/reload/policy-bundle") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let bundle = match serde_json::from_slice::<PolicyBundle>(&request.payload) {
                    Ok(bundle) => bundle,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            r#"{{"status":"error","message":{}}}"#,
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.reload_policy_bundle_with_legacy(
                    &bundle.rules,
                    &bundle.regex_rules,
                    &bundle.profiles,
                    &bundle.client_groups,
                    &bundle.rewrites,
                    &bundle.country_policy,
                    bundle.blocklists.as_deref(),
                    bundle.mode,
                    bundle.domains.as_deref(),
                    bundle.default_action,
                ) {
                    Ok(_) => Ok(Response::ok(r#"{"status":"reloaded"}"#)),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        r#"{{"status":"error","message":{}}}"#,
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/profiles") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<ProfileReload>(&request.payload) {
                    Ok(update) => update,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self
                    .policy
                    .reload_profiles(&update.profiles, &update.client_groups)
                {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/profiles/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<ProfileUpsert>(&request.payload) {
                    Ok(update) => update,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.upsert_profiles(&update.profiles) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/profiles/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let ids = match serde_json::from_slice::<Vec<u32>>(&request.payload) {
                    Ok(ids) => ids,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.remove_profiles(&ids) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"removed\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/client-groups/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<ClientGroupUpsert>(&request.payload) {
                    Ok(update) => update,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.upsert_client_groups(&update.client_groups) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/client-groups/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let names = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(names) => names,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.remove_client_groups(&names) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"removed\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("GET", "/logs") => Ok(Response::ok(self.policy.admin_query_log())),
            ("POST", "/cache/clear") => Ok(Response::ok(format!(
                "{{\"status\":\"cleared\",\"entries\":{}}}",
                self.policy.clear_cache()
            ))),
            ("POST", "/logs/clear") => Ok(Response::ok(format!(
                "{{\"status\":\"cleared\",\"entries\":{}}}",
                self.policy.clear_query_log()
            ))),
            ("POST", "/reload/blocklists") => match self.policy.reload_blocklists() {
                Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                Err(error) => Ok(Response::new(500).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/blocklists/replace") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let paths = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(paths) => paths,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.replace_blocklist_sources(&paths) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"replaced\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/country") => match self.policy.reload_country_policy() {
                Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                Err(error) => Ok(Response::new(422).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/policy" | "/reload/policy/add" | "/reload/policy/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let rules = match serde_json::from_slice::<Vec<RuleConfig>>(&request.payload) {
                    Ok(rules) => rules,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                if rules.is_empty() {
                    return Ok(Response::new(422).with_body(
                        "{\"status\":\"error\",\"message\":\"policy must contain at least one rule\"}",
                    ));
                }
                if path == "/reload/policy/add" && rules.is_empty() {
                    return Ok(Response::new(422).with_body(
                        "{\"status\":\"error\",\"message\":\"policy additions must contain at least one rule\"}",
                    ));
                }
                let result = if path == "/reload/policy/add" {
                    self.policy.append_rules(&rules)
                } else if path == "/reload/policy/upsert" {
                    self.policy.upsert_rules(&rules)
                } else {
                    self.policy.reload_rules(&rules)
                };
                match result {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/policy/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let ids = match serde_json::from_slice::<Vec<u32>>(&request.payload) {
                    Ok(ids) => ids,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.remove_rules(&ids) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"removed\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/regex") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let rules = match serde_json::from_slice::<Vec<RegexRuleConfig>>(&request.payload) {
                    Ok(rules) => rules,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.reload_regex_rules(&rules) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/regex/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let rules = match serde_json::from_slice::<Vec<RegexRuleConfig>>(&request.payload) {
                    Ok(rules) => rules,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.upsert_regex_rules(&rules) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/regex/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let ids = match serde_json::from_slice::<Vec<u32>>(&request.payload) {
                    Ok(ids) => ids,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.remove_regex_rules(&ids) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"removed\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/rewrites/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<RewriteUpsert>(&request.payload) {
                    Ok(update) => update,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.upsert_rewrites(&update.rewrites) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/rewrites") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let rewrites = match serde_json::from_slice::<Vec<RewriteConfig>>(&request.payload)
                {
                    Ok(rewrites) => rewrites,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.reload_rewrites(&rewrites) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/rewrites/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let names = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(names) => names,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.remove_rewrites(&names) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"removed\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            (
                _,
                "/"
                | "/health"
                | "/status"
                | "/admission/status"
                | "/country/status"
                | "/policy/status"
                | "/privacy/status"
                | "/rules"
                | "/profiles"
                | "/client-groups"
                | "/rewrites"
                | "/reload/profiles"
                | "/reload/profiles/upsert"
                | "/reload/profiles/remove"
                | "/reload/client-groups/upsert"
                | "/reload/client-groups/remove"
                | "/reload/policy-bundle"
                | "/logs"
                | "/cache/clear"
                | "/logs/clear"
                | "/reload/blocklists"
                | "/reload/blocklists/replace"
                | "/reload/country"
                | "/reload/policy"
                | "/reload/policy/add"
                | "/reload/policy/upsert"
                | "/reload/policy/remove"
                | "/reload/regex"
                | "/reload/regex/upsert"
                | "/reload/regex/remove"
                | "/reload/rewrites"
                | "/reload/rewrites/upsert"
                | "/reload/rewrites/remove",
            ) => Ok(Response::new(405)),
            _ => Ok(Response::not_found()),
        }
    }
}

/// Build a Proxima bearer-authenticated admin handler.
pub fn authenticated_handle(
    policy: Arc<Policy>,
    token: String,
) -> Result<PipeHandle, ProximaError> {
    if token.is_empty() || token.len() > 4096 || token.bytes().any(|byte| byte <= 0x20) {
        return Err(ProximaError::Config(
            "admin token must be 1-4096 bytes without whitespace".into(),
        ));
    }
    let auth = Auth {
        inner: into_handle(AdminHandler::new(policy)),
        header: "authorization".into(),
        allow: BTreeSet::from([token]),
        realm: Arc::from(b"blackhole-admin".as_slice()),
        on_unauthorized_status: 401,
        strip_prefix: Some("Bearer ".into()),
    };
    Ok(into_handle(auth))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use proxima::pipe::SendPipe;

    fn request(method: &str, path: &str) -> Request<Bytes> {
        Request::builder()
            .method(method)
            .path(path)
            .build()
            .expect("valid admin request")
    }

    #[test]
    fn health_and_unknown_routes_are_bounded() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let health = block_on(handler.call(request("GET", "/health"))).expect("health response");
        assert_eq!(health.status, 200);
        assert_eq!(health.payload, Bytes::from_static(b"{\"status\":\"ok\"}"));
        let ui = block_on(handler.call(request("GET", "/"))).expect("UI response");
        assert_eq!(ui.status, 200);
        assert!(ui.payload.starts_with(b"<!doctype html>"));
        assert!(ui.payload.windows(5).any(|window| window == b"/logs"));
        assert!(
            ui.payload
                .windows(b"/privacy/status".len())
                .any(|window| window == b"/privacy/status")
        );
        assert!(
            ui.payload
                .windows(b"/admission/status".len())
                .any(|window| window == b"/admission/status")
        );
        assert!(
            ui.payload
                .windows(b"/country/status".len())
                .any(|window| window == b"/country/status")
        );
        assert!(
            ui.payload
                .windows(b"/reload/blocklists".len())
                .any(|window| window == b"/reload/blocklists")
        );
        assert!(ui.payload.len() < 4 * 1024);
        let clear =
            block_on(handler.call(request("POST", "/cache/clear"))).expect("cache clear response");
        assert_eq!(clear.status, 200);
        assert_eq!(
            clear.payload,
            Bytes::from_static(b"{\"status\":\"cleared\",\"entries\":0}")
        );
        let status = block_on(handler.call(request("GET", "/status"))).expect("status response");
        assert_eq!(status.status, 200);
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("status JSON");
        assert_eq!(status["status"], "ok");
        assert_eq!(status["rules_configured"], false);
        let policy_status =
            block_on(handler.call(request("GET", "/policy/status"))).expect("policy status");
        assert_eq!(policy_status.status, 200);
        let policy_status: serde_json::Value =
            serde_json::from_slice(&policy_status.payload).expect("policy status JSON");
        assert_eq!(policy_status["domain_rules"], 0);
        assert_eq!(policy_status["blocklist_sources"], 0);
        assert_eq!(policy_status["legacy_domain_count"], 0);
        assert_eq!(policy_status["legacy_mode"], "nxdomain");
        assert_eq!(policy_status["default_action"], "pass");
        assert_eq!(policy_status["legacy_mode_active"], true);
        let privacy_status =
            block_on(handler.call(request("GET", "/privacy/status"))).expect("privacy status");
        assert_eq!(privacy_status.status, 200);
        let privacy_status: serde_json::Value =
            serde_json::from_slice(&privacy_status.payload).expect("privacy status JSON");
        assert_eq!(privacy_status["query_log_enabled"], false);
        assert_eq!(privacy_status["query_recording_enabled"], false);
        assert_eq!(privacy_status["query_recording_rotation_enabled"], false);
        assert_eq!(privacy_status["query_recording_max_files"], 3);
        assert_eq!(privacy_status["payload_recording"], "disabled");
        assert_eq!(privacy_status["client_identity_recording"], "disabled");
        let admission_status =
            block_on(handler.call(request("GET", "/admission/status"))).expect("admission status");
        assert_eq!(admission_status.status, 200);
        let admission_status: serde_json::Value =
            serde_json::from_slice(&admission_status.payload).expect("admission status JSON");
        assert_eq!(
            admission_status["max_response_bytes_per_network_per_second"],
            4_194_304
        );
        assert_eq!(admission_status["network_abuse_ipv4_prefix"], 24);
        assert_eq!(admission_status["network_abuse_ipv6_prefix"], 64);
        let country_status =
            block_on(handler.call(request("GET", "/country/status"))).expect("country status");
        assert_eq!(country_status.status, 200);
        let country_status: serde_json::Value =
            serde_json::from_slice(&country_status.payload).expect("country status JSON");
        assert_eq!(country_status["map_configured"], false);
        assert_eq!(country_status["entries"], 0);
        assert_eq!(country_status["deny"], serde_json::json!([]));
        assert_eq!(country_status["observe"], serde_json::json!([]));
        assert_eq!(status["profiles_configured"], 0);
        assert_eq!(status["client_groups_configured"], 0);
        assert_eq!(status["upstream_configured"], false);
        assert_eq!(status["country_policy_configured"], false);
        assert_eq!(status["country_reload_interval_secs"], 0);
        assert_eq!(status["cache_entries"], 0);
        let rules = block_on(handler.call(request("GET", "/rules"))).expect("rules response");
        assert_eq!(rules.status, 200);
        let rules: serde_json::Value = serde_json::from_slice(&rules.payload).expect("rules JSON");
        assert_eq!(rules["total"], 0);
        assert_eq!(rules["truncated"], false);
        let logs = block_on(handler.call(request("GET", "/logs"))).expect("logs response");
        assert_eq!(logs.status, 200);
        assert_eq!(
            logs.payload,
            Bytes::from_static(b"{\"enabled\":false,\"entries\":[]}")
        );
        let clear_logs =
            block_on(handler.call(request("POST", "/logs/clear"))).expect("log clear response");
        assert_eq!(clear_logs.status, 200);
        assert_eq!(
            clear_logs.payload,
            Bytes::from_static(b"{\"status\":\"cleared\",\"entries\":0}")
        );
        let unknown = block_on(handler.call(request("GET", "/private"))).expect("404 response");
        assert_eq!(unknown.status, 404);
        let wrong_method =
            block_on(handler.call(request("GET", "/reload/blocklists"))).expect("405 response");
        assert_eq!(wrong_method.status, 405);
        let wrong_country_method =
            block_on(handler.call(request("GET", "/reload/country"))).expect("405 response");
        assert_eq!(wrong_country_method.status, 405);
        let wrong_status_method =
            block_on(handler.call(request("POST", "/status"))).expect("405 status response");
        assert_eq!(wrong_status_method.status, 405);
        let wrong_privacy_status_method =
            block_on(handler.call(request("POST", "/privacy/status")))
                .expect("405 privacy status response");
        assert_eq!(wrong_privacy_status_method.status, 405);
        let wrong_admission_status_method =
            block_on(handler.call(request("POST", "/admission/status")))
                .expect("405 admission status response");
        assert_eq!(wrong_admission_status_method.status, 405);
        let wrong_country_status_method =
            block_on(handler.call(request("POST", "/country/status")))
                .expect("405 country status response");
        assert_eq!(wrong_country_status_method.status, 405);
        let wrong_rules_method =
            block_on(handler.call(request("POST", "/rules"))).expect("405 rules response");
        assert_eq!(wrong_rules_method.status, 405);
    }

    #[test]
    fn blocklist_source_replacement_is_atomic() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-admin-blocklist-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::write(&path, "ads.example\n").expect("write blocklist");
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let path_json = serde_json::to_string(&vec![path.to_string_lossy().into_owned()])
            .expect("blocklist paths JSON");
        let replaced = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/replace")
                    .payload(path_json)
                    .build()
                    .expect("replacement request"),
            ),
        )
        .expect("replacement response");
        assert_eq!(replaced.status, 200);
        let status =
            block_on(handler.call(request("GET", "/policy/status"))).expect("status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["blocklist_sources"], 1);
        assert_eq!(status["blocklist_rules"], 2, "apex plus subdomain rule");

        let failed = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/replace")
                    .payload(r#"["/definitely/missing/blackhole.list"]"#)
                    .build()
                    .expect("invalid replacement request"),
            ),
        )
        .expect("invalid replacement response");
        assert_eq!(failed.status, 422);
        let status =
            block_on(handler.call(request("GET", "/policy/status"))).expect("status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["blocklist_sources"], 1);
        assert_eq!(
            status["blocklist_rules"], 2,
            "previous blocklist remains live"
        );
        std::fs::remove_file(path).expect("remove blocklist");
    }

    #[test]
    fn rules_route_lists_metadata_and_caps_large_responses() {
        let mut config = crate::Config::default();
        config.policy.rules = vec![RuleConfig {
            id: 7,
            domain: "blocked.example".into(),
            action: crate::Action::Nxdomain,
            priority: 4,
            qtype: Some(1),
            qclass: Some(1),
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        }];
        config.policy.regex_rules = (0..80)
            .map(|id| RegexRuleConfig {
                id: 100 + id,
                pattern: format!("^host{id}{}$", "a".repeat(900)),
                action: crate::Action::Drop,
                priority: 0,
                qtype: None,
                qclass: None,
                client: None,
                client_cidrs: Vec::new(),
            })
            .collect();
        config.policy.profiles = vec![crate::ServiceProfileConfig {
            id: 400,
            name: "family".into(),
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: vec!["home".into()],
            priority: 10,
            client_cidrs: vec![],
            qtype: None,
            qclass: None,
        }];
        config.policy.client_groups = vec![crate::ClientGroupConfig {
            name: "home".into(),
            client_addresses: Vec::new(),
            client_cidrs: vec!["192.0.2.0/24".into()],
        }];
        let handler = AdminHandler::new(Arc::new(Policy::new(config).expect("valid rules")));
        let response = block_on(handler.call(request("GET", "/rules"))).expect("rules response");
        assert_eq!(response.status, 200);
        assert!(response.payload.len() <= 64 * 1024);
        let body: serde_json::Value =
            serde_json::from_slice(&response.payload).expect("rules JSON");
        assert_eq!(body["total"], 82);
        assert_eq!(body["truncated"], true);
        assert_eq!(body["rules"][0]["kind"], "domain");
        assert_eq!(body["rules"][0]["action"], "nxdomain");
        let profiles = block_on(handler.call(request("GET", "/profiles"))).expect("profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("profiles JSON");
        assert_eq!(profiles["total"], 1);
        assert_eq!(profiles["profiles"][0]["name"], "family");
        let groups =
            block_on(handler.call(request("GET", "/client-groups"))).expect("client groups");
        let groups: serde_json::Value =
            serde_json::from_slice(&groups.payload).expect("client groups JSON");
        assert_eq!(groups["total"], 1);
        assert_eq!(groups["client_groups"][0]["name"], "home");

        let replacement = Request::builder()
            .method("POST")
            .path("/reload/profiles")
            .payload(
                r#"{"profiles":[{"id":500,"name":"new-family","domains":["new.example"],"action":"reject","groups":[],"priority":8,"client_cidrs":[],"qtype":null,"qclass":null}],"client_groups":[]}"#,
            )
            .build()
            .expect("profile replacement request");
        let replacement = block_on(handler.call(replacement)).expect("profile reload");
        assert_eq!(replacement.status, 200);
        let profiles = block_on(handler.call(request("GET", "/profiles"))).expect("profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("replacement profiles JSON");
        assert_eq!(profiles["total"], 1);
        assert_eq!(profiles["profiles"][0]["name"], "new-family");
        let rules = block_on(handler.call(request("GET", "/rules"))).expect("rules");
        let rules: serde_json::Value = serde_json::from_slice(&rules.payload).expect("rules JSON");
        assert_eq!(
            rules["total"], 82,
            "explicit, profile, and regex rules remain"
        );
    }

    #[test]
    fn profile_reload_rejects_invalid_replacement_without_publishing() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let invalid = Request::builder()
            .method("POST")
            .path("/reload/profiles")
            .payload(
                r#"{"profiles":[{"id":1,"name":"bad","domains":[],"action":"drop"}],"client_groups":[]}"#,
            )
            .build()
            .expect("invalid profile replacement request");
        let response = block_on(handler.call(invalid)).expect("invalid profile response");
        assert_eq!(response.status, 422);
        let profiles = block_on(handler.call(request("GET", "/profiles"))).expect("profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("profiles JSON");
        assert_eq!(profiles["total"], 0);
    }

    #[test]
    fn client_group_upsert_republishes_profiles_atomically() {
        let mut config = crate::Config::default();
        config.policy.profiles = vec![crate::ServiceProfileConfig {
            id: 700,
            name: "family".into(),
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: vec!["home".into()],
            priority: 0,
            client_cidrs: Vec::new(),
            qtype: None,
            qclass: None,
        }];
        config.policy.client_groups = vec![crate::ClientGroupConfig {
            name: "home".into(),
            client_addresses: Vec::new(),
            client_cidrs: vec!["192.0.2.0/24".into()],
        }];
        let policy = Arc::new(Policy::new(config).expect("valid group policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let update = Request::builder()
            .method("POST")
            .path("/reload/client-groups/upsert")
            .payload(
                r#"{"client_groups":[{"name":"HOME","client_addresses":["192.0.2.53"],"client_cidrs":["198.51.100.0/24"]},{"name":"guest","client_cidrs":["203.0.113.0/24"]}]}"#,
            )
            .build()
            .expect("group upsert request");
        let response = block_on(handler.call(update)).expect("group upsert response");
        assert_eq!(response.status, 200);
        let groups =
            block_on(handler.call(request("GET", "/client-groups"))).expect("groups response");
        let groups: serde_json::Value =
            serde_json::from_slice(&groups.payload).expect("groups JSON");
        assert_eq!(groups["total"], 2);
        assert_eq!(
            groups["client_groups"][0]["client_addresses"][0],
            "192.0.2.53"
        );

        let invalid = Request::builder()
            .method("POST")
            .path("/reload/client-groups/upsert")
            .payload(r#"{"client_groups":[{"name":"guest","client_cidrs":[]}]}"#)
            .build()
            .expect("invalid group upsert request");
        let response = block_on(handler.call(invalid)).expect("invalid group response");
        assert_eq!(response.status, 422);
        let groups = block_on(handler.call(request("GET", "/client-groups")))
            .expect("groups remain response");
        let groups: serde_json::Value =
            serde_json::from_slice(&groups.payload).expect("groups remain JSON");
        assert_eq!(groups["total"], 2);
        assert_eq!(
            groups["client_groups"][0]["client_cidrs"][0],
            "198.51.100.0/24"
        );

        let remove_unused = Request::builder()
            .method("POST")
            .path("/reload/client-groups/remove")
            .payload(r#"["GUEST"]"#)
            .build()
            .expect("remove unused group request");
        let response = block_on(handler.call(remove_unused)).expect("remove unused response");
        assert_eq!(response.status, 200);
        let groups = block_on(handler.call(request("GET", "/client-groups")))
            .expect("removed groups response");
        let groups: serde_json::Value =
            serde_json::from_slice(&groups.payload).expect("removed groups JSON");
        assert_eq!(groups["total"], 1);

        let remove_referenced = Request::builder()
            .method("POST")
            .path("/reload/client-groups/remove")
            .payload(r#"["home"]"#)
            .build()
            .expect("remove referenced group request");
        let response =
            block_on(handler.call(remove_referenced)).expect("remove referenced response");
        assert_eq!(response.status, 422);
        let groups = block_on(handler.call(request("GET", "/client-groups")))
            .expect("retained groups response");
        let groups: serde_json::Value =
            serde_json::from_slice(&groups.payload).expect("retained groups JSON");
        assert_eq!(groups["total"], 1);
        assert_eq!(groups["client_groups"][0]["name"], "HOME");
    }

    #[test]
    fn profile_upsert_and_removal_are_atomic_by_stable_id() {
        let mut config = crate::Config::default();
        config.policy.profiles = vec![crate::ServiceProfileConfig {
            id: 800,
            name: "family".into(),
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: Vec::new(),
            priority: 0,
            client_cidrs: Vec::new(),
            qtype: None,
            qclass: None,
        }];
        let policy = Arc::new(Policy::new(config).expect("valid profile policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let update = Request::builder()
            .method("POST")
            .path("/reload/profiles/upsert")
            .payload(
                r#"{"profiles":[{"id":800,"name":"family-edited","domains":["new.example"],"action":"reject"},{"id":801,"name":"guest","domains":["guest.example"],"action":"drop"}]}"#,
            )
            .build()
            .expect("profile upsert request");
        let response = block_on(handler.call(update)).expect("profile upsert response");
        assert_eq!(response.status, 200);
        let profiles =
            block_on(handler.call(request("GET", "/profiles"))).expect("profile listing");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("profile JSON");
        assert_eq!(profiles["total"], 2);
        assert_eq!(profiles["profiles"][0]["name"], "family-edited");

        let duplicate = Request::builder()
            .method("POST")
            .path("/reload/profiles/upsert")
            .payload(
                r#"{"profiles":[{"id":801,"name":"one","domains":["one.example"],"action":"drop"},{"id":801,"name":"two","domains":["two.example"],"action":"reject"}]}"#,
            )
            .build()
            .expect("duplicate profile upsert request");
        let response = block_on(handler.call(duplicate)).expect("duplicate profile response");
        assert_eq!(response.status, 422);
        let remove = Request::builder()
            .method("POST")
            .path("/reload/profiles/remove")
            .payload("[800]")
            .build()
            .expect("profile removal request");
        let response = block_on(handler.call(remove)).expect("profile removal response");
        assert_eq!(response.status, 200);
        let profiles =
            block_on(handler.call(request("GET", "/profiles"))).expect("remaining profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("remaining profile JSON");
        assert_eq!(profiles["total"], 1);
        assert_eq!(profiles["profiles"][0]["name"], "guest");

        let unknown = Request::builder()
            .method("POST")
            .path("/reload/profiles/remove")
            .payload("[999]")
            .build()
            .expect("unknown profile removal request");
        let response = block_on(handler.call(unknown)).expect("unknown removal response");
        assert_eq!(response.status, 422);
    }

    #[test]
    fn policy_bundle_replaces_all_tables_in_one_validated_snapshot() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let bundle = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(
                r#"{"rules":[{"id":7,"domain":"blocked.example","action":"nxdomain"}],"regex_rules":[{"id":8,"pattern":"^ads\\.","action":"drop"}],"profiles":[{"id":9,"name":"family","domains":["family.example"],"action":"reject"}],"client_groups":[],"rewrites":[{"name":"router.example","ipv4":"192.0.2.1","ipv6":null,"ttl":30}]}"#,
            )
            .build()
            .expect("policy bundle request");
        let response = block_on(handler.call(bundle)).expect("bundle response");
        assert_eq!(response.status, 200);
        let status = block_on(handler.call(request("GET", "/policy/status"))).expect("status");
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("status JSON");
        assert_eq!(status["policy_generation"], 2);
        let profiles = block_on(handler.call(request("GET", "/profiles"))).expect("profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("profiles JSON");
        assert_eq!(profiles["total"], 1);
        let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&[6, b'f', b'a', b'm', b'i', b'l', b'y', 7]);
        wire.extend_from_slice(b"example");
        wire.extend_from_slice(&[0, 0, 1, 0, 1]);
        let query = crate::query::QueryView::parse(&wire).expect("profile query");
        assert_eq!(policy.action_for_view(query), crate::Action::Reject);
        let rewrite_query = proxima_dns::DnsQuery {
            id: 1,
            recursion_desired: true,
            name: "router.example.".into(),
            qtype: 1,
            qclass: 1,
        };
        let answer = policy.evaluate(&rewrite_query).expect("rewrite answer");
        assert_eq!(answer.records[0].rdata, vec![192, 0, 2, 1]);
        let invalid = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(
                r#"{"rules":[{"id":7,"domain":"other.example","action":"drop"}],"regex_rules":[{"id":7,"pattern":"^other$","action":"drop"}]}"#,
            )
            .build()
            .expect("invalid policy bundle request");
        let response = block_on(handler.call(invalid)).expect("invalid bundle response");
        assert_eq!(response.status, 422);
        let profiles = block_on(handler.call(request("GET", "/profiles"))).expect("profiles");
        let profiles: serde_json::Value =
            serde_json::from_slice(&profiles.payload).expect("profiles JSON");
        assert_eq!(profiles["profiles"][0]["name"], "family");
        let answer = policy.evaluate(&rewrite_query).expect("retained rewrite");
        assert_eq!(answer.records[0].rdata, vec![192, 0, 2, 1]);
        let status = block_on(handler.call(request("GET", "/policy/status"))).expect("status");
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("status JSON");
        assert_eq!(status["policy_generation"], 2);
    }

    #[test]
    fn policy_bundle_reloads_legacy_defaults_atomically() {
        let mut config = crate::Config::default();
        config.policy.mode = crate::Mode::Ignore;
        config.policy.domains = vec!["old.example".into()];
        let policy = Arc::new(Policy::new(config).expect("legacy policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let query = |name: &str| proxima_dns::DnsQuery {
            id: 1,
            recursion_desired: true,
            name: name.into(),
            qtype: 1,
            qclass: 1,
        };
        assert!(policy.evaluate(&query("old.example.")).is_none());

        let replacement = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(r#"{"mode":"nxdomain","domains":["new.example"],"default_action":"reject"}"#)
            .build()
            .expect("legacy replacement request");
        let response = block_on(handler.call(replacement)).expect("legacy replacement response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.evaluate(&query("old.example.")).unwrap().rcode, 0);
        assert_eq!(policy.evaluate(&query("new.example.")).unwrap().rcode, 3);

        let invalid = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(r#"{"mode":"ignore","domains":["bad..name"]}"#)
            .build()
            .expect("invalid legacy replacement request");
        let response = block_on(handler.call(invalid)).expect("invalid legacy response");
        assert_eq!(response.status, 422);
        assert_eq!(policy.evaluate(&query("new.example.")).unwrap().rcode, 3);
    }

    #[test]
    fn policy_reload_publishes_valid_rules_and_rejects_bad_json() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let valid = Request::builder()
            .method("POST")
            .path("/reload/policy")
            .payload(
                r#"[{"id":7,"domain":"blocked.example","action":"nxdomain","priority":0,"qtype":null,"qclass":null,"client":null,"client_cidr":null}]"#,
            )
            .build()
            .expect("valid policy request");
        let response = block_on(handler.call(valid)).expect("reload response");
        assert_eq!(response.status, 200);
        let mut query_wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_wire.extend_from_slice(b"\x07blocked\x07example\0\0\x01\0\x01");
        let query = crate::query::QueryView::parse(&query_wire).expect("query");
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let addition = Request::builder()
            .method("POST")
            .path("/reload/policy/add")
            .payload(
                r#"[{"id":8,"domain":"added.example","action":"drop","priority":0,"qtype":null,"qclass":null,"client":null,"client_cidr":null}]"#,
            )
            .build()
            .expect("valid policy addition request");
        let response = block_on(handler.call(addition)).expect("addition response");
        assert_eq!(response.status, 200);
        let mut added_wire = vec![0, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        added_wire.extend_from_slice(b"\x05added\x07example\0\0\x01\0\x01");
        let added_query = crate::query::QueryView::parse(&added_wire).expect("added query");
        assert_eq!(policy.action_for_view(added_query), crate::Action::Drop);
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let upsert = Request::builder()
            .method("POST")
            .path("/reload/policy/upsert")
            .payload(
                r#"[{"id":7,"domain":"blocked.example","action":"reject","priority":0,"qtype":null,"qclass":null,"client":null,"client_cidr":null},{"id":9,"domain":"new.example","action":"sink","priority":0,"qtype":null,"qclass":null,"client":null,"client_cidr":null}]"#,
            )
            .build()
            .expect("valid policy upsert request");
        let response = block_on(handler.call(upsert)).expect("upsert response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.action_for_view(query), crate::Action::Reject);
        assert_eq!(policy.action_for_view(added_query), crate::Action::Drop);
        let mut new_wire = vec![0, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        new_wire.extend_from_slice(b"\x03new\x07example\0\0\x01\0\x01");
        let new_query = crate::query::QueryView::parse(&new_wire).expect("new query");
        assert_eq!(policy.action_for_view(new_query), crate::Action::Sink);

        let duplicate_upsert = Request::builder()
            .method("POST")
            .path("/reload/policy/upsert")
            .payload(
                r#"[{"id":9,"domain":"new.example","action":"reject"},{"id":9,"domain":"other.example","action":"drop"}]"#,
            )
            .build()
            .expect("duplicate upsert request");
        let response = block_on(handler.call(duplicate_upsert)).expect("duplicate response");
        assert_eq!(response.status, 422);
        assert_eq!(policy.action_for_view(new_query), crate::Action::Sink);

        let removal = Request::builder()
            .method("POST")
            .path("/reload/policy/remove")
            .payload("[8]")
            .build()
            .expect("valid policy removal request");
        let response = block_on(handler.call(removal)).expect("removal response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.action_for_view(added_query), crate::Action::Pass);
        assert_eq!(policy.action_for_view(query), crate::Action::Reject);

        let unknown_removal = Request::builder()
            .method("POST")
            .path("/reload/policy/remove")
            .payload("[999]")
            .build()
            .expect("unknown removal request");
        let response = block_on(handler.call(unknown_removal)).expect("unknown removal response");
        assert_eq!(response.status, 422);
        assert_eq!(policy.action_for_view(query), crate::Action::Reject);

        let invalid = Request::builder()
            .method("POST")
            .path("/reload/policy")
            .payload("not-json")
            .build()
            .expect("invalid request shape");
        let response = block_on(handler.call(invalid)).expect("error response");
        assert_eq!(response.status, 400);

        let empty = Request::builder()
            .method("POST")
            .path("/reload/policy")
            .payload("[]")
            .build()
            .expect("empty request shape");
        let response = block_on(handler.call(empty)).expect("empty policy response");
        assert_eq!(response.status, 422);
    }

    #[test]
    fn regex_reload_replaces_rules_and_allows_clearing_them() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let valid = Request::builder()
            .method("POST")
            .path("/reload/regex")
            .payload(
                r#"[{"id":9,"pattern":"^blocked\\.example$","action":"nxdomain","priority":0,"qtype":null,"qclass":null,"client":null}]"#,
            )
            .build()
            .expect("valid regex request");
        let response = block_on(handler.call(valid)).expect("regex reload response");
        assert_eq!(response.status, 200);
        let mut query_wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_wire.extend_from_slice(b"\x07blocked\x07example\0\0\x01\0\x01");
        let query = crate::query::QueryView::parse(&query_wire).expect("query");
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let conflicting_domain_rule = crate::RuleConfig {
            id: 9,
            domain: "other.example".into(),
            action: crate::Action::Drop,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        };
        assert_eq!(
            policy.reload_rules(&[conflicting_domain_rule]),
            Err(crate::policy::PolicyError::DuplicateRule { id: 9 })
        );
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let clear = Request::builder()
            .method("POST")
            .path("/reload/regex")
            .payload("[]")
            .build()
            .expect("clear regex request");
        let response = block_on(handler.call(clear)).expect("clear response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.action_for_view(query), crate::Action::Pass);
    }

    #[test]
    fn regex_upsert_and_removal_are_atomic_by_stable_id() {
        let mut config = crate::Config::default();
        config.policy.regex_rules = vec![RegexRuleConfig {
            id: 90,
            pattern: "^old\\.example$".into(),
            action: crate::Action::Drop,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidrs: Vec::new(),
        }];
        let policy = Arc::new(Policy::new(config).expect("valid regex policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let update = Request::builder()
            .method("POST")
            .path("/reload/regex/upsert")
            .payload(
                r#"[{"id":90,"pattern":"^new\\.example$","action":"nxdomain"},{"id":91,"pattern":"^guest\\.example$","action":"reject"}]"#,
            )
            .build()
            .expect("regex upsert request");
        assert_eq!(
            block_on(handler.call(update))
                .expect("upsert response")
                .status,
            200
        );

        let mut wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(b"\x03new\x07example\0\0\x01\0\x01");
        let query = crate::query::QueryView::parse(&wire).expect("new query");
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let invalid = Request::builder()
            .method("POST")
            .path("/reload/regex/upsert")
            .payload(r#"[{"id":90,"pattern":"[","action":"drop"}]"#)
            .build()
            .expect("invalid regex upsert request");
        assert_eq!(
            block_on(handler.call(invalid))
                .expect("invalid response")
                .status,
            422
        );
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let remove = Request::builder()
            .method("POST")
            .path("/reload/regex/remove")
            .payload("[90]")
            .build()
            .expect("regex removal request");
        assert_eq!(
            block_on(handler.call(remove))
                .expect("removal response")
                .status,
            200
        );
        assert_eq!(policy.action_for_view(query), crate::Action::Pass);

        let unknown = Request::builder()
            .method("POST")
            .path("/reload/regex/remove")
            .payload("[999]")
            .build()
            .expect("unknown removal request");
        assert_eq!(
            block_on(handler.call(unknown))
                .expect("unknown response")
                .status,
            422
        );
    }

    #[test]
    fn rewrite_upsert_and_removal_are_atomic_by_name() {
        let mut config = crate::Config::default();
        config.policy.rewrites = vec![RewriteConfig {
            name: "router.example".into(),
            ipv4: Some("192.0.2.1".parse().expect("address")),
            ipv6: None,
            ttl: 30,
        }];
        config.policy.rules = vec![crate::RuleConfig {
            id: 1,
            domain: "unrelated.example".into(),
            action: crate::Action::Pass,
            priority: 0,
            qtype: None,
            qclass: None,
            client: None,
            client_cidr: None,
            client_cidrs: Vec::new(),
        }];
        let policy = Arc::new(Policy::new(config).expect("valid rewrite policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let valid_reload = Request::builder()
            .method("POST")
            .path("/reload/rewrites")
            .payload(r#"[{"name":"router.example","ipv4":"192.0.2.1","ttl":30}]"#)
            .build()
            .expect("valid rewrite reload request");
        assert_eq!(
            block_on(handler.call(valid_reload))
                .expect("valid reload response")
                .status,
            200
        );
        let invalid_reload = Request::builder()
            .method("POST")
            .path("/reload/rewrites")
            .payload(r#"[{"name":"broken.example"}]"#)
            .build()
            .expect("invalid rewrite reload request");
        assert_eq!(
            block_on(handler.call(invalid_reload))
                .expect("invalid reload response")
                .status,
            422
        );
        let original = policy.evaluate(&proxima_dns::DnsQuery {
            id: 1,
            recursion_desired: true,
            name: "router.example.".into(),
            qtype: 1,
            qclass: 1,
        });
        assert_eq!(
            original.expect("original rewrite").records[0].rdata,
            vec![192, 0, 2, 1]
        );
        let update = Request::builder()
            .method("POST")
            .path("/reload/rewrites/upsert")
            .payload(
                r#"{"rewrites":[{"name":"ROUTER.EXAMPLE","ipv4":"198.51.100.1","ttl":60},{"name":"guest.example","ipv6":"2001:db8::1","ttl":20}]}"#,
            )
            .build()
            .expect("rewrite upsert request");
        assert_eq!(
            block_on(handler.call(update))
                .expect("upsert response")
                .status,
            200
        );
        let listed = block_on(handler.call(request("GET", "/rewrites"))).expect("rewrite list");
        let listed: serde_json::Value =
            serde_json::from_slice(&listed.payload).expect("rewrite list JSON");
        assert_eq!(listed["total"], 2);
        assert_eq!(listed["rewrites"][0]["name"], "ROUTER.EXAMPLE");

        let query = proxima_dns::DnsQuery {
            id: 1,
            recursion_desired: true,
            name: "router.example.".into(),
            qtype: 1,
            qclass: 1,
        };
        let answer = policy.evaluate(&query).expect("updated rewrite");
        assert_eq!(answer.records[0].rdata, vec![198, 51, 100, 1]);
        assert_eq!(answer.records[0].ttl, 60);

        let invalid = Request::builder()
            .method("POST")
            .path("/reload/rewrites/upsert")
            .payload(r#"{"rewrites":[{"name":"router.example","ttl":1}]}"#)
            .build()
            .expect("invalid rewrite request");
        assert_eq!(
            block_on(handler.call(invalid))
                .expect("invalid response")
                .status,
            422
        );
        let answer = policy.evaluate(&query).expect("rewrite retained");
        assert_eq!(answer.records[0].rdata, vec![198, 51, 100, 1]);

        let remove = Request::builder()
            .method("POST")
            .path("/reload/rewrites/remove")
            .payload(r#"["ROUTER.EXAMPLE"]"#)
            .build()
            .expect("rewrite removal request");
        assert_eq!(
            block_on(handler.call(remove))
                .expect("removal response")
                .status,
            200
        );
        let answer = policy.evaluate(&query).expect("pass answer after removal");
        assert!(answer.records.is_empty());

        let unknown = Request::builder()
            .method("POST")
            .path("/reload/rewrites/remove")
            .payload(r#"["missing.example"]"#)
            .build()
            .expect("unknown removal request");
        assert_eq!(
            block_on(handler.call(unknown))
                .expect("unknown response")
                .status,
            422
        );
    }

    #[test]
    fn country_reload_route_reloads_the_configured_snapshot() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(policy);
        let reload = block_on(handler.call(request("POST", "/reload/country")))
            .expect("country reload response");
        assert_eq!(reload.status, 200);
        assert_eq!(
            reload.payload,
            Bytes::from_static(b"{\"status\":\"reloaded\"}")
        );
    }

    #[test]
    fn bearer_auth_is_required_and_tokens_are_validated() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        assert!(authenticated_handle(Arc::clone(&policy), String::new()).is_err());
        let handle = authenticated_handle(policy, "secret-token".into()).expect("auth handle");
        let unauthorized = block_on(handle.call(request("GET", "/health"))).expect("response");
        assert_eq!(unauthorized.status, 401);
        let authorized = Request::builder()
            .method("GET")
            .path("/health")
            .header("Authorization", "Bearer secret-token")
            .build()
            .expect("authorized request");
        let response = block_on(handle.call(authorized)).expect("authorized response");
        assert_eq!(response.status, 200);
    }

    #[test]
    fn admin_bind_must_be_loopback_without_tls() {
        assert!(validate_bind("127.0.0.1:8081".parse().expect("address")).is_ok());
        assert!(validate_bind("[::1]:8081".parse().expect("address")).is_ok());
        assert!(validate_bind("192.0.2.1:8081".parse().expect("address")).is_err());
    }
}
