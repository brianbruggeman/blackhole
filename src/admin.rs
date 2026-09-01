//! Authenticated operator control plane built from Proxima's HTTP pipe path.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use proxima::middlewares::auth::Auth;
use proxima::pipe::{PipeHandle, into_handle};
use proxima::{ProximaError, Request, Response, SendPipe};

use crate::{
    ClientGroupConfig, CountryPolicyConfig, Policy, RegexRuleConfig, RewriteConfig, RuleConfig,
    ServiceProfileConfig,
};

const MAX_POLICY_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, serde::Deserialize)]
struct ProfileReload {
    profiles: Vec<ServiceProfileConfig>,
    #[serde(default)]
    client_groups: Vec<ClientGroupConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct PolicyBundle {
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
}
const ADMIN_UI: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>Blackhole DNS</title>
<style>body{font:15px system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}pre{background:#f3f3f3;padding:1rem;overflow:auto}button{padding:.4rem .7rem}</style>
<h1>Blackhole DNS</h1>
<p>Authenticated operator control plane. DNS names and packet payloads are not shown here.</p>
<p><button id="clear-logs">Clear privacy log</button></p>
<h2>Status</h2><pre id="status">loading…</pre>
<h2>Rules</h2><pre id="rules">loading…</pre>
<h2>Service profiles</h2><pre id="profiles">loading…</pre>
<h2>Client groups</h2><pre id="groups">loading…</pre>
<h2>Privacy log</h2><pre id="logs">loading…</pre>
<script>
const load = (path, target) => fetch(path).then(response => response.json()).then(value => {
  document.querySelector(target).textContent = JSON.stringify(value, null, 2);
});
const refresh = () => Promise.all([load('/status','#status'), load('/rules','#rules'), load('/profiles','#profiles'), load('/client-groups','#groups'), load('/logs','#logs')]);
document.querySelector('#clear-logs').onclick = () => fetch('/logs/clear', {method:'POST'}).then(refresh);
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
            ("GET", "/rules") => Ok(Response::ok(self.policy.admin_rules())),
            ("GET", "/profiles") => Ok(Response::ok(self.policy.admin_profiles())),
            ("GET", "/client-groups") => Ok(Response::ok(self.policy.admin_client_groups())),
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
                match self.policy.reload_policy_bundle(
                    &bundle.rules,
                    &bundle.regex_rules,
                    &bundle.profiles,
                    &bundle.client_groups,
                    &bundle.rewrites,
                    &bundle.country_policy,
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
            ("POST", "/reload/country") => match self.policy.reload_country_policy() {
                Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                Err(error) => Ok(Response::new(422).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/policy" | "/reload/policy/add") => {
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
            (
                _,
                "/"
                | "/health"
                | "/status"
                | "/rules"
                | "/profiles"
                | "/client-groups"
                | "/reload/profiles"
                | "/reload/policy-bundle"
                | "/logs"
                | "/cache/clear"
                | "/logs/clear"
                | "/reload/blocklists"
                | "/reload/country"
                | "/reload/policy"
                | "/reload/policy/add"
                | "/reload/policy/remove"
                | "/reload/regex",
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
        assert_eq!(status["profiles_configured"], 0);
        assert_eq!(status["client_groups_configured"], 0);
        assert_eq!(status["upstream_configured"], false);
        assert_eq!(status["country_policy_configured"], false);
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
        let wrong_rules_method =
            block_on(handler.call(request("POST", "/rules"))).expect("405 rules response");
        assert_eq!(wrong_rules_method.status, 405);
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

        let removal = Request::builder()
            .method("POST")
            .path("/reload/policy/remove")
            .payload("[8]")
            .build()
            .expect("valid policy removal request");
        let response = block_on(handler.call(removal)).expect("removal response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.action_for_view(added_query), crate::Action::Pass);
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

        let unknown_removal = Request::builder()
            .method("POST")
            .path("/reload/policy/remove")
            .payload("[999]")
            .build()
            .expect("unknown removal request");
        let response = block_on(handler.call(unknown_removal)).expect("unknown removal response");
        assert_eq!(response.status, 422);
        assert_eq!(policy.action_for_view(query), crate::Action::Nxdomain);

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
