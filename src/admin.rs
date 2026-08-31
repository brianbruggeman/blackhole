//! Authenticated operator control plane built from Proxima's HTTP pipe path.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use proxima::middlewares::auth::Auth;
use proxima::pipe::{PipeHandle, into_handle};
use proxima::{ProximaError, Request, Response, SendPipe};

use crate::{Policy, RegexRuleConfig, RuleConfig};

const MAX_POLICY_BODY_BYTES: usize = 64 * 1024;

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
            ("GET", "/health") => Ok(Response::ok("{\"status\":\"ok\"}")),
            ("GET", "/status") => Ok(Response::ok(self.policy.admin_status())),
            ("POST", "/reload/blocklists") => match self.policy.reload_blocklists() {
                Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                Err(error) => Ok(Response::new(500).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/policy") => {
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
                match self.policy.reload_rules(&rules) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
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
                "/health" | "/status" | "/reload/blocklists" | "/reload/policy" | "/reload/regex",
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
        let status = block_on(handler.call(request("GET", "/status"))).expect("status response");
        assert_eq!(status.status, 200);
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("status JSON");
        assert_eq!(status["status"], "ok");
        assert_eq!(status["rules_configured"], false);
        assert_eq!(status["upstream_configured"], false);
        assert_eq!(status["country_policy_configured"], false);
        assert_eq!(status["cache_entries"], 0);
        let unknown = block_on(handler.call(request("GET", "/private"))).expect("404 response");
        assert_eq!(unknown.status, 404);
        let wrong_method =
            block_on(handler.call(request("GET", "/reload/blocklists"))).expect("405 response");
        assert_eq!(wrong_method.status, 405);
        let wrong_status_method =
            block_on(handler.call(request("POST", "/status"))).expect("405 status response");
        assert_eq!(wrong_status_method.status, 405);
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
