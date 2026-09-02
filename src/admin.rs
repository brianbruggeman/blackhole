//! Authenticated operator control plane built from Proxima's HTTP pipe path.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use proxima::middlewares::auth::Auth;
use proxima::pipe::{PipeHandle, into_handle};
use proxima::{ProximaError, Request, Response, SendPipe};

use crate::{
    AdmissionConfig, ClientGroupConfig, ClientIdentityConfig, CountryPolicyConfig, Mode, Policy,
    RegexRuleConfig, RewriteConfig, RuleConfig, ServiceProfileConfig,
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
struct ClientIdentityUpsert {
    client_identities: Vec<ClientIdentityConfig>,
}

#[derive(Debug, serde::Deserialize)]
struct FilteringUpdate {
    enabled: bool,
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
    filtering_enabled: Option<bool>,
    #[serde(default)]
    rules: Vec<RuleConfig>,
    #[serde(default)]
    regex_rules: Vec<RegexRuleConfig>,
    #[serde(default)]
    profiles: Vec<ServiceProfileConfig>,
    #[serde(default)]
    client_groups: Vec<ClientGroupConfig>,
    #[serde(default)]
    client_identities: Vec<ClientIdentityConfig>,
    #[serde(default)]
    rewrites: Vec<RewriteConfig>,
    #[serde(default)]
    country_policy: CountryPolicyConfig,
    /// Omitted/null retains the currently loaded blocklist snapshot.
    #[serde(default)]
    blocklists: Option<Vec<String>>,
    /// Omitted retains the currently disabled source set.
    #[serde(default)]
    disabled_blocklists: Option<Vec<String>>,
    /// Required by the full configuration reload route; ignored by the
    /// policy-only route.
    #[serde(default)]
    admission: Option<AdmissionConfig>,
}
const ADMIN_UI: &str = r#"<!doctype html>
<meta charset="utf-8">
<title>Blackhole</title>
<h1>Blackhole</h1>
<p><button id="clear-logs">Clear log</button> <button id="clear-durable-logs">Delete durable log</button> <button id="clear-stats">Clear stats</button> <button id="clear-cache">Clear cache</button> <button id="clear-abuse">Clear abuse</button> <button id="reload-blocklists">Reload lists</button> <button id="reload-country">Reload country</button> <button id="reload-admission">Reload admission</button> <button id="reload-bundle">Publish config</button> <button id="toggle-filtering">Toggle filtering</button></p>
<p id="operation-status"></p>
<h2>Status</h2><pre id="status"></pre>
<h2>Stats</h2><pre id="stats"></pre>
<h2>Admission</h2><textarea id="admission-config" rows="16" cols="80"></textarea><pre id="admission-status"></pre>
<h2>Abuse</h2><pre id="abuse-status"></pre>
<h2>Denylist</h2><textarea id="denylist-config" rows="5" cols="80"></textarea><p><button id="add-denylist">Add</button> <button id="remove-denylist">Revoke</button></p>
<h2>Abuse</h2><textarea id="abuse-revoke"></textarea><button id="revoke-abuse">Revoke</button><button id="approve-abuse">Approve</button>
<h2>Incidents</h2><p><button id="export-abuse">Export durable</button></p><pre id="abuse-incidents"></pre>
<h2>Policy bundle</h2><textarea id="policy-bundle" rows="12" cols="80">loading…</textarea>
<h2>Blocklists</h2><textarea id="blocklist-sources"></textarea><button id="replace-blocklists">Replace</button><button id="add-blocklists">Add</button><button id="remove-blocklists">Remove</button><button id="reload-blocklists">Reload</button><div id="blocklist-controls"></div><pre id="blocklists"></pre>
<h2>Country</h2><textarea id="country-editor" rows="8" cols="80"></textarea><button id="replace-country">Replace country policy</button><pre id="country-status"></pre>
<h2>Privacy</h2><pre id="privacy-status"></pre>
<h2>Rules</h2><textarea id="rule-editor" rows="8" cols="80"></textarea><button id="upsert-rules">Upsert domain rules</button><textarea id="regex-editor" rows="8" cols="80"></textarea><button id="upsert-regex">Upsert regex rules</button><pre id="rules"></pre>
<h2>Profiles</h2><textarea id="profile-editor" rows="8" cols="80"></textarea><button id="upsert-profiles">Upsert profiles</button><div id="profile-controls"></div><pre id="profiles"></pre>
<h2>Groups</h2><textarea id="group-editor" rows="8" cols="80"></textarea><button id="upsert-groups">Upsert groups</button><div id="group-controls"></div><pre id="groups"></pre>
<h2>Identities</h2><textarea id="identity-editor" rows="8" cols="80"></textarea><button id="upsert-identities">Upsert identities</button><div id="identity-controls"></div><pre id="identities"></pre>
<h2>Rewrites</h2><textarea id="rewrite-editor" rows="8" cols="80"></textarea><button id="replace-rewrites">Replace rewrites</button><pre id="rewrites"></pre>
<h2>Privacy log</h2><pre id="logs"></pre>
<script>
const load = (path, target) => fetch(path).then(response => response.json()).then(value => {
  if (path === '/blocklists') {
    document.querySelector('#blocklist-sources').value = JSON.stringify((value.sources || []).map(source => source.path));
    const controls = document.querySelector('#blocklist-controls');
    controls.replaceChildren();
    for (const source of value.sources || []) {
      const button = document.createElement('button');
      button.textContent = `${source.enabled ? 'Disable' : 'Enable'} ${source.path}`;
      button.onclick = () => operate(`/reload/blocklists/${source.enabled ? 'disable' : 'enable'}`, {
        method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify([source.path])
      }).then(refresh);
      controls.append(button);
    }
  }
  if (path === '/policy-bundle') {
    document.querySelector('#toggle-filtering').textContent = `${value.filtering_enabled ? 'Disable' : 'Enable'} filtering`;
    const toggle = (id, items, route, field, removeRoute) => {
      const controls = document.querySelector(id);
      controls.replaceChildren();
      for (const item of items || []) {
        const button = document.createElement('button');
        button.textContent = `${item.enabled ? 'Disable' : 'Enable'} ${item.name || item.id}`;
        button.onclick = () => send(route, {[field]:[Object.assign({}, item, {enabled: !item.enabled})]});
        const remove = document.createElement('button');
        remove.textContent = 'Remove';
        remove.onclick = () => send(removeRoute, [item.name || item.id]);
        controls.append(button, remove, document.createTextNode(' '));
      }
    };
    toggle('#profile-controls', value.profiles, '/reload/profiles/upsert', 'profiles', '/reload/profiles/remove');
    toggle('#group-controls', value.client_groups, '/reload/client-groups/upsert', 'client_groups', '/reload/client-groups/remove');
    toggle('#identity-controls', value.client_identities, '/reload/client-identities/upsert', 'client_identities', '/reload/client-identities/remove');
    document.querySelector('#profile-editor').value = JSON.stringify(value.profiles || [], null, 2);
    document.querySelector('#group-editor').value = JSON.stringify(value.client_groups || [], null, 2);
    document.querySelector('#identity-editor').value = JSON.stringify(value.client_identities || [], null, 2);
    document.querySelector('#country-editor').value = JSON.stringify(value.country_policy || {}, null, 2);
    document.querySelector('#rewrite-editor').value = JSON.stringify(value.rewrites || [], null, 2);
    document.querySelector('#rule-editor').value = JSON.stringify(value.rules || [], null, 2);
    document.querySelector('#regex-editor').value = JSON.stringify(value.regex_rules || [], null, 2);
  }
  if (path === '/policy-bundle') document.querySelector(target).value = JSON.stringify(value, null, 2);
  else if (path === '/abuse/denylist') document.querySelector(target).value = JSON.stringify(value, null, 2);
  else document.querySelector(target).textContent = JSON.stringify(value, null, 2);
  if (path === '/admission/status') document.querySelector('#admission-config').value = JSON.stringify(value, null, 2);
});
const operate = (path, options) => fetch(path, options).then(async response => {
  const value = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(value.message || `HTTP ${response.status}`);
  document.querySelector('#operation-status').textContent = `${path}: ${value.status || 'ok'}`;
  return value;
}).catch(error => { document.querySelector('#operation-status').textContent = `${path}: ${error.message}`; throw error; });
const send = (path, body) => operate(path, {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)}).then(refresh);
const edit = (id, path, field) => {
  try { return send(path, {[field]: JSON.parse(document.querySelector(id).value)}); }
  catch (error) { document.querySelector('#operation-status').textContent = `${path}: ${error.message}`; return Promise.reject(error); }
};
const replaceCountry = () => {
  try { return operate('/reload/country/replace', {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#country-editor').value}).then(refresh); }
  catch (error) { document.querySelector('#operation-status').textContent = `/reload/country/replace: ${error.message}`; return Promise.reject(error); }
};
const replaceRewrites = () => {
  try { return operate('/reload/rewrites', {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#rewrite-editor').value}).then(refresh); }
  catch (error) { document.querySelector('#operation-status').textContent = `/reload/rewrites: ${error.message}`; return Promise.reject(error); }
};
const refresh = () => Promise.all([load('/status','#status'), load('/stats','#stats'), load('/admission/status','#admission-status'), load('/abuse/status','#abuse-status'), load('/abuse/incidents','#abuse-incidents'), load('/abuse/denylist','#denylist-config'), load('/policy-bundle','#policy-bundle'), load('/blocklists','#blocklists'), load('/country/status','#country-status'), load('/privacy/status','#privacy-status'), load('/rules','#rules'), load('/profiles','#profiles'), load('/client-groups','#groups'), load('/client-identities','#identities'), load('/rewrites','#rewrites'), load('/logs','#logs')]);
document.querySelector('#clear-logs').onclick = () => operate('/logs/clear', {method:'POST'}).then(refresh);
document.querySelector('#clear-durable-logs').onclick = () => operate('/logs/clear-durable', {method:'POST'}).then(refresh);
document.querySelector('#clear-stats').onclick = () => operate('/stats/clear', {method:'POST'}).then(refresh);
document.querySelector('#clear-cache').onclick = () => operate('/cache/clear', {method:'POST'}).then(refresh);
document.querySelector('#clear-abuse').onclick = () => operate('/abuse/clear', {method:'POST'}).then(refresh);
const updateDenylist = path => operate(path, {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#denylist-config').value}).then(refresh);
document.querySelector('#add-denylist').onclick = () => updateDenylist('/abuse/denylist/add');
document.querySelector('#remove-denylist').onclick = () => updateDenylist('/abuse/denylist/remove');
const updateAbuse = path => operate(path, {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#abuse-revoke').value}).then(refresh);
for (const [id,path] of [['revoke-abuse','/abuse/revoke'],['approve-abuse','/abuse/incidents/approve']]) document.querySelector(`#${id}`).onclick = () => updateAbuse(path);
document.querySelector('#export-abuse').onclick = () => fetch('/abuse/incidents/export').then(response => response.json()).then(value => { document.querySelector('#abuse-incidents').textContent = JSON.stringify(value, null, 2); });
const updateBlocklists = op => operate(`/reload/blocklists/${op}`, {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#blocklist-sources').value}).then(refresh);
for (const [id,op] of [['replace-blocklists','replace'],['add-blocklists','add'],['remove-blocklists','remove']]) document.querySelector(`#${id}`).onclick = () => updateBlocklists(op);
document.querySelector('#upsert-profiles').onclick = () => edit('#profile-editor', '/reload/profiles/upsert', 'profiles');
document.querySelector('#upsert-groups').onclick = () => edit('#group-editor', '/reload/client-groups/upsert', 'client_groups');
document.querySelector('#upsert-identities').onclick = () => edit('#identity-editor', '/reload/client-identities/upsert', 'client_identities');
document.querySelector('#replace-country').onclick = replaceCountry;
document.querySelector('#replace-rewrites').onclick = replaceRewrites;
document.querySelector('#upsert-rules').onclick = () => edit('#rule-editor', '/reload/policy/upsert', 'rules');
document.querySelector('#upsert-regex').onclick = () => edit('#regex-editor', '/reload/regex/upsert', 'regex_rules');
document.querySelector('#reload-blocklists').onclick = () => operate('/reload/blocklists', {method:'POST'}).then(refresh);
document.querySelector('#reload-country').onclick = () => operate('/reload/country', {method:'POST'}).then(refresh);
document.querySelector('#reload-admission').onclick = () => operate('/reload/admission', {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#admission-config').value}).then(refresh);
document.querySelector('#reload-bundle').onclick = () => operate('/reload/config', {method:'POST', headers:{'content-type':'application/json'}, body:document.querySelector('#policy-bundle').value}).then(refresh);
document.querySelector('#toggle-filtering').onclick = () => fetch('/policy-bundle').then(response => response.json()).then(value => operate('/reload/filtering', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({enabled: !value.filtering_enabled})}).then(refresh));
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
            ("GET", "/stats") => Ok(Response::ok(self.policy.admin_stats())),
            ("POST", "/stats/clear") => Ok(Response::ok(format!(
                "{{\"status\":\"cleared\",\"entries\":{}}}",
                self.policy.clear_stats()
            ))),
            ("GET", "/admission/status") => Ok(Response::ok(self.policy.admin_admission_status())),
            ("GET", "/abuse/status") => Ok(Response::ok(self.policy.admin_abuse_status())),
            ("GET", "/abuse/incidents") => Ok(Response::ok(self.policy.admin_abuse_incidents())),
            ("GET", "/abuse/incidents/export") => {
                match self.policy.admin_abuse_incident_export().await {
                    Ok(export) => Ok(Response::ok(export)),
                    Err(error) => Ok(Response::new(503).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("GET", "/abuse/denylist") => Ok(Response::ok(self.policy.admin_abuse_denylist())),
            ("POST", "/abuse/clear") => Ok(Response::ok(format!(
                "{{\"status\":\"cleared\",\"entries\":{}}}",
                self.policy.clear_abuse_state()
            ))),
            ("POST", "/abuse/revoke") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let clients = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(clients) if !clients.is_empty() && clients.len() <= 256 => clients,
                    Ok(_) => return Ok(Response::new(422)),
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let clients = match clients
                    .iter()
                    .map(|client| client.parse::<IpAddr>())
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(clients) => clients,
                    Err(error) => {
                        return Ok(Response::new(422).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&format!("invalid incident client: {error}"))
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                if let Err(error) = self.policy.persist_abuse_revocation(&clients).await {
                    return Ok(Response::new(503).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error).unwrap_or_else(|_| "null".into())
                    )));
                }
                for client in &clients {
                    self.policy.revoke_abuse_incident(*client);
                }
                Ok(Response::ok(format!(
                    "{{\"status\":\"revoked\",\"entries\":{}}}",
                    clients.len()
                )))
            }
            ("POST", "/abuse/incidents/approve") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let clients = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(clients) if !clients.is_empty() && clients.len() <= 256 => clients,
                    Ok(_) => return Ok(Response::new(422)),
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let cidrs = match clients
                    .iter()
                    .map(|client| {
                        client.parse::<IpAddr>().map(|client| match client {
                            IpAddr::V4(client) => format!("{client}/32"),
                            IpAddr::V6(client) => format!("{client}/128"),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(cidrs) => cidrs,
                    Err(error) => {
                        return Ok(Response::new(422).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&format!("invalid incident client: {error}"))
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let previous = self.policy.admission_config();
                if let Err(error) = self.policy.add_deny_client_cidrs(&cidrs) {
                    return Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    )));
                }
                if let Err(error) = self.policy.persist_denylist_change("approve", &cidrs).await {
                    let _ = self.policy.reload_admission(&previous);
                    return Ok(Response::new(503).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error).unwrap_or_else(|_| "null".into())
                    )));
                }
                Ok(Response::ok(format!(
                    "{{\"status\":\"approved\",\"entries\":{}}}",
                    cidrs.len()
                )))
            }
            ("POST", "/abuse/denylist/add") | ("POST", "/abuse/denylist/remove") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let cidrs = match serde_json::from_slice::<Vec<String>>(&request.payload) {
                    Ok(cidrs) => cidrs,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let previous = self.policy.admission_config();
                let result = if path.ends_with("/add") {
                    self.policy.add_deny_client_cidrs(&cidrs)
                } else {
                    self.policy.remove_deny_client_cidrs(&cidrs)
                };
                match result {
                    Ok(_) => {
                        let operation = if path.ends_with("/add") {
                            "add"
                        } else {
                            "remove"
                        };
                        if let Err(error) =
                            self.policy.persist_denylist_change(operation, &cidrs).await
                        {
                            let _ = self.policy.reload_admission(&previous);
                            return Ok(Response::new(503).with_body(format!(
                                "{{\"status\":\"error\",\"message\":{}}}",
                                serde_json::to_string(&error).unwrap_or_else(|_| "null".into())
                            )));
                        }
                        Ok(Response::ok("{\"status\":\"reloaded\"}"))
                    }
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/admission") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let admission = match serde_json::from_slice::<AdmissionConfig>(&request.payload) {
                    Ok(admission) => admission,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.reload_admission(&admission) {
                    Ok(crate::snapshot::ReloadState::Published) => {
                        Ok(Response::ok("{\"status\":\"reloaded\"}"))
                    }
                    Ok(crate::snapshot::ReloadState::Unchanged) => {
                        Ok(Response::ok("{\"status\":\"unchanged\"}"))
                    }
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/admission/denylist") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let deny_client_cidrs =
                    match serde_json::from_slice::<Vec<String>>(&request.payload) {
                        Ok(deny_client_cidrs) => deny_client_cidrs,
                        Err(error) => {
                            return Ok(Response::new(400).with_body(format!(
                                "{{\"status\":\"error\",\"message\":{}}}",
                                serde_json::to_string(&error.to_string())
                                    .unwrap_or_else(|_| "null".into())
                            )));
                        }
                    };
                let mut admission = self.policy.admission_config();
                admission.deny_client_cidrs = deny_client_cidrs;
                match self.policy.reload_admission(&admission) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("GET", "/country/status") => Ok(Response::ok(self.policy.admin_country_status())),
            ("POST", "/reload/country/replace") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let config = match serde_json::from_slice::<CountryPolicyConfig>(&request.payload) {
                    Ok(config) => config,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                match self.policy.replace_country_policy(&config) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"replaced\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("GET", "/policy/status") => Ok(Response::ok(self.policy.admin_policy_status())),
            ("POST", "/reload/filtering") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<FilteringUpdate>(&request.payload) {
                    Ok(update) => update,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            "{{\"status\":\"error\",\"message\":{}}}",
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let state = self.policy.set_filtering_enabled(update.enabled);
                let status = match state {
                    crate::snapshot::ReloadState::Published => "reloaded",
                    crate::snapshot::ReloadState::Unchanged => "unchanged",
                };
                Ok(Response::ok(format!("{{\"status\":\"{status}\"}}")))
            }
            ("GET", "/blocklists") => Ok(Response::ok(self.policy.admin_blocklists())),
            ("GET", "/policy-bundle") => Ok(Response::ok(self.policy.admin_policy_bundle())),
            ("GET", "/privacy/status") => Ok(Response::ok(self.policy.admin_privacy_status())),
            ("GET", "/rules") => Ok(Response::ok(self.policy.admin_rules())),
            ("GET", "/profiles") => Ok(Response::ok(self.policy.admin_profiles())),
            ("GET", "/client-groups") => Ok(Response::ok(self.policy.admin_client_groups())),
            ("GET", "/client-identities") => {
                Ok(Response::ok(self.policy.admin_client_identities()))
            }
            ("POST", "/reload/client-identities") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let identities =
                    match serde_json::from_slice::<Vec<ClientIdentityConfig>>(&request.payload) {
                        Ok(identities) => identities,
                        Err(error) => {
                            return Ok(Response::new(400).with_body(format!(
                                "{{\"status\":\"error\",\"message\":{}}}",
                                serde_json::to_string(&error.to_string())
                                    .unwrap_or_else(|_| "null".into())
                            )));
                        }
                    };
                match self.policy.reload_client_identities(&identities) {
                    Ok(crate::snapshot::ReloadState::Published) => {
                        Ok(Response::ok("{\"status\":\"reloaded\"}"))
                    }
                    Ok(crate::snapshot::ReloadState::Unchanged) => {
                        Ok(Response::ok("{\"status\":\"unchanged\"}"))
                    }
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/client-identities/upsert") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let update = match serde_json::from_slice::<ClientIdentityUpsert>(&request.payload)
                {
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
                    .upsert_client_identities(&update.client_identities)
                {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/client-identities/remove") => {
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
                match self.policy.remove_client_identities(&names) {
                    Ok(_) => Ok(Response::ok("{\"status\":\"reloaded\"}")),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
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
                    &bundle.client_identities,
                    &bundle.rewrites,
                    &bundle.country_policy,
                    bundle.blocklists.as_deref(),
                    bundle.mode,
                    bundle.domains.as_deref(),
                    bundle.default_action,
                    bundle.filtering_enabled,
                    bundle.disabled_blocklists.as_deref(),
                ) {
                    Ok(_) => Ok(Response::ok(r#"{"status":"reloaded"}"#)),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        r#"{{"status":"error","message":{}}}"#,
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/config") => {
                if request.payload.len() > MAX_POLICY_BODY_BYTES {
                    return Ok(Response::new(413));
                }
                let config = match serde_json::from_slice::<PolicyBundle>(&request.payload) {
                    Ok(config) => config,
                    Err(error) => {
                        return Ok(Response::new(400).with_body(format!(
                            r#"{{"status":"error","message":{}}}"#,
                            serde_json::to_string(&error.to_string())
                                .unwrap_or_else(|_| "null".into())
                        )));
                    }
                };
                let Some(admission) = config.admission.as_ref() else {
                    return Ok(Response::new(400)
                        .with_body(r#"{"status":"error","message":"admission is required"}"#));
                };
                match self.policy.reload_policy_bundle_with_legacy_and_admission(
                    &config.rules,
                    &config.regex_rules,
                    &config.profiles,
                    &config.client_groups,
                    &config.client_identities,
                    &config.rewrites,
                    &config.country_policy,
                    config.blocklists.as_deref(),
                    config.mode,
                    config.domains.as_deref(),
                    config.default_action,
                    config.filtering_enabled,
                    config.disabled_blocklists.as_deref(),
                    Some(admission),
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
                    Ok(crate::snapshot::ReloadState::Published) => {
                        Ok(Response::ok("{\"status\":\"reloaded\"}"))
                    }
                    Ok(crate::snapshot::ReloadState::Unchanged) => {
                        Ok(Response::ok("{\"status\":\"unchanged\"}"))
                    }
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
            ("POST", "/logs/clear-durable") => match self.policy.clear_durable_query_recording() {
                Ok(files) => Ok(Response::ok(format!(
                    "{{\"status\":\"deleted\",\"files\":{files}}}"
                ))),
                Err(error) => Ok(Response::new(422).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/blocklists") => match self.policy.reload_blocklists_if_changed() {
                Ok(crate::snapshot::ReloadState::Published) => {
                    Ok(Response::ok("{\"status\":\"reloaded\"}"))
                }
                Ok(crate::snapshot::ReloadState::Unchanged) => {
                    Ok(Response::ok("{\"status\":\"unchanged\"}"))
                }
                Err(error) => Ok(Response::new(500).with_body(format!(
                    "{{\"status\":\"error\",\"message\":{}}}",
                    serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                ))),
            },
            ("POST", "/reload/blocklists/enable" | "/reload/blocklists/disable") => {
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
                let enabled = path == "/reload/blocklists/enable";
                let result = if enabled {
                    self.policy.enable_blocklist_sources(&paths)
                } else {
                    self.policy.disable_blocklist_sources(&paths)
                };
                match result {
                    Ok(_) => Ok(Response::ok(if enabled {
                        "{\"status\":\"enabled\"}"
                    } else {
                        "{\"status\":\"disabled\"}"
                    })),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
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
            ("POST", "/reload/blocklists/add" | "/reload/blocklists/remove") => {
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
                let result = if path == "/reload/blocklists/add" {
                    self.policy.add_blocklist_sources(&paths)
                } else {
                    self.policy.remove_blocklist_sources(&paths)
                };
                match result {
                    Ok(_) => Ok(Response::ok(if path == "/reload/blocklists/add" {
                        "{\"status\":\"added\"}"
                    } else {
                        "{\"status\":\"removed\"}"
                    })),
                    Err(error) => Ok(Response::new(422).with_body(format!(
                        "{{\"status\":\"error\",\"message\":{}}}",
                        serde_json::to_string(&error.to_string()).unwrap_or_else(|_| "null".into())
                    ))),
                }
            }
            ("POST", "/reload/country") => match self.policy.reload_country_policy_if_changed() {
                Ok(crate::snapshot::ReloadState::Published) => {
                    Ok(Response::ok("{\"status\":\"reloaded\"}"))
                }
                Ok(crate::snapshot::ReloadState::Unchanged) => {
                    Ok(Response::ok("{\"status\":\"unchanged\"}"))
                }
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
                    Ok(crate::snapshot::ReloadState::Published) => {
                        Ok(Response::ok("{\"status\":\"reloaded\"}"))
                    }
                    Ok(crate::snapshot::ReloadState::Unchanged) => {
                        Ok(Response::ok("{\"status\":\"unchanged\"}"))
                    }
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
                | "/stats"
                | "/stats/clear"
                | "/admission/status"
                | "/abuse/status"
                | "/abuse/incidents"
                | "/abuse/incidents/export"
                | "/abuse/denylist"
                | "/abuse/clear"
                | "/abuse/revoke"
                | "/abuse/incidents/approve"
                | "/abuse/denylist/add"
                | "/abuse/denylist/remove"
                | "/reload/admission"
                | "/reload/admission/denylist"
                | "/country/status"
                | "/reload/country/replace"
                | "/policy/status"
                | "/blocklists"
                | "/policy-bundle"
                | "/privacy/status"
                | "/rules"
                | "/profiles"
                | "/client-groups"
                | "/client-identities"
                | "/rewrites"
                | "/reload/profiles"
                | "/reload/profiles/upsert"
                | "/reload/profiles/remove"
                | "/reload/client-groups/upsert"
                | "/reload/client-groups/remove"
                | "/reload/client-identities"
                | "/reload/client-identities/upsert"
                | "/reload/client-identities/remove"
                | "/reload/policy-bundle"
                | "/reload/config"
                | "/logs"
                | "/cache/clear"
                | "/logs/clear"
                | "/logs/clear-durable"
                | "/reload/blocklists"
                | "/reload/blocklists/replace"
                | "/reload/blocklists/add"
                | "/reload/blocklists/remove"
                | "/reload/blocklists/enable"
                | "/reload/blocklists/disable"
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
                .windows(b"/stats".len())
                .any(|window| window == b"/stats")
        );
        assert!(
            ui.payload
                .windows(b"/stats/clear".len())
                .any(|window| window == b"/stats/clear")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/denylist".len())
                .any(|window| window == b"/abuse/denylist")
        );
        assert!(
            ui.payload
                .windows(b"add-denylist".len())
                .any(|window| window == b"add-denylist")
        );
        assert!(
            ui.payload
                .windows(b"/admission/status".len())
                .any(|window| window == b"/admission/status")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/status".len())
                .any(|window| window == b"/abuse/status")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/incidents".len())
                .any(|window| window == b"/abuse/incidents")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/incidents/export".len())
                .any(|window| window == b"/abuse/incidents/export")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/clear".len())
                .any(|window| window == b"/abuse/clear")
        );
        assert!(
            ui.payload
                .windows(b"/abuse/revoke".len())
                .any(|window| window == b"/abuse/revoke")
        );
        assert!(
            ui.payload
                .windows(b"revoke-abuse".len())
                .any(|window| window == b"revoke-abuse")
        );
        assert!(
            ui.payload
                .windows(b"/cache/clear".len())
                .any(|window| window == b"/cache/clear")
        );
        assert!(
            ui.payload
                .windows(b"/country/status".len())
                .any(|window| window == b"/country/status")
        );
        assert!(
            ui.payload
                .windows(b"/client-identities".len())
                .any(|window| window == b"/client-identities")
        );
        assert!(
            ui.payload
                .windows(b"/reload/blocklists".len())
                .any(|window| window == b"/reload/blocklists")
        );
        assert!(
            ui.payload
                .windows(b"/blocklists".len())
                .any(|window| window == b"/blocklists")
        );
        assert!(
            ui.payload
                .windows(b"reload-country".len())
                .any(|window| window == b"reload-country")
        );
        assert!(
            ui.payload
                .windows(b"/reload/country".len())
                .any(|window| window == b"/reload/country")
        );
        assert!(
            ui.payload
                .windows(b"operation-status".len())
                .any(|window| window == b"operation-status")
        );
        assert!(
            ui.payload
                .windows(b"/reload/admission".len())
                .any(|window| window == b"/reload/admission")
        );
        assert!(
            ui.payload
                .windows(b"/policy-bundle".len())
                .any(|window| window == b"/policy-bundle")
        );
        assert!(
            ui.payload
                .windows(b"/reload/config".len())
                .any(|window| window == b"/reload/config")
        );
        assert!(
            ui.payload
                .windows(b"/reload/filtering".len())
                .any(|window| window == b"/reload/filtering")
        );
        assert!(
            ui.payload
                .windows(b"toggle-filtering".len())
                .any(|window| window == b"toggle-filtering")
        );
        assert!(
            ui.payload
                .windows(b"/logs/clear-durable".len())
                .any(|window| window == b"/logs/clear-durable")
        );
        for route in [
            b"/reload/profiles/upsert".as_slice(),
            b"/reload/profiles/remove".as_slice(),
            b"/reload/client-groups/upsert".as_slice(),
            b"/reload/client-groups/remove".as_slice(),
            b"/reload/client-identities/upsert".as_slice(),
            b"/reload/client-identities/remove".as_slice(),
        ] {
            assert!(
                ui.payload
                    .windows(route.len())
                    .any(|window| window == route)
            );
        }
        for control in [
            b"profile-controls".as_slice(),
            b"group-controls".as_slice(),
            b"identity-controls".as_slice(),
            b"profile-editor".as_slice(),
            b"group-editor".as_slice(),
            b"identity-editor".as_slice(),
            b"upsert-profiles".as_slice(),
            b"upsert-groups".as_slice(),
            b"upsert-identities".as_slice(),
            b"country-editor".as_slice(),
            b"replace-country".as_slice(),
            b"rewrite-editor".as_slice(),
            b"replace-rewrites".as_slice(),
            b"rule-editor".as_slice(),
            b"regex-editor".as_slice(),
            b"upsert-rules".as_slice(),
            b"upsert-regex".as_slice(),
        ] {
            assert!(
                ui.payload
                    .windows(control.len())
                    .any(|window| window == control)
            );
        }
        assert!(
            ui.payload.len() < 12 * 1024,
            "admin UI payload is {} bytes",
            ui.payload.len()
        );
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
        let stats = block_on(handler.call(request("GET", "/stats"))).expect("stats response");
        assert_eq!(stats.status, 200);
        let stats: serde_json::Value = serde_json::from_slice(&stats.payload).expect("stats JSON");
        assert_eq!(stats["total"], 0);
        assert_eq!(stats["actions"]["pass"], 0);
        let cleared =
            block_on(handler.call(request("POST", "/stats/clear"))).expect("stats clear response");
        assert_eq!(cleared.status, 200);
        assert_eq!(
            cleared.payload,
            Bytes::from_static(b"{\"status\":\"cleared\",\"entries\":0}")
        );
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
        assert_eq!(policy_status["filtering_enabled"], true);
        assert_eq!(policy_status["legacy_mode_active"], true);
        let bundle = block_on(handler.call(request("GET", "/policy-bundle")))
            .expect("policy bundle response");
        assert_eq!(bundle.status, 200);
        let bundle: serde_json::Value =
            serde_json::from_slice(&bundle.payload).expect("policy bundle JSON");
        assert_eq!(bundle["mode"], "nxdomain");
        assert_eq!(bundle["default_action"], "pass");
        assert_eq!(bundle["filtering_enabled"], true);
        assert_eq!(bundle["rules"], serde_json::json!([]));
        assert_eq!(bundle["regex_rules"], serde_json::json!([]));
        assert_eq!(bundle["profiles"], serde_json::json!([]));
        assert_eq!(bundle["client_groups"], serde_json::json!([]));
        assert_eq!(bundle["rewrites"], serde_json::json!([]));
        assert_eq!(bundle["blocklists"], serde_json::Value::Null);
        assert_eq!(bundle["admission"]["max_queries_per_second"], 10_000);
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
        let abuse_status =
            block_on(handler.call(request("GET", "/abuse/status"))).expect("abuse status");
        assert_eq!(abuse_status.status, 200);
        let abuse_status: serde_json::Value =
            serde_json::from_slice(&abuse_status.payload).expect("abuse status JSON");
        assert_eq!(abuse_status["client_entries"], 0);
        assert_eq!(abuse_status["network_entries"], 0);
        assert_eq!(abuse_status["automatic_blacklist"], "temporary_cooldown");
        let incidents =
            block_on(handler.call(request("GET", "/abuse/incidents"))).expect("incidents");
        assert_eq!(incidents.status, 200);
        let incidents: serde_json::Value =
            serde_json::from_slice(&incidents.payload).expect("incidents JSON");
        assert_eq!(incidents["enabled"], false);
        assert_eq!(incidents["incidents"], serde_json::json!([]));
        let export = block_on(handler.call(request("GET", "/abuse/incidents/export")))
            .expect("incident export");
        assert_eq!(export.status, 200);
        let export: serde_json::Value =
            serde_json::from_slice(&export.payload).expect("incident export JSON");
        assert_eq!(export["enabled"], false);
        assert_eq!(export["events"], serde_json::json!([]));
        let clear_abuse =
            block_on(handler.call(request("POST", "/abuse/clear"))).expect("abuse clear");
        assert_eq!(clear_abuse.status, 200);
        assert_eq!(
            clear_abuse.payload,
            Bytes::from_static(b"{\"status\":\"cleared\",\"entries\":0}")
        );
        let country_status =
            block_on(handler.call(request("GET", "/country/status"))).expect("country status");
        assert_eq!(country_status.status, 200);
        let country_status: serde_json::Value =
            serde_json::from_slice(&country_status.payload).expect("country status JSON");
        assert_eq!(country_status["map_configured"], false);
        assert_eq!(country_status["source_kind"], "none");
        assert_eq!(country_status["freshness_contract"], "none");
        assert_eq!(country_status["entries"], 0);
        assert_eq!(
            country_status["source_fingerprint"],
            serde_json::Value::Null
        );
        assert_eq!(country_status["deny"], serde_json::json!([]));
        assert_eq!(country_status["observe"], serde_json::json!([]));
        assert_eq!(country_status["deny_regions"], serde_json::json!([]));
        assert_eq!(country_status["observe_regions"], serde_json::json!([]));
        assert_eq!(country_status["deny_asns"], serde_json::json!([]));
        assert_eq!(country_status["observe_asns"], serde_json::json!([]));
        assert_eq!(status["profiles_configured"], 0);
        assert_eq!(status["client_groups_configured"], 0);
        assert_eq!(status["upstream_configured"], false);
        assert_eq!(status["country_policy_configured"], false);
        assert_eq!(status["country_reload_interval_secs"], 0);
        assert_eq!(status["cache_entries"], 0);
        let identities = block_on(handler.call(request("GET", "/client-identities")))
            .expect("client identities response");
        assert_eq!(identities.status, 200);
        let identities: serde_json::Value =
            serde_json::from_slice(&identities.payload).expect("client identities JSON");
        assert_eq!(identities["total"], 0);
        assert_eq!(identities["client_identities"], serde_json::json!([]));
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
        let wrong_abuse_status_method = block_on(handler.call(request("POST", "/abuse/status")))
            .expect("405 abuse status response");
        assert_eq!(wrong_abuse_status_method.status, 405);
        let wrong_abuse_clear_method =
            block_on(handler.call(request("GET", "/abuse/clear"))).expect("405 abuse clear");
        assert_eq!(wrong_abuse_clear_method.status, 405);
        let wrong_abuse_revoke_method =
            block_on(handler.call(request("GET", "/abuse/revoke"))).expect("405 abuse revoke");
        assert_eq!(wrong_abuse_revoke_method.status, 405);
        let wrong_country_status_method =
            block_on(handler.call(request("POST", "/country/status")))
                .expect("405 country status response");
        assert_eq!(wrong_country_status_method.status, 405);
        let wrong_rules_method =
            block_on(handler.call(request("POST", "/rules"))).expect("405 rules response");
        assert_eq!(wrong_rules_method.status, 405);
        let wrong_policy_bundle_method = block_on(handler.call(request("POST", "/policy-bundle")))
            .expect("405 policy bundle response");
        assert_eq!(wrong_policy_bundle_method.status, 405);
        let durable_delete = block_on(handler.call(request("POST", "/logs/clear-durable")))
            .expect("durable log deletion response");
        assert_eq!(durable_delete.status, 422);
        let wrong_durable_delete_method =
            block_on(handler.call(request("GET", "/logs/clear-durable")))
                .expect("405 durable log deletion response");
        assert_eq!(wrong_durable_delete_method.status, 405);
    }

    #[test]
    fn client_identity_reload_route_replaces_the_live_snapshot() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let reload = Request::builder()
            .method("POST")
            .path("/reload/client-identities")
            .payload(r#"[{"name":"family-router","enabled":false,"clients":["192.0.2.10"],"client_cidrs":["192.0.2.0/24"]}]"#)
            .build()
            .expect("identity reload request");
        let response = block_on(handler.call(reload)).expect("identity reload response");
        assert_eq!(response.status, 200);

        let unchanged = Request::builder()
            .method("POST")
            .path("/reload/client-identities")
            .payload(r#"[{"name":"family-router","enabled":false,"clients":["192.0.2.10"],"client_cidrs":["192.0.2.0/24"]}]"#)
            .build()
            .expect("unchanged identity reload request");
        let response = block_on(handler.call(unchanged)).expect("unchanged identity response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"unchanged"}"#);

        let status = block_on(handler.call(request("GET", "/client-identities")))
            .expect("identity status response");
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("identity status JSON");
        assert_eq!(status["total"], 1);
        assert_eq!(status["client_identities"][0]["name"], "family-router");
        assert_eq!(status["client_identities"][0]["enabled"], false);
        assert_eq!(status["client_identities"][0]["client_cidrs"], 1);

        let upsert = Request::builder()
            .method("POST")
            .path("/reload/client-identities/upsert")
            .payload(r#"{"client_identities":[{"name":"guest-router","clients":["192.0.2.11"]},{"name":"family-router","enabled":true,"clients":["192.0.2.10"],"client_cidrs":["192.0.2.0/24"]}]}"#)
            .build()
            .expect("identity upsert request");
        assert_eq!(
            block_on(handler.call(upsert))
                .expect("identity upsert response")
                .status,
            200
        );

        let remove = Request::builder()
            .method("POST")
            .path("/reload/client-identities/remove")
            .payload(r#"["family-router"]"#)
            .build()
            .expect("identity removal request");
        assert_eq!(
            block_on(handler.call(remove))
                .expect("identity removal response")
                .status,
            200
        );
        let status = block_on(handler.call(request("GET", "/client-identities")))
            .expect("updated identity status response");
        let status: serde_json::Value =
            serde_json::from_slice(&status.payload).expect("updated identity status JSON");
        assert_eq!(status["total"], 1);
        assert_eq!(status["client_identities"][0]["name"], "guest-router");
        assert_eq!(status["client_identities"][0]["enabled"], true);
    }

    #[test]
    fn admission_reload_updates_live_limits_and_rejects_capacity_changes() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let reload = Request::builder()
            .method("POST")
            .path("/reload/admission")
            .payload(r#"{"reject_any":true,"max_queries_per_second":7}"#)
            .build()
            .expect("valid admission reload");
        let response = block_on(handler.call(reload)).expect("admission reload response");
        assert_eq!(response.status, 200);
        let status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("admission status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["reject_any"], true);
        assert_eq!(status["max_queries_per_second"], 7);

        let unchanged = Request::builder()
            .method("POST")
            .path("/reload/admission")
            .payload(r#"{"reject_any":true,"max_queries_per_second":7}"#)
            .build()
            .expect("unchanged admission reload");
        let response = block_on(handler.call(unchanged)).expect("unchanged admission response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"unchanged"}"#);

        let rejected = Request::builder()
            .method("POST")
            .path("/reload/admission")
            .payload(r#"{"max_inflight_requests":1}"#)
            .build()
            .expect("valid capacity reload");
        let response = block_on(handler.call(rejected)).expect("capacity response");
        assert_eq!(response.status, 422);
        let status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("admission status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["reject_any"], true);
        assert_eq!(status["max_queries_per_second"], 7);
    }

    #[test]
    fn denylist_route_replaces_only_the_live_client_denylist() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let reload = Request::builder()
            .method("POST")
            .path("/reload/admission/denylist")
            .payload(r#"["192.0.2.10/32","2001:db8:42::/48"]"#)
            .build()
            .expect("valid denylist reload");
        let response = block_on(handler.call(reload)).expect("denylist response");
        assert_eq!(response.status, 200);
        let status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("admission status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["deny_client_cidr_count"], 2);
        assert_eq!(status["max_queries_per_second"], 10_000);

        let rejected = Request::builder()
            .method("POST")
            .path("/reload/admission/denylist")
            .payload(r#"["not-a-cidr"]"#)
            .build()
            .expect("invalid denylist reload");
        let response = block_on(handler.call(rejected)).expect("invalid response");
        assert_eq!(response.status, 422);
        let status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("admission status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["deny_client_cidr_count"], 2);
    }

    #[test]
    fn managed_denylist_can_be_exported_added_and_revoked_atomically() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let add = Request::builder()
            .method("POST")
            .path("/abuse/denylist/add")
            .payload(r#"["192.0.2.10/32","2001:db8:42::/48"]"#)
            .build()
            .expect("valid denylist add");
        let response = block_on(handler.call(add)).expect("add response");
        assert_eq!(response.status, 200);
        let exported =
            block_on(handler.call(request("GET", "/abuse/denylist"))).expect("denylist export");
        assert_eq!(
            serde_json::from_slice::<Vec<String>>(&exported.payload).expect("export JSON"),
            vec!["192.0.2.10/32", "2001:db8:42::/48"]
        );

        let remove = Request::builder()
            .method("POST")
            .path("/abuse/denylist/remove")
            .payload(r#"["192.0.2.10/32"]"#)
            .build()
            .expect("valid denylist removal");
        let response = block_on(handler.call(remove)).expect("remove response");
        assert_eq!(response.status, 200);
        let exported = block_on(handler.call(request("GET", "/abuse/denylist")))
            .expect("denylist export after removal");
        assert_eq!(
            serde_json::from_slice::<Vec<String>>(&exported.payload).expect("export JSON"),
            vec!["2001:db8:42::/48"]
        );
    }

    #[test]
    fn temporary_incident_revoke_route_is_bounded_and_validates_clients() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let revoke = Request::builder()
            .method("POST")
            .path("/abuse/revoke")
            .payload(r#"["192.0.2.10","2001:db8::10"]"#)
            .build()
            .expect("valid incident revoke");
        let response = block_on(handler.call(revoke)).expect("revoke response");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.payload,
            Bytes::from_static(b"{\"status\":\"revoked\",\"entries\":2}")
        );

        let invalid = Request::builder()
            .method("POST")
            .path("/abuse/revoke")
            .payload(r#"["not-an-ip"]"#)
            .build()
            .expect("invalid incident revoke");
        let response = block_on(handler.call(invalid)).expect("invalid revoke response");
        assert_eq!(response.status, 422);
    }

    #[test]
    fn incident_approval_promotes_exact_clients_to_the_managed_denylist() {
        let handler = AdminHandler::new(Arc::new(
            Policy::new(crate::Config::default()).expect("default policy"),
        ));
        let approve = Request::builder()
            .method("POST")
            .path("/abuse/incidents/approve")
            .payload(r#"["192.0.2.10","2001:db8::10"]"#)
            .build()
            .expect("valid incident approval");
        let response = block_on(handler.call(approve)).expect("approval response");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.payload,
            Bytes::from_static(b"{\"status\":\"approved\",\"entries\":2}")
        );
        let denylist =
            block_on(handler.call(request("GET", "/abuse/denylist"))).expect("denylist response");
        assert_eq!(
            serde_json::from_slice::<Vec<String>>(&denylist.payload).expect("denylist JSON"),
            vec!["192.0.2.10/32", "2001:db8::10/128"]
        );
    }

    #[test]
    fn persisted_managed_denylist_rolls_back_when_recording_is_unavailable() {
        let mut config = crate::Config::default();
        config.admission.ddos.persist_incidents = true;
        config.privacy.query_recording_path = Some("operator-denylist.jsonl".into());
        let handler = AdminHandler::new(Arc::new(Policy::new(config).expect("valid config")));
        let add = Request::builder()
            .method("POST")
            .path("/abuse/denylist/add")
            .payload(r#"["192.0.2.10/32"]"#)
            .build()
            .expect("valid denylist add");
        let response = block_on(handler.call(add)).expect("add response");
        assert_eq!(response.status, 503);
        let exported =
            block_on(handler.call(request("GET", "/abuse/denylist"))).expect("denylist export");
        assert_eq!(exported.payload, Bytes::from_static(b"[]"));
    }

    #[test]
    fn durable_recording_delete_route_removes_and_verifies_bounded_rotations() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-admin-recording-{}-{}.jsonl",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let mut config = crate::Config::default();
        config.privacy.query_recording_path = Some(path.to_string_lossy().into_owned());
        let policy = Arc::new(Policy::new(config).expect("valid recording config"));
        let handler = AdminHandler::new(policy);
        let mut targets = vec![path.clone()];
        for index in 1..=16 {
            let mut rotated = path.as_os_str().to_os_string();
            rotated.push(format!(".{index}"));
            targets.push(std::path::PathBuf::from(rotated));
        }
        for target in &targets {
            std::fs::write(target, b"metadata\n").expect("write recording fixture");
        }

        let response = block_on(handler.call(request("POST", "/logs/clear-durable")))
            .expect("durable deletion response");
        assert_eq!(response.status, 200);
        let body: serde_json::Value =
            serde_json::from_slice(&response.payload).expect("durable deletion JSON");
        assert_eq!(body["status"], "deleted");
        assert_eq!(body["files"], 17);
        for target in targets {
            assert!(
                !target.exists(),
                "deleted target remains: {}",
                target.display()
            );
        }
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
        let blocklists = block_on(handler.call(request("GET", "/blocklists")))
            .expect("blocklist inspection response");
        assert_eq!(blocklists.status, 200);
        let blocklists: serde_json::Value =
            serde_json::from_slice(&blocklists.payload).expect("blocklist inspection JSON");
        assert_eq!(blocklists["source_count"], 1);
        assert_eq!(blocklists["rule_count"], 2);
        assert_eq!(
            blocklists["sources"][0]["path"],
            path.to_string_lossy().as_ref()
        );
        assert_eq!(blocklists["sources"][0]["status"], "ok");
        assert_eq!(blocklists["sources"][0]["load_status"], "ok");
        assert_eq!(blocklists["sources"][0]["rule_count"], 2);
        assert_eq!(blocklists["sources"][0]["bytes"], 12);
        assert!(blocklists["sources"][0]["modified_age_secs"].is_number());

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
        let second_path = path.with_file_name(format!(
            "blackhole-admin-blocklist-second-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::write(&second_path, "tracking.example\n").expect("write second blocklist");
        let second_json = serde_json::to_string(&vec![second_path.to_string_lossy().into_owned()])
            .expect("second blocklist JSON");
        let added = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/add")
                    .payload(second_json)
                    .build()
                    .expect("addition request"),
            ),
        )
        .expect("addition response");
        assert_eq!(added.status, 200);
        let status =
            block_on(handler.call(request("GET", "/policy/status"))).expect("status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["blocklist_sources"], 2);
        assert_eq!(
            status["blocklist_rules"], 4,
            "both apex plus subdomain rules"
        );

        let first_path = path.to_string_lossy().into_owned();
        let first_json =
            serde_json::to_string(std::slice::from_ref(&first_path)).expect("first blocklist JSON");
        let disabled = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/disable")
                    .payload(Bytes::from(first_json.clone()))
                    .build()
                    .expect("disable request"),
            ),
        )
        .expect("disable response");
        assert_eq!(disabled.status, 200);
        let status = block_on(handler.call(request("GET", "/policy/status")))
            .expect("disabled status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["disabled_blocklist_sources"], 1);
        assert_eq!(status["blocklist_rules"], 2);
        let blocklists = block_on(handler.call(request("GET", "/blocklists")))
            .expect("disabled blocklist inspection response");
        let blocklists: serde_json::Value =
            serde_json::from_slice(&blocklists.payload).expect("disabled blocklist JSON");
        assert_eq!(blocklists["sources"][0]["enabled"], false);
        assert_eq!(blocklists["sources"][0]["load_status"], "disabled");
        assert_eq!(blocklists["sources"][0]["rule_count"], 0);

        let enabled = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/enable")
                    .payload(Bytes::from(first_json.clone()))
                    .build()
                    .expect("enable request"),
            ),
        )
        .expect("enable response");
        assert_eq!(enabled.status, 200);
        let status = block_on(handler.call(request("GET", "/policy/status")))
            .expect("enabled status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["disabled_blocklist_sources"], 0);
        assert_eq!(status["blocklist_rules"], 4);

        let removed = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/remove")
                    .payload(first_json)
                    .build()
                    .expect("removal request"),
            ),
        )
        .expect("removal response");
        assert_eq!(removed.status, 200);
        let status =
            block_on(handler.call(request("GET", "/policy/status"))).expect("status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["blocklist_sources"], 1);
        assert_eq!(status["blocklist_rules"], 2);

        let unknown = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/blocklists/remove")
                    .payload(r#"["/definitely/missing/blackhole.list"]"#)
                    .build()
                    .expect("unknown removal request"),
            ),
        )
        .expect("unknown removal response");
        assert_eq!(unknown.status, 422);
        std::fs::remove_file(path).expect("remove blocklist");
        std::fs::remove_file(second_path).expect("remove second blocklist");
    }

    #[test]
    fn country_policy_replacement_is_atomic_and_updates_bundle() {
        let path = std::env::temp_dir().join(format!(
            "blackhole-admin-country-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        std::fs::write(&path, "US 192.0.2.0/24 us-ca 64501\n").expect("write country map");
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let config = CountryPolicyConfig {
            map_path: Some(path.to_string_lossy().into_owned()),
            deny: vec!["US".into()],
            deny_regions: vec!["us-ca".into()],
            ..CountryPolicyConfig::default()
        };
        let payload = serde_json::to_string(&config).expect("country config JSON");
        let replaced = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/country/replace")
                    .payload(payload)
                    .build()
                    .expect("country replacement request"),
            ),
        )
        .expect("country replacement response");
        assert_eq!(replaced.status, 200);
        let status = block_on(handler.call(request("GET", "/country/status")))
            .expect("country status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["map_configured"], true);
        assert_eq!(status["entries"], 1);
        assert_eq!(status["deny"], serde_json::json!(["US"]));
        assert_eq!(status["deny_regions"], serde_json::json!(["us-ca"]));

        let failed = block_on(
            handler.call(
                Request::builder()
                    .method("POST")
                    .path("/reload/country/replace")
                    .payload(r#"{"map_path":"/definitely/missing/country.map","deny":["CA"]}"#)
                    .build()
                    .expect("invalid country replacement request"),
            ),
        )
        .expect("invalid country replacement response");
        assert_eq!(failed.status, 422);
        let status = block_on(handler.call(request("GET", "/country/status")))
            .expect("country status response");
        let status: serde_json::Value = serde_json::from_slice(&status.payload).expect("status");
        assert_eq!(status["deny"], serde_json::json!(["US"]));
        let bundle = block_on(handler.call(request("GET", "/policy-bundle")))
            .expect("policy bundle response");
        let bundle: serde_json::Value = serde_json::from_slice(&bundle.payload).expect("bundle");
        assert_eq!(bundle["country_policy"]["deny"], serde_json::json!(["US"]));
        std::fs::remove_file(path).expect("remove country map");
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
            client_identity: None,
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
            enabled: true,
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: vec!["home".into()],
            client_identity: Some("family-router".into()),
            priority: 10,
            client_cidrs: vec![],
            qtype: None,
            qclass: None,
        }];
        config.policy.client_groups = vec![crate::ClientGroupConfig {
            name: "home".into(),
            enabled: true,
            client_addresses: Vec::new(),
            client_cidrs: vec!["192.0.2.0/24".into()],
        }];
        config.policy.client_identities = vec![crate::ClientIdentityConfig {
            name: "family-router".into(),
            enabled: true,
            clients: vec!["192.0.2.10".parse().expect("identity address")],
            client_cidrs: Vec::new(),
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
        assert_eq!(profiles["profiles"][0]["client_identity"], "family-router");
        assert_eq!(profiles["profiles"][0]["expanded_rule_count"], 1);
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
    fn profile_reload_reports_an_unchanged_snapshot() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(policy);
        let request = Request::builder()
            .method("POST")
            .path("/reload/profiles")
            .payload(r#"{"profiles":[],"client_groups":[]}"#)
            .build()
            .expect("profile replacement request");
        let response = block_on(handler.call(request)).expect("profile reload response");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.payload,
            Bytes::from_static(b"{\"status\":\"unchanged\"}")
        );
    }

    #[test]
    fn client_group_upsert_republishes_profiles_atomically() {
        let mut config = crate::Config::default();
        config.policy.profiles = vec![crate::ServiceProfileConfig {
            id: 700,
            name: "family".into(),
            enabled: true,
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: vec!["home".into()],
            client_identity: None,
            priority: 0,
            client_cidrs: Vec::new(),
            qtype: None,
            qclass: None,
        }];
        config.policy.client_groups = vec![crate::ClientGroupConfig {
            name: "home".into(),
            enabled: true,
            client_addresses: Vec::new(),
            client_cidrs: vec!["192.0.2.0/24".into()],
        }];
        let policy = Arc::new(Policy::new(config).expect("valid group policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let update = Request::builder()
            .method("POST")
            .path("/reload/client-groups/upsert")
            .payload(
                r#"{"client_groups":[{"name":"HOME","enabled":false,"client_addresses":["192.0.2.53"],"client_cidrs":["198.51.100.0/24"]},{"name":"guest","client_cidrs":["203.0.113.0/24"]}]}"#,
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
        assert_eq!(groups["client_groups"][0]["enabled"], false);
        let mut query_wire = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query_wire.extend_from_slice(b"\x03ads\x07example\0\0\x01\0\x01");
        let query = crate::query::QueryView::parse(&query_wire).expect("group query");
        assert_eq!(
            policy.action_for_view_with_client(query, Some("192.0.2.53".parse().unwrap())),
            crate::Action::Pass
        );

        let reenable = Request::builder()
            .method("POST")
            .path("/reload/client-groups/upsert")
            .payload(
                r#"{"client_groups":[{"name":"HOME","enabled":true,"client_addresses":["192.0.2.53"],"client_cidrs":["198.51.100.0/24"]}]}"#,
            )
            .build()
            .expect("group re-enable request");
        let response = block_on(handler.call(reenable)).expect("group re-enable response");
        assert_eq!(response.status, 200);
        let query = crate::query::QueryView::parse(&query_wire).expect("group query");
        assert_eq!(
            policy.action_for_view_with_client(query, Some("192.0.2.53".parse().unwrap())),
            crate::Action::Nxdomain
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
            enabled: true,
            domains: vec!["ads.example".into()],
            action: crate::Action::Nxdomain,
            groups: Vec::new(),
            client_identity: Some("family-router".into()),
            priority: 0,
            client_cidrs: Vec::new(),
            qtype: None,
            qclass: None,
        }];
        config.policy.client_identities = vec![crate::ClientIdentityConfig {
            name: "family-router".into(),
            enabled: true,
            clients: vec!["192.0.2.10".parse().expect("identity address")],
            client_cidrs: Vec::new(),
        }];
        let policy = Arc::new(Policy::new(config).expect("valid profile policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let update = Request::builder()
            .method("POST")
            .path("/reload/profiles/upsert")
            .payload(
                r#"{"profiles":[{"id":800,"name":"family-edited","domains":["new.example"],"action":"reject","client_identity":"family-router"},{"id":801,"name":"guest","domains":["guest.example"],"action":"drop","enabled":false}]}"#,
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
        assert_eq!(profiles["profiles"][0]["client_identity"], "family-router");
        assert_eq!(profiles["profiles"][1]["enabled"], false);
        assert_eq!(profiles["profiles"][1]["expanded_rule_count"], 0);
        let bundle =
            block_on(handler.call(request("GET", "/policy-bundle"))).expect("policy bundle");
        let bundle: serde_json::Value = serde_json::from_slice(&bundle.payload).expect("bundle");
        assert_eq!(bundle["profiles"][0]["client_identity"], "family-router");

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
                r#"{"rules":[{"id":7,"domain":"blocked.example","action":"nxdomain"}],"regex_rules":[{"id":8,"pattern":"^ads\\.","action":"drop"}],"profiles":[{"id":9,"name":"family","domains":["family.example"],"action":"reject"}],"client_groups":[],"client_identities":[{"name":"family-router","clients":["192.0.2.10"]}],"rewrites":[{"name":"router.example","ipv4":"192.0.2.1","ipv6":null,"ttl":30}]}"#,
            )
            .build()
            .expect("policy bundle request");
        let response = block_on(handler.call(bundle)).expect("bundle response");
        assert_eq!(response.status, 200);
        let bundle = block_on(handler.call(request("GET", "/policy-bundle")))
            .expect("published policy bundle response");
        assert_eq!(bundle.status, 200);
        let bundle: serde_json::Value =
            serde_json::from_slice(&bundle.payload).expect("published policy bundle JSON");
        assert_eq!(bundle["rules"][0]["id"], 7);
        assert_eq!(bundle["rules"][0]["action"], "nxdomain");
        assert_eq!(bundle["regex_rules"][0]["pattern"], "^ads\\.");
        assert_eq!(bundle["regex_rules"][0]["action"], "drop");
        assert_eq!(bundle["profiles"][0]["name"], "family");
        assert_eq!(bundle["profiles"][0]["action"], "reject");
        assert_eq!(bundle["client_identities"][0]["name"], "family-router");
        assert_eq!(bundle["client_identities"][0]["clients"][0], "192.0.2.10");
        assert_eq!(bundle["rewrites"][0]["name"], "router.example");
        assert_eq!(bundle["rewrites"][0]["ipv4"], "192.0.2.1");
        assert_eq!(bundle["blocklists"], serde_json::Value::Null);
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
    fn full_config_reload_publishes_policy_and_admission_together() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let publish = Request::builder()
            .method("POST")
            .path("/reload/config")
            .payload(
                r#"{"rules":[{"id":77,"domain":"blocked.example","action":"reject"}],"admission":{"max_queries_per_second":7}}"#,
            )
            .build()
            .expect("full config request");
        assert_eq!(
            block_on(handler.call(publish))
                .expect("full config response")
                .status,
            200
        );

        let policy_status = block_on(handler.call(request("GET", "/policy/status")))
            .expect("policy status response");
        let policy_status: serde_json::Value =
            serde_json::from_slice(&policy_status.payload).expect("policy status JSON");
        assert_eq!(policy_status["domain_rules"], 1);
        let admission_status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("admission status response");
        let admission_status: serde_json::Value =
            serde_json::from_slice(&admission_status.payload).expect("admission status JSON");
        assert_eq!(admission_status["max_queries_per_second"], 7);

        let rejected = Request::builder()
            .method("POST")
            .path("/reload/config")
            .payload(r#"{"rules":[],"admission":{"max_inflight_requests":1}}"#)
            .build()
            .expect("invalid full config request");
        assert_eq!(
            block_on(handler.call(rejected))
                .expect("rejected response")
                .status,
            422
        );
        let admission_status = block_on(handler.call(request("GET", "/admission/status")))
            .expect("retained admission status response");
        let admission_status: serde_json::Value =
            serde_json::from_slice(&admission_status.payload).expect("retained admission JSON");
        assert_eq!(admission_status["max_queries_per_second"], 7);
        let policy_status = block_on(handler.call(request("GET", "/policy/status")))
            .expect("retained policy status response");
        let policy_status: serde_json::Value =
            serde_json::from_slice(&policy_status.payload).expect("retained policy JSON");
        assert_eq!(policy_status["domain_rules"], 1);
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

        let disabled = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(r#"{"filtering_enabled":false}"#)
            .build()
            .expect("filtering toggle request");
        let response = block_on(handler.call(disabled)).expect("filtering toggle response");
        assert_eq!(response.status, 200);
        assert_eq!(policy.evaluate(&query("new.example.")).unwrap().rcode, 0);
        let status: serde_json::Value =
            serde_json::from_str(&policy.admin_policy_status()).expect("policy status");
        assert_eq!(status["filtering_enabled"], false);

        let enabled = Request::builder()
            .method("POST")
            .path("/reload/policy-bundle")
            .payload(r#"{"filtering_enabled":true}"#)
            .build()
            .expect("filtering re-enable request");
        let response = block_on(handler.call(enabled)).expect("filtering re-enable response");
        assert_eq!(response.status, 200);
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
    fn filtering_toggle_route_is_bounded_atomic_and_reports_unchanged() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(Arc::clone(&policy));
        let disabled = Request::builder()
            .method("POST")
            .path("/reload/filtering")
            .payload(r#"{"enabled":false}"#)
            .build()
            .expect("disable filtering request");
        let response = block_on(handler.call(disabled)).expect("disable filtering response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"reloaded"}"#);

        let unchanged = Request::builder()
            .method("POST")
            .path("/reload/filtering")
            .payload(r#"{"enabled":false}"#)
            .build()
            .expect("unchanged filtering request");
        let response = block_on(handler.call(unchanged)).expect("unchanged filtering response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"unchanged"}"#);
        assert!(
            policy
                .admin_policy_status()
                .contains("\"filtering_enabled\":false")
        );

        let malformed = Request::builder()
            .method("POST")
            .path("/reload/filtering")
            .payload(r#"{"enabled":"false"}"#)
            .build()
            .expect("malformed filtering request");
        assert_eq!(
            block_on(handler.call(malformed))
                .expect("malformed response")
                .status,
            400
        );

        let oversized = Request::builder()
            .method("POST")
            .path("/reload/filtering")
            .payload("x".repeat(MAX_POLICY_BODY_BYTES + 1))
            .build()
            .expect("oversized filtering request");
        assert_eq!(
            block_on(handler.call(oversized))
                .expect("oversized response")
                .status,
            413
        );
    }

    #[test]
    fn blocklist_reload_route_reports_an_unchanged_snapshot() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(policy);
        let response = block_on(handler.call(request("POST", "/reload/blocklists")))
            .expect("blocklist reload response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"unchanged"}"#);
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
            client_identity: None,
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
            cname: None,
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
            client_identity: None,
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
        let unchanged_reload = Request::builder()
            .method("POST")
            .path("/reload/rewrites")
            .payload(r#"[{"name":"router.example","ipv4":"192.0.2.1","ttl":30}]"#)
            .build()
            .expect("unchanged rewrite reload request");
        let response = block_on(handler.call(unchanged_reload)).expect("unchanged reload response");
        assert_eq!(response.status, 200);
        assert_eq!(response.payload.as_ref(), br#"{"status":"unchanged"}"#);
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
    fn country_reload_route_reports_an_unchanged_default_snapshot() {
        let policy = Arc::new(Policy::new(crate::Config::default()).expect("default policy"));
        let handler = AdminHandler::new(policy);
        let reload = block_on(handler.call(request("POST", "/reload/country")))
            .expect("country reload response");
        assert_eq!(reload.status, 200);
        assert_eq!(
            reload.payload,
            Bytes::from_static(b"{\"status\":\"unchanged\"}")
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
