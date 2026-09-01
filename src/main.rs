#![cfg(feature = "std")]

use blackhole::admin::{authenticated_handle, validate_bind};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use blackhole::linux_capture::{CaptureController, FileOwnershipStore};
#[cfg(target_os = "linux")]
use blackhole::linux_capture::{NftRulePlan, native::NftCommandBackend};
#[cfg(feature = "std")]
use blackhole::listener::{TcpProtocol, UdpProtocol};
#[cfg(target_os = "macos")]
use blackhole::pf_capture::{PfRulePlan, native::PfctlCommandBackend};
#[cfg(feature = "std")]
use blackhole::{BoundedQueryRecordingSink, Config, Policy, UpstreamTransport};
#[cfg(feature = "std")]
use bytes::Bytes;
#[cfg(feature = "std")]
use conflaguration::builder as config_builder;
#[cfg(feature = "std")]
use futures::StreamExt;
#[cfg(feature = "std")]
use proxima::pipe::into_handle;
#[cfg(feature = "std")]
use proxima::recording::{AccumulatingSink, FormatKind, LazyFanOut, SinkSpec, deferred_runtime};
#[cfg(feature = "std")]
use proxima::runtime::PrimeRuntime;
#[cfg(feature = "std")]
use proxima::{H1ClientUpstream, Request, Response, SendPipe};
#[cfg(feature = "std")]
use proxima::{Listener, ListenerBuilderEntry, ProximaError, RecordingSource};
#[cfg(feature = "std")]
use proxima_net::prime::{PrimeDatagramFactory, PrimeTcpUpstream};
use proxima_primitives::pipe::{
    IntervalPipe, ProducerLifecycle, Request as PipeRequest, Response as PipeResponse,
    into_handle as into_pipe_handle, into_source_handle,
};
#[cfg(feature = "std")]
use proxima_primitives::stream::{StreamConnection, StreamUpstream};
#[cfg(feature = "doq")]
use proxima_quic::QuicUpstream;
#[cfg(feature = "std")]
use proxima_tls::{TlsClientConfig, TlsStreamUpstream};
#[cfg(feature = "std")]
use std::{
    collections::BTreeMap,
    env, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    task::{Context, Poll},
};

const MAX_RECORDING_ROTATIONS: usize = 16;

#[cfg(feature = "doq")]
fn doq_tls_config() -> Result<rustls::ClientConfig, ProximaError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ProximaError::Config(format!("invalid DoQ TLS versions: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    Ok(config)
}

#[cfg(feature = "std")]
fn validate_query_recording_path(path: &str) -> Result<(), ProximaError> {
    let destination = Path::new(path);
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = std::fs::metadata(parent).map_err(|error| {
        ProximaError::Config(format!(
            "query recording parent {} is unavailable: {error}",
            parent.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ProximaError::Config(format!(
            "query recording parent {} is not a directory",
            parent.display()
        )));
    }
    match std::fs::metadata(destination) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(ProximaError::Config(format!(
                "query recording destination {} is not a regular file",
                destination.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ProximaError::Config(format!(
                "query recording destination {} is unavailable: {error}",
                destination.display()
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
fn delete_query_recording(path: &Path) -> Result<usize, ProximaError> {
    let path_string = path
        .to_str()
        .ok_or_else(|| ProximaError::Record("query recording path must be valid UTF-8".into()))?;
    validate_query_recording_path(path_string)?;
    let mut targets = Vec::with_capacity(MAX_RECORDING_ROTATIONS + 1);
    targets.push(path.to_owned());
    for index in 1..=MAX_RECORDING_ROTATIONS {
        targets.push(rotated_query_recording_path(path, index));
    }
    for target in &targets {
        match std::fs::metadata(target) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(ProximaError::Record(format!(
                    "query recording target {} is not a regular file",
                    target.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ProximaError::Record(format!(
                    "inspect query recording target {}: {error}",
                    target.display()
                )));
            }
        }
    }
    let mut removed = 0;
    for target in &targets {
        match std::fs::remove_file(target) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ProximaError::Record(format!(
                    "delete query recording target {}: {error}",
                    target.display()
                )));
            }
        }
    }
    for target in &targets {
        match std::fs::metadata(target) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(ProximaError::Record(format!(
                    "query recording target {} remains after deletion",
                    target.display()
                )));
            }
            Err(error) => {
                return Err(ProximaError::Record(format!(
                    "verify query recording deletion {}: {error}",
                    target.display()
                )));
            }
        }
    }
    Ok(removed)
}

fn rotated_query_recording_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

fn rotate_query_recording(
    path: &Path,
    max_bytes: u64,
    max_files: usize,
) -> Result<(), ProximaError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ProximaError::Record(format!(
                "inspect query recording {} for rotation: {error}",
                path.display()
            )));
        }
    };
    if metadata.len() <= max_bytes {
        return Ok(());
    }
    if max_files == 0 || max_files > 16 {
        return Err(ProximaError::Config(
            "query recording rotation file bound is invalid".into(),
        ));
    }

    let oldest = rotated_query_recording_path(path, max_files + 1);
    match std::fs::remove_file(&oldest) {
        Ok(()) => {
            if oldest.exists() {
                return Err(ProximaError::Record(format!(
                    "query recording rotation could not delete {}",
                    oldest.display()
                )));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ProximaError::Record(format!(
                "query recording rotation delete {}: {error}",
                oldest.display()
            )));
        }
    }

    for index in (1..max_files).rev() {
        let from = rotated_query_recording_path(path, index);
        if from.exists() {
            let to = rotated_query_recording_path(path, index + 1);
            std::fs::rename(&from, &to).map_err(|error| {
                ProximaError::Record(format!(
                    "query recording rotation rename {} to {}: {error}",
                    from.display(),
                    to.display()
                ))
            })?;
        }
    }
    let first = rotated_query_recording_path(path, 1);
    std::fs::rename(path, &first).map_err(|error| {
        ProximaError::Record(format!(
            "query recording rotation rename {} to {}: {error}",
            path.display(),
            first.display()
        ))
    })?;
    Ok(())
}

const MAX_REPLAY_BYTES: u64 = 64 * 1024 * 1024;

fn count_replay_event(
    event: &proxima::RecordingEvent,
    actions: &mut BTreeMap<String, u64>,
    incidents: &mut u64,
    events: &mut u64,
) -> Result<(), ProximaError> {
    let proxima::ProtocolEvent::Custom { kind, payload } = &event.event else {
        return Err(ProximaError::Record(
            "blackhole replay accepts only metadata custom events".into(),
        ));
    };
    *events = events
        .checked_add(1)
        .ok_or_else(|| ProximaError::Record("blackhole replay event count overflow".into()))?;
    match kind.as_str() {
        "blackhole.dns_decision" => {
            let action = payload
                .get("action")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ProximaError::Record(
                        "blackhole replay decision is missing its action label".into(),
                    )
                })?;
            if !matches!(
                action,
                "pass"
                    | "reject"
                    | "honeypot"
                    | "sink"
                    | "observe"
                    | "forward"
                    | "drop"
                    | "nxdomain"
            ) {
                return Err(ProximaError::Record(format!(
                    "blackhole replay has an unsupported action label: {action}"
                )));
            }
            let counter = actions.entry(action.to_owned()).or_default();
            *counter = counter.checked_add(1).ok_or_else(|| {
                ProximaError::Record("blackhole replay action count overflow".into())
            })?;
        }
        "blackhole.ddos_incident" => {
            *incidents = incidents.checked_add(1).ok_or_else(|| {
                ProximaError::Record("blackhole replay incident count overflow".into())
            })?;
        }
        other => {
            return Err(ProximaError::Record(format!(
                "blackhole replay does not support event kind: {other}"
            )));
        }
    }
    Ok(())
}

async fn replay_metadata(path: &Path) -> Result<(), ProximaError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        ProximaError::Record(format!("inspect replay source {}: {error}", path.display()))
    })?;
    if !metadata.is_file() {
        return Err(ProximaError::Record(format!(
            "replay source {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > MAX_REPLAY_BYTES {
        return Err(ProximaError::Record(format!(
            "replay source exceeds the {} byte bound",
            MAX_REPLAY_BYTES
        )));
    }
    let runtime = Arc::new(PrimeRuntime::new(1)?);
    let source = proxima::JsonlSource::new(path, runtime);
    let mut stream = source.events();
    let mut actions = BTreeMap::new();
    let mut incidents = 0;
    let mut events = 0;
    while let Some(event) = stream.next().await {
        let event = event?;
        count_replay_event(&event, &mut actions, &mut incidents, &mut events)?;
    }
    println!(
        "{}",
        serde_json::json!({
            "events": events,
            "decisions": actions.values().sum::<u64>(),
            "actions": actions,
            "ddos_incidents": incidents,
        })
    );
    Ok(())
}

async fn restore_persisted_abuse(
    policy: &Policy,
    path: &Path,
    max_bytes: u64,
) -> Result<usize, ProximaError> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        ProximaError::Record(format!(
            "inspect abuse recording {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(ProximaError::Record(format!(
            "abuse recording {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes.min(MAX_REPLAY_BYTES) {
        return Err(ProximaError::Record(format!(
            "abuse recording exceeds the {} byte bound",
            max_bytes.min(MAX_REPLAY_BYTES)
        )));
    }
    let runtime = Arc::new(PrimeRuntime::new(1)?);
    let source = proxima::JsonlSource::new(path, runtime);
    let mut stream = source.events();
    let mut restored = 0usize;
    let mut seen = 0usize;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u128::from(u64::MAX)) as u64
        });
    while let Some(event) = stream.next().await {
        seen = seen
            .checked_add(1)
            .ok_or_else(|| ProximaError::Record("abuse recording event count overflow".into()))?;
        if seen > 1_000_000 {
            return Err(ProximaError::Record(
                "abuse recording exceeds the event bound".into(),
            ));
        }
        let event = event?;
        let proxima::ProtocolEvent::Custom { kind, payload } = event.event else {
            continue;
        };
        if kind != "blackhole.ddos_incident" {
            continue;
        }
        let Some(expires_at_ms) = payload
            .get("expires_at_ms")
            .and_then(serde_json::Value::as_u64)
        else {
            continue;
        };
        let client = payload
            .get("client")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ProximaError::Record("abuse recording incident is missing its client".into())
            })?
            .parse()
            .map_err(|error| {
                ProximaError::Record(format!(
                    "abuse recording incident has invalid client: {error}"
                ))
            })?;
        if policy.restore_abuse_incident(client, expires_at_ms, now_ms) {
            restored = restored.saturating_add(1);
        }
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::restore_persisted_abuse;
    use super::{
        count_replay_event, delete_query_recording, rotate_query_recording,
        validate_query_recording_path,
    };
    use blackhole::{Config, Policy};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn temporary_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "blackhole-recording-path-{}-{}-{suffix}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ))
    }

    #[test]
    fn recording_path_requires_an_existing_parent_directory() {
        let path = temporary_path("missing").join("decisions.jsonl");
        assert!(validate_query_recording_path(path.to_str().expect("UTF-8 path")).is_err());
    }

    #[test]
    fn recording_path_rejects_a_directory_destination() {
        let path = temporary_path("directory");
        std::fs::create_dir(&path).expect("temporary directory");
        assert!(validate_query_recording_path(path.to_str().expect("UTF-8 path")).is_err());
        std::fs::remove_dir(&path).expect("remove temporary directory");
    }

    #[test]
    fn recording_rotation_bounds_retained_files_and_verifies_oldest_deletion() {
        let directory = temporary_path("rotation");
        std::fs::create_dir(&directory).expect("temporary directory");
        let path = directory.join("decisions.jsonl");
        std::fs::write(&path, b"active").expect("active recording");
        std::fs::write(path.with_extension("jsonl.1"), b"one").expect("first rotation");
        std::fs::write(path.with_extension("jsonl.2"), b"two").expect("second rotation");
        std::fs::write(path.with_extension("jsonl.3"), b"oldest").expect("oldest rotation");

        rotate_query_recording(&path, 3, 2).expect("rotate recording");

        assert!(!path.exists());
        assert_eq!(
            std::fs::read(path.with_extension("jsonl.1")).unwrap(),
            b"active"
        );
        assert_eq!(
            std::fs::read(path.with_extension("jsonl.2")).unwrap(),
            b"one"
        );
        assert!(!path.with_extension("jsonl.3").exists());
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn durable_recording_deletion_removes_bounded_rotations_and_verifies_absence() {
        let directory = temporary_path("delete");
        std::fs::create_dir(&directory).expect("temporary directory");
        let path = directory.join("decisions.jsonl");
        std::fs::write(&path, b"active").expect("active recording");
        std::fs::write(path.with_extension("jsonl.1"), b"one").expect("first rotation");
        std::fs::write(path.with_extension("jsonl.16"), b"old").expect("old rotation");

        assert_eq!(delete_query_recording(&path).expect("delete recording"), 3);
        assert!(!path.exists());
        assert!(!path.with_extension("jsonl.1").exists());
        assert!(!path.with_extension("jsonl.16").exists());
        std::fs::remove_dir(&directory).expect("remove temporary directory");
    }

    #[test]
    fn replay_counts_actions_and_incidents_without_accepting_payload_events() {
        let decision = proxima::RecordingEvent {
            id: proxima::InteractionId::new(),
            ts_ms: 1,
            parent: None,
            event: proxima::ProtocolEvent::Custom {
                kind: "blackhole.dns_decision".into(),
                payload: serde_json::json!({"action":"reject","qtype":1,"qclass":1}),
            },
        };
        let incident = proxima::RecordingEvent {
            id: proxima::InteractionId::new(),
            ts_ms: 2,
            parent: None,
            event: proxima::ProtocolEvent::Custom {
                kind: "blackhole.ddos_incident".into(),
                payload: serde_json::json!({"client":"192.0.2.1","cause":"rate_limit"}),
            },
        };
        let mut actions = BTreeMap::new();
        let mut incidents = 0;
        let mut events = 0;
        count_replay_event(&decision, &mut actions, &mut incidents, &mut events)
            .expect("decision event");
        count_replay_event(&incident, &mut actions, &mut incidents, &mut events)
            .expect("incident event");
        assert_eq!(events, 2);
        assert_eq!(actions.get("reject"), Some(&1));
        assert_eq!(incidents, 1);
    }

    #[test]
    fn startup_restores_active_incident_from_proxima_jsonl() {
        let directory = temporary_path("restore");
        std::fs::create_dir(&directory).expect("temporary directory");
        let path = directory.join("incidents.jsonl");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_millis() as u64;
        let event = proxima::RecordingEvent {
            id: proxima::InteractionId::new(),
            ts_ms: now_ms,
            parent: None,
            event: proxima::ProtocolEvent::Custom {
                kind: "blackhole.ddos_incident".into(),
                payload: serde_json::json!({
                    "client":"192.0.2.10",
                    "cause":"client_rate_overflow",
                    "response":"temporary_blacklist",
                    "expires_at_ms":now_ms + 60_000,
                }),
            },
        };
        let mut line =
            proxima::recording::jsonl::encode_jsonl_line(event).expect("encode incident event");
        line.push(b'\n');
        std::fs::write(&path, line).expect("write incident recording");
        let policy = Policy::new(Config::default()).expect("valid default policy");
        let restored = futures::executor::block_on(restore_persisted_abuse(&policy, &path, 4_096))
            .expect("restore incident recording");
        assert_eq!(restored, 1);
        std::fs::remove_dir_all(directory).expect("remove temporary directory");
    }
}

#[cfg(feature = "std")]
struct BoxedTlsUpstream {
    inner: TlsStreamUpstream<PrimeTcpUpstream>,
}

#[cfg(feature = "std")]
impl StreamUpstream for BoxedTlsUpstream {
    type Conn = Box<dyn StreamConnection>;

    fn poll_connect(&self, cx: &mut Context<'_>) -> Poll<io::Result<Self::Conn>> {
        match self.inner.poll_connect(cx) {
            Poll::Ready(Ok(connection)) => Poll::Ready(Ok(Box::new(connection))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(target_os = "linux")]
struct CaptureGuard {
    controller: CaptureController<NftCommandBackend, FileOwnershipStore>,
    plan: NftRulePlan,
}

#[cfg(target_os = "macos")]
struct CaptureGuard {
    controller: CaptureController<PfctlCommandBackend, FileOwnershipStore>,
    plan: PfRulePlan,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl CaptureGuard {
    fn cleanup(&mut self) -> Result<(), ProximaError> {
        self.controller
            .cleanup(&self.plan)
            .map_err(|error| ProximaError::Config(format!("capture cleanup failed: {error}")))
    }
}

#[cfg(feature = "std")]
struct AnyHandler;

#[cfg(feature = "std")]
struct BlocklistReloadHandler {
    policy: Arc<Policy>,
}

#[cfg(feature = "std")]
struct CountryReloadHandler {
    policy: Arc<Policy>,
}

#[cfg(feature = "std")]
struct ConfigReloadHandler {
    policy: Arc<Policy>,
    path: PathBuf,
}

#[cfg(feature = "std")]
impl SendPipe for CountryReloadHandler {
    type In = PipeRequest<Bytes>;
    type Out = PipeResponse<Bytes>;
    type Err = ProximaError;

    async fn call(&self, _request: Self::In) -> Result<Self::Out, Self::Err> {
        match self.policy.reload_country_policy_if_changed() {
            Ok(_) => Ok(PipeResponse::ok(Bytes::new())),
            Err(error) => Err(ProximaError::Config(format!(
                "background country-map reload failed: {error}"
            ))),
        }
    }
}

#[cfg(feature = "std")]
impl SendPipe for ConfigReloadHandler {
    type In = PipeRequest<Bytes>;
    type Out = PipeResponse<Bytes>;
    type Err = ProximaError;

    async fn call(&self, _request: Self::In) -> Result<Self::Out, Self::Err> {
        let mut config = Config::from_file(&self.path).map_err(|error| {
            ProximaError::Config(format!(
                "background configuration reload cannot load {}: {error}",
                self.path.display()
            ))
        })?;
        apply_environment_overrides(&mut config)?;
        self.policy.reload_config(&config).map_err(|error| {
            ProximaError::Config(format!("background configuration reload failed: {error}"))
        })?;
        Ok(PipeResponse::ok(Bytes::new()))
    }
}

#[cfg(feature = "std")]
impl SendPipe for BlocklistReloadHandler {
    type In = PipeRequest<Bytes>;
    type Out = PipeResponse<Bytes>;
    type Err = ProximaError;

    async fn call(&self, _request: Self::In) -> Result<Self::Out, Self::Err> {
        match self.policy.reload_blocklists_if_changed() {
            Ok(_) => Ok(PipeResponse::ok(Bytes::new())),
            Err(error) => Err(ProximaError::Config(format!(
                "background blocklist reload failed: {error}"
            ))),
        }
    }
}

fn admin_endpoint(
    config: &blackhole::AdminConfig,
) -> Result<Option<(SocketAddr, String)>, ProximaError> {
    match (&config.listen, &config.token) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(ProximaError::Config(
            "admin.token requires admin.listen".into(),
        )),
        (Some(_), None) => Err(ProximaError::Config(
            "admin.listen requires admin.token".into(),
        )),
        (Some(listen), Some(token)) => {
            let bind = listen
                .parse()
                .map_err(|error| ProximaError::Config(format!("invalid admin.listen: {error}")))?;
            validate_bind(bind)?;
            Ok(Some((bind, token.clone())))
        }
    }
}

#[cfg(feature = "std")]
fn apply_environment_overrides(config: &mut Config) -> Result<(), ProximaError> {
    config.admission.ddos = config_builder()
        .value(config.admission.ddos.clone())
        .env_with_prefix("BLACKHOLE_DDOS")
        .build()
        .map_err(|error| {
            ProximaError::Config(format!("invalid BLACKHOLE_DDOS settings: {error}"))
        })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<(), ProximaError> {
    if !config.enabled {
        return Ok(());
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    NftRulePlan::for_destination(
        &config.chain,
        original_destination,
        config.inbound_port,
        listen_port,
        config.mark,
    )
    .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if !config.enabled {
        return Ok(None);
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    let plan = NftRulePlan::for_destination(
        &config.chain,
        original_destination,
        config.inbound_port,
        listen_port,
        config.mark,
    )
    .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    let store = FileOwnershipStore::new(&config.ownership_path);
    let mut controller = CaptureController::with_store(NftCommandBackend::default(), store);
    controller
        .recover(&plan)
        .map_err(|error| ProximaError::Config(format!("capture recovery failed: {error}")))?;
    controller
        .install(&plan)
        .map_err(|error| ProximaError::Config(format!("capture install failed: {error}")))?;
    Ok(Some(CaptureGuard { controller, plan }))
}

#[cfg(target_os = "macos")]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<(), ProximaError> {
    if !config.enabled {
        return Ok(());
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    PfRulePlan::new(&config.chain, original_destination, listen_port)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_capture(
    config: &blackhole::CaptureConfig,
    listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if !config.enabled {
        return Ok(None);
    }
    let original_destination = config.original_destination.parse().map_err(|error| {
        ProximaError::Config(format!("invalid capture original_destination: {error}"))
    })?;
    let plan = PfRulePlan::new(&config.chain, original_destination, listen_port)
        .map_err(|error| ProximaError::Config(format!("invalid capture plan: {error}")))?;
    let store = FileOwnershipStore::new(&config.ownership_path);
    let mut controller = CaptureController::with_store(PfctlCommandBackend::default(), store);
    controller
        .recover(&plan)
        .map_err(|error| ProximaError::Config(format!("capture recovery failed: {error}")))?;
    controller
        .install(&plan)
        .map_err(|error| ProximaError::Config(format!("capture install failed: {error}")))?;
    Ok(Some(CaptureGuard { controller, plan }))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn validate_capture(
    config: &blackhole::CaptureConfig,
    _listen_port: u16,
) -> Result<(), ProximaError> {
    if config.enabled {
        Err(ProximaError::Config(
            "capture is unsupported on this platform".into(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
struct CaptureGuard;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl CaptureGuard {
    fn cleanup(&mut self) -> Result<(), ProximaError> {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn install_capture(
    config: &blackhole::CaptureConfig,
    _listen_port: u16,
) -> Result<Option<CaptureGuard>, ProximaError> {
    if config.enabled {
        Err(ProximaError::Config(
            "capture is unsupported on this platform".into(),
        ))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "std")]
impl SendPipe for AnyHandler {
    type In = Request<Bytes>;
    type Out = Response<Bytes>;
    type Err = ProximaError;

    async fn call(&self, request: Self::In) -> Result<Self::Out, Self::Err> {
        Ok(Response::ok(request.payload))
    }
}

#[cfg(feature = "std")]
#[proxima::main]
async fn main() -> Result<(), ProximaError> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if let [flag, path] = arguments.as_slice()
        && flag == "--delete-recording"
    {
        let removed = delete_query_recording(Path::new(path))?;
        println!("{{\"status\":\"deleted\",\"files\":{removed}}}");
        return Ok(());
    }
    let (check_only, explicit_config_path, replay_path) = match arguments.as_slice() {
        [] => (false, None, None),
        [flag] if flag == "--check" => (true, None, None),
        [flag, path] if flag == "--check" => (true, Some(path.as_str()), None),
        [flag, path] if flag == "--replay" => (false, None, Some(path.as_str())),
        [path] => (false, Some(path.as_str()), None),
        _ => {
            return Err(ProximaError::Config(
                "usage: blackhole [--check] [config.toml] | --replay recording.jsonl".into(),
            ));
        }
    };
    if let Some(replay_path) = replay_path {
        return replay_metadata(Path::new(replay_path)).await;
    }
    let config_file_path = explicit_config_path.map(PathBuf::from);
    let mut config = if let Some(config_path) = config_file_path.as_deref() {
        Config::from_file(config_path).map_err(|error| {
            ProximaError::Config(format!("cannot load {}: {error}", config_path.display()))
        })?
    } else {
        Config::default()
    };
    apply_environment_overrides(&mut config)?;
    let bind: SocketAddr = config
        .server
        .listen
        .parse()
        .map_err(|error| ProximaError::Config(format!("invalid server.listen: {error}")))?;
    let admin_endpoint = admin_endpoint(&config.admin)?;
    if check_only {
        validate_capture(&config.capture, bind.port())?;
        let policy =
            Arc::new(Policy::new(config).map_err(|error| {
                ProximaError::Config(format!("invalid configuration: {error}"))
            })?);
        if let Some((_, token)) = admin_endpoint {
            authenticated_handle(policy, token)?;
        }
        println!("configuration valid (listener bind: {bind})");
        return Ok(());
    }
    let capture_config = config.capture.clone();
    let dhcp_config = config.dhcp.clone();
    let blocklist_reload_interval = config.policy.blocklist_reload_interval_secs;
    let blocklist_reload_enabled =
        blocklist_reload_interval != 0 && !config.policy.blocklists.is_empty();
    let country_reload_interval = config.country_policy.reload_interval_secs;
    let country_reload_enabled =
        country_reload_interval != 0 && config.country_policy.map_path.is_some();
    let config_reload_interval = config.reload_interval_secs;
    let config_reload_enabled = config_reload_interval != 0 && config_file_path.is_some();
    let query_recording_path = config.privacy.query_recording_path.clone();
    let query_recording_max_bytes = config.privacy.query_recording_max_bytes;
    let query_recording_rotation_enabled = config.privacy.query_recording_rotation_enabled;
    let query_recording_max_files = config.privacy.query_recording_max_files;
    let persist_ddos_incidents = config.admission.ddos.persist_incidents;
    if let Some(path) = query_recording_path.as_deref() {
        validate_query_recording_path(path)?;
        if query_recording_rotation_enabled {
            rotate_query_recording(
                Path::new(path),
                query_recording_max_bytes,
                query_recording_max_files,
            )?;
        }
    }
    let mut capture = install_capture(&capture_config, bind.port())?;
    let upstream = config.upstream.clone();
    let mut policy = Policy::new(config)
        .map_err(|error| ProximaError::Config(format!("invalid policy rule: {error}")))?;
    if persist_ddos_incidents && let Some(path) = query_recording_path.as_deref() {
        let restored =
            restore_persisted_abuse(&policy, Path::new(path), query_recording_max_bytes).await?;
        if restored != 0 {
            println!("blackhole restored {restored} active DDoS incident(s)");
        }
    }
    if let Some(upstream) = upstream {
        let resolver = Policy::resolver_config(&upstream);
        let resolver_addr = SocketAddr::new(
            upstream.resolver_ip.parse().map_err(|error| {
                ProximaError::Config(format!("invalid upstream resolver address: {error}"))
            })?,
            upstream.port,
        );
        policy = policy.with_upstream(
            Arc::new(PrimeDatagramFactory),
            resolver,
            upstream.max_outstanding,
        );
        if matches!(upstream.transport, UpstreamTransport::Doh) {
            let server_name = upstream.tls_server_name.clone().ok_or_else(|| {
                ProximaError::Config("tls_server_name is required for DoH upstreams".into())
            })?;
            let tls = TlsStreamUpstream::with_webpki_roots(
                PrimeTcpUpstream::new(resolver_addr),
                server_name.clone(),
            )
            .map_err(|error| ProximaError::Config(format!("invalid DoH TLS upstream: {error}")))?;
            let http = H1ClientUpstream::new(tls, server_name, "blackhole.doh");
            policy = policy.with_doh_upstream(into_handle(http));
        } else {
            let tcp_upstream: Arc<dyn StreamUpstream<Conn = Box<dyn StreamConnection>>> =
                match upstream.transport {
                    UpstreamTransport::Udp | UpstreamTransport::Tcp => {
                        PrimeTcpUpstream::boxed(resolver_addr)
                    }
                    UpstreamTransport::Tls => {
                        let server_name = upstream.tls_server_name.ok_or_else(|| {
                            ProximaError::Config(
                                "tls_server_name is required for TLS upstreams".into(),
                            )
                        })?;
                        let tls_config = TlsClientConfig {
                            server_name,
                            // DNS-over-TLS does not require an HTTP ALPN token.
                            alpn_protocols: Vec::new(),
                        };
                        let tls = TlsStreamUpstream::from_config(
                            PrimeTcpUpstream::new(resolver_addr),
                            &tls_config,
                        )
                        .map_err(|error| {
                            ProximaError::Config(format!("invalid TLS upstream: {error}"))
                        })?;
                        Arc::new(BoxedTlsUpstream { inner: tls })
                    }
                    UpstreamTransport::Doq => {
                        #[cfg(feature = "doq")]
                        {
                            let server_name = upstream.tls_server_name.ok_or_else(|| {
                                ProximaError::Config(
                                    "tls_server_name is required for DoQ upstreams".into(),
                                )
                            })?;
                            let tls = doq_tls_config()?;
                            Arc::new(
                                QuicUpstream::with_client_config(resolver_addr, server_name, tls)
                                    .map_err(|error| {
                                    ProximaError::Config(format!("invalid DoQ upstream: {error}"))
                                })?,
                            )
                        }
                        #[cfg(not(feature = "doq"))]
                        {
                            return Err(ProximaError::Config(
                                "DoQ upstreams require the `doq` feature".into(),
                            ));
                        }
                    }
                    UpstreamTransport::Doh => unreachable!("DoH handled above"),
                };
            policy = policy.with_tcp_upstream(tcp_upstream);
            if !matches!(upstream.transport, UpstreamTransport::Udp) {
                policy = policy.with_tcp_only();
            }
        }
    }
    if let Some(path) = query_recording_path {
        let spigot = deferred_runtime();
        let durable = Arc::new(LazyFanOut::new(
            vec![SinkSpec::new(path.clone(), FormatKind::Json)],
            Arc::clone(&spigot),
        ));
        spigot
            .set(Arc::new(PrimeRuntime::new(1).map_err(|error| {
                ProximaError::Config(format!("cannot start recording runtime: {error}"))
            })?))
            .map_err(|_| ProximaError::Config("recording runtime already initialized".into()))?;
        let buffered = Arc::new(AccumulatingSink::new(durable, 32));
        let bounded =
            BoundedQueryRecordingSink::new(buffered, Path::new(&path), query_recording_max_bytes)
                .map_err(|error| ProximaError::Config(error.to_string()))?;
        policy = policy.with_recording_sink(Arc::new(bounded));
        println!("blackhole query recording enabled ({path})");
    }
    let policy = Arc::new(policy);
    let dhcp_server = if dhcp_config.enabled {
        println!("blackhole DHCP listening on {}", dhcp_config.listen);
        Some(
            blackhole::dhcp::Server::start(dhcp_config).map_err(|error| {
                ProximaError::Config(format!("cannot start DHCP listener: {error}"))
            })?,
        )
    } else {
        None
    };
    let admin_server = if let Some((admin_bind, token)) = admin_endpoint {
        let handle = authenticated_handle(Arc::clone(&policy), token)?;
        let server = match Listener::http(admin_bind).handle(handle).serve().await {
            Ok(server) => server,
            Err(error) => {
                if let Some(capture) = capture.as_mut() {
                    let _ = capture.cleanup();
                }
                return Err(error);
            }
        };
        println!("blackhole admin listening on {admin_bind} (HTTP bearer auth)");
        Some(server)
    } else {
        None
    };
    let mut source_lifecycle = ProducerLifecycle::new();
    if blocklist_reload_enabled {
        let reload_handler = into_pipe_handle(BlocklistReloadHandler {
            policy: Arc::clone(&policy),
        });
        let reload_source = into_source_handle(IntervalPipe::new(
            std::time::Duration::from_secs(blocklist_reload_interval),
            reload_handler,
            IntervalPipe::empty_request_factory(),
            "blackhole-blocklist-reload",
        ));
        source_lifecycle.spawn_from_source("blocklist-reload", &reload_source);
        println!(
            "blackhole blocklist reload enabled ({}s)",
            blocklist_reload_interval
        );
    }
    if country_reload_enabled {
        let reload_handler = into_pipe_handle(CountryReloadHandler {
            policy: Arc::clone(&policy),
        });
        let reload_source = into_source_handle(IntervalPipe::new(
            std::time::Duration::from_secs(country_reload_interval),
            reload_handler,
            IntervalPipe::empty_request_factory(),
            "blackhole-country-reload",
        ));
        source_lifecycle.spawn_from_source("country-reload", &reload_source);
        println!(
            "blackhole country-map reload enabled ({}s)",
            country_reload_interval
        );
    }
    if config_reload_enabled {
        let reload_handler = into_pipe_handle(ConfigReloadHandler {
            policy: Arc::clone(&policy),
            path: config_file_path
                .clone()
                .expect("configuration reload path is present"),
        });
        let reload_source = into_source_handle(IntervalPipe::new(
            std::time::Duration::from_secs(config_reload_interval),
            reload_handler,
            IntervalPipe::empty_request_factory(),
            "blackhole-config-reload",
        ));
        source_lifecycle.spawn_from_source("config-reload", &reload_source);
        println!(
            "blackhole configuration reload enabled ({}s)",
            config_reload_interval
        );
    }
    let server = match Listener::builder()
        .bind(bind)
        .any()
        .protocol(UdpProtocol::new(Arc::clone(&policy)))
        .protocol(TcpProtocol::new(Arc::clone(&policy)))
        .handle(into_handle(AnyHandler))
        .serve()
        .await
    {
        Ok(server) => server,
        Err(error) => {
            if let Some(admin_server) = admin_server {
                admin_server.stop();
            }
            source_lifecycle
                .shutdown(std::time::Duration::from_secs(2))
                .await;
            if let Some(capture) = capture.as_mut() {
                let _ = capture.cleanup();
            }
            if let Some(server) = dhcp_server {
                let _ = server.shutdown();
            }
            return Err(error);
        }
    };
    println!("blackhole listening on {bind} (UDP+TCP DNS)");
    if let Some(admin_server) = admin_server {
        futures::future::join(server.run_until_signal(), admin_server.run_until_signal()).await;
    } else {
        server.run_until_signal().await;
    }
    source_lifecycle
        .shutdown(std::time::Duration::from_secs(2))
        .await;
    if let Some(server) = dhcp_server {
        server.shutdown().map_err(|error| {
            ProximaError::Config(format!("DHCP listener shutdown failed: {error}"))
        })?;
    }
    if let Some(capture) = capture.as_mut() {
        capture.cleanup()?;
    }
    Ok(())
}
