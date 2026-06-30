use std::env;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bollard::query_parameters::{
    PruneBuildOptions, PruneContainersOptions, PruneImagesOptions, PruneVolumesOptions,
};
use bollard::{API_DEFAULT_VERSION, Docker};
use serde::{Deserialize, Serialize};

use cleanton_common::{CleantonError, Result};

#[derive(Debug, Clone)]
pub struct DockerCleaner {
    endpoints: Vec<DockerEndpoint>,
    checked_socket_candidates: Vec<DockerSocketCandidate>,
    docker_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub id: String,
    pub tags: Vec<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub size: u64,
    pub age_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCacheInfo {
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerAnalysis {
    pub dangling_images: Vec<ImageInfo>,
    pub stopped_containers: Vec<ContainerInfo>,
    pub unused_volumes: Vec<VolumeInfo>,
    pub build_cache: BuildCacheInfo,
    pub total_reclaimable: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerCleanupPlan {
    pub clean_dangling_images: bool,
    pub clean_stopped_containers: bool,
    pub clean_unused_volumes: bool,
    pub clean_build_cache: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerCleanupResult {
    pub images_freed: u64,
    pub containers_freed: u64,
    pub volumes_freed: u64,
    pub build_cache_freed: u64,
    pub total_freed: u64,
}

const DOCKER_TIMEOUT_SECONDS: u64 = 5;
/// Overall per-request bound for Docker calls, so a stale `DOCKER_HOST` or an
/// unresponsive daemon can't stall a command for bollard's 120s default.
const DOCKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(DOCKER_TIMEOUT_SECONDS);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DockerRuntimeKind {
    DockerHost,
    DockerDesktop,
    OrbStack,
    Colima,
    Podman,
}

impl DockerRuntimeKind {
    const fn label(self) -> &'static str {
        match self {
            Self::DockerHost => "DOCKER_HOST",
            Self::DockerDesktop => "Docker Desktop",
            Self::OrbStack => "OrbStack",
            Self::Colima => "Colima",
            Self::Podman => "Podman",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerSocketCandidate {
    kind: DockerRuntimeKind,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerEndpoint {
    kind: DockerRuntimeKind,
    connection: DockerConnection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DockerConnection {
    Host(String),
    UnixSocket(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerRuntimeDiscovery {
    endpoints: Vec<DockerEndpoint>,
    checked_socket_candidates: Vec<DockerSocketCandidate>,
    docker_host: Option<String>,
}

impl DockerCleaner {
    pub fn new() -> Result<Self> {
        let discovery = docker_runtime_discovery();
        Ok(Self {
            endpoints: discovery.endpoints,
            checked_socket_candidates: discovery.checked_socket_candidates,
            docker_host: discovery.docker_host,
        })
    }

    /// List all cleanable Docker resources
    pub async fn analyze(&self) -> Result<DockerAnalysis> {
        let Some(df_info) = self.first_reachable_df().await else {
            // Docker accounting is VM-internal. If no compatible runtime is reachable, report no
            // reclaimable Docker VM space instead of failing the broader analysis.
            return Ok(empty_analysis());
        };

        let dangling_images = dangling_images(&df_info);
        let stopped_containers = stopped_containers(&df_info);
        let unused_volumes = unused_volumes(&df_info);
        let build_cache = BuildCacheInfo {
            size: build_cache_size(&df_info),
        };
        let total_reclaimable = dangling_images.iter().map(|i| i.size).sum::<u64>()
            + stopped_containers.iter().map(|c| c.size).sum::<u64>()
            + unused_volumes.iter().map(|v| v.size).sum::<u64>()
            + build_cache.size;

        Ok(DockerAnalysis {
            dangling_images,
            stopped_containers,
            unused_volumes,
            build_cache,
            total_reclaimable,
        })
    }

    /// Execute Docker cleanup
    pub async fn clean(&self, plan: DockerCleanupPlan) -> Result<DockerCleanupResult> {
        if !docker_plan_has_actions(&plan) {
            return Ok(DockerCleanupResult {
                images_freed: 0,
                containers_freed: 0,
                volumes_freed: 0,
                build_cache_freed: 0,
                total_freed: 0,
            });
        }

        let client = self.first_reachable_client().await?;
        let mut result = DockerCleanupResult {
            images_freed: 0,
            containers_freed: 0,
            volumes_freed: 0,
            build_cache_freed: 0,
            total_freed: 0,
        };

        if plan.clean_stopped_containers
            && let Ok(res) = client
                .prune_containers(None::<PruneContainersOptions>)
                .await
        {
            result.containers_freed = nonnegative_i64_to_u64(res.space_reclaimed.unwrap_or(0));
        }

        if plan.clean_dangling_images
            && let Ok(res) = client.prune_images(None::<PruneImagesOptions>).await
        {
            result.images_freed = nonnegative_i64_to_u64(res.space_reclaimed.unwrap_or(0));
        }

        if plan.clean_unused_volumes
            && let Ok(res) = client.prune_volumes(None::<PruneVolumesOptions>).await
        {
            result.volumes_freed = nonnegative_i64_to_u64(res.space_reclaimed.unwrap_or(0));
        }

        if plan.clean_build_cache
            && let Ok(res) = client.prune_build(None::<PruneBuildOptions>).await
        {
            result.build_cache_freed = nonnegative_i64_to_u64(res.space_reclaimed.unwrap_or(0));
        }

        result.total_freed = result.images_freed
            + result.containers_freed
            + result.volumes_freed
            + result.build_cache_freed;

        Ok(result)
    }

    /// Fetch `/system/df` from the first reachable endpoint.
    ///
    /// We deliberately bypass bollard's typed `Docker::df` here: its
    /// `SystemDataUsageResponse` expects the `*DiskUsage` JSON keys
    /// (`ImagesDiskUsage`/`BuildCacheDiskUsage`/...), but real daemons return the
    /// stable flat keys (`Images`/`Containers`/`Volumes`/`BuildCache`). Those flat
    /// keys are version-independent (>= API 1.40), so we parse them ourselves and
    /// avoid the silent all-`None` (zeroed) deserialization. bollard is still used
    /// for ping (`first_reachable_client`) and the prune/`clean` path.
    async fn first_reachable_df(&self) -> Option<SystemDf> {
        for endpoint in &self.endpoints {
            if let Ok(df) = fetch_system_df(&endpoint.connection).await {
                return Some(df);
            }
        }
        None
    }

    async fn first_reachable_client(&self) -> Result<Docker> {
        let mut failures = Vec::new();
        for endpoint in &self.endpoints {
            let client = match endpoint.connect() {
                Ok(client) => client,
                Err(err) => {
                    failures.push(format!("{}: {err}", endpoint.description()));
                    continue;
                }
            };

            match tokio::time::timeout(DOCKER_REQUEST_TIMEOUT, client.ping()).await {
                Ok(Ok(_)) => return Ok(client),
                Ok(Err(err)) => failures.push(format!("{}: {err}", endpoint.description())),
                Err(_) => failures.push(format!(
                    "{}: timed out after {}s",
                    endpoint.description(),
                    DOCKER_REQUEST_TIMEOUT.as_secs()
                )),
            }
        }

        Err(CleantonError::Scan(
            self.connection_failure_message(&failures),
        ))
    }

    fn connection_failure_message(&self, failures: &[String]) -> String {
        let mut message = String::from("no reachable Docker-compatible runtime found");

        if let Some(docker_host) = &self.docker_host {
            // Writing to a `String` is infallible; ignore the always-`Ok` result
            // rather than `.expect()` (no panic path) per the deleter no-panic policy.
            let _ = write!(&mut message, " using DOCKER_HOST={docker_host:?}");
        } else if self.checked_socket_candidates.is_empty() {
            message.push_str("; no local socket candidates were available");
        } else {
            let checked = self
                .checked_socket_candidates
                .iter()
                .map(DockerSocketCandidate::description)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = write!(&mut message, "; checked local sockets: {checked}");
        }

        if !failures.is_empty() {
            message.push_str("; failures: ");
            message.push_str(&failures.join("; "));
        }

        if self.docker_host.is_none() {
            message.push_str("; set DOCKER_HOST to override runtime discovery");
        }

        message
    }
}

impl DockerSocketCandidate {
    fn endpoint(&self) -> DockerEndpoint {
        DockerEndpoint {
            kind: self.kind,
            connection: DockerConnection::UnixSocket(self.path.clone()),
        }
    }

    fn description(&self) -> String {
        format!("{} at {}", self.kind.label(), self.path.display())
    }
}

impl DockerEndpoint {
    fn docker_host(host: String) -> Self {
        Self {
            kind: DockerRuntimeKind::DockerHost,
            connection: DockerConnection::Host(host),
        }
    }

    fn connect(&self) -> std::result::Result<Docker, bollard::errors::Error> {
        match &self.connection {
            DockerConnection::Host(host) => Docker::connect_with_host(host),
            DockerConnection::UnixSocket(path) => {
                let socket_path = path.to_string_lossy();
                Docker::connect_with_unix(
                    socket_path.as_ref(),
                    DOCKER_TIMEOUT_SECONDS,
                    API_DEFAULT_VERSION,
                )
            }
        }
    }

    fn description(&self) -> String {
        match &self.connection {
            DockerConnection::Host(host) => format!("{} {host:?}", self.kind.label()),
            DockerConnection::UnixSocket(path) => {
                format!("{} at {}", self.kind.label(), path.display())
            }
        }
    }
}

fn docker_runtime_discovery() -> DockerRuntimeDiscovery {
    let docker_host = env::var("DOCKER_HOST").ok();
    let home = env::var_os("HOME").map(PathBuf::from);
    let xdg_runtime_dir = env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);

    docker_runtime_discovery_from(
        docker_host.as_deref(),
        home.as_deref(),
        xdg_runtime_dir.as_deref(),
    )
}

fn docker_runtime_discovery_from(
    docker_host: Option<&str>,
    home: Option<&Path>,
    xdg_runtime_dir: Option<&Path>,
) -> DockerRuntimeDiscovery {
    if let Some(docker_host) = docker_host.map(str::trim).filter(|host| !host.is_empty()) {
        return DockerRuntimeDiscovery {
            endpoints: vec![DockerEndpoint::docker_host(docker_host.to_owned())],
            checked_socket_candidates: Vec::new(),
            docker_host: Some(docker_host.to_owned()),
        };
    }

    let checked_socket_candidates = docker_socket_candidates(home, xdg_runtime_dir);
    let endpoints = discovered_socket_endpoints(&checked_socket_candidates);

    DockerRuntimeDiscovery {
        endpoints,
        checked_socket_candidates,
        docker_host: None,
    }
}

fn docker_socket_candidates(
    home: Option<&Path>,
    xdg_runtime_dir: Option<&Path>,
) -> Vec<DockerSocketCandidate> {
    let mut candidates = Vec::new();

    if let Some(home) = home {
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::DockerDesktop,
            path: home.join(".docker/run/docker.sock"),
        });
    }

    candidates.push(DockerSocketCandidate {
        kind: DockerRuntimeKind::DockerDesktop,
        path: PathBuf::from("/var/run/docker.sock"),
    });

    if let Some(home) = home {
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::OrbStack,
            path: home.join(".orbstack/run/docker.sock"),
        });
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::Colima,
            path: home.join(".colima/default/docker.sock"),
        });
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::Podman,
            path: home
                .join(".local/share/containers/podman/machine/podman-machine-default/podman.sock"),
        });
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::Podman,
            path: home.join(".local/share/containers/podman/machine/qemu/podman.sock"),
        });
    }

    if let Some(xdg_runtime_dir) = xdg_runtime_dir {
        candidates.push(DockerSocketCandidate {
            kind: DockerRuntimeKind::Podman,
            path: xdg_runtime_dir.join("podman/podman.sock"),
        });
    }

    candidates
}

fn discovered_socket_endpoints(candidates: &[DockerSocketCandidate]) -> Vec<DockerEndpoint> {
    candidates
        .iter()
        .filter(|candidate| is_unix_socket(&candidate.path))
        .map(DockerSocketCandidate::endpoint)
        .collect()
}

#[cfg(unix)]
fn is_unix_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(not(unix))]
fn is_unix_socket(_path: &Path) -> bool {
    false
}

fn docker_plan_has_actions(plan: &DockerCleanupPlan) -> bool {
    plan.clean_dangling_images
        || plan.clean_stopped_containers
        || plan.clean_unused_volumes
        || plan.clean_build_cache
}

fn empty_analysis() -> DockerAnalysis {
    DockerAnalysis {
        dangling_images: Vec::new(),
        stopped_containers: Vec::new(),
        unused_volumes: Vec::new(),
        build_cache: BuildCacheInfo { size: 0 },
        total_reclaimable: 0,
    }
}

/// Flat `/system/df` response as returned by the Docker daemon (API >= 1.40).
///
/// Only the fields we actually consume are bound; unknown keys are ignored by
/// serde, and every bound field is `#[serde(default)]`/`Option` so a slightly
/// different daemon version still parses without erroring.
#[derive(Debug, Default, Deserialize)]
struct SystemDf {
    #[serde(rename = "Images", default)]
    images: Vec<DfImage>,
    #[serde(rename = "Containers", default)]
    containers: Vec<DfContainer>,
    #[serde(rename = "Volumes", default)]
    volumes: Vec<DfVolume>,
    #[serde(rename = "BuildCache", default)]
    build_cache: Vec<DfBuildCache>,
}

#[derive(Debug, Deserialize)]
struct DfImage {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Size", default)]
    size: i64,
}

#[derive(Debug, Deserialize)]
struct DfContainer {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Option<Vec<String>>,
    #[serde(rename = "State", default)]
    state: Option<String>,
    #[serde(rename = "Created", default)]
    created: Option<i64>,
    #[serde(rename = "SizeRw", default)]
    size_rw: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct DfVolume {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "UsageData", default)]
    usage_data: Option<DfVolumeUsage>,
}

#[derive(Debug, Deserialize)]
struct DfVolumeUsage {
    #[serde(rename = "Size", default)]
    size: i64,
    #[serde(rename = "RefCount", default)]
    ref_count: i64,
}

#[derive(Debug, Deserialize)]
struct DfBuildCache {
    #[serde(rename = "Size", default)]
    size: i64,
    #[serde(rename = "InUse", default)]
    in_use: Option<bool>,
    #[serde(rename = "Shared", default)]
    shared: Option<bool>,
}

/// Resolved transport target for a raw `/system/df` fetch.
enum StreamTarget {
    Unix(PathBuf),
    Tcp(String),
}

/// Fetch and parse `/system/df` over the given connection, bounded by
/// `DOCKER_REQUEST_TIMEOUT`. Never panics; unsupported transports
/// (e.g. `ssh://`) and any IO/parse failure surface as `Err` so the caller can
/// degrade gracefully.
async fn fetch_system_df(connection: &DockerConnection) -> Result<SystemDf> {
    let body = match tokio::time::timeout(DOCKER_REQUEST_TIMEOUT, fetch_system_df_body(connection))
        .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(CleantonError::Scan(format!(
                "Docker /system/df request timed out after {}s",
                DOCKER_REQUEST_TIMEOUT.as_secs()
            )));
        }
    };

    serde_json::from_slice::<SystemDf>(&body)
        .map_err(|err| CleantonError::Scan(format!("failed to parse Docker /system/df: {err}")))
}

/// Connect to the daemon and return the (already de-chunked) HTTP response body.
async fn fetch_system_df_body(connection: &DockerConnection) -> Result<Vec<u8>> {
    match stream_target(connection)? {
        StreamTarget::Unix(path) => {
            let stream = tokio::net::UnixStream::connect(&path)
                .await
                .map_err(|err| {
                    CleantonError::Scan(format!(
                        "failed to connect to Docker socket {}: {err}",
                        path.display()
                    ))
                })?;
            http_get_system_df(stream).await
        }
        StreamTarget::Tcp(addr) => {
            let stream = tokio::net::TcpStream::connect(&addr).await.map_err(|err| {
                CleantonError::Scan(format!("failed to connect to Docker at {addr}: {err}"))
            })?;
            http_get_system_df(stream).await
        }
    }
}

/// Map a `DockerConnection` to a concrete transport. Supports unix sockets
/// (`UnixSocket(path)` and `unix://` hosts) and TCP (`tcp://`/`http://` hosts).
/// `ssh://` and anything else are rejected without panicking.
fn stream_target(connection: &DockerConnection) -> Result<StreamTarget> {
    match connection {
        DockerConnection::UnixSocket(path) => Ok(StreamTarget::Unix(path.clone())),
        DockerConnection::Host(host) => host_stream_target(host),
    }
}

fn host_stream_target(host: &str) -> Result<StreamTarget> {
    let host = host.trim();
    if let Some(path) = host.strip_prefix("unix://") {
        return Ok(StreamTarget::Unix(PathBuf::from(path)));
    }
    if let Some(addr) = host
        .strip_prefix("tcp://")
        .or_else(|| host.strip_prefix("http://"))
    {
        let addr = addr.trim_end_matches('/');
        return Ok(StreamTarget::Tcp(addr.to_owned()));
    }
    Err(CleantonError::Scan(format!(
        "unsupported DOCKER_HOST {host:?} for raw /system/df fetch"
    )))
}

/// Issue an HTTP/1.1 `GET /v1.41/system/df` over `stream` and return the body.
///
/// Uses `Connection: close`, so reading to EOF yields the full response. Any
/// `Transfer-Encoding: chunked` body is decoded; otherwise the body is the bytes
/// after the header terminator. Non-2xx responses are errors.
async fn http_get_system_df<S>(mut stream: S) -> Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const REQUEST: &[u8] = b"GET /v1.41/system/df HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n";

    stream.write_all(REQUEST).await.map_err(|err| {
        CleantonError::Scan(format!("failed to send Docker /system/df request: {err}"))
    })?;
    stream.flush().await.map_err(|err| {
        CleantonError::Scan(format!("failed to flush Docker /system/df request: {err}"))
    })?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.map_err(|err| {
        CleantonError::Scan(format!("failed to read Docker /system/df response: {err}"))
    })?;

    parse_http_response(&raw)
}

/// Split an HTTP/1.1 response into status + body, validate the status, and
/// de-chunk the body when `Transfer-Encoding: chunked` is set.
fn parse_http_response(raw: &[u8]) -> Result<Vec<u8>> {
    let header_end = find_subsequence(raw, b"\r\n\r\n").ok_or_else(|| {
        CleantonError::Scan("malformed Docker HTTP response: no header terminator".to_owned())
    })?;
    let headers = raw
        .get(..header_end)
        .ok_or_else(|| CleantonError::Scan("malformed Docker HTTP response headers".to_owned()))?;
    let body = raw
        .get(header_end.saturating_add(4)..)
        .ok_or_else(|| CleantonError::Scan("malformed Docker HTTP response body".to_owned()))?;

    let header_text = String::from_utf8_lossy(headers);
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            CleantonError::Scan(format!(
                "malformed Docker HTTP status line: {status_line:?}"
            ))
        })?;
    if !(200..300).contains(&status_code) {
        return Err(CleantonError::Scan(format!(
            "Docker /system/df returned HTTP {status_code}"
        )));
    }

    if lines.any(header_is_chunked) {
        decode_chunked_body(body)
    } else {
        Ok(body.to_vec())
    }
}

fn header_is_chunked(line: &str) -> bool {
    line.split_once(':').is_some_and(|(name, value)| {
        name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    })
}

/// Decode an HTTP/1.1 chunked transfer body. Each chunk is a hex length line
/// (`<hex-len>[;ext]CRLF`), then exactly that many data bytes, then `CRLF`;
/// a zero-length chunk terminates the body. Uses `get()` throughout so a
/// truncated or malformed stream yields `Err` rather than panicking.
fn decode_chunked_body(mut body: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = find_subsequence(body, b"\r\n").ok_or_else(|| {
            CleantonError::Scan("malformed chunked Docker response: missing chunk size".to_owned())
        })?;
        // `line_end` is a valid in-bounds index found above, so `split_at` cannot panic.
        let (size_part, remainder) = body.split_at(line_end);
        let after_size_line = remainder.get(2..).ok_or_else(|| {
            CleantonError::Scan("malformed chunked Docker response: truncated size line".to_owned())
        })?;

        let size_text = std::str::from_utf8(size_part)
            .map_err(|err| CleantonError::Scan(format!("invalid chunk size encoding: {err}")))?;
        // Drop any chunk extension after ';'. `split` always yields >= 1 item.
        let size_hex = size_text.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|err| {
            CleantonError::Scan(format!("invalid chunk size {size_hex:?}: {err}"))
        })?;

        if chunk_size == 0 {
            break;
        }

        let chunk = after_size_line.get(..chunk_size).ok_or_else(|| {
            CleantonError::Scan(
                "malformed chunked Docker response: chunk longer than body".to_owned(),
            )
        })?;
        decoded.extend_from_slice(chunk);

        // Skip the chunk's trailing CRLF before the next size line.
        body = after_size_line
            .get(chunk_size.saturating_add(2)..)
            .ok_or_else(|| {
                CleantonError::Scan(
                    "malformed chunked Docker response: missing chunk terminator".to_owned(),
                )
            })?;
    }
    Ok(decoded)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn dangling_images(df: &SystemDf) -> Vec<ImageInfo> {
    df.images
        .iter()
        .filter(|image| is_dangling_image(image.repo_tags.as_deref()))
        .map(|image| ImageInfo {
            id: image.id.clone(),
            tags: image.repo_tags.clone().unwrap_or_default(),
            size: nonnegative_i64_to_u64(image.size),
        })
        .collect()
}

fn is_dangling_image(tags: Option<&[String]>) -> bool {
    // Missing or empty RepoTags, or the untagged `<none>` placeholder => dangling.
    tags.is_none_or(|tags| {
        tags.is_empty() || tags.iter().any(|t| t == "<none>:<none>" || t == "<none>")
    })
}

fn stopped_containers(df: &SystemDf) -> Vec<ContainerInfo> {
    df.containers
        .iter()
        .filter_map(stopped_container_info)
        .collect()
}

fn stopped_container_info(container: &DfContainer) -> Option<ContainerInfo> {
    // Missing State is treated as stopped (anything that is not "running").
    let state = container.state.clone().unwrap_or_default();
    if state == "running" {
        return None;
    }

    Some(ContainerInfo {
        id: container.id.clone(),
        name: container
            .names
            .as_ref()
            .and_then(|names| names.first().cloned())
            .unwrap_or_default(),
        state,
        size: nonnegative_i64_to_u64(container.size_rw.unwrap_or(0)),
        age_days: container_age_days(container.created),
    })
}

fn container_age_days(created: Option<i64>) -> u64 {
    created.map_or(0, |created| {
        let now = chrono::Utc::now().timestamp();
        let diff_secs = now.saturating_sub(created);
        nonnegative_i64_to_u64(diff_secs / (24 * 3600))
    })
}

fn unused_volumes(df: &SystemDf) -> Vec<VolumeInfo> {
    df.volumes.iter().filter_map(unused_volume_info).collect()
}

fn unused_volume_info(volume: &DfVolume) -> Option<VolumeInfo> {
    let ref_count = volume
        .usage_data
        .as_ref()
        .map_or(0, |usage| usage.ref_count);
    if ref_count > 0 {
        return None;
    }

    let size = volume.usage_data.as_ref().map_or(0, |usage| usage.size);
    Some(VolumeInfo {
        name: volume.name.clone(),
        size: nonnegative_i64_to_u64(size),
    })
}

fn build_cache_size(df: &SystemDf) -> u64 {
    // Reclaimable build cache only, matching `docker system df`'s RECLAIMABLE
    // column: entries that are neither in use nor shared. (The previous code
    // summed ALL cache, which over-reports.) Shared layers are deduplicated
    // against image layers, so reclaiming them frees no additional space and is
    // excluded — summing `!InUse` alone would equal the SIZE column, not
    // RECLAIMABLE.
    df.build_cache
        .iter()
        .filter(|cache| cache.in_use != Some(true) && cache.shared != Some(true))
        .map(|cache| nonnegative_i64_to_u64(cache.size))
        .sum()
}

fn nonnegative_i64_to_u64(value: i64) -> u64 {
    value.max(0).cast_unsigned()
}

#[cfg(test)]
mod tests {
    // Test-only: fixed-shape fixtures make direct indexing into expected results clearer.
    #![allow(clippy::indexing_slicing)]
    use std::fs;
    use std::os::unix::net::UnixListener;

    use super::*;

    #[tokio::test]
    async fn analyze_returns_empty_when_no_runtime_candidates() {
        let cleaner = DockerCleaner {
            endpoints: Vec::new(),
            checked_socket_candidates: Vec::new(),
            docker_host: None,
        };

        let analysis = cleaner.analyze().await.unwrap();

        assert_eq!(analysis.total_reclaimable, 0);
        assert!(analysis.dangling_images.is_empty());
        assert!(analysis.stopped_containers.is_empty());
        assert!(analysis.unused_volumes.is_empty());
        assert_eq!(analysis.build_cache.size, 0);
    }

    #[test]
    fn docker_host_takes_precedence_over_socket_discovery() {
        let discovery = docker_runtime_discovery_from(
            Some(" unix:///custom/docker.sock "),
            Some(Path::new("/Users/tester")),
            Some(Path::new("/run/user/501")),
        );

        assert_eq!(
            discovery.docker_host.as_deref(),
            Some("unix:///custom/docker.sock")
        );
        assert!(discovery.checked_socket_candidates.is_empty());
        assert_eq!(
            discovery.endpoints,
            vec![DockerEndpoint::docker_host(
                "unix:///custom/docker.sock".to_owned()
            )]
        );
    }

    #[test]
    fn empty_docker_host_falls_back_to_socket_discovery() {
        let discovery =
            docker_runtime_discovery_from(Some(" "), Some(Path::new("/Users/tester")), None);

        assert!(discovery.docker_host.is_none());
        assert!(!discovery.checked_socket_candidates.is_empty());
    }

    #[test]
    fn socket_candidates_include_supported_macos_runtimes() {
        let candidates = docker_socket_candidates(
            Some(Path::new("/Users/tester")),
            Some(Path::new("/run/user/501")),
        );
        let paths = candidates
            .iter()
            .map(|candidate| (candidate.kind, candidate.path.as_path()))
            .collect::<Vec<_>>();

        assert_eq!(
            paths[0],
            (
                DockerRuntimeKind::DockerDesktop,
                Path::new("/Users/tester/.docker/run/docker.sock"),
            )
        );
        assert_eq!(
            paths[1],
            (
                DockerRuntimeKind::DockerDesktop,
                Path::new("/var/run/docker.sock"),
            )
        );
        assert!(paths.contains(&(
            DockerRuntimeKind::OrbStack,
            Path::new("/Users/tester/.orbstack/run/docker.sock"),
        )));
        assert!(paths.contains(&(
            DockerRuntimeKind::Colima,
            Path::new("/Users/tester/.colima/default/docker.sock"),
        )));
        assert!(paths.contains(&(
            DockerRuntimeKind::Podman,
            Path::new("/run/user/501/podman/podman.sock"),
        )));
    }

    #[test]
    fn parse_http_response_decodes_identity_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let body = parse_http_response(raw).unwrap();
        assert_eq!(body, b"{\"ok\":true}");
    }

    #[test]
    fn parse_http_response_decodes_chunked_body() {
        // "Wikipedia" classic chunked example, split across two data chunks.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n4\r\n:1}\n\r\n0\r\n\r\n";
        let body = parse_http_response(raw).unwrap();
        assert_eq!(body, b"{\"a\":1}\n");
    }

    #[test]
    fn parse_http_response_rejects_non_2xx() {
        let raw = b"HTTP/1.1 500 Internal Server Error\r\n\r\nboom";
        assert!(parse_http_response(raw).is_err());
    }

    #[test]
    fn host_stream_target_resolves_supported_transports() {
        assert!(matches!(
            host_stream_target("unix:///run/docker.sock").unwrap(),
            StreamTarget::Unix(path) if path == Path::new("/run/docker.sock")
        ));
        assert!(matches!(
            host_stream_target("tcp://127.0.0.1:2375").unwrap(),
            StreamTarget::Tcp(addr) if addr == "127.0.0.1:2375"
        ));
        assert!(matches!(
            host_stream_target("http://127.0.0.1:2375/").unwrap(),
            StreamTarget::Tcp(addr) if addr == "127.0.0.1:2375"
        ));
        assert!(host_stream_target("ssh://node").is_err());
    }

    #[test]
    fn flat_df_parses_into_expected_analysis() {
        let json = br#"{
            "LayersSize": 100,
            "Images": [
                {"Id":"sha256:a","RepoTags":["<none>:<none>"],"Size":10,"Containers":0},
                {"Id":"sha256:b","RepoTags":["ubuntu:22.04"],"Size":20,"Containers":1}
            ],
            "Containers": [
                {"Id":"c1","Names":["/run"],"State":"running","SizeRw":5},
                {"Id":"c2","Names":["/stop"],"State":"exited","SizeRw":7}
            ],
            "Volumes": [
                {"Name":"used","UsageData":{"Size":3,"RefCount":2}},
                {"Name":"free","UsageData":{"Size":4,"RefCount":0}}
            ],
            "BuildCache": [
                {"ID":"x","Size":1000,"InUse":false,"Shared":false},
                {"ID":"y","Size":2000,"InUse":false,"Shared":true},
                {"ID":"z","Size":4000,"InUse":true,"Shared":false}
            ]
        }"#;
        let df: SystemDf = serde_json::from_slice(json).unwrap();

        let images = dangling_images(&df);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].id, "sha256:a");
        assert_eq!(images[0].size, 10);

        let containers = stopped_containers(&df);
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "/stop");
        assert_eq!(containers[0].size, 7);

        let volumes = unused_volumes(&df);
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].name, "free");
        assert_eq!(volumes[0].size, 4);

        // Only the !InUse && !Shared entry counts (matches docker system df RECLAIMABLE).
        assert_eq!(build_cache_size(&df), 1000);
    }

    #[test]
    fn discovered_socket_endpoints_keep_existing_candidates_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing/docker.sock");
        let first_existing = temp.path().join("first/docker.sock");
        let second_existing = temp.path().join("second/docker.sock");
        fs::create_dir_all(first_existing.parent().unwrap()).unwrap();
        fs::create_dir_all(second_existing.parent().unwrap()).unwrap();
        let _first_socket = UnixListener::bind(&first_existing).unwrap();
        let _second_socket = UnixListener::bind(&second_existing).unwrap();

        let candidates = vec![
            DockerSocketCandidate {
                kind: DockerRuntimeKind::DockerDesktop,
                path: missing,
            },
            DockerSocketCandidate {
                kind: DockerRuntimeKind::OrbStack,
                path: first_existing.clone(),
            },
            DockerSocketCandidate {
                kind: DockerRuntimeKind::Colima,
                path: second_existing,
            },
        ];

        let endpoints = discovered_socket_endpoints(&candidates);

        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints[0],
            DockerEndpoint {
                kind: DockerRuntimeKind::OrbStack,
                connection: DockerConnection::UnixSocket(first_existing),
            }
        );
    }
}
