use anyhow::{anyhow, bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use futures::{stream, StreamExt};
use percent_encoding::percent_decode_str;
use rand::Rng;
use reqwest::StatusCode;
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use std::{
    collections::{HashMap, HashSet},
    net::TcpListener as StdTcpListener,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncWriteExt, BufWriter},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time::{sleep, timeout, Instant},
};
use url::Url;

const INPUT_FILE: &str = "keys.txt";
const OUTPUT_FILE: &str = "alive_keys.txt";
const CONCURRENCY: usize = 80;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5); // было 10
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5); // было 10

// Bug 18: несколько независимых liveness-эндпоинтов. Если один из них
// блокирует ноду (Cloudflare часто отвечает 403/429) или недоступен,
// проверка переходит к следующему. Живой туннель должен пройти хотя бы один.
const CLOUDFLARE_LIVENESS_URL: &str = "https://cp.cloudflare.com/generate_204";
const GOOGLE_LIVENESS_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";
const MICROSOFT_LIVENESS_URL: &str = "https://www.msftconnecttest.com/connecttest.txt";
const APPLE_LIVENESS_URL: &str = "http://captive.apple.com/hotspot-detect.html";
const FIREFOX_LIVENESS_URL: &str = "http://detectportal.firefox.com/success.txt";
const LIVENESS_URLS: [&str; 5] = [
    CLOUDFLARE_LIVENESS_URL,
    GOOGLE_LIVENESS_URL,
    MICROSOFT_LIVENESS_URL,
    APPLE_LIVENESS_URL,
    FIREFOX_LIVENESS_URL,
];
// Этап 2 (диагностический): небольшая контрольная загрузка. Её провал НЕ
// делает ключ мёртвым, иначе медленные, но живые ноды снова отсеиваются.
const SPEED_URL: &str = "https://speed.cloudflare.com/__down?bytes=20000";
const SPEED_MIN_BYTES: usize = 10 * 1024;
const SPEED_TIMEOUT: Duration = Duration::from_secs(10);
const TEST_ATTEMPTS: usize = 2;
const TEST_RETRY_DELAY: Duration = Duration::from_millis(1500);
// Сколько последних строк stderr ядра печатать рядом с FAIL.
const STDERR_TAIL_LINES: usize = 8;
const STDERR_TAIL_MAX_CHARS: usize = 400;
const PORT_MIN: u16 = 10_000;
const PORT_MAX: u16 = 60_000;
const MAX_BASE64_DEPTH: usize = 2;
const MAX_DECODED_SUBSCRIPTION_BYTES: usize = 16 * 1024 * 1024;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static TEMP_CONFIG_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
struct RealitySpec {
    public_key: String,
    short_id: Option<String>,
}

#[derive(Debug, Clone)]
struct TlsSpec {
    server_name: Option<String>,
    insecure: bool,
    alpn: Vec<String>,
    fingerprint: Option<String>,
    reality: Option<RealitySpec>,
}

impl TlsSpec {
    fn to_json(&self) -> JsonValue {
        let mut map = JsonMap::new();
        map.insert("enabled".to_string(), json!(true));
        if let Some(server_name) = self.server_name.as_deref().filter(|s| !s.is_empty()) {
            map.insert("server_name".to_string(), json!(server_name));
        }
        if self.insecure {
            map.insert("insecure".to_string(), json!(true));
        }
        if !self.alpn.is_empty() {
            map.insert("alpn".to_string(), json!(self.alpn));
        }
        if let Some(fingerprint) = self.fingerprint.as_deref().filter(|s| !s.is_empty()) {
            map.insert(
                "utls".to_string(),
                json!({"enabled": true, "fingerprint": fingerprint}),
            );
        }
        if let Some(reality) = &self.reality {
            let mut reality_map = JsonMap::new();
            reality_map.insert("enabled".to_string(), json!(true));
            reality_map.insert("public_key".to_string(), json!(reality.public_key));
            if let Some(short_id) = reality.short_id.as_deref().filter(|s| !s.is_empty()) {
                reality_map.insert("short_id".to_string(), json!(short_id));
            }
            map.insert("reality".to_string(), JsonValue::Object(reality_map));
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Engine {
    SingBox,
    Xray,
}

impl Engine {
    fn label(self) -> &'static str {
        match self {
            Engine::SingBox => "Sing-box",
            Engine::Xray => "Xray",
        }
    }
}

#[derive(Debug, Clone)]
enum TransportSpec {
    Ws {
        path: String,
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
    Http {
        host: Vec<String>,
        path: String,
    },
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    Xhttp {
        path: String,
        host: Option<String>,
        mode: Option<String>,
        extra: Option<JsonValue>,
    },
    Quic,
}

impl TransportSpec {
    fn to_json(&self) -> JsonValue {
        let mut map = JsonMap::new();
        match self {
            TransportSpec::Ws { path, host } => {
                map.insert("type".to_string(), json!("ws"));
                map.insert("path".to_string(), json!(path));
                if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("headers".to_string(), json!({ "Host": host }));
                }
            }
            TransportSpec::Grpc { service_name } => {
                map.insert("type".to_string(), json!("grpc"));
                map.insert("service_name".to_string(), json!(service_name));
            }
            TransportSpec::Http { host, path } => {
                map.insert("type".to_string(), json!("http"));
                map.insert("path".to_string(), json!(path));
                if !host.is_empty() {
                    map.insert("host".to_string(), json!(host));
                }
            }
            TransportSpec::HttpUpgrade { path, host } => {
                map.insert("type".to_string(), json!("httpupgrade"));
                map.insert("path".to_string(), json!(path));
                if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("headers".to_string(), json!({ "Host": host }));
                }
            }
            // sing-box has no native XHTTP transport, so this branch is only a
            // defensive fallback. Engine selection routes all XHTTP keys to Xray.
            TransportSpec::Xhttp { path, host, .. } => {
                map.insert("type".to_string(), json!("httpupgrade"));
                map.insert("path".to_string(), json!(path));
                if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("headers".to_string(), json!({ "Host": host }));
                }
            }
            TransportSpec::Quic => {
                map.insert("type".to_string(), json!("quic"));
            }
        }
        JsonValue::Object(map)
    }
}

#[derive(Debug, Clone)]
enum ProxyProtocol {
    Vmess {
        uuid: String,
        security: String,
        alter_id: u16,
    },
    Vless {
        uuid: String,
        flow: Option<String>,
    },
    Trojan {
        password: String,
    },
    Shadowsocks {
        method: String,
        password: String,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct OutboundSpec {
    server: String,
    port: u16,
    protocol: ProxyProtocol,
    tls: Option<TlsSpec>,
    transport: Option<TransportSpec>,
    engine: Engine,
    finalmask: Option<JsonValue>,
}

impl OutboundSpec {
    fn to_json(&self) -> JsonValue {
        let mut map = JsonMap::new();
        map.insert("tag".to_string(), json!("proxy"));
        map.insert("server".to_string(), json!(self.server));
        map.insert("server_port".to_string(), json!(self.port));
        match &self.protocol {
            ProxyProtocol::Vmess {
                uuid,
                security,
                alter_id,
            } => {
                map.insert("type".to_string(), json!("vmess"));
                map.insert("uuid".to_string(), json!(uuid));
                map.insert("security".to_string(), json!(security));
                map.insert("alter_id".to_string(), json!(alter_id));
            }
            ProxyProtocol::Vless { uuid, flow } => {
                map.insert("type".to_string(), json!("vless"));
                map.insert("uuid".to_string(), json!(uuid));
                if let Some(flow) = flow.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("flow".to_string(), json!(flow));
                }
            }
            ProxyProtocol::Trojan { password } => {
                map.insert("type".to_string(), json!("trojan"));
                map.insert("password".to_string(), json!(password));
            }
            ProxyProtocol::Shadowsocks {
                method,
                password,
                plugin,
                plugin_opts,
            } => {
                map.insert("type".to_string(), json!("shadowsocks"));
                map.insert("method".to_string(), json!(method));
                map.insert("password".to_string(), json!(password));
                if let Some(plugin) = plugin.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("plugin".to_string(), json!(plugin));
                }
                if let Some(plugin_opts) = plugin_opts.as_deref().filter(|s| !s.is_empty()) {
                    map.insert("plugin_opts".to_string(), json!(plugin_opts));
                }
            }
        }
        if let Some(tls) = &self.tls {
            map.insert("tls".to_string(), tls.to_json());
        }
        if let Some(transport) = &self.transport {
            map.insert("transport".to_string(), transport.to_json());
        }
        JsonValue::Object(map)
    }
}

#[derive(Clone)]
struct CheckItem {
    display: String,
    original: String,
    spec: OutboundSpec,
}
struct ParseReport {
    keys: Vec<CheckItem>,
    skipped: usize,
}
struct CheckResult {
    display: String,
    original: String,
    alive: bool,
    engine: Engine,
    /// Причина FAIL: текст ошибки плюс хвост stderr ядра, если он был.
    detail: Option<String>,
}

struct PortPool {
    used: StdMutex<HashSet<u16>>,
}
impl PortPool {
    fn new() -> Self {
        Self {
            used: StdMutex::new(HashSet::new()),
        }
    }
    fn acquire(self: &Arc<Self>) -> Result<PortLease> {
        let mut used = self
            .used
            .lock()
            .map_err(|_| anyhow!("пул портов заблокирован после паники"))?;
        let mut rng = rand::thread_rng();
        for _ in 0..4_000 {
            let port = rng.gen_range(PORT_MIN..=PORT_MAX);
            if used.contains(&port) {
                continue;
            }
            match StdTcpListener::bind(("127.0.0.1", port)) {
                Ok(listener) => {
                    drop(listener);
                    used.insert(port);
                    return Ok(PortLease {
                        port,
                        pool: Arc::clone(self),
                    });
                }
                Err(_) => continue,
            }
        }
        bail!(
            "не удалось найти свободный локальный порт в диапазоне {}-{}",
            PORT_MIN,
            PORT_MAX
        )
    }
}
struct PortLease {
    port: u16,
    pool: Arc<PortPool>,
}
impl Drop for PortLease {
    fn drop(&mut self) {
        if let Ok(mut used) = self.pool.used.lock() {
            used.remove(&self.port);
        }
    }
}

/// RAII-обёртка для временных файлов (конфиг ядра, stderr ядра).
/// Удаляет файл при выходе из области видимости, в том числе при ошибке,
/// раннем `return` или панике.
struct TempFileGuard {
    path: PathBuf,
}
impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
    fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct CheckContext {
    pool: Arc<PortPool>,
    singbox: PathBuf,
    xray: PathBuf,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Ошибка: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let singbox = find_core("sing-box.exe").ok_or_else(|| anyhow!("не найден sing-box.exe"))?;
    let xray = find_core("xray.exe").ok_or_else(|| anyhow!("не найден xray.exe"))?;
    let input_path = Path::new(INPUT_FILE);
    if !input_path.is_file() {
        bail!("не найден файл {}", INPUT_FILE);
    }
    let input = fs::read_to_string(input_path).await?;
    let ParseReport { keys, skipped } = parse_keys(&input);
    println!("Загружено ключей: {}. Пропущено: {}.", keys.len(), skipped);
    if keys.is_empty() {
        return Ok(());
    }

    let total = keys.len();
    let output = fs::File::create(OUTPUT_FILE).await?;
    let writer = Arc::new(Mutex::new(BufWriter::new(output)));
    let context = Arc::new(CheckContext {
        pool: Arc::new(PortPool::new()),
        singbox,
        xray,
    });

    let mut checks = stream::iter(keys)
        .map(|item| {
            let context = Arc::clone(&context);
            async move { check_item(item, context).await }
        })
        .buffer_unordered(CONCURRENCY);

    let mut completed = 0usize;
    let mut alive_count = 0usize;

    while let Some(result) = checks.next().await {
        completed += 1;
        if result.alive {
            write_alive(&writer, &result.original).await?;
            alive_count += 1;
            println!(
                "[{completed}/{total}] {} -> OK ({})",
                result.display,
                result.engine.label()
            );
        } else {
            match result.detail {
                Some(detail) => println!(
                    "[{completed}/{total}] {} -> FAIL ({detail})",
                    result.display
                ),
                None => println!("[{completed}/{total}] {} -> FAIL", result.display),
            }
        }
    }
    let mut output = writer.lock().await;
    output.flush().await?;
    println!(
        "Готово: {alive_count} из {total} рабочих. Результат в {}.",
        OUTPUT_FILE
    );
    Ok(())
}

async fn write_alive(writer: &Mutex<BufWriter<fs::File>>, original: &str) -> Result<()> {
    let original = original.trim_end_matches(['\r', '\n']);
    let mut output = writer.lock().await;
    output.write_all(original.as_bytes()).await?;
    output.write_all(b"\n").await?;
    output.flush().await?;
    Ok(())
}

async fn check_item(item: CheckItem, context: Arc<CheckContext>) -> CheckResult {
    let CheckItem {
        display,
        original,
        spec,
    } = item;
    let engine = spec.engine;
    let (alive, detail) = match try_check_item(&spec, &context).await {
        Ok(()) => (true, None),
        Err(error) => (false, Some(format!("{error:#}"))),
    };
    CheckResult {
        display,
        original,
        alive,
        engine,
        detail,
    }
}

async fn try_check_item(spec: &OutboundSpec, context: &CheckContext) -> Result<()> {
    let port_lease = context.pool.acquire()?;
    let config = match spec.engine {
        Engine::SingBox => build_singbox_config(&spec.to_json(), port_lease.port),
        Engine::Xray => build_xray_config(spec, port_lease.port)?,
    };
    let config_bytes = serde_json::to_vec_pretty(&config)?;
    let config_guard = TempFileGuard::new(temp_config_path());
    fs::write(config_guard.path(), &config_bytes).await?;

    let binary = match spec.engine {
        Engine::SingBox => &context.singbox,
        Engine::Xray => &context.xray,
    };

    // stderr ядра уходит в отдельный временный файл: без него причины
    // падения Sing-box/Xray на большинстве ключей не видны в консоли.
    let (stderr_stdio, stderr_guard) = prepare_stderr_log(port_lease.port).await;

    let mut command = Command::new(binary);
    command
        .arg("run")
        .arg("-c")
        .arg(config_guard.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_stdio)
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let spawn_result = command
        .spawn()
        .with_context(|| format!("не удалось запустить {}", binary.display()));
    let mut child = match spawn_result {
        Ok(child) => child,
        Err(error) => return Err(with_stderr_tail(error, stderr_guard.as_ref()).await),
    };

    let check_result: Result<()> = async {
        wait_for_socks_port(&mut child, port_lease.port).await?;
        test_proxy(port_lease.port).await
    }
    .await;

    // kill() дожидается завершения процесса, поэтому stderr уже дописан в файл
    // и его можно безопасно прочитать (и затем удалить guard'ом).
    let _ = child.kill().await;

    match check_result {
        Ok(()) => Ok(()),
        Err(error) => Err(with_stderr_tail(error, stderr_guard.as_ref()).await),
    }
}

/// Создаёт временный файл под stderr ядра и возвращает Stdio для команды.
/// Если файл создать не удалось, проверка продолжается без логов stderr.
async fn prepare_stderr_log(port: u16) -> (Stdio, Option<TempFileGuard>) {
    let path = temp_stderr_path(port);
    match fs::File::create(&path).await {
        Ok(file) => {
            let std_file = file.into_std().await;
            (Stdio::from(std_file), Some(TempFileGuard::new(path)))
        }
        Err(_) => (Stdio::null(), None),
    }
}

/// Читает последние `max_lines` непустых строк stderr ядра и склеивает их
/// в одну строку, пригодную для печати рядом с FAIL.
async fn read_stderr_tail(path: &Path, max_lines: usize) -> Option<String> {
    let bytes = fs::read(path).await.ok()?;
    if bytes.is_empty() {
        return None;
    }
    let text = strip_ansi(&String::from_utf8_lossy(&bytes));
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }
    let start = lines.len().saturating_sub(max_lines);
    let tail = lines[start..].join(" | ");
    Some(sanitize_display(&tail, STDERR_TAIL_MAX_CHARS))
}

/// Убирает ANSI CSI-последовательности: Sing-box и Xray красят уровень лога
/// в цвета, а в консоли эти escape-коды выглядят как мусор.
fn strip_ansi(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(character) = chars.next() {
        if character == '\u{1b}' {
            // ESC '[' ... финальный байт в диапазоне '@'..='~'
            if chars.next() == Some('[') {
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            continue;
        }
        result.push(character);
    }
    result
}

/// Дополняет ошибку хвостом stderr, если временный лог ядра сохранился.
async fn with_stderr_tail(error: anyhow::Error, guard: Option<&TempFileGuard>) -> anyhow::Error {
    let Some(guard) = guard else {
        return error;
    };
    match read_stderr_tail(guard.path(), STDERR_TAIL_LINES).await {
        Some(tail) => anyhow!("{error:#}; stderr: {tail}"),
        None => error,
    }
}

async fn wait_for_socks_port(child: &mut Child, port: u16) -> Result<()> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("ядро завершилось до открытия SOCKS-порта: {status}");
        }
        let connected = timeout(
            Duration::from_millis(500),
            TcpStream::connect(("127.0.0.1", port)),
        )
        .await
        .is_ok_and(|result| result.is_ok());
        if connected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "SOCKS-порт 127.0.0.1:{port} не открылся за {} с",
                READY_TIMEOUT.as_secs()
            );
        }
        sleep(READY_POLL_INTERVAL).await;
    }
}

fn build_singbox_config(outbound: &JsonValue, port: u16) -> JsonValue {
    json!({
        "log": {"level": "error", "timestamp": false},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": port}],
        "outbounds": [outbound.clone()],
        "route": {"final": "proxy"}
    })
}

// ---------------------------------------------------------------------------
// XRAY CONFIG
// ---------------------------------------------------------------------------

fn build_xray_config(spec: &OutboundSpec, port: u16) -> Result<JsonValue> {
    Ok(json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": false}
        }],
        "outbounds": [build_xray_outbound(spec)?]
    }))
}

fn build_xray_outbound(spec: &OutboundSpec) -> Result<JsonValue> {
    let mut outbound = JsonMap::new();
    match &spec.protocol {
        ProxyProtocol::Vless { uuid, flow } => {
            let mut user = JsonMap::new();
            user.insert("id".to_string(), json!(uuid));
            user.insert("encryption".to_string(), json!("none"));
            if let Some(flow) = flow.as_deref().filter(|s| !s.is_empty()) {
                user.insert("flow".to_string(), json!(flow));
            }
            outbound.insert("protocol".to_string(), json!("vless"));
            outbound.insert(
                "settings".to_string(),
                json!({
                    "vnext": [{
                        "address": spec.server,
                        "port": spec.port,
                        "users": [JsonValue::Object(user)]
                    }]
                }),
            );
        }
        ProxyProtocol::Vmess {
            uuid,
            security,
            alter_id,
        } => {
            outbound.insert("protocol".to_string(), json!("vmess"));
            outbound.insert(
                "settings".to_string(),
                json!({
                    "vnext": [{
                        "address": spec.server,
                        "port": spec.port,
                        "users": [{
                            "id": uuid,
                            "alterId": alter_id,
                            "security": security
                        }]
                    }]
                }),
            );
        }
        ProxyProtocol::Trojan { password } => {
            outbound.insert("protocol".to_string(), json!("trojan"));
            outbound.insert(
                "settings".to_string(),
                json!({
                    "servers": [{
                        "address": spec.server,
                        "port": spec.port,
                        "password": password
                    }]
                }),
            );
        }
        ProxyProtocol::Shadowsocks {
            method,
            password,
            plugin,
            plugin_opts,
        } => {
            let mut server = JsonMap::new();
            server.insert("address".to_string(), json!(spec.server));
            server.insert("port".to_string(), json!(spec.port));
            server.insert("method".to_string(), json!(method));
            server.insert("password".to_string(), json!(password));
            if let Some(plugin) = plugin.as_deref().filter(|s| !s.is_empty()) {
                server.insert("plugin".to_string(), json!(plugin));
            }
            if let Some(plugin_opts) = plugin_opts.as_deref().filter(|s| !s.is_empty()) {
                server.insert("pluginOpts".to_string(), json!(plugin_opts));
            }
            outbound.insert("protocol".to_string(), json!("shadowsocks"));
            outbound.insert(
                "settings".to_string(),
                json!({
                    "servers": [JsonValue::Object(server)]
                }),
            );
        }
    }

    let mut stream = build_xray_stream(spec)?;
    if let Some(finalmask) = &spec.finalmask {
        stream.insert("finalmask".to_string(), finalmask.clone());
    }
    outbound.insert("streamSettings".to_string(), JsonValue::Object(stream));
    Ok(JsonValue::Object(outbound))
}

fn build_xray_stream(spec: &OutboundSpec) -> Result<JsonMap<String, JsonValue>> {
    let mut stream = JsonMap::new();

    match &spec.transport {
        None => {
            stream.insert("network".to_string(), json!("tcp"));
        }
        Some(TransportSpec::Ws { path, host }) => {
            stream.insert("network".to_string(), json!("ws"));
            let mut settings = JsonMap::new();
            settings.insert("path".to_string(), json!(path));
            if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("headers".to_string(), json!({"Host": host}));
            }
            stream.insert("wsSettings".to_string(), JsonValue::Object(settings));
        }
        Some(TransportSpec::Grpc { service_name }) => {
            stream.insert("network".to_string(), json!("grpc"));
            stream.insert(
                "grpcSettings".to_string(),
                json!({"serviceName": service_name}),
            );
        }
        Some(TransportSpec::HttpUpgrade { path, host }) => {
            stream.insert("network".to_string(), json!("httpupgrade"));
            let mut settings = JsonMap::new();
            settings.insert("path".to_string(), json!(path));
            if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("host".to_string(), json!(host));
            }
            stream.insert(
                "httpupgradeSettings".to_string(),
                JsonValue::Object(settings),
            );
        }
        Some(TransportSpec::Http { .. }) => {
            bail!("Xray не поддерживает HTTP/2 transport");
        }
        Some(TransportSpec::Quic) => {
            bail!("Xray не поддерживает QUIC transport");
        }
        Some(TransportSpec::Xhttp {
            path,
            host,
            mode,
            extra,
        }) => {
            stream.insert("network".to_string(), json!("xhttp"));
            let mut settings = JsonMap::new();
            settings.insert("path".to_string(), json!(path));
            if let Some(host) = host.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("host".to_string(), json!(host));
            }
            if let Some(mode) = mode.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("mode".to_string(), json!(mode));
            }
            if let Some(extra) = extra {
                settings.insert("extra".to_string(), extra.clone());
            }
            stream.insert("xhttpSettings".to_string(), JsonValue::Object(settings));
        }
    }

    if let Some(tls) = &spec.tls {
        if let Some(reality) = &tls.reality {
            stream.insert("security".to_string(), json!("reality"));
            let server_name = tls
                .server_name
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or(&spec.server);
            let mut settings = JsonMap::new();
            settings.insert("serverName".to_string(), json!(server_name));
            settings.insert("publicKey".to_string(), json!(reality.public_key));
            if let Some(short_id) = reality.short_id.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("shortId".to_string(), json!(short_id));
            }
            if let Some(fingerprint) = tls.fingerprint.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("fingerprint".to_string(), json!(fingerprint));
            }
            stream.insert("realitySettings".to_string(), JsonValue::Object(settings));
        } else {
            stream.insert("security".to_string(), json!("tls"));
            let mut settings = JsonMap::new();
            if let Some(server_name) = tls.server_name.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("serverName".to_string(), json!(server_name));
            }
            if tls.insecure {
                settings.insert("allowInsecure".to_string(), json!(true));
            }
            if !tls.alpn.is_empty() {
                settings.insert("alpn".to_string(), json!(tls.alpn));
            }
            if let Some(fingerprint) = tls.fingerprint.as_deref().filter(|s| !s.is_empty()) {
                settings.insert("fingerprint".to_string(), json!(fingerprint));
            }
            stream.insert("tlsSettings".to_string(), JsonValue::Object(settings));
        }
    }

    Ok(stream)
}

// ---------------------------------------------------------------------------
// ПРОВЕРКА ЧЕРЕЗ SOCKS
// ---------------------------------------------------------------------------
//
// Двухступенчатая проверка:
//
// 1. Один из liveness-эндпоинтов из `LIVENESS_URLS`. Успешный ответ
//    подтверждает, что SOCKS-туннель жив, TLS и HTTP проходят. Если провайдер
//    блокирует конкретный URL (Cloudflare нередко отвечает 403/429), проверка
//    переходит к следующему эндпоинту.
// 2. Контрольная загрузка 20 КБ с `speed.cloudflare.com`. Она нужна только как
//    диагностика пропускной способности: если liveness прошёл, а загрузка
//    упала (в том числе по таймауту), ключ всё равно считается рабочим — он
//    живой, просто медленный.
//
// Нестабильные ноды часто рвут первую попытку, поэтому этап 1 повторяется
// TEST_ATTEMPTS раз с паузой 1.5 с. Ядро при этом не перезапускается:
// SOCKS-порт уже поднят, между попытками переиспользуется тот же процесс.
async fn test_proxy(port: u16) -> Result<()> {
    let mut last_error: Option<anyhow::Error> = None;
    for attempt in 0..TEST_ATTEMPTS {
        match test_proxy_once(port, attempt).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                if attempt + 1 < TEST_ATTEMPTS {
                    sleep(TEST_RETRY_DELAY).await;
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("не выполнено ни одной тестовой попытки")))
}

async fn test_proxy_once(port: u16, attempt: usize) -> Result<()> {
    let client = build_probe_client(port)?;

    // Этап 1: обязательный. Любой endpoint, прошедший is_liveness_ok,
    // доказывает живость туннеля.
    probe_liveness_endpoints(&client, attempt).await?;

    // Этап 2: необязательный. Liveness уже доказал живость, поэтому результат
    // загрузки намеренно игнорируется (медленная нода остаётся рабочей).
    let _ = probe_download(&client).await;

    Ok(())
}

/// Перебирает liveness-эндпоинты по кругу, начиная с `start_index`.
///
/// Общий бюджет попытки ограничен `REQUEST_TIMEOUT`: fallback не должен
/// умножать таймаут на число URL. Быстрый отказ (403/429/404) освобождает
/// бюджет следующему эндпоинту, а зависший первый запрос не превращает
/// мёртвый ключ в 25-секундное ожидание. Номер попытки сдвигает стартовый URL,
/// поэтому вторая попытка не повторяет тот же зависший endpoint.
async fn probe_liveness_endpoints(client: &reqwest::Client, start_index: usize) -> Result<()> {
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let count = LIVENESS_URLS.len();
    let mut failures = Vec::with_capacity(count);

    for offset in 0..count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            failures.push("общий бюджет попытки исчерпан".to_string());
            break;
        }
        let url = LIVENESS_URLS[(start_index + offset) % count];
        match timeout(remaining, probe_liveness(client, url)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => failures.push(format!("{url}: {error:#}")),
            Err(_) => failures.push(format!("{url}: таймаут")),
        }
    }

    bail!(
        "ни один liveness-эндпоинт не ответил корректно: {}",
        failures.join("; ")
    )
}

async fn probe_liveness(client: &reqwest::Client, url: &str) -> Result<()> {
    let response = client
        .get(url)
        .send()
        .await
        .context("не удалось подключиться к тестовому серверу")?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !is_liveness_ok(status, &body, url) {
        bail!(
            "статус {status}, тело: \"{}\"",
            sanitize_display(body.trim(), 80)
        );
    }
    Ok(())
}

fn build_probe_client(port: u16) -> Result<reqwest::Client> {
    // Только явный прокси. `.no_proxy()` больше не нужен: он отключал
    // обработку окружения, но заодно мешал диагностике реальных условий.
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?;
    Ok(reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()?)
}

/// Проверяет ответ liveness-эндпоинта с учётом его контракта.
///
/// Cloudflare и Google отдают пустой 204. Остальные провайдеры отвечают 200 и
/// коротким текстом-маркером, поэтому одного статуса недостаточно: captive
/// portal или подменённая страница тоже могут вернуть 200.
fn is_liveness_ok(status: StatusCode, body: &str, url: &str) -> bool {
    match url {
        CLOUDFLARE_LIVENESS_URL | GOOGLE_LIVENESS_URL => status == StatusCode::NO_CONTENT,
        MICROSOFT_LIVENESS_URL => {
            status == StatusCode::OK && body.contains("Microsoft Connect Test")
        }
        APPLE_LIVENESS_URL => status == StatusCode::OK && body.contains("Success"),
        FIREFOX_LIVENESS_URL => status == StatusCode::OK && body.contains("success"),
        _ => false,
    }
}

fn download_sufficient(bytes: usize) -> bool {
    bytes >= SPEED_MIN_BYTES
}

/// Контрольная загрузка 20 КБ. Любая ошибка здесь — только диагностика.
async fn probe_download(client: &reqwest::Client) -> Result<usize> {
    let mut response = client
        .get(SPEED_URL)
        .timeout(SPEED_TIMEOUT)
        .send()
        .await
        .context("не удалось начать скачивание")?;

    if !response.status().is_success() {
        bail!("сервер вернул статус {}", response.status());
    }

    let mut downloaded = 0usize;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("ошибка при скачивании тестового файла")?
    {
        downloaded += chunk.len();
        if download_sufficient(downloaded) {
            break;
        }
    }
    if !download_sufficient(downloaded) {
        bail!(
            "скачалось слишком мало данных: {} байт (минимум {})",
            downloaded,
            SPEED_MIN_BYTES
        );
    }
    Ok(downloaded)
}

fn find_core(binary_name: &str) -> Option<PathBuf> {
    let binary_name = if cfg!(windows) && !binary_name.ends_with(".exe") {
        format!("{binary_name}.exe")
    } else {
        binary_name.to_string()
    };
    let mut candidates = Vec::new();
    if let Ok(current_dir) = std::env::current_dir() {
        candidates.push(current_dir.join(&binary_name));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(directory) = executable.parent() {
            candidates.push(directory.join(&binary_name));
            if let Some(project_root) = directory.parent().and_then(Path::parent) {
                candidates.push(project_root.join(&binary_name));
            }
        }
    }
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&binary_name));
    candidates.into_iter().find(|path| path.is_file())
}

fn temp_config_path() -> PathBuf {
    let sequence = TEMP_CONFIG_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = rand::random::<u64>();
    std::env::temp_dir().join(format!(
        "vpn-key-checker-{}-{sequence}-{nonce:016x}.json",
        std::process::id()
    ))
}

// Порт уникален на время проверки (PortLease), поэтому имя файла тоже
// уникально среди одновременно работающих проверок.
fn temp_stderr_path(port: u16) -> PathBuf {
    std::env::temp_dir().join(format!("vpn-err-{port}.log"))
}

// ---------------------------------------------------------------------------
// ПАРСИНГ (с добавленной поддержкой XHTTP)
// ---------------------------------------------------------------------------

fn parse_keys(text: &str) -> ParseReport {
    let mut keys = Vec::new();
    let mut skipped = 0usize;
    parse_subscription_text(text, 0, &mut keys, &mut skipped);
    ParseReport { keys, skipped }
}

fn parse_subscription_text(
    text: &str,
    depth: usize,
    keys: &mut Vec<CheckItem>,
    skipped: &mut usize,
) {
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return;
    }

    if let Some(proxies) = extract_clash_proxies(text) {
        for (index, proxy) in proxies.iter().enumerate() {
            match clash_proxy_to_item(proxy, index) {
                Ok(item) => keys.push(item),
                Err(_) => *skipped += 1,
            }
        }
        return;
    }

    if let Some((remaining, proxies)) = extract_embedded_clash_blocks(text) {
        for (index, proxy) in proxies.iter().enumerate() {
            match clash_proxy_to_item(proxy, index) {
                Ok(item) => keys.push(item),
                Err(_) => *skipped += 1,
            }
        }
        if !remaining.trim().is_empty() {
            parse_subscription_text(&remaining, depth, keys, skipped);
        }
        return;
    }

    if depth < MAX_BASE64_DEPTH && !text.contains("://") && !text.contains("proxies:") {
        if let Some(decoded) = try_decode_subscription(text) {
            parse_subscription_text(&decoded, depth + 1, keys, skipped);
            return;
        }
    }

    for raw_line in text.lines() {
        let line = raw_line.trim_start_matches('\u{feff}').trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if is_supported_uri(line) {
            match parse_uri(line) {
                Ok(spec) => keys.push(make_uri_item(line, spec)),
                Err(_) => *skipped += 1,
            }
            continue;
        }

        if depth < MAX_BASE64_DEPTH && line.len() >= 16 {
            if let Some(decoded) = try_decode_subscription(line) {
                let keys_before = keys.len();
                let skipped_before = *skipped;
                parse_subscription_text(&decoded, depth + 1, keys, skipped);
                if keys.len() > keys_before || *skipped > skipped_before {
                    continue;
                }
            }
        }
        *skipped += 1;
    }
}

fn make_uri_item(uri: &str, spec: OutboundSpec) -> CheckItem {
    CheckItem {
        display: display_for_uri(uri),
        original: uri.to_string(),
        spec,
    }
}

fn is_supported_uri(line: &str) -> bool {
    ["vmess://", "vless://", "trojan://", "ss://"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn extract_clash_proxies(text: &str) -> Option<Vec<YamlValue>> {
    let document: YamlValue = serde_yaml::from_str(text).ok()?;
    if let Some(proxies) = yaml_get(&document, "proxies") {
        if let Some(sequence) = proxies.as_sequence() {
            if sequence.iter().any(is_clash_proxy) {
                return Some(sequence.clone());
            }
        }
    }
    if let Some(sequence) = document.as_sequence() {
        if sequence.iter().any(is_clash_proxy) {
            return Some(sequence.clone());
        }
    }
    if is_clash_proxy(&document) {
        return Some(vec![document]);
    }
    None
}

fn extract_embedded_clash_blocks(text: &str) -> Option<(String, Vec<YamlValue>)> {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return None;
    }
    let mut removed = vec![false; lines.len()];
    let mut proxies = Vec::new();
    let mut found_block = false;
    let mut index = 0usize;

    while index < lines.len() {
        if lines[index] != "proxies:" {
            index += 1;
            continue;
        }
        let start = index;
        let mut end = index + 1;
        while end < lines.len() {
            let line = lines[end];
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                end += 1;
                continue;
            }
            let indented = line.starts_with(' ') || line.starts_with('\t');
            if indented || trimmed.starts_with('-') {
                end += 1;
                continue;
            }
            break;
        }
        let block = lines[start..end].join("\n");
        if let Ok(document) = serde_yaml::from_str::<YamlValue>(&block) {
            if let Some(sequence) = yaml_get(&document, "proxies").and_then(YamlValue::as_sequence)
            {
                if sequence.iter().any(is_clash_proxy) {
                    proxies.extend(sequence.iter().cloned());
                    for line in removed.iter_mut().take(end).skip(start) {
                        *line = true;
                    }
                    found_block = true;
                }
            }
        }
        index = end;
    }
    if !found_block {
        return None;
    }
    let remaining = lines
        .iter()
        .enumerate()
        .map(|(line_index, line)| if removed[line_index] { "" } else { *line })
        .collect::<Vec<_>>()
        .join("\n");
    Some((remaining, proxies))
}

fn is_clash_proxy(value: &YamlValue) -> bool {
    yaml_get(value, "type")
        .and_then(YamlValue::as_str)
        .is_some()
        && yaml_get(value, "server")
            .and_then(YamlValue::as_str)
            .is_some()
}

fn try_decode_subscription(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 16 {
        return None;
    }
    let bytes = decode_base64_any(&compact)?;
    if bytes.len() > MAX_DECODED_SUBSCRIPTION_BYTES {
        return None;
    }
    let decoded = String::from_utf8(bytes).ok()?;
    if looks_like_subscription(&decoded) {
        Some(decoded)
    } else {
        None
    }
}

fn looks_like_subscription(text: &str) -> bool {
    let text = text.trim_start_matches('\u{feff}');
    if text.contains("proxies:") || text.contains("proxy-groups:") {
        return true;
    }
    text.lines()
        .take(64)
        .any(|line| is_supported_uri(line.trim()))
}

fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }
    STANDARD
        .decode(&compact)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(&compact).ok())
        .or_else(|| URL_SAFE.decode(&compact).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(&compact).ok())
}

fn parse_uri(line: &str) -> Result<OutboundSpec> {
    if let Some(payload) = line.strip_prefix("vmess://") {
        return parse_vmess(payload);
    }
    if line.starts_with("vless://") {
        return parse_vless(line);
    }
    if let Some(payload) = line.strip_prefix("trojan://") {
        return parse_trojan(payload);
    }
    if let Some(payload) = line.strip_prefix("ss://") {
        return parse_ss(payload);
    }
    bail!("неподдерживаемая схема ключа")
}

fn parse_vmess(payload: &str) -> Result<OutboundSpec> {
    let payload = payload.trim();
    if let Some(decoded) =
        decode_base64_any(payload).and_then(|bytes| String::from_utf8(bytes).ok())
    {
        if let Ok(value) = serde_json::from_str::<JsonValue>(&decoded) {
            if let Ok(spec) = parse_vmess_json(&value) {
                return Ok(spec);
            }
        }
    }
    parse_vmess_url(payload)
}

fn parse_vmess_json(value: &JsonValue) -> Result<OutboundSpec> {
    if !value.is_object() {
        bail!("vmess: JSON не является объектом");
    }
    let server = json_get_str(value, "add")
        .filter(|s| !s.trim().is_empty())
        .context("vmess: отсутствует сервер (add)")?;
    let port = json_get_u16(value, "port").context("vmess: отсутствует или неверный порт")?;
    if port == 0 {
        bail!("vmess: порт не может быть 0");
    }
    let uuid = json_get_str(value, "id")
        .filter(|s| !s.trim().is_empty())
        .context("vmess: отсутствует UUID (id)")?;
    let alter_id = json_get_u16(value, "aid").unwrap_or(0);
    let security = json_get_str(value, "scy")
        .or_else(|| json_get_str(value, "security"))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "auto".to_string());
    let network = json_get_str(value, "net")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "tcp".to_string());
    let host = json_get_str(value, "host").filter(|s| !s.trim().is_empty());
    let path = json_get_str(value, "path").filter(|s| !s.trim().is_empty());
    let service = json_get_str_multi(value, &["serviceName", "service_name", "service"]);
    let tls_raw = json_get_str(value, "tls")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let tls_enabled = !matches!(tls_raw.as_str(), "" | "none" | "false" | "0");
    let is_reality = tls_raw == "reality";
    let server_name =
        json_get_str_multi(value, &["sni", "serverName", "servername", "server_name"])
            .filter(|s| !s.trim().is_empty())
            .or_else(|| first_host(host.as_deref()))
            .or_else(|| Some(server.clone()));
    let tls = if tls_enabled {
        let reality = if is_reality {
            let public_key = json_get_str_multi(value, &["pbk", "publicKey", "public_key"])
                .filter(|s| !s.trim().is_empty())
                .context("vmess reality: отсутствует public key (pbk)")?;
            Some(RealitySpec {
                public_key,
                short_id: json_get_str_multi(value, &["sid", "shortId", "short_id"])
                    .filter(|s| !s.is_empty()),
            })
        } else {
            None
        };
        Some(TlsSpec {
            server_name,
            insecure: json_get_bool(
                value,
                &["allowInsecure", "allow_insecure", "skip-cert-verify"],
            ),
            alpn: json_get_string_list(value, "alpn"),
            fingerprint: json_get_str_multi(value, &["fp", "fingerprint"])
                .filter(|s| !s.is_empty()),
            reality,
        })
    } else {
        None
    };
    let transport = transport_from_parts(
        &network,
        host.as_deref(),
        path.as_deref(),
        service.as_deref(),
        json_get_str(value, "mode").filter(|s| !s.trim().is_empty()),
        json_extra_field(value, "extra"),
    )?;
    ensure_quic_tls(&tls, &transport)?;
    Ok(OutboundSpec {
        server,
        port,
        protocol: ProxyProtocol::Vmess {
            uuid,
            security,
            alter_id,
        },
        tls,
        transport,
        engine: engine_from_json(value),
        finalmask: finalmask_from_json(value),
    })
}

fn parse_vmess_url(payload: &str) -> Result<OutboundSpec> {
    let url = Url::parse(&format!("vmess://{payload}")).context("vmess: некорректный URI")?;
    let uuid = decode_component(url.username());
    if uuid.trim().is_empty() {
        bail!("vmess: пустой UUID");
    }
    let server = url
        .host_str()
        .filter(|s| !s.is_empty())
        .context("vmess: отсутствует сервер")?
        .to_string();
    let port = url.port().context("vmess: отсутствует порт")?;
    if port == 0 {
        bail!("vmess: порт не может быть 0");
    }
    let query = query_map(url.query());
    let network = q_get(&query, &["type", "network", "net"]).unwrap_or_else(|| "tcp".to_string());
    let host = q_get(&query, &["host"]);
    let path = q_get(&query, &["path"]);
    let service = q_get(
        &query,
        &[
            "servicename",
            "service_name",
            "service",
            "grpc-service-name",
        ],
    );
    let security = q_get(&query, &["scy", "cipher"])
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "auto".to_string());
    let alter_id = q_get(&query, &["aid", "alterid", "alter-id"])
        .and_then(|s| s.trim().parse::<u16>().ok())
        .unwrap_or(0);
    let tls = tls_from_query(&query, false, &server)?;
    let transport = transport_from_parts(
        &network,
        host.as_deref(),
        path.as_deref(),
        service.as_deref(),
        q_get(&query, &["mode"]),
        extra_from_query(&query),
    )?;
    ensure_quic_tls(&tls, &transport)?;
    Ok(OutboundSpec {
        server: server.clone(),
        port,
        protocol: ProxyProtocol::Vmess {
            uuid,
            security,
            alter_id,
        },
        tls,
        transport,
        engine: detect_engine(&query, &network),
        finalmask: finalmask_from_query(&query),
    })
}

fn parse_vless(line: &str) -> Result<OutboundSpec> {
    let url = Url::parse(line).context("vless: некорректный URI")?;
    let uuid = decode_component(url.username());
    if uuid.trim().is_empty() {
        bail!("vless: пустой UUID");
    }
    let server = url
        .host_str()
        .filter(|s| !s.is_empty())
        .context("vless: отсутствует сервер")?
        .to_string();
    let port = url.port().context("vless: отсутствует порт")?;
    if port == 0 {
        bail!("vless: порт не может быть 0");
    }
    let query = query_map(url.query());
    let network = q_get(&query, &["type", "network", "net"]).unwrap_or_else(|| "tcp".to_string());
    let host = q_get(&query, &["host"]);
    let path = q_get(&query, &["path"]);
    let service = q_get(
        &query,
        &[
            "servicename",
            "service_name",
            "service",
            "grpc-service-name",
        ],
    );
    let flow = q_get(&query, &["flow"]).filter(|s| !s.trim().is_empty());
    let tls = tls_from_query(&query, false, &server)?;
    let transport = transport_from_parts(
        &network,
        host.as_deref(),
        path.as_deref(),
        service.as_deref(),
        q_get(&query, &["mode"]),
        extra_from_query(&query),
    )?;
    ensure_quic_tls(&tls, &transport)?;
    Ok(OutboundSpec {
        server: server.clone(),
        port,
        protocol: ProxyProtocol::Vless { uuid, flow },
        tls,
        transport,
        engine: detect_engine(&query, &network),
        finalmask: finalmask_from_query(&query),
    })
}

fn parse_trojan(payload: &str) -> Result<OutboundSpec> {
    let (main, query_raw) = split_query_fragment(payload);
    let (userinfo, host_port) = main
        .rsplit_once('@')
        .context("trojan: отсутствует пароль или сервер")?;
    let password = decode_component(userinfo);
    if password.is_empty() {
        bail!("trojan: пустой пароль");
    }
    let (server, port) = parse_host_port(host_port)?;
    let query = query_map(query_raw);
    let network = q_get(&query, &["type", "network", "net"]).unwrap_or_else(|| "tcp".to_string());
    let host = q_get(&query, &["host"]);
    let path = q_get(&query, &["path"]);
    let service = q_get(
        &query,
        &[
            "servicename",
            "service_name",
            "service",
            "grpc-service-name",
        ],
    );
    let tls = tls_from_query(&query, true, &server)?;
    let transport = transport_from_parts(
        &network,
        host.as_deref(),
        path.as_deref(),
        service.as_deref(),
        q_get(&query, &["mode"]),
        extra_from_query(&query),
    )?;
    ensure_quic_tls(&tls, &transport)?;
    Ok(OutboundSpec {
        server: server.clone(),
        port,
        protocol: ProxyProtocol::Trojan { password },
        tls,
        transport,
        engine: detect_engine(&query, &network),
        finalmask: finalmask_from_query(&query),
    })
}

fn parse_ss(payload: &str) -> Result<OutboundSpec> {
    let (main, query_raw) = split_query_fragment(payload);
    let (userinfo, host_port) = if let Some((userinfo, host_port)) = main.rsplit_once('@') {
        (userinfo.to_string(), host_port.to_string())
    } else {
        let decoded = decode_base64_any(main)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .context("ss: не удалось декодировать данные ключа")?;
        let (userinfo, host_port) = decoded
            .rsplit_once('@')
            .context("ss: в декодированном ключе нет символа @")?;
        (userinfo.to_string(), host_port.to_string())
    };
    let decoded_userinfo = decode_base64_any(&userinfo)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .filter(|decoded| decoded.contains(':'))
        .unwrap_or_else(|| decode_component(&userinfo));
    let (method, password) = decoded_userinfo
        .split_once(':')
        .context("ss: ожидается формат method:password")?;
    let method = method.trim();
    if method.is_empty() {
        bail!("ss: пустой метод шифрования");
    }
    let (server, port) = parse_host_port(&host_port)?;
    let query = query_map(query_raw);
    let (plugin, plugin_opts) = ss_plugin_from_query(&query);
    Ok(OutboundSpec {
        server,
        port,
        protocol: ProxyProtocol::Shadowsocks {
            method: method.to_string(),
            password: password.to_string(),
            plugin,
            plugin_opts,
        },
        tls: None,
        transport: None,
        engine: detect_engine(&query, "tcp"),
        finalmask: finalmask_from_query(&query),
    })
}

fn ss_plugin_from_query(query: &HashMap<String, String>) -> (Option<String>, Option<String>) {
    let Some(raw) = query.get("plugin").map(String::as_str).map(str::trim) else {
        return (None, None);
    };
    if raw.is_empty() {
        return (None, None);
    }
    let mut parts = raw.split(';');
    let name = parts.next().unwrap_or_default().trim();
    if name.is_empty() {
        return (None, None);
    }
    let name = if name.eq_ignore_ascii_case("obfs") {
        "obfs-local".to_string()
    } else {
        name.to_string()
    };
    let opts = parts.collect::<Vec<_>>().join(";");
    let opts = if opts.trim().is_empty() {
        None
    } else {
        Some(opts)
    };
    (Some(name), opts)
}

fn clash_proxy_to_item(proxy: &YamlValue, index: usize) -> Result<CheckItem> {
    let proxy_type = yaml_get_str(proxy, "type")
        .context("Clash: у прокси отсутствует type")?
        .to_ascii_lowercase();
    let server = yaml_get_str(proxy, "server")
        .filter(|s| !s.trim().is_empty())
        .context("Clash: у прокси отсутствует server")?;
    let port = yaml_get_u16(proxy, "port").context("Clash: отсутствует или неверный port")?;
    if port == 0 {
        bail!("Clash: порт не может быть 0");
    }
    let name = yaml_get_str(proxy, "name")
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("proxy-{}", index + 1));
    let network = yaml_get_str(proxy, "network")
        .or_else(|| yaml_get_str(proxy, "net"))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "tcp".to_string());
    let tls = clash_tls(proxy, &proxy_type)?;
    let transport = if proxy_type == "ss" {
        None
    } else {
        clash_transport(proxy, &network)?
    };
    ensure_quic_tls(&tls, &transport)?;
    let protocol = match proxy_type.as_str() {
        "vmess" => {
            let uuid = yaml_get_str(proxy, "uuid")
                .filter(|s| !s.trim().is_empty())
                .context("Clash vmess: отсутствует uuid")?;
            let alter_id =
                yaml_get_u16_multi(proxy, &["alterId", "alter-id", "alterid", "aid"]).unwrap_or(0);
            let security = yaml_get_str(proxy, "cipher")
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "auto".to_string());
            ProxyProtocol::Vmess {
                uuid,
                security,
                alter_id,
            }
        }
        "vless" => {
            let uuid = yaml_get_str(proxy, "uuid")
                .filter(|s| !s.trim().is_empty())
                .context("Clash vless: отсутствует uuid")?;
            let flow = yaml_get_str(proxy, "flow").filter(|s| !s.trim().is_empty());
            ProxyProtocol::Vless { uuid, flow }
        }
        "trojan" => {
            let password = yaml_get_str(proxy, "password")
                .filter(|s| !s.is_empty())
                .context("Clash trojan: отсутствует password")?;
            ProxyProtocol::Trojan { password }
        }
        "ss" => {
            let method = yaml_get_str(proxy, "cipher")
                .or_else(|| yaml_get_str(proxy, "method"))
                .filter(|s| !s.trim().is_empty())
                .context("Clash ss: отсутствует cipher/method")?;
            let password =
                yaml_get_str(proxy, "password").context("Clash ss: отсутствует password")?;
            let (plugin, plugin_opts) = clash_plugin(proxy);
            ProxyProtocol::Shadowsocks {
                method,
                password,
                plugin,
                plugin_opts,
            }
        }
        other => bail!("Clash: неподдерживаемый тип прокси {other}"),
    };
    let engine = clash_engine(proxy, &network);
    let finalmask = clash_finalmask(proxy);
    let spec = OutboundSpec {
        server,
        port,
        protocol,
        tls,
        transport,
        engine,
        finalmask,
    };
    Ok(CheckItem {
        display: format!("yaml://{} ({})", sanitize_display(&name, 90), proxy_type),
        original: yaml_list_item(proxy)?,
        spec,
    })
}

fn clash_tls(proxy: &YamlValue, proxy_type: &str) -> Result<Option<TlsSpec>> {
    if proxy_type == "ss" {
        return Ok(None);
    }
    let security = yaml_get_str(proxy, "security")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reality_value = yaml_get(proxy, "reality-opts");
    let mut enabled = proxy_type == "trojan";
    if let Some(tls_value) = yaml_get(proxy, "tls") {
        enabled = yaml_truthy(tls_value);
    }
    if matches!(security.as_str(), "tls" | "reality") || reality_value.is_some() {
        enabled = true;
    }
    if security == "none" {
        enabled = false;
    }
    if !enabled {
        return Ok(None);
    }
    let server_name = yaml_get_str(proxy, "servername")
        .or_else(|| yaml_get_str(proxy, "sni"))
        .or_else(|| yaml_get_str(proxy, "server-name"))
        .filter(|s| !s.trim().is_empty());
    let insecure = yaml_get_bool(proxy, "skip-cert-verify").unwrap_or(false);
    let alpn = yaml_string_list(proxy, "alpn");
    let fingerprint = yaml_get_str(proxy, "client-fingerprint")
        .or_else(|| yaml_get_str(proxy, "fingerprint"))
        .filter(|s| !s.trim().is_empty());
    let reality = if let Some(reality_value) = reality_value {
        let public_key = yaml_get_str(reality_value, "public-key")
            .or_else(|| yaml_get_str(reality_value, "public_key"))
            .or_else(|| yaml_get_str(reality_value, "publicKey"))
            .filter(|s| !s.trim().is_empty())
            .context("Clash reality: отсутствует public-key")?;
        let short_id = yaml_get_str(reality_value, "short-id")
            .or_else(|| yaml_get_str(reality_value, "short_id"))
            .or_else(|| yaml_get_str(reality_value, "shortId"))
            .filter(|s| !s.is_empty());
        Some(RealitySpec {
            public_key,
            short_id,
        })
    } else {
        None
    };
    if security == "reality" && reality.is_none() {
        bail!("Clash reality: отсутствует reality-opts");
    }
    Ok(Some(TlsSpec {
        server_name,
        insecure,
        alpn,
        fingerprint,
        reality,
    }))
}

fn clash_transport(proxy: &YamlValue, network: &str) -> Result<Option<TransportSpec>> {
    match network.trim().to_ascii_lowercase().as_str() {
        "" | "tcp" => Ok(None),
        "ws" => {
            let options = yaml_get(proxy, "ws-opts");
            let path = options
                .and_then(|value| yaml_first_scalar(value, "path"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            let host = options
                .and_then(|value| yaml_get(value, "headers"))
                .and_then(|headers| {
                    yaml_get_str(headers, "Host")
                        .or_else(|| yaml_get_str(headers, "host"))
                        .or_else(|| yaml_get_str(headers, "HOST"))
                })
                .filter(|s| !s.is_empty());
            Ok(Some(TransportSpec::Ws { path, host }))
        }
        "grpc" => {
            let options = yaml_get(proxy, "grpc-opts");
            let service_name = options
                .and_then(|value| {
                    yaml_get_str(value, "grpc-service-name")
                        .or_else(|| yaml_get_str(value, "service-name"))
                        .or_else(|| yaml_get_str(value, "serviceName"))
                })
                .or_else(|| yaml_get_str(proxy, "grpc-service-name"))
                .or_else(|| yaml_get_str(proxy, "serviceName"))
                .unwrap_or_default();
            Ok(Some(TransportSpec::Grpc { service_name }))
        }
        "http" | "h2" | "http2" => {
            let options = yaml_get(proxy, "h2-opts").or_else(|| yaml_get(proxy, "http-opts"));
            let path = options
                .and_then(|value| yaml_first_scalar(value, "path"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            let mut host = options
                .and_then(|value| yaml_get(value, "host"))
                .map(yaml_string_list_value)
                .unwrap_or_default();
            if host.is_empty() {
                if let Some(host_value) = yaml_get_str(proxy, "host") {
                    host = split_hosts(&host_value);
                }
            }
            Ok(Some(TransportSpec::Http { host, path }))
        }
        "httpupgrade" => {
            let options = yaml_get(proxy, "ws-opts").or_else(|| yaml_get(proxy, "http-opts"));
            let path = options
                .and_then(|value| yaml_first_scalar(value, "path"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            let host = options
                .and_then(|value| yaml_get(value, "headers"))
                .and_then(|headers| {
                    yaml_get_str(headers, "Host").or_else(|| yaml_get_str(headers, "host"))
                })
                .filter(|s| !s.is_empty());
            Ok(Some(TransportSpec::HttpUpgrade { path, host }))
        }
        "xhttp" | "splithttp" => {
            let options = yaml_get(proxy, "xhttp-opts").or_else(|| yaml_get(proxy, "ws-opts"));
            let path = options
                .and_then(|value| yaml_first_scalar(value, "path"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "/".to_string());
            let host = options
                .and_then(|value| {
                    yaml_get_str(value, "host").or_else(|| {
                        yaml_get(value, "headers").and_then(|headers| {
                            yaml_get_str(headers, "Host")
                                .or_else(|| yaml_get_str(headers, "host"))
                                .or_else(|| yaml_get_str(headers, "HOST"))
                        })
                    })
                })
                .filter(|s| !s.is_empty());
            let mode = options
                .and_then(|value| yaml_get_str(value, "mode"))
                .filter(|s| !s.trim().is_empty());
            let extra = options
                .and_then(|value| yaml_get(value, "extra"))
                .and_then(yaml_to_json)
                .filter(JsonValue::is_object);
            Ok(Some(TransportSpec::Xhttp {
                path,
                host,
                mode,
                extra,
            }))
        }
        "quic" => Ok(Some(TransportSpec::Quic)),
        other => bail!("Clash: неподдерживаемый transport/network {other}"),
    }
}

fn clash_plugin(proxy: &YamlValue) -> (Option<String>, Option<String>) {
    let Some(raw_name) = yaml_get_str(proxy, "plugin") else {
        return (None, None);
    };
    let raw_name = raw_name.trim();
    if raw_name.is_empty() {
        return (None, None);
    }
    let name = if raw_name.eq_ignore_ascii_case("obfs") {
        "obfs-local".to_string()
    } else {
        raw_name.to_string()
    };
    let opts = yaml_get(proxy, "plugin-opts").and_then(|value| clash_plugin_opts(value, &name));
    (Some(name), opts)
}

fn clash_plugin_opts(value: &YamlValue, plugin: &str) -> Option<String> {
    if let Some(raw) = value.as_str() {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Some(raw.to_string());
        }
        return None;
    }
    let mapping = value.as_mapping()?;
    let mut parts = Vec::new();
    for (key, value) in mapping {
        let Some(key) = key.as_str() else {
            continue;
        };
        if let Some(scalar) = yaml_scalar_string(value) {
            if plugin == "obfs-local" && key == "mode" {
                parts.push(format!("obfs={scalar}"));
            } else if plugin == "obfs-local" && key == "host" {
                parts.push(format!("obfs-host={scalar}"));
            } else if plugin == "v2ray-plugin" && key == "mode" {
                parts.push(format!("mode={scalar}"));
            } else {
                parts.push(format!("{key}={scalar}"));
            }
        } else if yaml_truthy(value) {
            parts.push(key.to_string());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(";"))
    }
}

fn yaml_list_item(value: &YamlValue) -> Result<String> {
    let yaml = serde_yaml::to_string(value).context("не удалось сериализовать Clash-прокси")?;
    let yaml = yaml
        .strip_prefix("---\n")
        .or_else(|| yaml.strip_prefix("---\r\n"))
        .unwrap_or(&yaml);
    let mut result = String::new();
    for (index, line) in yaml.trim_end().lines().enumerate() {
        if index == 0 {
            result.push_str("- ");
        } else {
            result.push_str("  ");
        }
        result.push_str(line);
        result.push('\n');
    }
    let result = result.trim_end().to_string();
    if result.is_empty() {
        bail!("Clash: пустое представление прокси");
    }
    Ok(result)
}

fn tls_from_query(
    query: &HashMap<String, String>,
    default_enabled: bool,
    server: &str,
) -> Result<Option<TlsSpec>> {
    let security = q_get(query, &["security"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let tls_flag = q_get(query, &["tls"]).map(|value| truthy_str(&value));
    let enabled = if security.is_empty() {
        tls_flag.unwrap_or(default_enabled)
    } else {
        !matches!(security.as_str(), "none" | "false" | "0")
    };
    if !enabled {
        return Ok(None);
    }
    let server_name = q_get(
        query,
        &["sni", "peer", "servername", "server_name", "server-name"],
    )
    .filter(|s| !s.trim().is_empty())
    .or_else(|| q_get(query, &["host"]).and_then(|host| first_host(Some(&host))))
    .or_else(|| Some(server.to_string()));
    let insecure = q_get(
        query,
        &[
            "allowinsecure",
            "insecure",
            "skip-cert-verify",
            "skip_cert_verify",
        ],
    )
    .map(|value| truthy_str(&value))
    .unwrap_or(false);
    let alpn = q_get(query, &["alpn"])
        .map(|value| split_csv(&value))
        .unwrap_or_default();
    let fingerprint =
        q_get(query, &["fp", "fingerprint", "client-fingerprint"]).filter(|s| !s.trim().is_empty());
    let reality = if security == "reality" {
        let public_key = q_get(query, &["pbk", "publickey", "public_key"])
            .filter(|s| !s.trim().is_empty())
            .context("reality: отсутствует public key (pbk)")?;
        let short_id = q_get(query, &["sid", "shortid", "short_id"]).filter(|s| !s.is_empty());
        Some(RealitySpec {
            public_key,
            short_id,
        })
    } else {
        None
    };
    Ok(Some(TlsSpec {
        server_name,
        insecure,
        alpn,
        fingerprint,
        reality,
    }))
}

fn transport_from_parts(
    network: &str,
    host: Option<&str>,
    path: Option<&str>,
    service: Option<&str>,
    mode: Option<String>,
    extra: Option<JsonValue>,
) -> Result<Option<TransportSpec>> {
    match network.trim().to_ascii_lowercase().as_str() {
        "" | "tcp" | "none" => Ok(None),
        "ws" => {
            let path = path
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_string();
            let host = host.and_then(|value| first_host(Some(value)));
            Ok(Some(TransportSpec::Ws { path, host }))
        }
        "grpc" => {
            let service_name = service
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.trim_start_matches('/').to_string())
                .or_else(|| {
                    path.map(str::trim)
                        .filter(|value| !value.is_empty() && *value != "/")
                        .map(|value| value.trim_start_matches('/').to_string())
                })
                .unwrap_or_default();
            Ok(Some(TransportSpec::Grpc { service_name }))
        }
        "http" | "h2" | "http2" => {
            let path = path
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_string();
            let host = host.map(split_hosts).unwrap_or_default();
            Ok(Some(TransportSpec::Http { host, path }))
        }
        "httpupgrade" => {
            let path = path
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_string();
            let host = host.and_then(|value| first_host(Some(value)));
            Ok(Some(TransportSpec::HttpUpgrade { path, host }))
        }
        "xhttp" | "splithttp" => {
            let path = path
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("/")
                .to_string();
            let host = host.and_then(|value| first_host(Some(value)));
            Ok(Some(TransportSpec::Xhttp {
                path,
                host,
                mode,
                extra,
            }))
        }
        "quic" => Ok(Some(TransportSpec::Quic)),
        other => bail!("неподдерживаемый транспорт: {other}"),
    }
}

// Единая точка выбора движка.
//
// Правила (проверено на Xray 26.11.9 и sing-box 1.14.4):
// * http/h2/http2/quic не поддерживаются Xray вообще -> всегда Sing-box,
//   даже если в ключе есть fragment/fm.
// * xhttp/splithttp умеет только Xray -> всегда Xray.
// * fragment/fm (finalmask) поддерживает только Xray и только для tcp/ws;
//   для остальных транспортов оставляем Sing-box.
fn engine_for_network(network: &str, xhttp: bool, masked: bool) -> Engine {
    let network = network.trim().to_ascii_lowercase();
    if matches!(network.as_str(), "http" | "h2" | "http2" | "quic") {
        return Engine::SingBox;
    }
    if xhttp {
        return Engine::Xray;
    }
    if masked && matches!(network.as_str(), "" | "tcp" | "ws") {
        return Engine::Xray;
    }
    Engine::SingBox
}

fn detect_engine(query: &HashMap<String, String>, network: &str) -> Engine {
    let xhttp = matches!(
        network.trim().to_ascii_lowercase().as_str(),
        "xhttp" | "splithttp"
    ) || q_get(query, &["type", "network", "net"])
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "xhttp" | "splithttp"
            )
        })
        .unwrap_or(false);
    let masked = ["fragment", "fm", "finalmask"].iter().any(|key| {
        query
            .get(*key)
            .is_some_and(|value| !value.trim().is_empty())
    });
    engine_for_network(network, xhttp, masked)
}

// sing-box падает с FATAL на transport=quic без TLS. Такие ключи заведомо
// нерабочие, поэтому отсеиваем их на парсинге, не запуская ядро.
fn ensure_quic_tls(tls: &Option<TlsSpec>, transport: &Option<TransportSpec>) -> Result<()> {
    if matches!(transport, Some(TransportSpec::Quic)) && tls.is_none() {
        bail!("QUIC transport требует TLS (ключ отброшен)");
    }
    Ok(())
}

fn extra_from_query(query: &HashMap<String, String>) -> Option<JsonValue> {
    let raw = query.get("extra").map(String::as_str)?.trim();
    if raw.is_empty() {
        return None;
    }
    serde_json::from_str::<JsonValue>(raw)
        .ok()
        .filter(JsonValue::is_object)
}

fn finalmask_from_query(query: &HashMap<String, String>) -> Option<JsonValue> {
    for key in ["finalmask", "fm"] {
        if let Some(raw) = query.get(key).map(String::as_str).map(str::trim) {
            if raw.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<JsonValue>(raw) {
                if value.get("tcp").is_some() || value.get("udp").is_some() {
                    return Some(value);
                }
            }
        }
    }
    query
        .get("fragment")
        .and_then(|raw| fragment_finalmask(raw))
}

// fragment=length,delay,packets[,maxSplit] -> Xray "finalmask" TCP fragment mask
fn fragment_finalmask(raw: &str) -> Option<JsonValue> {
    let raw = raw.trim();
    if raw.is_empty() || raw.eq_ignore_ascii_case("null") {
        return None;
    }
    if raw.starts_with('{') {
        return serde_json::from_str::<JsonValue>(raw)
            .ok()
            .filter(|value| value.get("tcp").is_some() || value.get("udp").is_some());
    }

    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    let mut settings = JsonMap::new();
    let length = parts.first().copied().filter(|value| !value.is_empty());
    let delay = parts.get(1).copied().filter(|value| !value.is_empty());
    let packets = parts.get(2).copied().filter(|value| !value.is_empty());
    let max_split = parts
        .get(3)
        .copied()
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("null"));

    if let Some(length) = length {
        settings.insert("length".to_string(), json!(length));
    }
    if let Some(delay) = delay {
        settings.insert("delay".to_string(), json!(delay));
    }
    if let Some(packets) = packets {
        settings.insert("packets".to_string(), json!(packets));
    }
    if let Some(max_split) = max_split {
        settings.insert("maxSplit".to_string(), json!(max_split));
    }
    if settings.is_empty() {
        return None;
    }

    Some(json!({
        "tcp": [{
            "type": "fragment",
            "settings": JsonValue::Object(settings)
        }]
    }))
}

fn engine_from_json(value: &JsonValue) -> Engine {
    let network =
        json_get_str_multi(value, &["net", "network", "type"]).unwrap_or_else(|| "tcp".to_string());
    let xhttp = matches!(
        network.trim().to_ascii_lowercase().as_str(),
        "xhttp" | "splithttp"
    );
    let masked = ["fragment", "fm", "finalmask"]
        .iter()
        .any(|key| value.get(*key).is_some());
    engine_for_network(&network, xhttp, masked)
}

fn finalmask_from_json(value: &JsonValue) -> Option<JsonValue> {
    for key in ["finalmask", "fm"] {
        let Some(field) = value.get(key) else {
            continue;
        };
        if field.is_object() && (field.get("tcp").is_some() || field.get("udp").is_some()) {
            return Some(field.clone());
        }
        if let Some(raw) = field.as_str() {
            if let Ok(parsed) = serde_json::from_str::<JsonValue>(raw) {
                if parsed.get("tcp").is_some() || parsed.get("udp").is_some() {
                    return Some(parsed);
                }
            }
        }
    }
    json_get_str_multi(value, &["fragment"]).and_then(|raw| fragment_finalmask(&raw))
}

fn json_extra_field(value: &JsonValue, key: &str) -> Option<JsonValue> {
    match value.get(key)? {
        JsonValue::Object(_) => value.get(key).cloned(),
        JsonValue::String(raw) => serde_json::from_str::<JsonValue>(raw)
            .ok()
            .filter(JsonValue::is_object),
        _ => None,
    }
}

fn yaml_to_json(value: &YamlValue) -> Option<JsonValue> {
    Some(match value {
        YamlValue::Null => JsonValue::Null,
        YamlValue::Bool(value) => json!(value),
        YamlValue::Number(number) => {
            if let Some(value) = number.as_i64() {
                json!(value)
            } else if let Some(value) = number.as_u64() {
                json!(value)
            } else {
                let value = number.as_f64()?;
                json!(value)
            }
        }
        YamlValue::String(value) => json!(value),
        YamlValue::Sequence(sequence) => {
            JsonValue::Array(sequence.iter().filter_map(yaml_to_json).collect())
        }
        YamlValue::Mapping(mapping) => {
            let mut object = JsonMap::new();
            for (key, value) in mapping {
                let key = match key {
                    YamlValue::String(value) => value.clone(),
                    other => yaml_scalar_string(other)?,
                };
                object.insert(key, yaml_to_json(value)?);
            }
            JsonValue::Object(object)
        }
        YamlValue::Tagged(tagged) => yaml_to_json(&tagged.value)?,
    })
}

fn clash_engine(proxy: &YamlValue, network: &str) -> Engine {
    let xhttp = matches!(
        network.trim().to_ascii_lowercase().as_str(),
        "xhttp" | "splithttp"
    ) || yaml_get(proxy, "xhttp-opts").is_some();
    let masked = ["fragment", "fm", "finalmask"]
        .iter()
        .any(|key| yaml_get(proxy, key).is_some());
    engine_for_network(network, xhttp, masked)
}

fn clash_finalmask(proxy: &YamlValue) -> Option<JsonValue> {
    for key in ["finalmask", "fm"] {
        let Some(value) = yaml_get(proxy, key) else {
            continue;
        };
        if let Some(raw) = value.as_str() {
            if let Ok(parsed) = serde_json::from_str::<JsonValue>(raw) {
                if parsed.get("tcp").is_some() || parsed.get("udp").is_some() {
                    return Some(parsed);
                }
            }
        } else if let Some(parsed) = yaml_to_json(value) {
            if parsed.get("tcp").is_some() || parsed.get("udp").is_some() {
                return Some(parsed);
            }
        }
    }
    yaml_get(proxy, "fragment")
        .and_then(yaml_scalar_string)
        .and_then(|raw| fragment_finalmask(&raw))
}

fn split_query_fragment(value: &str) -> (&str, Option<&str>) {
    let before_fragment = match value.find('#') {
        Some(index) => &value[..index],
        None => value,
    };
    match before_fragment.find('?') {
        Some(index) => (
            &before_fragment[..index],
            Some(&before_fragment[index + 1..]),
        ),
        None => (before_fragment, None),
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let value = value.trim();
    let value = match value.find('/') {
        Some(index) => &value[..index],
        None => value,
    };
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .context("некорректный IPv6-адрес: отсутствует ]")?;
        let port = after
            .strip_prefix(':')
            .context("некорректный IPv6-адрес: отсутствует порт")?;
        (host.to_string(), port)
    } else {
        let (host, port) = value.rsplit_once(':').context("не указан порт сервера")?;
        (host.to_string(), port)
    };
    if host.trim().is_empty() {
        bail!("пустой адрес сервера");
    }
    let port = port
        .trim()
        .parse::<u16>()
        .context("некорректный порт сервера")?;
    if port == 0 {
        bail!("порт не может быть 0");
    }
    Ok((host, port))
}

fn query_map(raw: Option<&str>) -> HashMap<String, String> {
    raw.map(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .map(|(key, value)| (key.to_ascii_lowercase(), value.into_owned()))
            .collect()
    })
    .unwrap_or_default()
}

fn q_get(query: &HashMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| query.get(*key).cloned())
        .filter(|value| !value.is_empty())
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_hosts(value: &str) -> Vec<String> {
    split_csv(value)
}

fn first_host(value: Option<&str>) -> Option<String> {
    value.and_then(|hosts| {
        hosts
            .split(',')
            .map(str::trim)
            .find(|host| !host.is_empty())
            .map(str::to_string)
    })
}

fn decode_component(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn truthy_str(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "tls" | "reality"
    )
}

fn yaml_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    value
        .as_mapping()?
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

fn yaml_scalar_string(value: &YamlValue) -> Option<String> {
    match value {
        YamlValue::String(value) => Some(value.clone()),
        YamlValue::Number(value) => Some(value.to_string()),
        YamlValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn yaml_get_str(value: &YamlValue, key: &str) -> Option<String> {
    yaml_get(value, key).and_then(yaml_scalar_string)
}

fn yaml_get_u16(value: &YamlValue, key: &str) -> Option<u16> {
    yaml_get_str(value, key).and_then(|value| value.trim().parse::<u16>().ok())
}

fn yaml_get_u16_multi(value: &YamlValue, keys: &[&str]) -> Option<u16> {
    keys.iter().find_map(|key| yaml_get_u16(value, key))
}

fn yaml_get_bool(value: &YamlValue, key: &str) -> Option<bool> {
    yaml_get(value, key).map(yaml_truthy)
}

fn yaml_truthy(value: &YamlValue) -> bool {
    match value {
        YamlValue::Bool(value) => *value,
        YamlValue::Number(value) => value.as_i64().unwrap_or(0) != 0,
        YamlValue::String(value) => truthy_str(value),
        _ => false,
    }
}

fn yaml_string_list_value(value: &YamlValue) -> Vec<String> {
    match value {
        YamlValue::String(value) => split_csv(value),
        YamlValue::Sequence(sequence) => sequence
            .iter()
            .filter_map(yaml_scalar_string)
            .flat_map(|value| split_csv(&value))
            .collect(),
        _ => Vec::new(),
    }
}

fn yaml_string_list(value: &YamlValue, key: &str) -> Vec<String> {
    yaml_get(value, key)
        .map(yaml_string_list_value)
        .unwrap_or_default()
}

fn yaml_first_scalar(value: &YamlValue, key: &str) -> Option<String> {
    match yaml_get(value, key)? {
        YamlValue::String(value) => Some(value.clone()),
        YamlValue::Sequence(sequence) => sequence.first().and_then(yaml_scalar_string),
        other => yaml_scalar_string(other),
    }
}

fn json_scalar_string(value: &JsonValue) -> Option<String> {
    match value {
        JsonValue::String(value) => Some(value.clone()),
        JsonValue::Number(value) => Some(value.to_string()),
        JsonValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn json_get_str(value: &JsonValue, key: &str) -> Option<String> {
    value.get(key).and_then(json_scalar_string)
}

fn json_get_str_multi(value: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| json_get_str(value, key))
        .filter(|value| !value.is_empty())
}

fn json_get_u16(value: &JsonValue, key: &str) -> Option<u16> {
    match value.get(key)? {
        JsonValue::Number(number) => number
            .as_u64()
            .and_then(|number| u16::try_from(number).ok()),
        JsonValue::String(value) => value.trim().parse::<u16>().ok(),
        _ => None,
    }
}

fn json_get_bool(value: &JsonValue, keys: &[&str]) -> bool {
    keys.iter()
        .find_map(|key| value.get(*key))
        .map(|value| match value {
            JsonValue::Bool(value) => *value,
            JsonValue::Number(value) => value.as_i64().unwrap_or(0) != 0,
            JsonValue::String(value) => truthy_str(value),
            _ => false,
        })
        .unwrap_or(false)
}

fn json_get_string_list(value: &JsonValue, key: &str) -> Vec<String> {
    match value.get(key) {
        Some(JsonValue::String(value)) => split_csv(value),
        Some(JsonValue::Array(values)) => values
            .iter()
            .filter_map(json_scalar_string)
            .flat_map(|value| split_csv(&value))
            .collect(),
        _ => Vec::new(),
    }
}

fn display_for_uri(uri: &str) -> String {
    sanitize_display(uri, 110)
}

fn sanitize_display(value: &str, max_chars: usize) -> String {
    let flattened = value
        .chars()
        .map(|character| match character {
            '\r' | '\n' | '\t' => ' ',
            other => other,
        })
        .collect::<String>();
    let mut result = String::new();
    for (index, character) in flattened.chars().enumerate() {
        if index >= max_chars {
            result.push_str("...");
            break;
        }
        result.push(character);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-1111-1111-1111-111111111111";

    fn parse_one(input: &str) -> CheckItem {
        let report = parse_keys(input);
        assert_eq!(report.keys.len(), 1, "expected exactly one parsed key");
        report.keys.into_iter().next().expect("one key")
    }

    fn xray_stream(item: &CheckItem) -> JsonValue {
        let config = build_xray_config(&item.spec, 23456).expect("xray config");
        config["outbounds"][0]["streamSettings"].clone()
    }

    #[test]
    fn selects_singbox_for_plain_vless() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws#plain"
        ));
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Ws { .. })
        ));
    }

    #[test]
    fn selects_xray_for_xhttp() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&sni=example.com&fp=chrome&type=xhttp&host=cdn.example.com&path=%2Fapi&mode=packet-up&extra=%7B%22noGRPCHeader%22%3Atrue%7D#xhttp"
        ));
        assert_eq!(item.spec.engine, Engine::Xray);
        match &item.spec.transport {
            Some(TransportSpec::Xhttp {
                path,
                host,
                mode,
                extra,
            }) => {
                assert_eq!(path, "/api");
                assert_eq!(host.as_deref(), Some("cdn.example.com"));
                assert_eq!(mode.as_deref(), Some("packet-up"));
                assert_eq!(
                    extra.as_ref().and_then(|value| value.get("noGRPCHeader")),
                    Some(&json!(true))
                );
            }
            other => panic!("expected XHTTP transport, got {other:?}"),
        }
    }

    #[test]
    fn selects_xray_for_splithttp_alias() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=splithttp&path=%2F#alias"
        ));
        assert_eq!(item.spec.engine, Engine::Xray);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Xhttp { .. })
        ));
    }

    #[test]
    fn selects_xray_for_fragment_only() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=tcp&fragment=3-3,0-1,tlshello,null#fragment"
        ));
        assert_eq!(item.spec.engine, Engine::Xray);
        let mask = item.spec.finalmask.expect("fragment finalmask");
        assert_eq!(mask["tcp"][0]["type"], "fragment");
        assert_eq!(mask["tcp"][0]["settings"]["length"], "3-3");
        assert_eq!(mask["tcp"][0]["settings"]["delay"], "0-1");
        assert_eq!(mask["tcp"][0]["settings"]["packets"], "tlshello");
    }

    #[test]
    fn prefers_fm_over_fragment() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=xhttp&fragment=3-3,0-1,tlshello,null&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A%7B%22length%22%3A%221-2%22%7D%7D%5D%7D#fm"
        ));
        let mask = item.spec.finalmask.expect("fm finalmask");
        assert_eq!(mask["tcp"][0]["settings"]["length"], "1-2");
    }

    #[test]
    fn parses_raw_json_fm_parameter() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?type=xhttp&security=tls&fm={{\"tcp\":[{{\"settings\":{{\"delay\":\"0-1\",\"length\":\"3-3\",\"packets\":\"tlshello\"}},\"type\":\"fragment\"}}]}}#raw"
        ));
        assert_eq!(item.spec.engine, Engine::Xray);
        assert_eq!(
            item.spec.finalmask.expect("finalmask")["tcp"][0]["type"],
            "fragment"
        );
    }

    #[test]
    fn builds_xray_xhttp_config() {
        let item = parse_one(&format!(
            "vless://{UUID}@151.101.36.111:443?encryption=none&security=tls&sni=accounts.fastly.com&alpn=h3&fp=chrome&type=xhttp&host=ovd11.global.ssl.fastly.net&path=%2F&mode=auto&extra=%7B%22noGRPCHeader%22%3Atrue%7D#xray"
        ));
        let config = build_xray_config(&item.spec, 23456).expect("xray config");
        assert_eq!(config["inbounds"][0]["port"], 23456);
        assert_eq!(config["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"],
            "none"
        );

        let stream = xray_stream(&item);
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "tls");
        assert_eq!(stream["tlsSettings"]["serverName"], "accounts.fastly.com");
        assert_eq!(stream["tlsSettings"]["fingerprint"], "chrome");
        assert_eq!(stream["tlsSettings"]["alpn"][0], "h3");
        assert_eq!(stream["xhttpSettings"]["path"], "/");
        assert_eq!(
            stream["xhttpSettings"]["host"],
            "ovd11.global.ssl.fastly.net"
        );
        assert_eq!(stream["xhttpSettings"]["mode"], "auto");
        assert_eq!(stream["xhttpSettings"]["extra"]["noGRPCHeader"], true);
    }

    #[test]
    fn builds_xray_reality_finalmask() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=XnDAJzVC-0H6QU5US4zUwjXrxoF88OA2A0zzyAALnSo&sid=12&type=tcp&fragment=3-3,0-1,tlshello#reality"
        ));
        let stream = xray_stream(&item);
        assert_eq!(stream["network"], "tcp");
        assert_eq!(stream["security"], "reality");
        assert_eq!(
            stream["realitySettings"]["publicKey"],
            "XnDAJzVC-0H6QU5US4zUwjXrxoF88OA2A0zzyAALnSo"
        );
        assert_eq!(stream["realitySettings"]["shortId"], "12");
        assert_eq!(stream["finalmask"]["tcp"][0]["type"], "fragment");
    }

    #[test]
    fn builds_xray_trojan_outbound() {
        let item = parse_one("trojan://secret@example.com:443?fragment=3-3,0-1,tlshello#trojan");
        assert_eq!(item.spec.engine, Engine::Xray);
        let config = build_xray_config(&item.spec, 23457).expect("xray config");
        assert_eq!(config["outbounds"][0]["protocol"], "trojan");
        assert_eq!(
            config["outbounds"][0]["settings"]["servers"][0]["password"],
            "secret"
        );
    }

    #[test]
    fn parses_clash_xhttp_proxy() {
        let input = concat!(
            "proxies:\n",
            "  - name: \"XHTTP node\"\n",
            "    type: vless\n",
            "    server: example.com\n",
            "    port: 443\n",
            "    uuid: 11111111-1111-1111-1111-111111111111\n",
            "    network: xhttp\n",
            "    tls: true\n",
            "    servername: example.com\n",
            "    xhttp-opts:\n",
            "      path: /api\n",
            "      host: cdn.example.com\n",
            "      mode: auto\n",
            "      extra:\n",
            "        noGRPCHeader: true\n"
        );
        let item = parse_one(input);
        assert_eq!(item.spec.engine, Engine::Xray);
        match &item.spec.transport {
            Some(TransportSpec::Xhttp {
                path,
                host,
                mode,
                extra,
            }) => {
                assert_eq!(path, "/api");
                assert_eq!(host.as_deref(), Some("cdn.example.com"));
                assert_eq!(mode.as_deref(), Some("auto"));
                assert_eq!(
                    extra.as_ref().and_then(|value| value.get("noGRPCHeader")),
                    Some(&json!(true))
                );
            }
            other => panic!("expected XHTTP transport, got {other:?}"),
        }
    }

    #[test]
    fn parses_vmess_base64_json() {
        let payload = STANDARD.encode(
            format!(
                "{{\"v\":\"2\",\"ps\":\"node\",\"add\":\"example.com\",\"port\":\"443\",\"id\":\"{UUID}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"host\":\"example.com\",\"path\":\"/ws\",\"tls\":\"tls\"}}"
            )
            .as_bytes(),
        );
        let item = parse_one(&format!("vmess://{payload}"));
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert_eq!(item.spec.server, "example.com");
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Ws { .. })
        ));
    }

    #[test]
    fn parses_ss_sip002() {
        let userinfo = STANDARD.encode("aes-256-gcm:secret");
        let item = parse_one(&format!("ss://{userinfo}@example.com:8388#ss"));
        match item.spec.protocol {
            ProxyProtocol::Shadowsocks {
                method, password, ..
            } => {
                assert_eq!(method, "aes-256-gcm");
                assert_eq!(password, "secret");
            }
            other => panic!("expected Shadowsocks, got {other:?}"),
        }
        assert_eq!(item.spec.engine, Engine::SingBox);
    }

    #[test]
    fn parses_trojan_with_encoded_password() {
        let item = parse_one("trojan://p%40ss@example.com:443?security=tls#trojan");
        match item.spec.protocol {
            ProxyProtocol::Trojan { password } => assert_eq!(password, "p@ss"),
            other => panic!("expected Trojan, got {other:?}"),
        }
    }

    #[test]
    fn parses_base64_subscription() {
        let inner = format!("vless://{UUID}@example.com:443?security=tls&type=ws#one\n");
        let encoded = STANDARD.encode(inner.as_bytes());
        let report = parse_keys(&encoded);
        assert_eq!(report.keys.len(), 1);
        assert_eq!(report.keys[0].spec.server, "example.com");
    }

    #[test]
    fn fragment_with_http_uses_singbox() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=http&path=%2Fh2&fragment=3-3,0-1,tlshello#http-fragment"
        ));
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Http { .. })
        ));
        // finalmask поддерживает только Xray, но движок обязан быть Sing-box.
        assert!(item.spec.finalmask.is_some());
    }

    #[test]
    fn fragment_with_http_json_uses_singbox() {
        let payload = STANDARD.encode(
            format!(
                "{{\"v\":\"2\",\"ps\":\"node\",\"add\":\"example.com\",\"port\":\"443\",\"id\":\"{UUID}\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"http\",\"path\":\"/h2\",\"tls\":\"tls\",\"fragment\":\"3-3,0-1,tlshello\"}}"
            )
            .as_bytes(),
        );
        let item = parse_one(&format!("vmess://{payload}"));
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Http { .. })
        ));
    }

    #[test]
    fn fragment_with_clash_http_uses_singbox() {
        let input = concat!(
            "proxies:\n",
            "  - name: \"HTTP fragment\"\n",
            "    type: vless\n",
            "    server: example.com\n",
            "    port: 443\n",
            "    uuid: 11111111-1111-1111-1111-111111111111\n",
            "    network: http\n",
            "    tls: true\n",
            "    servername: example.com\n",
            "    fragment: \"3-3,0-1,tlshello\"\n",
            "    h2-opts:\n",
            "      path: /h2\n"
        );
        let item = parse_one(input);
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Http { .. })
        ));
    }

    #[test]
    fn fragment_with_ws_stays_xray() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&fragment=3-3,0-1,tlshello#ws-fragment"
        ));
        assert_eq!(item.spec.engine, Engine::Xray);
        assert!(matches!(
            item.spec.transport,
            Some(TransportSpec::Ws { .. })
        ));
    }

    #[test]
    fn fragment_with_grpc_uses_singbox() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=svc&fragment=3-3,0-1,tlshello#grpc-fragment"
        ));
        assert_eq!(item.spec.engine, Engine::SingBox);
    }

    #[test]
    fn quic_with_tls_uses_singbox() {
        let item = parse_one(&format!(
            "vless://{UUID}@example.com:443?security=tls&sni=example.com&type=quic&fragment=3-3,0-1,tlshello#quic"
        ));
        assert_eq!(item.spec.engine, Engine::SingBox);
        assert!(matches!(item.spec.transport, Some(TransportSpec::Quic)));
        assert!(item.spec.tls.is_some());
    }

    #[test]
    fn rejects_quic_without_tls() {
        let report = parse_keys(&format!(
            "vless://{UUID}@example.com:443?security=none&type=quic#quic-no-tls"
        ));
        assert!(report.keys.is_empty());
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn rejects_clash_quic_without_tls() {
        let input = concat!(
            "proxies:\n",
            "  - name: \"QUIC without TLS\"\n",
            "    type: vless\n",
            "    server: example.com\n",
            "    port: 443\n",
            "    uuid: 11111111-1111-1111-1111-111111111111\n",
            "    network: quic\n",
            "    tls: false\n"
        );
        let report = parse_keys(input);
        assert!(report.keys.is_empty());
        assert_eq!(report.skipped, 1);
    }

    // --- Bug 6 / Bug 18: мультиплатформенная liveness-проверка -------------

    #[test]
    fn liveness_endpoints_cover_all_providers() {
        assert_eq!(
            LIVENESS_URLS,
            [
                CLOUDFLARE_LIVENESS_URL,
                GOOGLE_LIVENESS_URL,
                MICROSOFT_LIVENESS_URL,
                APPLE_LIVENESS_URL,
                FIREFOX_LIVENESS_URL,
            ]
        );
        assert_eq!(LIVENESS_URLS.len(), 5);
    }

    #[test]
    fn liveness_accepts_cloudflare_204() {
        assert!(is_liveness_ok(
            StatusCode::NO_CONTENT,
            "",
            CLOUDFLARE_LIVENESS_URL
        ));
    }

    #[test]
    fn liveness_rejects_cloudflare_403_even_with_body() {
        assert!(!is_liveness_ok(
            StatusCode::FORBIDDEN,
            "blocked",
            CLOUDFLARE_LIVENESS_URL
        ));
        assert!(!is_liveness_ok(StatusCode::OK, "", CLOUDFLARE_LIVENESS_URL));
        assert!(!is_liveness_ok(
            StatusCode::TOO_MANY_REQUESTS,
            "",
            CLOUDFLARE_LIVENESS_URL
        ));
    }

    #[test]
    fn liveness_accepts_apple_200_with_success_text() {
        let body = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
        assert!(is_liveness_ok(StatusCode::OK, body, APPLE_LIVENESS_URL));
    }

    #[test]
    fn liveness_rejects_apple_200_without_marker() {
        // Captive portal тоже может вернуть 200, поэтому одного статуса мало.
        assert!(!is_liveness_ok(
            StatusCode::OK,
            "<html>Captive Portal</html>",
            APPLE_LIVENESS_URL
        ));
    }

    #[test]
    fn liveness_checks_bodies_for_text_endpoints() {
        assert!(is_liveness_ok(
            StatusCode::OK,
            "Microsoft Connect Test",
            MICROSOFT_LIVENESS_URL
        ));
        assert!(is_liveness_ok(
            StatusCode::OK,
            "success",
            FIREFOX_LIVENESS_URL
        ));
        assert!(is_liveness_ok(
            StatusCode::NO_CONTENT,
            "",
            GOOGLE_LIVENESS_URL
        ));
    }

    #[test]
    fn liveness_rejects_wrong_status_for_text_endpoints() {
        assert!(!is_liveness_ok(
            StatusCode::NO_CONTENT,
            "success",
            FIREFOX_LIVENESS_URL
        ));
        assert!(!is_liveness_ok(
            StatusCode::FORBIDDEN,
            "Something",
            APPLE_LIVENESS_URL
        ));
    }

    #[test]
    fn liveness_rejects_unknown_endpoint() {
        assert!(!is_liveness_ok(
            StatusCode::NO_CONTENT,
            "",
            "https://example.com/generate_204"
        ));
    }

    #[test]
    fn speed_probe_downloads_only_20kb() {
        assert_eq!(SPEED_URL, "https://speed.cloudflare.com/__down?bytes=20000");
        assert_eq!(SPEED_MIN_BYTES, 10 * 1024);
        assert!(download_sufficient(SPEED_MIN_BYTES));
        assert!(!download_sufficient(SPEED_MIN_BYTES - 1));
        // Прежний тяжёлый тест (200 КБ / порог 64 КБ) больше не используется.
        assert!(!SPEED_URL.contains("bytes=200000"));
        const { assert!(SPEED_MIN_BYTES < 64 * 1024) };
    }

    // --- Bug 19: быстрый отвал мёртвых ключей ------------------------------

    #[test]
    fn request_timeout_is_five_seconds() {
        assert_eq!(REQUEST_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn test_attempts_are_two() {
        assert_eq!(TEST_ATTEMPTS, 2);
    }

    #[test]
    fn probe_client_uses_only_explicit_proxy() {
        // Клиент собирается без .no_proxy(); проверяем, что SOCKS5 URL
        // корректно парсится для любого порта.
        assert!(build_probe_client(1080).is_ok());
        assert!(build_probe_client(65535).is_ok());
    }

    // --- Bug 7: stderr ядра ------------------------------------------------

    #[test]
    fn stderr_log_path_is_per_port_in_temp_dir() {
        let path = temp_stderr_path(41000);
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("vpn-err-41000.log")
        );
        assert_eq!(
            path.parent().and_then(|parent| parent.canonicalize().ok()),
            std::env::temp_dir().canonicalize().ok()
        );
        assert_ne!(temp_stderr_path(41001), path);
    }

    #[tokio::test]
    async fn stderr_tail_keeps_only_last_lines() {
        let path =
            std::env::temp_dir().join(format!("vpn-err-test-{}-tail.log", std::process::id()));
        let mut text = String::new();
        for line in 1..=20 {
            text.push_str(&format!("line {line}\n"));
        }
        fs::write(&path, text).await.expect("write stderr log");

        let tail = read_stderr_tail(&path, 8).await.expect("stderr tail");
        assert!(tail.contains("line 20"), "tail: {tail}");
        assert!(tail.contains("line 13"), "tail: {tail}");
        assert!(!tail.contains("line 12"), "tail: {tail}");
        assert!(
            !tail.contains('\n'),
            "tail must be one console line: {tail}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stderr_tail_is_none_for_empty_log() {
        let path =
            std::env::temp_dir().join(format!("vpn-err-test-{}-empty.log", std::process::id()));
        fs::write(&path, b"").await.expect("write empty log");
        assert!(read_stderr_tail(&path, 8).await.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn temp_file_guard_removes_stderr_log() {
        let path =
            std::env::temp_dir().join(format!("vpn-err-test-{}-guard.log", std::process::id()));
        fs::write(&path, b"FATAL: boom\n").await.expect("write log");
        assert!(path.exists());
        {
            let guard = TempFileGuard::new(path.clone());
            assert_eq!(guard.path(), path.as_path());
        }
        assert!(!path.exists(), "Drop guard must delete the stderr log");
    }

    #[tokio::test]
    async fn failure_details_include_stderr_tail() {
        let path =
            std::env::temp_dir().join(format!("vpn-err-test-{}-merged.log", std::process::id()));
        fs::write(&path, b"FATAL: quic TLS required\n")
            .await
            .expect("write log");
        let guard = TempFileGuard::new(path.clone());

        let error = with_stderr_tail(anyhow!("SOCKS-порт не открылся"), Some(&guard)).await;
        let text = format!("{error:#}");
        assert!(text.contains("SOCKS-порт не открылся"), "text: {text}");
        assert!(
            text.contains("stderr: FATAL: quic TLS required"),
            "text: {text}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn failure_details_without_log_stay_unchanged() {
        let error = with_stderr_tail(anyhow!("порт не открылся"), None).await;
        assert_eq!(format!("{error:#}"), "порт не открылся");
    }

    #[test]
    fn strip_ansi_removes_color_codes() {
        assert_eq!(
            strip_ansi("\u{1b}[31mERROR\u{1b}[0m[0000] boom"),
            "ERROR[0000] boom"
        );
        assert_eq!(strip_ansi("plain text"), "plain text");
        assert_eq!(strip_ansi(""), "");
    }
}
