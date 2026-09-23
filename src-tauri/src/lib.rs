use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crossbeam_channel::{unbounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use ssh2::{CheckResult, KnownHostFileKind, Session};
use std::{
    collections::HashMap,
    fs,
    io::{ErrorKind, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tauri::{AppHandle, Emitter, State};

const SERVICE: &str = "com.relay.terminal";
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectRequest {
    session_id: String,
    connection_id: String,
    host: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: Option<String>,
    accept_new_host_key: bool,
    replace_changed_host_key: bool,
    cols: u32,
    rows: u32,
}
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SerialConnectRequest {
    session_id: String,
    device: String,
    baud_rate: u32,
    data_bits: u8,
    parity: String,
    stop_bits: u8,
    flow_control: String,
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalEvent {
    session_id: String,
    kind: String,
    data: Option<String>,
    message: Option<String>,
    fingerprint: Option<String>,
}
enum Command {
    Input(Vec<u8>),
    Resize(u32, u32),
    ListDirectory(String),
    Close,
}
#[derive(Default)]
struct Registry(Mutex<HashMap<String, Sender<Command>>>);
#[derive(Clone, Default)]
struct CredentialCache(Arc<Mutex<HashMap<String, String>>>);
#[derive(Serialize)]
struct RemoteEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
}
#[derive(Serialize)]
struct DirectoryListing {
    path: String,
    entries: Vec<RemoteEntry>,
}
fn event(
    app: &AppHandle,
    id: &str,
    kind: &str,
    data: Option<String>,
    message: Option<String>,
    fingerprint: Option<String>,
) {
    let _ = app.emit(
        "terminal-event",
        TerminalEvent {
            session_id: id.into(),
            kind: kind.into(),
            data,
            message,
            fingerprint,
        },
    );
}
fn known_hosts() -> Result<PathBuf, String> {
    let dir = dirs::home_dir()
        .ok_or("Cannot locate home directory")?
        .join(".ssh");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("known_hosts"))
}
fn verify(ssh: &Session, r: &ConnectRequest) -> Result<(), String> {
    let (key, key_type) = ssh.host_key().ok_or("Server sent no host key")?;
    let fingerprint = ssh
        .host_key_hash(ssh2::HashType::Sha256)
        .map(|v| B64.encode(v))
        .unwrap_or_else(|| B64.encode(key));
    let path = known_hosts()?;
    let mut hosts = ssh.known_hosts().map_err(|e| e.to_string())?;
    if path.exists() {
        hosts
            .read_file(&path, KnownHostFileKind::OpenSSH)
            .map_err(|e| e.to_string())?;
    }
    match hosts.check_port(&r.host, r.port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch if r.replace_changed_host_key => {
            for old in hosts.iter().map_err(|e| e.to_string())? {
                let line = hosts
                    .write_string(&old, KnownHostFileKind::OpenSSH)
                    .unwrap_or_default();
                let old_key = line
                    .split_whitespace()
                    .nth(2)
                    .and_then(|value| B64.decode(value).ok());
                if old_key.as_deref().is_some_and(|value| {
                    matches!(hosts.check_port(&r.host, r.port, value), CheckResult::Match)
                }) {
                    hosts.remove(&old).map_err(|e| e.to_string())?;
                }
            }
            hosts
                .add(
                    &format!("[{}]:{}", r.host, r.port),
                    key,
                    "Relay replaced after user confirmation",
                    key_type.into(),
                )
                .map_err(|e| e.to_string())?;
            hosts
                .write_file(&path, KnownHostFileKind::OpenSSH)
                .map_err(|e| e.to_string())
        }
        CheckResult::Mismatch => Err(format!("HOST_KEY_CHANGED:{fingerprint}")),
        CheckResult::NotFound if r.accept_new_host_key => {
            hosts
                .add(
                    &format!("[{}]:{}", r.host, r.port),
                    key,
                    "Relay",
                    key_type.into(),
                )
                .map_err(|e| e.to_string())?;
            hosts
                .write_file(&path, KnownHostFileKind::OpenSSH)
                .map_err(|e| e.to_string())
        }
        CheckResult::NotFound => Err(format!("UNKNOWN_HOST_KEY:{fingerprint}")),
        CheckResult::Failure => Err("Host-key verification failed".into()),
    }
}
fn cached_secret(cache: &CredentialCache, id: &str) -> Result<Option<String>, String> {
    let mut credentials = cache.0.lock().map_err(|_| "Credential cache unavailable")?;
    if let Some(secret) = credentials.get(id).cloned() {
        return Ok(Some(secret));
    }
    match keyring::Entry::new(SERVICE, id)
        .map_err(|e| e.to_string())?
        .get_password()
    {
        Ok(secret) => {
            credentials.insert(id.to_string(), secret.clone());
            Ok(Some(secret))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => Err(format!("Cannot read the system keychain: {error}")),
    }
}
fn auth(ssh: &Session, r: &ConnectRequest, cache: &CredentialCache) -> Result<(), String> {
    match r.auth_method.as_str() {
        "password" => {
            let s = cached_secret(cache, &r.connection_id)?
                .ok_or("No password saved in the system keychain")?;
            ssh.userauth_password(&r.username, &s)
                .map_err(|e| format!("Password authentication failed: {e}"))?
        }
        "key" => {
            let p = r
                .key_path
                .as_ref()
                .ok_or("No private-key path configured")?;
            let expanded =
                if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
                    dirs::home_dir()
                        .ok_or("Cannot locate home directory")?
                        .join(rest)
                } else {
                    PathBuf::from(p)
                };
            let pass = cached_secret(cache, &r.connection_id)?;
            ssh.userauth_pubkey_file(&r.username, None, &expanded, pass.as_deref())
                .map_err(|e| format!("Key authentication failed: {e}"))?
        }
        "agent" => ssh
            .userauth_agent(&r.username)
            .map_err(|e| format!("Agent authentication failed: {e}"))?,
        _ => return Err("Unsupported authentication method".into()),
    };
    if ssh.authenticated() {
        Ok(())
    } else {
        Err("Server rejected authentication".into())
    }
}
fn list_directory(ssh: &Session, requested: &str) -> Result<DirectoryListing, String> {
    let sftp = ssh.sftp().map_err(|e| format!("Cannot start SFTP: {e}"))?;
    let requested_path = std::path::Path::new(if requested.is_empty() { "." } else { requested });
    let resolved = sftp
        .realpath(requested_path)
        .map_err(|e| format!("Cannot open directory: {e}"))?;
    let mut entries = sftp
        .readdir(&resolved)
        .map_err(|e| format!("Cannot list directory: {e}"))?
        .into_iter()
        .filter_map(|(path, stat)| {
            let name = path.file_name()?.to_string_lossy().to_string();
            if name == "." || name == ".." {
                return None;
            }
            let is_dir = stat.perm.is_some_and(|mode| mode & 0o170000 == 0o040000);
            Some(RemoteEntry {
                name,
                path: path.to_string_lossy().to_string(),
                is_dir,
                size: stat.size.unwrap_or(0),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(DirectoryListing {
        path: resolved.to_string_lossy().to_string(),
        entries,
    })
}
fn worker(
    app: AppHandle,
    r: ConnectRequest,
    rx: Receiver<Command>,
    credentials: CredentialCache,
) -> Result<(), String> {
    let address = format!("{}:{}", r.host, r.port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .next()
        .ok_or("Host did not resolve")?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(12))
        .map_err(|e| format!("Connection failed: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut ssh = Session::new().map_err(|e| e.to_string())?;
    ssh.set_tcp_stream(tcp);
    ssh.handshake()
        .map_err(|e| format!("Handshake failed: {e}"))?;
    verify(&ssh, &r)?;
    auth(&ssh, &r, &credentials)?;
    let mut channel = ssh.channel_session().map_err(|e| e.to_string())?;
    channel
        .request_pty("xterm-256color", None, Some((r.cols, r.rows, 0, 0)))
        .map_err(|e| e.to_string())?;
    channel.shell().map_err(|e| e.to_string())?;
    ssh.set_blocking(false);
    event(&app, &r.session_id, "connected", None, None, None);
    let mut buf = [0u8; 16384];
    loop {
        while let Ok(cmd) = rx.try_recv() {
            match cmd {
                Command::Input(v) => {
                    channel.write_all(&v).map_err(|e| e.to_string())?;
                    let _ = channel.flush();
                }
                Command::Resize(c, rows) => channel
                    .request_pty_size(c, rows, None, None)
                    .map_err(|e| e.to_string())?,
                Command::ListDirectory(path) => {
                    ssh.set_blocking(true);
                    let listing = list_directory(&ssh, &path);
                    ssh.set_blocking(false);
                    match listing {
                        Ok(value) => event(
                            &app,
                            &r.session_id,
                            "directory",
                            serde_json::to_string(&value).ok(),
                            None,
                            None,
                        ),
                        Err(message) => event(
                            &app,
                            &r.session_id,
                            "directoryError",
                            None,
                            Some(message),
                            None,
                        ),
                    }
                }
                Command::Close => {
                    channel.close().ok();
                    return Ok(());
                }
            }
        }
        match channel.read(&mut buf) {
            Ok(0) if channel.eof() => return Ok(()),
            Ok(0) => thread::sleep(Duration::from_millis(8)),
            Ok(n) => event(
                &app,
                &r.session_id,
                "data",
                Some(B64.encode(&buf[..n])),
                None,
                None,
            ),
            Err(e) if e.kind() == ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(8)),
            Err(e) => return Err(format!("Read failed: {e}")),
        }
    }
}
fn serial_worker(
    app: AppHandle,
    request: SerialConnectRequest,
    rx: Receiver<Command>,
) -> Result<(), String> {
    use serialport::{DataBits, FlowControl, Parity, StopBits};

    let data_bits = match request.data_bits {
        5 => DataBits::Five,
        6 => DataBits::Six,
        7 => DataBits::Seven,
        8 => DataBits::Eight,
        _ => return Err("Serial data bits must be between 5 and 8".into()),
    };
    let parity = match request.parity.as_str() {
        "none" => Parity::None,
        "odd" => Parity::Odd,
        "even" => Parity::Even,
        _ => return Err("Unsupported serial parity setting".into()),
    };
    let stop_bits = match request.stop_bits {
        1 => StopBits::One,
        2 => StopBits::Two,
        _ => return Err("Serial stop bits must be 1 or 2".into()),
    };
    let flow_control = match request.flow_control.as_str() {
        "none" => FlowControl::None,
        "software" => FlowControl::Software,
        "hardware" => FlowControl::Hardware,
        _ => return Err("Unsupported serial flow-control setting".into()),
    };
    let mut port = serialport::new(&request.device, request.baud_rate)
        .data_bits(data_bits)
        .parity(parity)
        .stop_bits(stop_bits)
        .flow_control(flow_control)
        .timeout(Duration::from_millis(20))
        .open()
        .map_err(|e| format!("Cannot open serial port {}: {e}", request.device))?;

    event(&app, &request.session_id, "connected", None, None, None);
    let mut buf = [0u8; 16384];
    loop {
        while let Ok(command) = rx.try_recv() {
            match command {
                Command::Input(value) => {
                    port.write_all(&value)
                        .map_err(|e| format!("Serial write failed: {e}"))?;
                    port.flush().ok();
                }
                Command::Resize(_, _) => {}
                Command::ListDirectory(_) => event(
                    &app,
                    &request.session_id,
                    "directoryError",
                    None,
                    Some("File Explorer is only available for SSH sessions".into()),
                    None,
                ),
                Command::Close => return Ok(()),
            }
        }
        match port.read(&mut buf) {
            Ok(0) => thread::sleep(Duration::from_millis(4)),
            Ok(count) => event(
                &app,
                &request.session_id,
                "data",
                Some(B64.encode(&buf[..count])),
                None,
                None,
            ),
            Err(error)
                if error.kind() == ErrorKind::TimedOut || error.kind() == ErrorKind::WouldBlock => {
            }
            Err(error) => return Err(format!("Serial read failed: {error}")),
        }
    }
}
#[tauri::command]
fn connect_ssh(
    app: AppHandle,
    registry: State<Registry>,
    credentials: State<CredentialCache>,
    request: ConnectRequest,
) -> Result<(), String> {
    let (tx, rx) = unbounded();
    registry
        .0
        .lock()
        .map_err(|_| "Registry unavailable")?
        .insert(request.session_id.clone(), tx);
    let id = request.session_id.clone();
    let credential_cache = credentials.inner().clone();
    thread::spawn(move || {
        if let Err(m) = worker(app.clone(), request, rx, credential_cache) {
            let (k, f) = if let Some(v) = m.strip_prefix("UNKNOWN_HOST_KEY:") {
                ("unknownHost", Some(v.into()))
            } else if let Some(v) = m.strip_prefix("HOST_KEY_CHANGED:") {
                ("hostKeyChanged", Some(v.into()))
            } else {
                ("error", None)
            };
            event(&app, &id, k, None, Some(m), f)
        }
        event(&app, &id, "closed", None, None, None);
    });
    Ok(())
}
#[tauri::command]
fn connect_serial(
    app: AppHandle,
    registry: State<Registry>,
    request: SerialConnectRequest,
) -> Result<(), String> {
    let (tx, rx) = unbounded();
    registry
        .0
        .lock()
        .map_err(|_| "Registry unavailable")?
        .insert(request.session_id.clone(), tx);
    let id = request.session_id.clone();
    thread::spawn(move || {
        if let Err(message) = serial_worker(app.clone(), request, rx) {
            event(&app, &id, "error", None, Some(message), None);
        }
        event(&app, &id, "closed", None, None, None);
    });
    Ok(())
}
#[tauri::command]
fn list_serial_ports() -> Result<Vec<String>, String> {
    let mut ports = serialport::available_ports()
        .map_err(|e| format!("Cannot enumerate serial ports: {e}"))?
        .into_iter()
        .map(|port| port.port_name)
        .filter(|port| {
            #[cfg(target_os = "macos")]
            {
                let name = port.to_lowercase();
                return port.starts_with("/dev/cu.")
                    && !name.contains("bluetooth-incoming-port")
                    && !name.contains("debug-console");
            }
            #[cfg(not(target_os = "macos"))]
            {
                true
            }
        })
        .collect::<Vec<_>>();
    ports.sort_by_key(|port| port.to_lowercase());
    Ok(ports)
}
fn send(reg: &State<Registry>, id: &str, c: Command) -> Result<(), String> {
    reg.0
        .lock()
        .map_err(|_| "Registry unavailable")?
        .get(id)
        .ok_or("Session is not running")?
        .send(c)
        .map_err(|_| "Session closed".into())
}
#[tauri::command]
fn terminal_input(
    registry: State<Registry>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    send(
        &registry,
        &session_id,
        Command::Input(B64.decode(data).map_err(|e| e.to_string())?),
    )
}
#[tauri::command]
fn resize_terminal(
    registry: State<Registry>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    send(&registry, &session_id, Command::Resize(cols, rows))
}
#[tauri::command]
fn list_remote_directory(
    registry: State<Registry>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    send(&registry, &session_id, Command::ListDirectory(path))
}
#[tauri::command]
fn close_session(registry: State<Registry>, session_id: String) -> Result<(), String> {
    let result = send(&registry, &session_id, Command::Close);
    if let Ok(mut m) = registry.0.lock() {
        m.remove(&session_id);
    }
    result
}
#[tauri::command]
fn save_credential(
    credentials: State<CredentialCache>,
    id: String,
    secret: String,
) -> Result<(), String> {
    keyring::Entry::new(SERVICE, &id)
        .map_err(|e| e.to_string())?
        .set_password(&secret)
        .map_err(|e| e.to_string())?;
    credentials
        .0
        .lock()
        .map_err(|_| "Credential cache unavailable")?
        .insert(id, secret);
    Ok(())
}
#[tauri::command]
fn delete_credential(credentials: State<CredentialCache>, id: String) -> Result<(), String> {
    let result = keyring::Entry::new(SERVICE, &id)
        .map_err(|e| e.to_string())?
        .delete_credential()
        .map_err(|e| e.to_string());
    if let Ok(mut cache) = credentials.0.lock() {
        cache.remove(&id);
    }
    result
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Registry::default())
        .manage(CredentialCache::default())
        .invoke_handler(tauri::generate_handler![
            connect_ssh,
            connect_serial,
            list_serial_ports,
            terminal_input,
            resize_terminal,
            list_remote_directory,
            close_session,
            save_credential,
            delete_credential
        ])
        .run(tauri::generate_context!())
        .expect("Relay failed")
}
