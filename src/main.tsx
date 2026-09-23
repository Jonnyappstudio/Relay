import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import "./styles.css";
import "./extras.css";

type Auth = "agent" | "password" | "key";
type ConnectionType = "ssh" | "serial";
type Status = "connecting" | "connected" | "closed" | "error";
type Conn = {
  id: string; name: string; folder: string; connectionType?: ConnectionType;
  host: string; port: number; user: string; authMethod: Auth; keyPath?: string;
  serialPort?: string; baudRate?: number; dataBits?: number; parity?: "none" | "odd" | "even";
  stopBits?: number; flowControl?: "none" | "software" | "hardware";
};
type Cmd = { id: string; name: string; command: string; uses: number; usesByConnection?: Record<string, number>; connectionId?: string; favorite?: boolean };
type Sess = { id: string; connection: Conn; status: Status };
type TermEvent = { sessionId: string; kind: string; data?: string; message?: string; fingerprint?: string };
type FolderDialog = { mode: "create" | "rename" | "delete"; folder?: string };
type HostIssue = { sessionId: string; kind: "unknownHost" | "hostKeyChanged"; fingerprint: string };
type AuthIssue = { sessionId: string; message: string };
type RemoteEntry = { name: string; path: string; is_dir: boolean; size: number };
type DirectoryListing = { path: string; entries: RemoteEntry[] };
type ExplorerState = DirectoryListing & { loading: boolean; error?: string };

const native = () => "__TAURI_INTERNALS__" in window;
const connectionTypeOf = (connection: Conn): ConnectionType => connection.connectionType || "ssh";
const connectionEndpoint = (connection: Conn) => connectionTypeOf(connection) === "serial"
  ? `${connection.serialPort || "Serial port"} · ${connection.baudRate || 115200} baud`
  : `${connection.user}@${connection.host}`;
const load = <T,>(key: string, fallback: T): T => {
  try { return JSON.parse(localStorage.getItem(`relay.${key}`) || "null") || fallback; }
  catch { return fallback; }
};
const encode = (value: string) => {
  let raw = "";
  new TextEncoder().encode(value).forEach(byte => raw += String.fromCharCode(byte));
  return btoa(raw);
};
const decode = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const shellQuote = (value: string) => `'${value.replaceAll("'", `'"'"'`)}'`;
const containsSensitiveMaterial = (command: string) => [
  /\b(pass(word)?|passwd|token|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*\S+/i,
  /(^|\s)(--password|--token|--secret|--api-key)(=|\s+)\S+/i,
  /\bsshpass\b/i,
  /\bcurl\b.*(^|\s)(-u|--user)\s+\S+:\S+/i,
  /\b(export|set)\s+\w*(PASS|TOKEN|SECRET|KEY)\w*\s*=\s*\S+/i,
  /^\s*(passwd|chpasswd)\b/i,
  /\b(mysql|mysqldump)\b.*\s-p\S+/i,
  /:\/\/[^\s/:]+:[^\s/@]+@/i
].some(pattern => pattern.test(command));

function migrateLegacyData() {
  const legacyNames = new Set(["Production", "Staging", "Personal", "Unsorted"]);
  let connections = load<Conn[]>("connections", []).filter(connection => !connection.id.startsWith("demo-"));
  let folders = load<string[]>("folders", []);
  if (Number(localStorage.getItem("relay.dataVersion") || 0) < 4) {
    connections = connections.map(connection => legacyNames.has(connection.folder) ? { ...connection, folder: "" } : connection);
    folders = folders.filter(folder => !legacyNames.has(folder));
    localStorage.setItem("relay.connections", JSON.stringify(connections));
    localStorage.setItem("relay.folders", JSON.stringify(folders));
    localStorage.setItem("relay.dataVersion", "4");
  }
  return { connections, folders };
}

const startupData = migrateLegacyData();
function loadSafeCommands() {
  let commands = load<Cmd[]>("commands", []).filter(command => !["c1", "c2", "c3"].includes(command.id) && !containsSensitiveMaterial(command.command));
  if (Number(localStorage.getItem("relay.commandPrivacyVersion") || 0) < 1) {
    commands = commands.filter(command => !(command.favorite === false && Boolean(command.connectionId) && command.name === command.command));
    localStorage.setItem("relay.commands", JSON.stringify(commands));
    localStorage.setItem("relay.commandPrivacyVersion", "1");
  }
  return commands;
}

function TerminalView({ session, visible, reconnect, setStatus, onHistory }: {
  session: Sess;
  visible: boolean;
  reconnect: (replaceChanged: boolean, acceptNew: boolean) => void;
  setStatus: (status: Status) => void;
  onHistory: (commands: string[]) => void;
}) {
  const element = useRef<HTMLDivElement>(null);
  const fit = useRef<FitAddon>();

  useEffect(() => {
    if (!element.current) return;
    const terminal = new Terminal({
      cursorBlink: true, scrollback: 8000, fontFamily: "DM Mono, monospace", fontSize: 13,
      theme: { background: "#101416", foreground: "#c8cfcc", cursor: "#57d49b" }
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(element.current);
    fitAddon.fit();
    fit.current = fitAddon;
    terminal.writeln(`\x1b[32mConnecting to ${connectionEndpoint(session.connection)}…\x1b[0m`);

    const input = terminal.onData(data => {
      if (native()) invoke("terminal_input", { sessionId: session.id, data: encode(data) }).catch(() => {});
    });
    const resize = terminal.onResize(size => {
      if (native()) invoke("resize_terminal", { sessionId: session.id, cols: size.cols, rows: size.rows }).catch(() => {});
    });
    const observer = new ResizeObserver(() => fitAddon.fit());
    observer.observe(element.current);
    let stop: (() => void) | undefined;
    const outputDecoder = new TextDecoder();
    let scanBuffer = "";

    listen<TermEvent>("terminal-event", ({ payload }) => {
      if (payload.sessionId !== session.id) return;
      if (payload.kind === "data" && payload.data) {
        const output = decode(payload.data);
        terminal.write(output);
        scanBuffer += outputDecoder.decode(output, { stream: true });
        const beginMarker = "\u001eRELAY_HISTORY_BEGIN\u001f";
        const endMarker = "\u001eRELAY_HISTORY_END\u001f";
        const begin = scanBuffer.indexOf(beginMarker);
        const end = begin >= 0 ? scanBuffer.indexOf(endMarker, begin + beginMarker.length) : -1;
        if (begin >= 0 && end >= 0) {
          const history = scanBuffer.slice(begin + beginMarker.length, end);
          const commands = history.split(/\r?\n/).map(line => line.replace(/^\s*\d+\s+/, "").trim()).filter(Boolean);
          onHistory(commands);
          scanBuffer = scanBuffer.slice(end + endMarker.length);
        } else if (begin < 0 && scanBuffer.length > 4096) {
          scanBuffer = scanBuffer.slice(-4096);
        }
      }
      if (payload.kind === "connected") setStatus("connected");
      if (payload.kind === "error") {
        setStatus("error");
        terminal.writeln(`\r\n\x1b[31m${payload.message}\x1b[0m`);
      }
      if (payload.kind === "unknownHost") terminal.writeln("\r\n\x1b[33mWaiting for host-key confirmation…\x1b[0m");
      if (payload.kind === "hostKeyChanged") terminal.writeln("\r\n\x1b[31mThe saved host key differs. Review the security prompt.\x1b[0m");
    }).then(unlisten => stop = unlisten);

    return () => { stop?.(); observer.disconnect(); input.dispose(); resize.dispose(); terminal.dispose(); };
  }, [session.id]);

  useEffect(() => { if (visible) setTimeout(() => fit.current?.fit(), 0); }, [visible]);
  return <div ref={element} className="term" style={{ display: visible ? "block" : "none" }} />;
}

function App() {
  const [connections, setConnections] = useState(startupData.connections);
  const [folders, setFolders] = useState(startupData.folders);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => load("collapsedFolders", {}));
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null);
  const [commands, setCommands] = useState<Cmd[]>(loadSafeCommands);
  const [commandTab, setCommandTab] = useState<"favorites" | "used">("favorites");
  const [commandDialog, setCommandDialog] = useState<{ command?: Cmd }>();
  const [historySyncing, setHistorySyncing] = useState(false);
  const [sessions, setSessions] = useState<Sess[]>([]);
  const [activeId, setActiveId] = useState<string>();
  const [leftOpen, setLeftOpen] = useState(true);
  const [rightOpen, setRightOpen] = useState(true);
  const [leftView, setLeftView] = useState<"connections" | "explorer">("connections");
  const [explorerSessionId, setExplorerSessionId] = useState<string>();
  const [explorers, setExplorers] = useState<Record<string, ExplorerState>>({});
  const [search, setSearch] = useState("");
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<Conn>();
  const [connectionType, setConnectionType] = useState<ConnectionType>("ssh");
  const [serialPorts, setSerialPorts] = useState<string[]>([]);
  const [serialPortsLoading, setSerialPortsLoading] = useState(false);
  const [draggedId, setDraggedId] = useState<string>();
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [folderDialog, setFolderDialog] = useState<FolderDialog>();
  const [hostIssue, setHostIssue] = useState<HostIssue>();
  const [authIssue, setAuthIssue] = useState<AuthIssue>();
  const [error, setError] = useState("");
  const [availableUpdate, setAvailableUpdate] = useState<Update>();
  const [updateChecking, setUpdateChecking] = useState(false);
  const [updateInstalling, setUpdateInstalling] = useState(false);
  const [updateProgress, setUpdateProgress] = useState(0);
  const active = sessions.find(session => session.id === activeId);

  useEffect(() => {
    if (!native()) return;
    const timer = window.setTimeout(() => checkForUpdates(true), 1800);
    return () => window.clearTimeout(timer);
  }, []);
  useEffect(() => localStorage.setItem("relay.connections", JSON.stringify(connections)), [connections]);
  useEffect(() => localStorage.setItem("relay.folders", JSON.stringify(folders)), [folders]);
  useEffect(() => localStorage.setItem("relay.collapsedFolders", JSON.stringify(collapsed)), [collapsed]);
  useEffect(() => localStorage.setItem("relay.commands", JSON.stringify(commands)), [commands]);
  useEffect(() => {
    let stop: (() => void) | undefined;
    listen<TermEvent>("terminal-event", ({ payload }) => {
      if ((payload.kind === "unknownHost" || payload.kind === "hostKeyChanged") && payload.fingerprint) {
        setHostIssue({ sessionId: payload.sessionId, kind: payload.kind, fingerprint: payload.fingerprint });
        setSessions(items => items.map(item => item.id === payload.sessionId ? { ...item, status: "error" } : item));
      }
      if (payload.kind === "error" && payload.message && /authentication failed|no password saved|no private-key path|server rejected authentication/i.test(payload.message)) {
        setAuthIssue({ sessionId: payload.sessionId, message: payload.message });
      }
      if (payload.kind === "connected") {
        setSessions(items => {
          const session = items.find(item => item.id === payload.sessionId);
          if (session && connectionTypeOf(session.connection) === "ssh") {
            setLeftView("explorer");
            setExplorerSessionId(payload.sessionId);
            loadRemoteDirectory(payload.sessionId, ".");
          }
          return items;
        });
      }
      if (payload.kind === "directory" && payload.data) {
        const listing = JSON.parse(payload.data) as DirectoryListing;
        setExplorers(items => ({ ...items, [payload.sessionId]: { ...listing, loading: false } }));
      }
      if (payload.kind === "directoryError") {
        setExplorers(items => ({ ...items, [payload.sessionId]: { path: items[payload.sessionId]?.path || ".", entries: items[payload.sessionId]?.entries || [], loading: false, error: payload.message || "Unable to list directory" } }));
      }
    }).then(unlisten => stop = unlisten);
    return () => stop?.();
  }, []);

  async function checkForUpdates(silent = false) {
    if (!native() || updateChecking || updateInstalling) return;
    setUpdateChecking(true);
    try {
      const update = await check({ timeout: 10000 });
      if (update) setAvailableUpdate(update);
      else if (!silent) setError("Relay is up to date.");
    } catch (reason) {
      if (!silent) setError(`Could not check for updates: ${String(reason)}`);
    } finally {
      setUpdateChecking(false);
    }
  }

  async function installAvailableUpdate() {
    if (!availableUpdate || updateInstalling) return;
    setUpdateInstalling(true);
    setUpdateProgress(0);
    let downloaded = 0;
    let total = 0;
    try {
      await availableUpdate.downloadAndInstall(event => {
        if (event.event === "Started") total = event.data.contentLength || 0;
        if (event.event === "Progress") downloaded += event.data.chunkLength;
        if (event.event === "Finished") setUpdateProgress(100);
        else if (total) setUpdateProgress(Math.min(99, Math.round(downloaded / total * 100)));
      });
      await relaunch();
    } catch (reason) {
      setUpdateInstalling(false);
      setError(`Update failed: ${String(reason)}`);
    }
  }

  async function start(session: Sess, replaceChanged = false, acceptNew = false) {
    setSessions(items => items.map(item => item.id === session.id ? { ...item, status: "connecting" } : item));
    if (!native()) { setError("Run the Relay desktop app to open connections."); return; }
    try {
      if (connectionTypeOf(session.connection) === "serial") {
        await invoke("connect_serial", { request: {
          sessionId: session.id,
          device: session.connection.serialPort,
          baudRate: session.connection.baudRate || 115200,
          dataBits: session.connection.dataBits || 8,
          parity: session.connection.parity || "none",
          stopBits: session.connection.stopBits || 1,
          flowControl: session.connection.flowControl || "none"
        }});
      } else {
        await invoke("connect_ssh", { request: {
          sessionId: session.id, connectionId: session.connection.id, host: session.connection.host,
          port: session.connection.port, username: session.connection.user,
          authMethod: session.connection.authMethod, keyPath: session.connection.keyPath || null,
          acceptNewHostKey: acceptNew, replaceChangedHostKey: replaceChanged, cols: 80, rows: 24
        }});
      }
    } catch (reason) { setError(String(reason)); }
  }

  function connect(connection: Conn) {
    const existing = sessions.find(session => session.connection.id === connection.id && session.status !== "closed");
    if (existing) {
      setActiveId(existing.id);
      if (existing.status === "connected" && connectionTypeOf(existing.connection) === "ssh") {
        setLeftView("explorer");
        setExplorerSessionId(existing.id);
        loadRemoteDirectory(existing.id, explorers[existing.id]?.path || ".");
      }
      return;
    }
    const session: Sess = { id: crypto.randomUUID(), connection, status: "connecting" };
    setSessions(items => [...items, session]);
    setActiveId(session.id);
    start(session);
  }

  async function closeSession(id: string) {
    if (native()) await invoke("close_session", { sessionId: id }).catch(() => {});
    const remaining = sessions.filter(session => session.id !== id);
    setSessions(remaining);
    if (activeId === id) setActiveId(remaining.at(-1)?.id);
  }

  async function loadRemoteDirectory(sessionId: string, path: string) {
    const session = sessions.find(item => item.id === sessionId);
    if (session && connectionTypeOf(session.connection) !== "ssh") {
      setError("File Explorer is only available for SSH connections.");
      return;
    }
    setExplorers(items => ({ ...items, [sessionId]: { path, entries: items[sessionId]?.entries || [], loading: true } }));
    try { await invoke("list_remote_directory", { sessionId, path }); }
    catch (reason) { setExplorers(items => ({ ...items, [sessionId]: { path, entries: items[sessionId]?.entries || [], loading: false, error: String(reason) } })); }
  }

  async function openExplorerPathInTerminal() {
    if (!explorerSession || explorerSession.status !== "connected" || !explorer?.path) {
      setError("Connect a session and choose a folder first.");
      return;
    }
    try {
      setActiveId(explorerSession.id);
      await invoke("terminal_input", {
        sessionId: explorerSession.id,
        data: encode(`cd ${shellQuote(explorer.path)}\r`)
      });
    } catch (reason) {
      setError(`Could not change the terminal directory: ${String(reason)}`);
    }
  }

  function openNewConnection() {
    setEditing(undefined);
    setConnectionType("ssh");
    setModalOpen(true);
  }

  async function refreshSerialPorts() {
    if (!native()) return;
    setSerialPortsLoading(true);
    try {
      setSerialPorts(await invoke<string[]>("list_serial_ports"));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setSerialPortsLoading(false);
    }
  }

  function editConnection(connection: Conn) {
    const type = connectionTypeOf(connection);
    setEditing(connection);
    setConnectionType(type);
    setModalOpen(true);
    if (type === "serial") refreshSerialPorts();
  }

  async function saveConnection(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const id = editing?.id || crypto.randomUUID();
    const type = String(data.get("connectionType")) as ConnectionType;
    const connection: Conn = {
      id, name: String(data.get("name")), folder: String(data.get("folder")), connectionType: type,
      host: type === "ssh" ? String(data.get("host")) : "",
      port: type === "ssh" ? Number(data.get("port")) : 22,
      user: type === "ssh" ? String(data.get("user")) : "",
      authMethod: type === "ssh" ? String(data.get("auth")) as Auth : "password",
      keyPath: type === "ssh" ? String(data.get("keyPath") || "") || undefined : undefined,
      serialPort: type === "serial" ? String(data.get("serialPort")).trim() : undefined,
      baudRate: type === "serial" ? Number(data.get("baudRate")) : undefined,
      dataBits: type === "serial" ? Number(data.get("dataBits")) : undefined,
      parity: type === "serial" ? String(data.get("parity")) as Conn["parity"] : undefined,
      stopBits: type === "serial" ? Number(data.get("stopBits")) : undefined,
      flowControl: type === "serial" ? String(data.get("flowControl")) as Conn["flowControl"] : undefined
    };
    const secret = String(data.get("secret") || "");
    try {
      if (type === "ssh" && secret && native()) await invoke("save_credential", { id, secret });
      setConnections(items => editing ? items.map(item => item.id === id ? connection : item) : [...items, connection]);
      setModalOpen(false);
      setEditing(undefined);
      if (!editing) connect(connection);
    } catch (reason) { setError(String(reason)); }
  }

  function submitFolder(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folderDialog) return;
    const oldName = folderDialog.folder || "";
    if (folderDialog.mode === "delete") {
      const parent = oldName.includes("/") ? oldName.slice(0, oldName.lastIndexOf("/")) : "";
      setConnections(items => items.map(item => item.folder === oldName || item.folder.startsWith(`${oldName}/`) ? { ...item, folder: parent } : item));
      setFolders(items => items.filter(item => item !== oldName && !item.startsWith(`${oldName}/`)));
      if (selectedFolder === oldName || selectedFolder?.startsWith(`${oldName}/`)) setSelectedFolder(parent || null);
    } else {
      const name = String(new FormData(event.currentTarget).get("folderName") || "").trim().replaceAll("/", "-");
      if (!name) return;
      if (folderDialog.mode === "create") {
        const path = oldName ? `${oldName}/${name}` : name;
        if (folders.includes(path)) { setError("A folder with that name already exists here."); return; }
        setFolders(items => [...items, path]);
        setSelectedFolder(path);
        setCollapsed(items => ({ ...items, [oldName]: false, [path]: false }));
      } else {
        const parent = oldName.includes("/") ? oldName.slice(0, oldName.lastIndexOf("/")) : "";
        const path = parent ? `${parent}/${name}` : name;
        if (folders.includes(path) && path !== oldName) { setError("A folder with that name already exists here."); return; }
        const replacePrefix = (value: string) => value === oldName ? path : value.startsWith(`${oldName}/`) ? `${path}${value.slice(oldName.length)}` : value;
        setFolders(items => items.map(replacePrefix));
        setConnections(items => items.map(item => ({ ...item, folder: replacePrefix(item.folder) })));
        setSelectedFolder(current => current ? replacePrefix(current) : current);
        setCollapsed(current => Object.fromEntries(Object.entries(current).map(([key, value]) => [replacePrefix(key), value])));
      }
    }
    setFolderDialog(undefined);
  }

  function deleteConnection(connection: Conn) {
    if (!confirm(`Delete bookmark “${connection.name}”?`)) return;
    setConnections(items => items.filter(item => item.id !== connection.id));
    if (native() && connectionTypeOf(connection) === "ssh") invoke("delete_credential", { id: connection.id }).catch(() => {});
  }

  async function retryAuthentication(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!authIssue) return;
    const session = sessions.find(item => item.id === authIssue.sessionId);
    if (!session) return;
    const data = new FormData(event.currentTarget);
    const authMethod = String(data.get("auth")) as Auth;
    const secret = String(data.get("secret") || "");
    const keyPath = String(data.get("keyPath") || "") || undefined;
    if (authMethod === "password" && !secret) { setError("Enter the SSH password."); return; }
    if (authMethod === "key" && !keyPath) { setError("Choose a private-key path."); return; }
    const connection = { ...session.connection, authMethod, keyPath };
    try {
      if (secret && native()) await invoke("save_credential", { id: connection.id, secret });
      setConnections(items => items.map(item => item.id === connection.id ? connection : item));
      setSessions(items => items.map(item => item.id === session.id ? { ...item, connection, status: "connecting" } : item));
      setAuthIssue(undefined);
      start({ ...session, connection, status: "connecting" });
    } catch (reason) { setError(String(reason)); }
  }

  function saveCommand(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!commandDialog) return;
    const data = new FormData(event.currentTarget);
    const existing = commandDialog.command;
    const scope = String(data.get("scope"));
    const commandText = String(data.get("command")).trim();
    if (containsSensitiveMaterial(commandText)) {
      setError("Relay will not save commands that appear to contain a password, token, API key, or other secret.");
      return;
    }
    const command: Cmd = {
      id: existing?.id || crypto.randomUUID(),
      name: String(data.get("name")).trim(),
      command: commandText,
      uses: existing?.uses || 0,
      usesByConnection: existing?.usesByConnection || {},
      favorite: data.get("favorite") === "on",
      connectionId: scope === "session" ? active?.connection.id : undefined
    };
    setCommands(items => existing ? items.map(item => item.id === existing.id ? command : item) : [...items, command]);
    setCommandDialog(undefined);
  }

  async function runCommand(command: Cmd) {
    if (!active || active.status !== "connected") { setError("Connect a session before running a command."); return; }
    try {
      await invoke("terminal_input", { sessionId: active.id, data: encode(`${command.command}\r`) });
      const connectionId = active.connection.id;
      setCommands(items => items.map(item => item.id === command.id ? {
        ...item,
        uses: item.uses + 1,
        usesByConnection: { ...item.usesByConnection, [connectionId]: (item.usesByConnection?.[connectionId] || 0) + 1 }
      } : item));
    } catch (reason) {
      setError(`Could not run command: ${String(reason)}`);
    }
  }

  const commandUses = (command: Cmd) => active ? command.usesByConnection?.[active.connection.id] || 0 : 0;

  async function syncShellHistory() {
    if (!active || active.status !== "connected") { setError("Connect a session before syncing shell history."); return; }
    if (connectionTypeOf(active.connection) !== "ssh") { setError("Shell-history sync is only available for SSH sessions."); return; }
    setHistorySyncing(true);
    const request = `printf '\\036RELAY_HISTORY_BEGIN\\037'; fc -l -200; printf '\\036RELAY_HISTORY_END\\037'\r`;
    try { await invoke("terminal_input", { sessionId: active.id, data: encode(request) }); }
    catch (reason) { setHistorySyncing(false); setError(`Could not sync shell history: ${String(reason)}`); }
  }

  function importHistory(connectionId: string, history: string[]) {
    const usable = history.filter(command => command && !command.includes("RELAY_HISTORY_") && !/^fc\s+-l\b/.test(command) && !containsSensitiveMaterial(command));
    const frequencies = new Map<string, number>();
    usable.forEach(command => frequencies.set(command, (frequencies.get(command) || 0) + 1));
    setCommands(items => {
      const next = [...items];
      frequencies.forEach((count, commandText) => {
        const index = next.findIndex(command => command.command === commandText && (command.connectionId === connectionId || !command.connectionId));
        if (index >= 0) {
          const command = next[index];
          next[index] = { ...command, usesByConnection: { ...command.usesByConnection, [connectionId]: Math.max(command.usesByConnection?.[connectionId] || 0, count) } };
        } else {
          next.push({ id: crypto.randomUUID(), name: commandText, command: commandText, uses: count, usesByConnection: { [connectionId]: count }, connectionId, favorite: false });
        }
      });
      return next;
    });
    setHistorySyncing(false);
  }

  const visible = (folder: string) => connections.filter(connection => connection.folder === folder && `${connection.name} ${connectionEndpoint(connection)}`.toLowerCase().includes(search.toLowerCase()));
  const move = (id: string, folder: string) => {
    if (!id) return;
    setConnections(items => items.map(item => item.id === id ? { ...item, folder } : item));
    setDraggedId(undefined);
  };
  function beginDrag(event: React.PointerEvent, connection: Conn) {
    event.preventDefault();
    const id = connection.id;
    let target: string | null = null;
    setDraggedId(id);
    document.body.classList.add("dragging-bookmark");
    const pointerMove = (moveEvent: PointerEvent) => {
      const destination = document.elementFromPoint(moveEvent.clientX, moveEvent.clientY)?.closest<HTMLElement>("[data-drop-folder]");
      target = destination?.dataset.dropFolder ?? null;
      setDropTarget(target);
    };
    const pointerUp = () => {
      if (target !== null) move(id, target);
      setDraggedId(undefined);
      setDropTarget(null);
      document.body.classList.remove("dragging-bookmark");
      document.removeEventListener("pointermove", pointerMove);
      document.removeEventListener("pointerup", pointerUp);
      document.removeEventListener("pointercancel", pointerUp);
    };
    document.addEventListener("pointermove", pointerMove);
    document.addEventListener("pointerup", pointerUp);
    document.addEventListener("pointercancel", pointerUp);
  }
  const bookmark = (connection: Conn) => <div className={`bookmark ${active?.connection.id === connection.id ? "active" : ""} ${draggedId === connection.id ? "dragging" : ""}`} key={connection.id}>
    <button className="drag-handle" title="Drag to another folder" aria-label={`Move ${connection.name}`} onPointerDown={event => beginDrag(event, connection)}>⠿</button>
    <button className="bookmark-main" onClick={() => connect(connection)}><i/><span><b>{connection.name}</b><small>{connectionEndpoint(connection)}</small></span><em>{connectionTypeOf(connection).toUpperCase()}</em></button>
    <button className="bookmark-edit" title="Edit bookmark" onClick={() => editConnection(connection)}>✎</button>
    <button className="bookmark-delete" title="Delete bookmark" onClick={() => deleteConnection(connection)}>×</button>
  </div>;

  function renderFolders(parent: string, depth = 0): React.ReactNode {
    return folders.filter(path => {
      const index = path.lastIndexOf("/");
      return (index < 0 ? "" : path.slice(0, index)) === parent;
    }).map(folder => {
      const label = folder.slice(folder.lastIndexOf("/") + 1);
      const childCount = folders.filter(path => path.startsWith(`${folder}/`) && !path.slice(folder.length + 1).includes("/")).length;
      return <section data-drop-folder={folder} style={{ "--folder-depth": depth } as React.CSSProperties} className={`folder-section ${selectedFolder === folder ? "selected-folder" : ""} ${draggedId ? "drop-ready" : ""} ${dropTarget === folder ? "drop-target" : ""}`} key={folder}>
        <h3><button className="collapse" title={collapsed[folder] ? "Open folder" : "Minimize folder"} onClick={() => setCollapsed(value => ({ ...value, [folder]: !value[folder] }))}>{collapsed[folder] ? "›" : "⌄"}</button><button className="folder-name" onClick={() => { setSelectedFolder(folder); setCollapsed(value => ({ ...value, [folder]: !value[folder] })); }}>▰　{label}</button><span className="folder-tools"><button title="Add subfolder" onClick={() => setFolderDialog({ mode: "create", folder })}>＋</button><button title="Rename folder" onClick={() => setFolderDialog({ mode: "rename", folder })}>✎</button><button title="Delete folder" onClick={() => setFolderDialog({ mode: "delete", folder })}>×</button><small>{visible(folder).length + childCount}</small></span></h3>
        {!collapsed[folder] && <div className="folder-contents">{visible(folder).map(bookmark)}{renderFolders(folder, depth + 1)}</div>}
      </section>;
    });
  }

  const explorerId = explorerSessionId || activeId;
  const explorerSession = sessions.find(session => session.id === explorerId && connectionTypeOf(session.connection) === "ssh");
  const explorer = explorerId ? explorers[explorerId] : undefined;
  const parentDirectory = (path: string) => path === "/" ? "/" : path.slice(0, path.lastIndexOf("/")) || "/";
  const fileSize = (size: number) => size < 1024 ? `${size} B` : size < 1048576 ? `${(size / 1024).toFixed(1)} KB` : `${(size / 1048576).toFixed(1)} MB`;

  return <div className={`app ${leftOpen ? "" : "lc"} ${rightOpen ? "" : "rc"}`}>
    <header><b><i>R</i>Relay</b>{availableUpdate && <button className="update-ready" onClick={() => setAvailableUpdate(availableUpdate)}>⬆ Update {availableUpdate.version}</button>}<button className="update-check" title="Check for updates" disabled={updateChecking || updateInstalling} onClick={() => checkForUpdates()}>{updateChecking ? "Checking…" : "↻ Updates"}</button><button onClick={openNewConnection}>＋ New session</button></header>
    <aside className="left">
      <Title over="Workspace" title={leftView === "connections" ? "Connections" : "Explorer"} close={() => setLeftOpen(false)} symbol="‹" />
      <div className="left-tabs"><button className={leftView === "connections" ? "active" : ""} onClick={() => setLeftView("connections")}>Connections</button><button className={leftView === "explorer" ? "active" : ""} disabled={!sessions.some(session => session.status === "connected" && connectionTypeOf(session.connection) === "ssh")} onClick={() => setLeftView("explorer")}>Explorer</button></div>
      {leftView === "connections" ? <>
        <label className="search">⌕<input value={search} onChange={event => setSearch(event.target.value)} placeholder="Find a connection…" /></label>
        <div className="add"><button onClick={openNewConnection}>＋ Connection</button><button onClick={() => setFolderDialog({ mode: "create", folder: selectedFolder || undefined })}>＋ Folder</button></div>
        <nav>
          <section data-drop-folder="" className={`folder-section unfiled ${selectedFolder === null ? "selected-folder" : ""} ${draggedId ? "drop-ready" : ""} ${dropTarget === "" ? "drop-target" : ""}`}>
            <h3><button className="folder-name" onClick={() => setSelectedFolder(null)}>⌄　No folder</button><small>{visible("").length}</small></h3>
            {visible("").map(bookmark)}
          </section>
          {renderFolders("")}
        </nav>
      </> : <div className="explorer-panel">
        <select className="explorer-session" value={explorerSession?.id || ""} onChange={event => { const id = event.target.value; setExplorerSessionId(id); setActiveId(id); loadRemoteDirectory(id, explorers[id]?.path || "."); }}>{sessions.filter(session => session.status === "connected" && connectionTypeOf(session.connection) === "ssh").map(session => <option key={session.id} value={session.id}>{session.connection.name}</option>)}</select>
        {explorerSession ? <>
          <div className="explorer-toolbar"><button title="Parent folder" disabled={!explorer || explorer.path === "/"} onClick={() => explorer && loadRemoteDirectory(explorerSession.id, parentDirectory(explorer.path))}>↑</button><code title={explorer?.path}>{explorer?.path || "Loading…"}</code><button title="Refresh" onClick={() => loadRemoteDirectory(explorerSession.id, explorer?.path || ".")}>↻</button></div>
          <button className="open-in-terminal" disabled={!explorer || explorer.loading} onClick={openExplorerPathInTerminal}><span>›_</span> Open this folder in terminal</button>
          {explorer?.error && <div className="explorer-error">{explorer.error}</div>}
          <div className={`file-list ${explorer?.loading ? "loading" : ""}`}>{explorer?.entries.map(entry => <button key={entry.path} className={entry.is_dir ? "directory" : "file"} onDoubleClick={() => entry.is_dir && loadRemoteDirectory(explorerSession.id, entry.path)} onClick={() => entry.is_dir && loadRemoteDirectory(explorerSession.id, entry.path)}><span className="file-icon">{entry.is_dir ? "▰" : "▤"}</span><span className="file-name">{entry.name}</span><small>{entry.is_dir ? "Folder" : fileSize(entry.size)}</small></button>)}{explorer && !explorer.loading && !explorer.entries.length && <div className="empty-folder">This folder is empty</div>}</div>
        </> : <div className="explorer-empty">Connect to a server to browse its files.</div>}
      </div>}
      <footer>♢　<b>Credentials secured</b><small>Windows Credential Manager / macOS Keychain</small></footer>
    </aside>
    {!leftOpen && <button className="reopen l" onClick={() => setLeftOpen(true)}>▰</button>}
    <main>
      <div className="tabs">{sessions.map(session => <button className={activeId === session.id ? "active" : ""} onClick={() => { setActiveId(session.id); if (leftView === "explorer" && session.status === "connected" && connectionTypeOf(session.connection) === "ssh") { setExplorerSessionId(session.id); loadRemoteDirectory(session.id, explorers[session.id]?.path || "."); } }} key={session.id}>● {session.connection.name} <span onClick={event => { event.stopPropagation(); closeSession(session.id); }}>×</span></button>)}<button onClick={openNewConnection}>＋</button></div>
      <div className="session">●　{active ? <><b>{active.connection.name}</b>　{connectionTypeOf(active.connection) === "serial" ? connectionEndpoint(active.connection) : `${active.connection.user}@${active.connection.host}:${active.connection.port}`}</> : <>No active session</>}<span>{active ? active.status : "Choose a bookmark"}</span></div>
      <div className="term-stack">{sessions.map(session => <TerminalView key={session.id} session={session} visible={session.id === activeId} reconnect={(replace, accept) => start(session, replace, accept)} setStatus={status => setSessions(items => items.map(item => item.id === session.id ? { ...item, status } : item))} onHistory={history => importHistory(session.connection.id, history)} />)}</div>
      <div className="status">●　{active?.status || "Ready"}<span>UTF-8　xterm-256color</span></div>
      {error && <button className="error" onClick={() => setError("")}>{error}　×</button>}
    </main>
    <aside className="right">
      <Title over="This session" title="Command shelf" close={() => setRightOpen(false)} symbol="›" />
      <div className="ctabs"><button className={commandTab === "favorites" ? "active" : ""} onClick={() => setCommandTab("favorites")}>Favorites</button><button className={commandTab === "used" ? "active" : ""} onClick={() => setCommandTab("used")}>Most used</button></div>
      <div className="commands">{[...commands].filter(command => !command.connectionId || command.connectionId === active?.connection.id).filter(command => commandTab === "used" || command.favorite !== false).sort((a,b) => commandTab === "used" ? commandUses(b)-commandUses(a) || a.name.localeCompare(b.name) : a.name.localeCompare(b.name)).map(command => { const sessionUses = commandUses(command); return <article key={command.id}><i>⌁</i><span><b>{command.name}</b><small>{command.command}</small>{commandTab === "used" && <em>{active ? `${sessionUses} run${sessionUses === 1 ? "" : "s"} on ${active.connection.name}` : "Select a connection"}</em>}</span><div className="command-actions"><button title={command.favorite === false ? "Add to favorites" : "Remove from favorites"} onClick={() => setCommands(items => items.map(item => item.id === command.id ? { ...item, favorite: item.favorite === false } : item))}>{command.favorite === false ? "☆" : "★"}</button><button title="Edit command" onClick={() => setCommandDialog({ command })}>✎</button><button title="Run command" disabled={!active || active.status !== "connected"} onClick={() => runCommand(command)}>▶</button></div></article>; })}</div>
      {!commands.filter(command => !command.connectionId || command.connectionId === active?.connection.id).some(command => commandTab === "used" || command.favorite !== false) && <div className="commands-empty"><b>{commandTab === "favorites" ? "No favorites yet" : "No saved commands yet"}</b><span>Save a command to start building your shelf.</span></div>}
      {commandTab === "used" && <button className="save history-sync" disabled={!active || active.status !== "connected" || connectionTypeOf(active.connection) !== "ssh" || historySyncing} onClick={syncShellHistory}>{historySyncing ? "↻ Syncing…" : "↻ Sync shell history"}</button>}
      <button className="save" onClick={() => setCommandDialog({})}>＋ Save a command</button>
    </aside>
    {!rightOpen && <button className="reopen r" onClick={() => setRightOpen(true)}>⌁</button>}
    {availableUpdate && <div className="modal update-modal"><div className="update-dialog">
      {!updateInstalling && <button className="x" onClick={() => { availableUpdate.close().catch(() => {}); setAvailableUpdate(undefined); }}>×</button>}
      <small>RELAY UPDATE</small><h2>Version {availableUpdate.version} is ready</h2>
      <p>{availableUpdate.body || "A new signed version of Relay is available."}</p>
      {updateInstalling && <div className="update-progress"><span style={{ width: `${updateProgress}%` }} /><small>{updateProgress ? `${updateProgress}%` : "Preparing download…"}</small></div>}
      <div className="update-actions"><button disabled={updateInstalling} onClick={() => { availableUpdate.close().catch(() => {}); setAvailableUpdate(undefined); }}>Later</button><button className="install-update" disabled={updateInstalling} onClick={installAvailableUpdate}>{updateInstalling ? "Installing…" : "Update and restart"}</button></div>
    </div></div>}
    {modalOpen && <div className="modal" onMouseDown={() => { setModalOpen(false); setEditing(undefined); }}><form onSubmit={saveConnection} onMouseDown={event => event.stopPropagation()}>
      <button type="button" className="x" onClick={() => { setModalOpen(false); setEditing(undefined); }}>×</button><small>{editing ? "EDIT BOOKMARK" : "NEW BOOKMARK"}</small><h2>{editing ? "Edit connection" : "Add connection"}</h2>
      <label>Name<input required name="name" defaultValue={editing?.name} placeholder="Production server" /></label>
      <label>Connection type<select name="connectionType" value={connectionType} onChange={event => { const type = event.target.value as ConnectionType; setConnectionType(type); if (type === "serial") refreshSerialPorts(); }}><option value="ssh">SSH</option><option value="serial">Serial</option></select></label>
      {connectionType === "ssh" ? <>
        <div className="formrow"><label>Host<input required name="host" defaultValue={editing?.host} placeholder="server.example.com" /></label><label className="port">Port<input required type="number" name="port" defaultValue={editing?.port || 22} min="1" max="65535" /></label></div>
        <label>Username<input required name="user" defaultValue={editing?.user} placeholder="ubuntu" /></label>
        <label>Authentication<select name="auth" defaultValue={editing?.authMethod || "password"}><option value="password">Password</option><option value="key">Private key</option><option value="agent">SSH agent</option></select></label>
        <label>Private-key path<input name="keyPath" defaultValue={editing?.keyPath} placeholder="~/.ssh/id_ed25519" /></label>
        <label>{editing ? "New password / passphrase (blank keeps current)" : "Password / key passphrase"}<input type="password" name="secret" autoComplete="new-password" /></label>
      </> : <div className="serial-settings">
        <div className="serial-port-row"><label>COM / serial port<input required name="serialPort" list="relay-serial-ports" defaultValue={editing?.serialPort} placeholder={navigator.userAgent.includes("Mac") ? "/dev/cu.usbserial…" : "COM3"} /><datalist id="relay-serial-ports">{serialPorts.map(port => <option key={port} value={port} />)}</datalist></label><button type="button" onClick={refreshSerialPorts} disabled={serialPortsLoading}>{serialPortsLoading ? "Scanning…" : "↻ Scan"}</button></div>
        <p>{navigator.userAgent.includes("Mac") ? "macOS names COM ports /dev/cu.*. Relay hides Bluetooth, debug-console, and duplicate /dev/tty.* entries." : "Windows serial devices appear as COM ports such as COM3 or COM4."}</p>
        {!serialPortsLoading && serialPorts.length === 0 && <p>No USB serial ports detected. Connect the device, scan again, or enter its port manually.</p>}
        <label>Baud rate<input required type="number" name="baudRate" defaultValue={editing?.baudRate || 115200} min="1" max="4000000" list="relay-baud-rates" /><datalist id="relay-baud-rates"><option value="9600"/><option value="19200"/><option value="38400"/><option value="57600"/><option value="115200"/><option value="230400"/><option value="460800"/><option value="921600"/></datalist></label>
        <div className="serial-line-settings"><label>Data bits<select name="dataBits" defaultValue={editing?.dataBits || 8}><option value="8">8</option><option value="7">7</option><option value="6">6</option><option value="5">5</option></select></label><label>Parity<select name="parity" defaultValue={editing?.parity || "none"}><option value="none">None</option><option value="odd">Odd</option><option value="even">Even</option></select></label><label>Stop bits<select name="stopBits" defaultValue={editing?.stopBits || 1}><option value="1">1</option><option value="2">2</option></select></label></div>
        <label>Flow control<select name="flowControl" defaultValue={editing?.flowControl || "none"}><option value="none">None</option><option value="hardware">Hardware (RTS/CTS)</option><option value="software">Software (XON/XOFF)</option></select></label>
      </div>}
      <label>Folder<select name="folder" defaultValue={editing?.folder ?? selectedFolder ?? ""}><option value="">No folder</option>{folders.map(folder => <option key={folder}>{folder}</option>)}</select></label>
      <p>{editing ? "Changing Folder moves this bookmark." : selectedFolder ? `This connection will be added to “${selectedFolder}”.` : "No folder is selected, so this connection will be unfiled."}</p>
      <div><button type="button" onClick={() => { setModalOpen(false); setEditing(undefined); }}>Cancel</button><button>{editing ? "Save changes" : "Save & connect"}</button></div>
    </form></div>}
    {folderDialog && <div className="modal" onMouseDown={() => setFolderDialog(undefined)}><form className="folder-dialog" onSubmit={submitFolder} onMouseDown={event => event.stopPropagation()}>
      <button type="button" className="x" onClick={() => setFolderDialog(undefined)}>×</button>
      <small>{folderDialog.mode === "create" ? "NEW FOLDER" : folderDialog.mode === "rename" ? "EDIT FOLDER" : "DELETE FOLDER"}</small>
      <h2>{folderDialog.mode === "create" ? folderDialog.folder ? `Create subfolder in “${folderDialog.folder.slice(folderDialog.folder.lastIndexOf("/") + 1)}”` : "Create folder" : folderDialog.mode === "rename" ? "Rename folder" : `Delete “${folderDialog.folder?.slice(folderDialog.folder.lastIndexOf("/") + 1)}”?`}</h2>
      {folderDialog.mode === "delete" ? <p>Bookmarks anywhere inside this folder will move to its parent folder. Subfolders will also be removed.</p> : <label>Folder name<input autoFocus required name="folderName" defaultValue={folderDialog.mode === "rename" ? folderDialog.folder?.slice(folderDialog.folder.lastIndexOf("/") + 1) : ""} placeholder="My servers" /></label>}
      <div><button type="button" onClick={() => setFolderDialog(undefined)}>Cancel</button><button className={folderDialog.mode === "delete" ? "danger" : ""}>{folderDialog.mode === "delete" ? "Delete folder" : folderDialog.mode === "rename" ? "Save name" : "Create folder"}</button></div>
    </form></div>}
    {hostIssue && (() => {
      const session = sessions.find(item => item.id === hostIssue.sessionId);
      if (!session) return null;
      const changed = hostIssue.kind === "hostKeyChanged";
      return <div className="modal host-key-modal"><div className="host-key-dialog">
        <small>{changed ? "HOST KEY CHANGED" : "NEW SSH HOST"}</small>
        <h2>{changed ? "The server identity has changed" : "Trust this server?"}</h2>
        <p>{changed ? "This often happens after a server reinstall or IP reuse, but it can also indicate interception. Verify the fingerprint when possible before replacing it." : "Relay has not connected to this server before. Confirm its fingerprint before saving it."}</p>
        <label>Server<span>{session.connection.host}:{session.connection.port}</span></label>
        <label>SHA-256 fingerprint<code>SHA256:{hostIssue.fingerprint}</code></label>
        <div className="host-key-actions"><button onClick={() => setHostIssue(undefined)}>Cancel</button><button className={changed ? "danger" : "trust"} onClick={() => { setHostIssue(undefined); start(session, changed, true); }}>{changed ? "Replace key & reconnect" : "Trust & connect"}</button></div>
      </div></div>;
    })()}
    {authIssue && (() => {
      const session = sessions.find(item => item.id === authIssue.sessionId);
      if (!session) return null;
      return <div className="modal auth-modal"><form className="auth-dialog" onSubmit={retryAuthentication} onMouseDown={event => event.stopPropagation()}>
        <button type="button" className="x" onClick={() => setAuthIssue(undefined)}>×</button>
        <small>AUTHENTICATION NEEDED</small><h2>Sign in to {session.connection.name}</h2>
        <p className="auth-error">{authIssue.message}</p>
        <label>Try another method<select name="auth" defaultValue="password"><option value="password">Password</option><option value="key">Private key</option><option value="agent">SSH agent</option></select></label>
        <label>Password or key passphrase<input name="secret" type="password" autoFocus autoComplete="current-password" placeholder="Stored securely in Keychain" /></label>
        <label>Private-key path<input name="keyPath" defaultValue={session.connection.keyPath} placeholder="~/.ssh/id_ed25519" /></label>
        <p>The chosen method is saved with this bookmark. Passwords and passphrases are stored only in the operating-system keychain.</p>
        <div><button type="button" onClick={() => setAuthIssue(undefined)}>Cancel</button><button>Save & reconnect</button></div>
      </form></div>;
    })()}
    {commandDialog && <div className="modal" onMouseDown={() => setCommandDialog(undefined)}><form className="command-dialog" onSubmit={saveCommand} onMouseDown={event => event.stopPropagation()}>
      <button type="button" className="x" onClick={() => setCommandDialog(undefined)}>×</button>
      <small>{commandDialog.command ? "EDIT COMMAND" : "NEW COMMAND"}</small><h2>{commandDialog.command ? "Edit saved command" : "Save a command"}</h2>
      <label>Name<input required name="name" defaultValue={commandDialog.command?.name} placeholder="Restart web server" /></label>
      <label>Command<textarea required name="command" defaultValue={commandDialog.command?.command} placeholder="sudo systemctl restart nginx" /></label>
      <label>Available in<select name="scope" defaultValue={commandDialog.command?.connectionId ? "session" : "global"}><option value="global">Every connection</option><option value="session" disabled={!active}>Current connection only{active ? ` — ${active.connection.name}` : ""}</option></select></label>
      <label className="check-label"><input type="checkbox" name="favorite" defaultChecked={commandDialog.command?.favorite !== false} /> Show in Favorites</label>
      {commandDialog.command && <p>{active ? `Used ${commandDialog.command.usesByConnection?.[active.connection.id] || 0} time${(commandDialog.command.usesByConnection?.[active.connection.id] || 0) === 1 ? "" : "s"} on ${active.connection.name}.` : `Used ${commandDialog.command.uses} times in total.`}</p>}
      <div><button type="button" className="delete-command" onClick={() => { if (commandDialog.command) setCommands(items => items.filter(item => item.id !== commandDialog.command?.id)); setCommandDialog(undefined); }}>{commandDialog.command ? "Delete" : "Cancel"}</button><button>{commandDialog.command ? "Save changes" : "Save command"}</button></div>
    </form></div>}
  </div>;
}

function Title({ over, title, close, symbol }: { over: string; title: string; close: () => void; symbol: string }) {
  return <div className="title"><div><small>{over}</small><h2>{title}</h2></div><button onClick={close}>{symbol}</button></div>;
}

createRoot(document.getElementById("root")!).render(<React.StrictMode><App /></React.StrictMode>);
