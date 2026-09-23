# Relay

Windows and macOS SSH workspace using Tauri 2, React, TypeScript, Rust, and xterm.js.

Implemented: real SSH2 terminal streaming, DNS and custom ports, password/private-key/SSH-agent authentication, strict known-host verification, resize and input forwarding, multiple independent tabs, collapsible sidebars, searchable bookmarks, drag-to-folder organization, persistent metadata, and commands ordered by usage. Secrets remain in Windows Credential Manager or macOS Keychain and are only read by Rust.

Unknown server keys display their SHA-256 fingerprint and require confirmation. Changed host keys are refused; verify the change and update `~/.ssh/known_hosts` manually.

Customers install Relay using the macOS `.dmg` or Windows `-setup.exe` attached to a GitHub Release. Relay checks the signed `latest.json` release feed automatically and can download, verify, install, and restart into an update without development tools.

Downloads and the signed update feed are published at `https://github.com/Jonnyappstudio/Relay/releases`.

Releases are automated by `.github/workflows/release.yml`. Run **Release Relay** from the GitHub Actions page, enter a new semantic version and release notes, and the workflow builds Apple Silicon Mac, Intel Mac, and Windows installers. The repository must define `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` Actions secrets. The updater public key is safe and is embedded in `src-tauri/tauri.conf.json`; never commit or share the private key.

For local development, install Node.js LTS, Rust stable, and the Tauri prerequisites, then run `npm install` and `npm run desktop`.

`npm run desktop` is development mode and stays attached to its launching terminal. For normal use, open the packaged `Relay.app` on macOS or the installed Relay shortcut on Windows. Release Windows builds suppress the console window.
