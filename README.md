# daemonseed

daemonseed is a desktop app for private group chat, direct messages and file sharing with no server behind it. It is for people who want to talk and share files with a group they trust, without any company or operator in the middle who could read, store or shut off the conversation. Pure Rust.

## What it does

- **Lobby chat.** A public room every user lands in. Anyone can read and post, with no account to create and nothing to coordinate.
- **Circles.** A private group formed from a shared phrase. Create a circle and the app generates a strong phrase; hand it to the people you want in, by any channel you trust. Anyone holding the phrase can read and post; nobody else can. You can be in several circles at once.
- **Direct messages.** One-to-one private conversations. A first message arrives as a contact request the other person can accept, decline or block. Each identity shows a fingerprint you can compare out of band.
- **Public shares.** Publish a folder from your computer while the app is running. Others browse what is on offer and download it; every downloaded file is checked against its content hash.
- **Presence.** Each room shows who is in it right now.
- **Announcements and a message of the day**, signed by the project and verified by your client before display.

Two clients ship from the same code: a graphical desktop app and a terminal app.

## Status

Current release: **v0.37.1** — beta (post-MVP). The features above work end to end. Message formats and on-disk formats may change between releases; `CHANGELOG.md` marks any such change. Only the current release receives fixes; `SECURITY.md` says how to report a vulnerability.

## Get it

Downloads are at <https://daemonseed.org>, with the release files at <https://github.com/caraka/daemonseed-releases>. Each release carries the desktop app for x86_64 Linux (a single-file AppImage) and for x86_64 Windows 10 or later (a single `.exe`), plus a `SHA256SUMS` file to check a download against. The terminal app is not published as a binary; build it from source (see Building from source).

## First launch

1. **Choose a passphrase.** It encrypts your identity keys, recovery phrase, display name, circle memberships, mute and hide lists, shared folder list and direct-message conversations on this computer. Files you download from a share are saved as ordinary files, and the settings file is plain text. There is no reset, so make it strong and memorable.
2. **Write down your recovery phrase.** The app shows 24 words. On this computer they are kept only encrypted under your passphrase. Writing them down is what lets you recover your identity on another computer or after forgetting the passphrase. You confirm the backup by typing three of the words back.
3. **Pick a display name.** This is what others see in chat; you can change it later.

The app then connects to the peer network. The first connection takes a little while to find other nodes, and the screen says so. You arrive in the Lobby. From the left rail, create a circle or join one with a phrase you were given, open a direct message from a person's name, and publish or browse shares from the Shares tab. On later launches you enter your passphrase once to unlock.

**Wayland.** On some Wayland desktops the window stops responding to the mouse. Start the app on XWayland instead with `--x11`, or set `DAEMONSEED_X11=1`. The AppImage does this by default; `DAEMONSEED_X11=0` restores native Wayland.

## How it works

There is no daemonseed server. Every running client is a node of [Veilid](https://veilid.com), an open-source peer-to-peer network whose distributed hash table stores small records across the participating nodes and whose private routes hide where a node is. Rooms, shares and direct messages are records on that network. Other nodes carry circle messages and direct messages without being able to read them; public rooms, public shares and announcements are readable by anyone.

What is private and what is not:

- **Circle chat and direct messages are end-to-end encrypted.** A circle's key is derived from its phrase, which is never on the network. A direct message is encrypted with keys only the two parties hold. Nodes carrying the traffic see encrypted bytes and the fact that someone is present at an address, never content or membership.
- **The Lobby, public shares, announcements and the message of the day are open by design.** They are encrypted in transit, but with a key anyone can derive, so anyone can read them. They carry no confidentiality.
- **Your identity is a key pair derived from the 24-word recovery phrase.** The phrase is the root of recovery; the only copy on disk is encrypted under your passphrase, alongside your keys and private state.

Cryptography follows the CNSA 2.0 suite (ML-DSA-87 signatures, ML-KEM-1024 key encapsulation, AES-256-GCM, SHA-384) through the [oxicrypt](https://github.com/oxiforge/oxicrypt) crates. The crypto module checks its own binary image against a signature slot before it does any work, and refuses to run if the check fails.

Not yet in place: the release-signing keys that would let a client verify an update against a published trust anchor (the trust anchor ships with an empty key set), reproducible builds, package-manager or app-store distribution, biometric unlock and start-on-login. Encrypted sharing inside a circle is shown in the app as coming soon. Presence beacons are a constant length, but chat messages are not padded in length or timing. Because public room addresses can be derived by anyone, an observer can tell that a client is subscribed to a known public room and can read what is posted there; circle addresses, circle messages and direct messages stay opaque. The full set of guarantees, each with the test that would show it broken, is the design contract in `ISA.md`.

## Building from source

```sh
packaging/appimage/build-appimage.sh   # Linux desktop app → dist/daemonseed-gui-x86_64.AppImage
packaging/windows/build-windows.sh     # Windows desktop app → dist/daemonseed-gui.exe
packaging/tui/build-tui.sh             # Linux terminal app → dist/daemonseed-tui-x86_64
```

A plain `cargo build` binary refuses to start: the crypto module's self-check fails on an unsigned image and the process exits with `Module image integrity`. The packaging scripts sign the binary as their last step, so what they produce runs. `BUILD.md` lists the toolchain (Rust pinned by `rust-toolchain.toml`, `cargo-zigbuild` and `zig`, `protoc`, Wayland headers), how to sign a hand-built binary, and how to run two clients on one machine. `packaging/appimage/README.md` covers the AppImage recipe.

## Contributing

Work is tracked in GitHub Issues; pick one, or open one before anything larger than a one-line fix. `CONTRIBUTING.md` is the short version of the rules and `AGENTS.md` the full contract: signed commits, documentation updated in the same commit as the code, and a pull request for every change. Before pushing, run the gate:

```sh
cargo xtask gate
```

`cargo xtask install-hooks` installs a pre-push hook that runs the quick part of it.

## License

Code crates: **AGPL-3.0-or-later** (`LICENSE-AGPL`). The `daemonseed-proto` wire schema: **Apache-2.0 OR MIT** (`LICENSE-APACHE`, `LICENSE-MIT`), so clients in other languages can implement the protocol without a copyleft obligation.

## For AI agents

Start at `lama.yaml` at the repository root; it indexes the per-crate API manifests under `docs/llm-api-manifest/`.
