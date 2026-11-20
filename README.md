# BGP-Speaker

`megaphone` is a Rust BGP speaker designed to:

- maintain multiple simultaneous BGP peer sessions;
- define outbound routes from a web UI/API;
- select which routes each peer receives;
- apply ordered export policies similar to `route-map` and Junos `policy-statement`.

## Current status

Project skeleton only. The first implementation target is IPv4 Unicast with
static routes, multi-peer EBGP, peer-specific export policies, UPDATE announce,
and withdraw.

## Build

```bash
cargo build
cargo run
```

Run the current outbound IPv4 EBGP implementation with the example config:

```bash
cargo run -- --config config.example.toml
```

It binds the configured listener, supports outbound and inbound IPv4 EBGP
sessions, exchanges OPEN/KEEPALIVE, and announces configured routes allowed by
each peer's permit list. IPv6 and the 4-byte ASN capability are not
implemented yet.

The web UI at `api_listen` (default `http://127.0.0.1:8080/`) manages
everything: peers (name, address, local/remote AS, hold time), prefixes, each
peer's permit list and attribute overrides, a live log, and the server
settings (BGP listen address, router ID, web address, web password) with a
Restart button. The route table has a checkbox per peer: tick it to send that
route to that peer, untick it to withdraw it. A new peer starts with nothing
ticked.

Every change is written back to the config file at once, so it survives a
restart. The file is rewritten in a fixed layout and comments are not kept.
Peer attribute overrides are stored as `override_med = "10"`,
`override_communities = "65000:9 65000:10"` and so on. Listener and router ID
changes apply after a restart.

If `api_listen` is anything but a loopback address (for example `0.0.0.0`),
`api_password` is required and megaphone refuses to start without it. The web
UI asks for it with a browser login (user `admin`). The login uses HTTP Basic
over plain HTTP, so use it on a trusted network or behind a TLS proxy. The
password is stored in clear text in the config file.

While running, the minimal control channel accepts:

```text
announce 198.51.100.0/24 192.0.2.1
announce 203.0.113.0/24 192.0.2.1 med=10 prepend=2 communities=65000:100,65535:666
withdraw 198.51.100.0/24
quit
```

Routes can carry these optional attributes, set the same way in `[[route]]`,
the web UI, the API (`POST /routes`) and the console:

| Key | Example | Attribute |
|---|---|---|
| `as_path` | `65010 13335` | ASes sent after the local AS: AS_PATH becomes `<local AS> 65010 13335` (max 200, 2-byte ASNs only) |
| `med` | `10` | MULTI_EXIT_DISC |
| `prepend` | `2` | adds the local AS that many extra times to AS_PATH (max 32) |
| `communities` | `65000:100 65535:666` | COMMUNITIES (RFC 1997) |
| `large_communities` | `65000:1:2` | LARGE_COMMUNITY (RFC 8092) |
| `extended_communities` | `rt:65000:100 soo:192.0.2.1:7 rt:4200000000:9` | route target / site of origin (RFC 4360) |

Lists are separated by spaces or commas; config files may use TOML arrays.
A route whose UPDATE would exceed 4096 bytes is rejected.

In the web UI's Policy Setting tab, each peer can also override `next_hop`
and any of the keys above (`PUT /overrides/<peer>`). A set override replaces
that attribute on every route sent to that peer; the rest of the route stays
as configured. Changing overrides re-sends the affected routes at once.

The binary name is `megaphone`.

## Policy matching

Policy rules match the exact prefix only; `10.0.0.0/8` does not match `10.1.0.0/16`.

## Install and uninstall

From a local checkout, run:

```bash
./install.sh
```

The installer asks for the Web port (1–65535, default 8080) and whether to
start automatically as a service. It builds with `cargo build --release --locked`
and installs the binary, config and uninstaller under `/opt/megaphone`.
Run it as your normal user; it uses sudo for system changes. Linux supports
apt, dnf and pacman for missing build tools. Missing Rust is installed with
rustup. On macOS, complete the Command Line Tools installer if prompted,
then run the script again.

The installer asks for the Web address (default `0.0.0.0`) and port, and for a
Web password (user `admin`) when the address is not loopback. Everything else
is set in the web UI; the initial config uses the example lab peer.
Reinstalling preserves existing peers and routes and backs up the config
before changing the Web address. Choosing no service stops/disables a previous service.

Services use systemd on Linux (running as the unprivileged user `megaphone`, which may only bind port 179) or launchd on macOS (running as root). They stop cleanly on SIGTERM, sending peers a Cease notice. On Linux:

```bash
sudo systemctl status megaphone
sudo journalctl -u megaphone
```

On macOS, inspect `sudo launchctl print system/com.megaphone.speaker`;
logs go to `/opt/megaphone/service.log`.
For manual operation:

```bash
sudo /opt/megaphone/megaphone --config /opt/megaphone/config.toml
```

Uninstall with `./uninstall.sh` or `/opt/megaphone/uninstall.sh`.
It asks before removing the service and all of `/opt/megaphone`, including
configuration, backups and logs. Stop any manually started instance first.
Rust and system build tools are kept because other projects may use them.

## Planned boundaries

The initial design keeps these concerns separate:

1. BGP wire protocol and per-peer finite-state machines;
2. an intended-route store owned by the controller;
3. policy evaluation that produces a per-peer export view;
4. a web/API layer for configuration and route operations.

Export is deny-by-default. A route is not sent to a peer until both route
selection and that peer's policy allow it.
