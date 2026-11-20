# BGP-Speaker

`megaphone` is a Rust BGP speaker designed to:

- maintain multiple simultaneous BGP peer sessions;
- define outbound routes from a web UI/API;
- select which routes each peer receives;
- apply ordered export policies similar to `route-map` and Junos `policy-statement`.

## Current status

Implemented: static IPv4 and IPv6 Unicast routes, inbound and outbound multi-peer EBGP,
peer-specific export policies, route announcements and withdrawals, and a web
dashboard/API for configuration and session management. ASNs are limited to
1–65535. 4-byte ASN negotiation is not implemented.

VPNv4 and VPNv6 static advertisements are also supported through MP-BGP
(AFI 1/2, SAFI 128). Prefix Setting separates unicast routes from VPN routes,
with distinct tables and add forms. VPN routes require an RD, MPLS label
(16–1048575), route target, and same-family next hop. The matching VPN
capability must be advertised by the peer; otherwise that family is skipped.
This is a route advertisement tool, not a VRF or MPLS forwarding engine.

VPN route identifiers use `RD@prefix`, for example `65000:100@10.0.0.0/24`.
The RD is part of route and policy identity, so multiple VPNs and unicast can
use the same network without affecting each other's exports or withdrawals.
RDs support `ASN:number` and `IPv4:number` forms. One MPLS label and a single
next-hop address are supported; label stacks and paired global/link-local
next hops are not implemented. VPNv6 currently requires an IPv6 next hop.

Example configuration:

```toml
[[route]]
prefix = "65000:100@10.0.0.0/24"
next_hop = "192.0.2.1"
label = "1000"
extended_communities = "rt:65000:100"
```

For the API, use `POST /routes` with `family` (`vpnv4` or `vpnv6`),
`rd`, bare `prefix`, `next_hop`, `label`, and `extended_communities`.
Policies and `DELETE /routes/<identifier>` use the full `RD@prefix`
identifier (percent-encoded in URLs). Unicast identifiers remain unchanged.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE) — personal, research,
educational, government, and public-benefit use permitted. Commercial use
requires written permission.

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
each peer's permit list. OPEN advertises IPv4 and IPv6 unicast. IPv6 routes
use MP_REACH_NLRI and MP_UNREACH_NLRI and are exported only when the peer
advertises IPv6 unicast. Prefixes and next hops must use the same IP family.
The BGP router ID remains an IPv4-format identifier.

For IPv6, add a prefix such as `2001:db8:100::/48` with next hop
`2001:db8::1`, then permit it in Policy Setting. IPv6 next hops currently
use a single 16-byte address; paired global/link-local next hops are not supported.
IPv6 transport addresses in config use `[2001:db8::2]:179`; the Add Peer
form accepts a bare IPv6 address and separate optional port. Incoming routes
are not installed or used for forwarding, for either family.

The web UI at `api_listen` (default `http://127.0.0.1:8080/`) manages
everything: peers (name, address, local/remote AS, hold time), prefixes, each
peer's permit list and attribute overrides, a live log, and the server
settings (BGP listen address, router ID, web address) with a
Restart button. The dashboard uses a compact business layout with responsive
forms and horizontally scrolling tables on small screens.

- **BGP Summary:** identifies peers by IP address and port, with local/remote
  AS, hold time, session state, and configured prefixes selected for export.
  Add peers with Peer IP, optional Port (blank uses 179), ASNs, and hold time.
  An internal name is generated from the address for configuration and API calls.
- **Reset:** reconnects only the selected peer, retaining its configuration,
  policies, and overrides. An established session receives a Cease notification.
  Reset temporarily interrupts that peer's routes; other peers keep running.
  A connection already waiting for OPEN may take time to close.
- **Delete:** removes that peer and its export settings.
- **Prefix Setting:** adds or withdraws routes and their attributes.
- **Policy Setting:** choose a peer, tick the prefixes to export, set optional
  overrides, then Apply. Unticking a prefix withdraws it from that peer. New
  peers start with no prefixes selected.
- **Log:** shows the last 500 events and polls every two seconds.
- **Settings:** saves listener/router ID settings and provides a full service
  restart. Automatic startup after Restart requires systemd or launchd.

Configuration changes are written back to the config file at once, so they survive a
restart. The file is rewritten in a fixed layout and comments are not kept.
Peer attribute overrides are stored as `override_med = "10"`,
`override_communities = "65000:9 65000:10"` and so on. Listener and router ID
changes apply after a restart.

The web UI and API have **no login**. Use `api_listen = "0.0.0.0:8080"` only on a
private lab network: anyone who can reach the port can announce routes.

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

## Peer API

Send POST and PUT requests with `Content-Type: application/json`. Peer names in
URLs must be percent-encoded. The API uses the same listener as the dashboard.

| Method | Path | Action |
|---|---|---|
| GET | `/peers` | List peers and session status |
| POST | `/peers` | Add a peer |
| POST | `/peers/<name>/reset` | Reset one peer; send `{}` as the body |
| DELETE | `/peers/<name>` | Delete one peer |

Example add-peer body:

```json
{"name":"lab-router","address":"192.0.2.2","port":"","local_as":65000,"remote_as":65111,"hold_time":90}
```

An absent or blank `port` defaults to 179 for a bare IP. Existing callers can
optionally supply `name`; otherwise an address-based identifier is generated.
Existing callers can
continue using `"address":"192.0.2.2:1179"` without a separate port. Config
files always store `address` as `IP:port`. Ensure each side's remote AS matches
the other side's local AS; a mismatch produces OPEN error 2/2 (Bad Peer AS).

After source changes, rebuild and restart the installed binary to load the
embedded UI. Validate development changes with `cargo test` and `cargo fmt --check`.

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
Build artifacts use a temporary directory. The installer removes that directory,
the downloaded Rust installer, and temporary configuration files on exit,
including after a failure. Existing project build files and the Cargo cache remain.
Run it as your normal user; it uses sudo for system changes. Linux supports
apt, dnf, yum and pacman for missing build tools. Missing Rust is installed with
rustup. On macOS, complete the Command Line Tools installer if prompted,
then run the script again.

On Red Hat Enterprise Linux and related distributions, the installer uses
dnf (or yum), preserves an existing `curl-minimal` installation, selects an
available `nologin` shell for the service account, and restores SELinux file
contexts when `restorecon` is available. Enabled package repositories and
access to the Rust download servers are required. SELinux remains enabled.
If firewalld is active, allow TCP 179 from BGP peers and the chosen web port
only from trusted management addresses when remote dashboard access is needed.
The scripts do not add or remove firewall rules. Installation on RHEL has not
yet been verified on a live host.

The interactive installer explains the setup, asks for the Web address
(default `127.0.0.1`, local access only) and port, then shows a summary for
confirmation before installing dependencies or changing the installation. Use
`0.0.0.0` for access from a trusted private network. There is
no web login, so keep it on a private network. Everything else
is set in the web UI; a new install starts with no peers or routes.
Reinstalling preserves existing peers and routes and backs up the config
before changing the Web address. Choosing no service stops/disables a previous service.

Services use systemd or OpenRC on Linux, or launchd on macOS. Systemd runs as
the unprivileged user `megaphone` with permission to bind privileged ports;
OpenRC and launchd run as root. OpenRC requires `supervise-daemon`, which
restarts the process after the dashboard's Restart action. Services stop
cleanly on SIGTERM, sending peers a Cease notice. On systemd:

```bash
sudo systemctl status megaphone
sudo journalctl -u megaphone
```

On OpenRC, use `sudo rc-service megaphone status` (or `start`, `stop`,
`restart`). Logs are in `/opt/megaphone/service.log`. The installer enables
the service in the `default` runlevel; the uninstaller removes it.

On macOS, inspect `sudo launchctl print system/com.megaphone.speaker`;
logs go to `/opt/megaphone/service.log`.
For manual operation:

```bash
sudo /opt/megaphone/megaphone --config /opt/megaphone/config.toml
```

Uninstall with `./uninstall.sh` or `/opt/megaphone/uninstall.sh`.
It offers to keep configuration, backups and logs (the default), then asks
for confirmation before removing the service and installed executables.
Choosing not to keep data permanently removes all of `/opt/megaphone`.
Both scripts require an interactive terminal. Stop any manually started instance first.
Use `./install.sh --help` or `./uninstall.sh --help` for usage without making
changes. Setup reports its current stage and provides service/log commands at
completion; failures report the stage to help troubleshooting. Uninstall
reports whether data was retained and how to reinstall.
Rust and system build tools are kept because other projects may use them.

## Architecture

The implementation keeps these concerns separate:

1. BGP wire protocol and per-peer finite-state machines;
2. an intended-route store owned by the controller;
3. policy evaluation that produces a per-peer export view;
4. a web/API layer for configuration and route operations.

Export is deny-by-default. A route is not sent to a peer until both route
selection and that peer's policy allow it.
