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

It exchanges OPEN/KEEPALIVE and announces configured routes allowed by each
peer's permit list. The management API/UI, inbound listener, reconnect
backoff, IPv6, 4-byte ASN capability, and persistent storage are not
implemented yet.

The binary name is `megaphone`.

## Planned boundaries

The initial design keeps these concerns separate:

1. BGP wire protocol and per-peer finite-state machines;
2. an intended-route store owned by the controller;
3. policy evaluation that produces a per-peer export view;
4. a web/API layer for configuration and route operations.

Export is deny-by-default. A route is not sent to a peer until both route
selection and that peer's policy allow it.
