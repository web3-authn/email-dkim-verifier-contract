# Outlayer Entrypoint

We use [OutLayer](https://outlayer.fastnear.com/docs/getting-started) to fetch DKIM DNS TXT records for an email and pass it to the `email-dkim-verifier-contract` to verify email DKIM signatures on‑chain.

This WASI bundle uses
```
wasi-http-client = { version = "0.2.1", features = ["json"] }
```
and must be compiled with `build_target`:
```
WASI Preview 2 (P2)
Target: wasm32-wasip2
Use for: HTTP requests, complex I/O, modern features
Binary size: Larger (~500KB-1MB)
Features: HTTP client, advanced filesystem, sockets
Requires: wasmtime 28+
```

See [Outlayer WASI code docs](https://outlayer.fastnear.com/docs/wasi#wasi-preview)
