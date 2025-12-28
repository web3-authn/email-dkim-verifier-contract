# Worker build helper

This folder contains a helper script for building the Outlayer WASI worker
and producing its SHA-256 hash for the WasmUrl code source flow.

## Usage

1. Install the target (once):
   ```bash
   rustup target add wasm32-wasip2
   ```
2. Build + hash:
   ```bash
   ./worker-build/build.sh
   ```

## Outputs

- `worker-build/dist/email-dkim-verifier-contract.wasm`
- `worker-build/dist/email-dkim-verifier-contract.wasm.sha256`

Upload the wasm to R2 (or any static host) and ensure the `.sha256` is
published alongside it. The CI workflow does this automatically.

## GitHub Actions (R2 publish)

There is a workflow in `.github/workflows/publish-worker-wasm.yml` that builds
the wasm and uploads it to Cloudflare R2.

Required secrets:
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`

Optional variable:
- `R2_PUBLIC_BASE_URL` (defaults to `https://outlayer.tatchi.xyz` for the build summary)

## Updating the contract

1. Set `OUTLAYER_WORKER_WASM_URL` in `.env` to the public URL of the `.wasm`.
2. Run:
   ```bash
   just set-outlayer-wasm
   ```
   This fetches the `.sha256` from R2 and updates contract state.
3. Optional: compute the hash from the downloaded wasm instead:
   ```bash
   just set-outlayer-wasm-from-r2
   ```
