# UPI Offline Mesh — C++ Interactive Demo

A C++17 web application that demonstrates simulated offline UPI-style payments routed through a Bluetooth-inspired mesh. The browser dashboard lets you create an encrypted demo payment, pass it through virtual phones, and settle it when a bridge device reconnects.

> **Educational demo only.** This does not connect to UPI, banks, Bluetooth hardware, or real payment rails. Do not use it to process real payments or sensitive credentials.

## Features

- Responsive blue-and-white payment dashboard inspired by Google Pay.
- C++ HTTP server with JSON API endpoints and an in-memory demo ledger.
- Hybrid encryption: AES-256-GCM protects the payment payload; RSA-OAEP with SHA-256 wraps the AES key.
- Simulated packet gossip between offline devices and bridge upload.
- SHA-256 ciphertext-based duplicate detection and demo account settlement.
- Docker multi-stage build and Docker Compose configuration.

## Run with Docker Compose

Prerequisites: Docker with Compose support.

From the project root:

```sh
docker compose up --build --pull always
```

Open <http://localhost:8081> in a browser. To choose a different host port, set `APP_PORT`, for example:

```sh
APP_PORT=8090 docker compose up --build
```

On Windows PowerShell:

```powershell
$env:APP_PORT = "8090"
docker compose up --build
```

Stop the foreground service with `Ctrl+C`. To run it in the background, use `docker compose up --build --pull always -d`; stop it with `docker compose down`.

## Build and run without Docker

Prerequisites:

- C++17 compiler
- CMake 3.20 or newer
- Boost.System
- OpenSSL development libraries
- `nlohmann/json` headers

Configure and build:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Start the server:

```sh
./build/upi-mesh
```

The server listens on port 8080 by default. Set `PORT` to override it:

```sh
PORT=8090 ./build/upi-mesh
```

On Windows, run the built executable from the generated build directory, for example `build/Release/upi-mesh.exe`, and set `$env:PORT = "8090"` if needed.

## Try the interactive demo

1. Open the dashboard and choose sender, receiver, amount, and demo PIN.
2. Select **Send payment** to encrypt a payment packet and inject it into `phone-alice`.
3. Select **Pass packets to nearby phones** to run a mesh gossip round. Repeat if desired.
4. Select **Upload from bridge** to send packets held by the internet-connected virtual bridge to the backend.
5. Review the account balances and payment activity sections for the settlement outcome.
6. Select **Reset demo** to clear mesh packets and the idempotency cache. Balances and transaction history are in-memory for the server lifetime.

The seeded demo accounts are `alice@demo`, `bob@demo`, `carol@demo`, and `dave@demo`. The default demo PIN shown in the form is `1234`; it is hashed in the demonstration payload, but the demo does not implement production authentication or PIN validation.

## API endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Interactive dashboard |
| `GET` | `/api/server-key` | Server public key and encryption metadata |
| `GET` | `/api/accounts` | Demo account balances |
| `GET` | `/api/transactions` | Recent payment ledger rows |
| `GET` | `/api/mesh/state` | Virtual device packet state and cache size |
| `POST` | `/api/demo/send` | Create and inject an encrypted demo payment |
| `POST` | `/api/mesh/gossip` | Run a packet gossip round |
| `POST` | `/api/mesh/flush` | Upload packets held by bridge devices |
| `POST` | `/api/mesh/reset` | Clear virtual-device packets and duplicate cache |
| `POST` | `/api/bridge/ingest` | Ingest a bridge packet directly |

Example payment request:

```sh
curl -X POST http://localhost:8081/api/demo/send \
  -H 'Content-Type: application/json' \
  -d '{"senderVpa":"alice@demo","receiverVpa":"bob@demo","amount":500,"pin":"1234","ttl":5,"startDevice":"phone-alice"}'
```

For direct bridge ingestion, send a JSON packet containing `packetId`, `ttl`, `createdAt`, and base64 `ciphertext`. Optional headers are `X-Bridge-Node-Id` and `X-Hop-Count`.

## Project layout

```text
CMakeLists.txt          CMake build configuration
Dockerfile              Multi-stage image build
docker-compose.yml       Local container orchestration
public/index.html        Interactive dashboard
src/main.cpp             C++ HTTP API, mesh simulation, crypto, and ledger
```

## Important limitations

- State is held in memory; restarting the server resets balances, ledger, mesh packets, and the duplicate cache.
- The simulator uses virtual devices and does not use Bluetooth or other phone-to-phone radio.
- Server RSA keys are generated at startup and are not persisted.
- The demo has no user authentication, authorization, rate limiting, durable database, or real banking integration.
- The bridge and API are plain HTTP unless deployed behind a TLS-terminating proxy.
- Duplicate detection is process-local and is not shared between multiple server instances.
- No real PIN verification is performed; the PIN hash is only part of the encrypted demonstration payload.

Do not deploy this demo as a payment service or expose it publicly without adding appropriate security, persistence, and operational controls.
