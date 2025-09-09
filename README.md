# cctvscan
A pentest toolkit to **discover, fingerprint, and sanity-check IP cameras** across HTTP/HTTPS, RTSP, ONVIF, and RTMP.

# CCTV Toolkit (Go, masscan-first)

A pentest toolkit to **discover, fingerprint, and sanity-check IP cameras** across HTTP/HTTPS, RTSP, ONVIF, and RTMP.

- **Fast discovery** with `masscan` over 0–65535 TCP (optional UDP as needed)
- **Accurate follow-ups** using tiny stdlib probes (HTTP(S), RTSP, ONVIF)
- **Brand fingerprinting** + **CVE hints** (internal DB with NVD links)
- **Login page detection** and **default credential** checks (Basic auth)
- **Stream checks** (RTSP DESCRIBE, MJPEG/snapshot) with **first-frame screenshots**
- **Outputs**: streaming JSONL + a concise Markdown report

> ⚠️ Use only on systems you own or are explicitly authorized to test.

---

## Why this tool

- **Speed first**: masscan does discovery; Go stdlib does precise verification and application probes.
- **Minimal dependencies**: requires only the `masscan` binary; Go code uses standard library.
- **DRY & testable**: single sources of truth for ports/paths; small packages with unit tests.

---

## Workflow
```bash
Targets ( IP ranges / File)
│
▼
[1] Port Scan w → 80/443/8080–8099/8443 · 554/8554 · 1935–1939 · 3702 (we scan 0–65535 TCP by default)
│
▼
[2] Camera Heuristics → HTTP Server/body + RTSP Server/Public
│
▼
[3] Brand Fingerprint → Hikvision / Dahua / Axis / CP Plus / Generic
│
▼
[4] CVE Hints (internal DB) → NVD links in logs
│
▼
[5] Login Pages → common paths (/, /login, /admin, …)
│
▼
[6] Default Creds → only where auth is required (401/403/WWW-Auth)
│
▼
[7] Streams → RTSP DESCRIBE (SDP), HTTP MJPEG/snapshots, RTMP hint
│
▼
[8] Report (JSONL + Markdown)
```

---

## Requirements

- **Go 1.22+**
- **masscan** installed and on `PATH` (Linux/macOS).  
  Needs **root / CAP_NET_RAW** to send raw SYN at speed.
- Network permission to scan the target scope.

---

## Install

```bash
git clone https://github.com/postfix/cctvscan.git
cd <repo>
go build ./cmd/cctvscan
```
```markdown
# Quick start

Targets from file:
```
sudo ./cctvtool \
  -iL targets.txt \
  --rate 10000 --wait 8 \
  --adapter eth0 --adapter-ip 192.168.1.10 \
  --verify-timeout 350ms \
  --creds defaults.txt \
  -o out/

LAN CIDR:
```
sudo ./cctvtool 192.168.1.0/24 -o out/
```

Outputs:

*   `out/results.jsonl` — one JSON document per host
*   `out/report.md` — human-readable summary
*   `out/shots/` — saved first-frame JPEGs when found

Flags:

*   `-iL path` to targets file (one IP or CIDR per line)
*   `-o output directory` (default `out`)
*   `--rate masscan rate` in packets/sec (default `10000`)
*   `--wait seconds` masscan waits for late replies (default `8`)
*   `--adapter network adapter name` for masscan (optional)
*   `--adapter-ip source IP` for masscan (optional)
*   `--timeout overall run timeout` (default `30m`)
*   `--verify-timeout TCP connect timeout` per port (default `350ms`)
*   `--creds file` with default credentials to try (optional)

Credentials file format:

Plain text, one `user:pass` per line. Lines starting with `#` are ignored.

```
admin:admin
admin:12345
root:root
```

Creds are attempted only on paths that request auth (`WWW-Authenticate` present or `401/403`).

What the tool does in detail:

Discovery:
Runs `masscan` over `0–65535/TCP` (configurable) with sane defaults.
Collects open tuples as `map[ip][]port`.

Verification:
Performs tiny TCP connect checks on those tuples to remove stateless false positives.

HTTP(S) heuristics:
*   `GET /` to extract `Server` header and a body snippet (`≤512 B`)
*   `HEAD` common login paths (`/`, `/login`, `/admin`, `/index.html`)
*   Marks endpoints requiring auth via `401/403/WWW-Authenticate`

RTSP:
*   `RTSP OPTIONS *` to confirm service and read `Server:` and `Public:`
*   Optional `DESCRIBE` can be added to parse SDP later

ONVIF:
*   Small unicast WS-Discovery probe to `UDP 3702` on the host when that port is open

Brand fingerprint:
*   Case-insensitive match across HTTP server/body and RTSP Server against common vendors
*   Emits brand and CVE hints from an internal DB with NVD links

Default creds:
*   Tries Basic auth from your `--creds` file on endpoints that requested authentication

Streams:
*   Attempts a small set of MJPEG/snapshot paths and saves first frame to `out/shots/`

Reporting:
*   Streams JSON lines to `out/results.jsonl` during the run
*   Writes a final `out/report.md` with open ports, brand, CVEs, login pages, findings

Repository layout:

*   `cmd/cctvscan/main.go` # orchestration (no sharding)
*   `internal/`
    *   `targets/expand.go` # parse args/file, expand CIDR safely
    *   `portscan/masscan.go` # thin wrapper: spawn masscan, stream-parse JSON
    *   `probe/httpmeta.go` # http meta + login pages
    *   `probe/rtsp.go` # rtsp OPTIONS/Public
    *   `probe/onvif.go` # unicast WS-Discovery probe (udp/3702)
    *   `fingerprint/brand.go` # brand detection + CVE links
    *   `cvedb/cvedb.go` # internal brand → CVE list
    *   `credbrute/basic.go` # default creds for Basic auth
    *   `streams/mjpeg.go` # snapshot/MJPEG first frame save
    *   `report/report.go` # JSON/Markdown outputs
*   `testdata/`
    *   `masscan.json` # parser fixtures for tests

Testing:

Run all tests:
```bash
go test ./...
```

What’s covered:

*   CIDR expansion and input parsing
*   `masscan` JSON parser (fixtures; no network required)
*   Brand detection and CVE mapping
*   Report JSON/Markdown routines

Add more tests as you extend probes (e.g., RTSP parsing, digest auth, ONVIF parsing).

Operational tips:

*   Start with conservative `--rate` on WAN (e.g., `10k`). On lab LANs you can go much higher.
*   `--wait` helps collect late SYN-ACKs; `5–8` seconds is a good default.
*   For HTTPS probing, we skip certificate verification on purpose to avoid handshake failures on cams with bad certs.
*   ONVIF discovery is unicast here; multicast discovery across a subnet is intentionally out of scope to keep the tool focused and safe by default.

Extending:

*   Digest auth in `credbrute` for models that default to Digest instead of Basic.
*   RTSP `DESCRIBE` with SDP parsing to extract codec/resolution.
*   Richer brand DB with better header/body fingerprint sets.
*   CVE DB refresh from external feeds (still keep a small internal map for hints).

Legal & ethics:

Only scan assets you are authorized to test. Respect rate limits and local laws. The authors assume no liability for misuse.

License:

MIT
```
