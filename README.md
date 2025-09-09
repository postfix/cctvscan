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

Targets (LAN / Single IP / File)
│
▼
[1] Port Scan → 80/443/8080–8099/8443 · 554/8554 · 1935–1939 · 3702 (we scan 0–65535 TCP by default)
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
