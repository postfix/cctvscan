## AGENT Handbook for CCTVScan

This document guides AI/code assistants working on this repository. It explains project goals, architecture, coding conventions, workflows, and the safest extension points. Follow it to make high-quality, idiomatic Go changes that integrate smoothly.

### Mission
- Discover, fingerprint, and assess IP cameras across HTTP/HTTPS, RTSP, ONVIF, RTMP, MMS.
- Prioritize performance, correctness, and safety. Default to fast scans; enable thorough scans via flags.

### Project Structure
- `cmd/cctvscan/`: CLI entrypoint and flags. Keep it thin.
- `internal/portscan/`: Masscan/Naabu wrappers and hybrid orchestration.
- `internal/probe/`: HTTP metadata, RTSP, ONVIF, and camera detection logic.
- `internal/fingerprint/`: Brand/model identification (content/server headers, optimized matchers).
- `internal/streams/`: Stream discovery (MJPEG/RTSP/RTMP/MMS/HLS).
- `internal/credbrute/`: Credential testing.
- `internal/cvedb/`: CVE lookup by brand.
- `internal/processor/`: Orchestrates concurrent post-scan processing and reporting.
- `internal/targets/`: Target parsing/expansion (IP, CIDR, file).
- `internal/search/`: Links to Shodan/Censys/Zoomeye/Google.
- `internal/geo/`: IP geo lookups.
- `internal/report/`: Reporting utilities.
- `internal/util/`: Shared helpers.

### Design Principles
- Keep binaries under `cmd/<app>`, internal logic under `internal/` packages.
- Clear is better than clever. Prefer readable code over micro-optimizations unless proven necessary.
- Make the zero value useful; prefer simple APIs with sensible defaults.
- Composition over inheritance; small cohesive packages.

### Go Standards (1.22+)
- Code must pass: `go fmt`, `go vet`, `staticcheck`, `govulncheck` (CI).
- Naming: packages lowercase; exported identifiers `PascalCase`; unexported `camelCase`; keep abbreviations uppercased (`ID`, `URL`).
- Use `context.Context` as the first param for I/O or long-running work. Respect cancellation in goroutines.
- Prefer pointer receivers for mutating/large structs.
- Always wrap errors with `%w`. Expose sentinel errors for control flow (`var ErrTimeout`). Only `panic` on programmer errors.
- Avoid reflection in hot paths. Pre-size slices/maps when capacity is known.

### Build, Lint, Test
```bash
go build ./...
go test ./... -race
go test -bench=. ./...
go vet ./...
staticcheck ./...
govulncheck ./...
```

### Running the tool
```bash
go build -o cctvscan ./cmd/cctvscan
sudo ./cctvscan 192.168.1.0/24                # default fast ports
sudo ./cctvscan --comprehensive 192.168.1.100 # 1000+ ports
sudo ./cctvscan --ports 80,443,8080,554 1.2.3.4
```

### Flags surfaced in CLI (`cmd/cctvscan/main.go`)
- `--comprehensive` toggles extensive camera ports.
- `--ports` overrides port set; default is camera-specific unless user specifies full range.
- `--rate`, `--retry`, `--wait`, `--threads`, `--adapter(-ip)` configure Naabu.
- `--privileged` (SYN), `--unprivileged` (CONNECT) scanning modes.
- `--timeout`, `--creds`, `--output`, `--debug`.

### Concurrency & Performance
- Use goroutines for independent probes; coordinate with `sync.WaitGroup` or channels.
- Respect `ctx.Done()` in long loops and network calls. Ensure goroutines terminate.
- Choose buffered channels intentionally; prefer unbuffered unless justified.
- Reuse `http.Client` and transports where safe; set timeouts (`Timeout`, `Dial`, TLS settings).
- Precompile regexes in hot paths or move to package-level vars if reused.

### Network Safety
- Set conservative default timeouts. Example in probes: 1.5–3s per request.
- Avoid flooding local networks; rate-limit via Naabu/Masscan flags.
- Only test credentials on endpoints that return 401/403.

### Logging
- Use structured logging where possible. Avoid `fmt.Println` in libraries. CLI can print user-facing summaries; libraries should return values/errors.

### Extension Points (safe to modify)
- `internal/fingerprint/`: Add brand keywords/model patterns. Keep generic last. Add tests in `brand_test.go`.
- `internal/probe/`: Extend camera indicators (`CameraServers`, `CameraContentTypes`, endpoints). Keep timeouts short and methods context-aware.
- `internal/streams/`: Add protocol detectors in `comprehensive.go`; ensure quick, cancellable checks.
- `internal/cvedb/`: Append CVEs per brand with NVD links; expose lookup helpers.
- `internal/credbrute/`: Add strategies guarded by context and backoff; avoid aggressive retries.
- `internal/portscan/`: Tune hybrid logic, add additional verification heuristics, but preserve defaults.

### Test Guidance
- Favor table-driven tests. Put them next to the code in `_test.go`.
- For detectors, create fixtures or inline cases with sample headers/bodies.
- Use `-race` and fuzz critical parsers: `go test -fuzz=Fuzz -fuzztime=30s`.

### Security Checklist
- Enforce server timeouts on all HTTP clients (`Timeout`, `ReadHeaderTimeout` via servers if added).
- Avoid storing secrets; read creds from files/flags/env.
- Use `crypto/rand` and `golang.org/x/crypto` for crypto when needed.
- Keep dependencies updated; run `govulncheck` regularly.

### Style Reminders
- Small functions, early returns, minimal nesting.
- Do not ignore errors; wrap with context: `fmt.Errorf("probe rtsp %s: %w", url, err)`.
- Keep regex and keyword lists near their usage; add brief comments for non-obvious indicators.

### Common Pitfalls Noticed
- Unused params: remove or use via existing inputs (e.g., `baseURL` already includes port).
- Case-insensitive matching: lowercase once and reuse.
- HEAD vs GET: prefer `HEAD` for existence checks; fall back to `GET` when needed.

### Definition of Done for a PR
- Compiles and passes `go test ./... -race`.
- No lints from `go vet` and `staticcheck`.
- Added or updated tests for new logic.
- Benchmarks unchanged or improved on hot paths.
- README/USAGE updated if flags/behavior changed.

### Quick Architecture Map
- Discovery: `internal/portscan/hybrid.go` → open ports.
- Probing: `internal/probe/*` (HTTP, RTSP, ONVIF) → metadata and indicators.
- Fingerprint: `internal/fingerprint/*` → brand/model.
- Streams: `internal/streams/*` → URLs.
- Security: `internal/cvedb/*`, `internal/credbrute/*` → CVEs/auth checks.
- Processing/Output: `internal/processor/*`, `internal/report/*`.

### How to Propose a New Detector
1. Define fast, cancellable probe with `context.Context`.
2. Add brand/keyword patterns; avoid false positives (prefer AND conditions when possible).
3. Cap body reads (e.g., `io.LimitReader(..., 8192)`).
4. Add unit tests with representative samples.
5. Document behavior in `README.md` if user-visible.

—
If in doubt, keep it simple, fast, and cancellable. Favor measurable improvements backed by tests.


