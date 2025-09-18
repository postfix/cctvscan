# CCTVScan Usage Guide

This comprehensive guide covers all features and usage patterns for CCTVScan, an advanced IP camera security assessment tool.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Command Line Options](#command-line-options)
3. [Scanning Modes](#scanning-modes)
4. [Advanced Features](#advanced-features)
5. [Output Interpretation](#output-interpretation)
6. [Examples](#examples)
7. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Usage

```bash
# Scan a single IP (default 79 ports)
sudo ./cctvscan 192.168.1.100

# Scan a network range
sudo ./cctvscan 192.168.1.0/24

# Scan targets from file
sudo ./cctvscan targets.txt

# Comprehensive scan (1000+ ports)
sudo ./cctvscan --comprehensive 192.168.1.100
```

### Prerequisites

```bash
# Install dependencies
sudo apt-get install masscan
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Set masscan capabilities
sudo setcap cap_net_raw+ep $(which masscan)

# Build the tool
go build -o cctvscan ./cmd/cctvscan
```

## Command Line Options

### Core Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--comprehensive` | Use 1000+ camera ports | false | `--comprehensive` |
| `--ports` | Custom port range | 0-65535 | `--ports 80,443,8080,554` |
| `--rate` | Packets per second | 1000 | `--rate 5000` |
| `--timeout` | Scan timeout | 30m | `--timeout 1h` |
| `--debug` | Debug mode | false | `--debug` |

### Scanning Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--privileged` | Force SYN scan | auto | `--privileged` |
| `--unprivileged` | Force CONNECT scan | auto | `--unprivileged` |
| `--retry` | Number of retries | 3 | `--retry 5` |
| `--wait` | Wait for late replies | 1 | `--wait 2` |
| `--threads` | Number of threads | 25 | `--threads 50` |

### Network Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--adapter` | Network adapter | auto | `--adapter eth0` |
| `--adapter-ip` | Source IP | auto | `--adapter-ip 192.168.1.10` |

### File Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `--creds` | Credentials file | /etc/cctvscan/credentials.txt | `--creds mycreds.txt` |
| `--output` | Output directory | . | `--output /tmp/results` |

### Help Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--version` | Show version information |

## Scanning Modes

### 1. Default Mode (79 ports) - Fast Scanning

**Use Case**: Quick reconnaissance and initial assessment

```bash
# Basic scan
sudo ./cctvscan 192.168.1.100

# Network range
sudo ./cctvscan 192.168.1.0/24

# With debug output
sudo ./cctvscan --debug 192.168.1.100
```

**Ports Scanned**:
- Web ports: 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 8080, 8443
- RTSP ports: 554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554
- RTMP ports: 1935, 1936, 1937, 1938, 1939
- ONVIF: 3702
- Miscellaneous: 37777, 5000, 7001, 8999, 9000-9002, 10000, 8181, 5001, 50000, 8880, 8889, 3001

### 2. Comprehensive Mode (1000+ ports) - Thorough Scanning

**Use Case**: Complete security assessment and penetration testing

```bash
# Comprehensive scan
sudo ./cctvscan --comprehensive 192.168.1.100

# With custom rate
sudo ./cctvscan --comprehensive --rate 2000 192.168.1.100

# With timeout
sudo ./cctvscan --comprehensive --timeout 2h 192.168.1.0/24
```

**Additional Ports**:
- Custom camera ports: 37777-37800
- ONVIF ports: 3702-3710
- High port ranges: 10000-65010 (increments of 10)
- MMS ports: 1755-1760
- Extended web ports: 5000-9010, 8888-9999
- VLC streaming: 8080-8190

### 3. Custom Port Mode - Targeted Scanning

**Use Case**: Specific port ranges or known services

```bash
# Specific ports
sudo ./cctvscan --ports 80,443,8080,554 192.168.1.100

# Port range
sudo ./cctvscan --ports 8000-9000 192.168.1.100

# Mixed ranges
sudo ./cctvscan --ports 80,443,8000-9000,554 192.168.1.100
```

## Advanced Features

### Enhanced Brand Detection

The tool automatically detects 15+ camera brands using multiple methods:

- **Server Headers**: Brand-specific server strings
- **Content Analysis**: Page titles, form fields, keywords
- **DVR/NVR Patterns**: Specialized detection for recording devices
- **Model Detection**: Specific model identification (e.g., CP Plus UVR-0401E1)

### Comprehensive Stream Detection

Multi-protocol stream detection supporting:

- **MJPEG Streams**: Real-time video streams
- **RTSP Streams**: Real-time streaming protocol
- **RTMP Streams**: Real-time messaging protocol
- **MMS Streams**: Microsoft media streaming
- **HLS Streams**: HTTP live streaming

### Geographic Intelligence

IP location lookup provides:

- **ISP Information**: Internet service provider details
- **Geographic Coordinates**: Latitude/longitude with Google Maps links
- **Location Details**: City, region, country, postal code
- **Timezone Information**: Local timezone data

### Search Integration

Direct integration with security search engines:

- **Shodan**: Device and service discovery
- **Censys**: Host and certificate analysis
- **Zoomeye**: Network device search
- **Google Dorking**: Advanced search queries for camera discovery

## Output Interpretation

### Basic Output

```
=== Processing 192.168.1.100 ===
Open ports: [80 443 8080 554]
HTTP ports: [80 443 8080]
RTSP ports: [554]
HTTP Server: Hikvision-Webs
Login pages: [http://192.168.1.100/ http://192.168.1.100/login]
```

### Enhanced Detection Output

```
🎥 Camera Detected: Hikvision
   Model: DS-2CD2143G0-I
   Server: Hikvision-Webs
   Indicators: [Server Header: Hikvision-Webs, Content Type: text/html]
   Auth Required: Basic
   Endpoints: [http://192.168.1.100/ http://192.168.1.100/login]

📺 Streams Found (3):
   RTSP: rtsp://192.168.1.100:554/Streaming/Channels/101
   HTTP-Video: http://192.168.1.100:8080/video/mjpg.cgi
   MJPEG: http://192.168.1.100:80/mjpg/video.mjpg

🛡️ CVEs Found:
   CVE-2021-36260: https://nvd.nist.gov/vuln/detail/CVE-2021-36260
   CVE-2017-7921: https://nvd.nist.gov/vuln/detail/CVE-2017-7921

🌍 Geographic Information:
   IP: 192.168.1.100
   ISP: Private Network
   Location: Local Network
   Coordinates: N/A (Private IP)

🔍 Search Integration:
   Shodan: https://www.shodan.io/search?query=192.168.1.100
   Censys: https://search.censys.io/hosts/192.168.1.100
   Zoomeye: https://www.zoomeye.org/searchResult?q=192.168.1.100
   Google Dork: https://www.google.com/search?q=site:192.168.1.100+inurl:view/view.shtml
```

## Examples

### Example 1: Basic Network Scan

```bash
# Scan local network
sudo ./cctvscan 192.168.1.0/24

# Output: Shows all cameras found in the network
```

### Example 2: Comprehensive Security Assessment

```bash
# Thorough scan with debug output
sudo ./cctvscan --comprehensive --debug 192.168.1.100

# Output: Detailed analysis with all detection features
```

### Example 3: Custom Port Range

```bash
# Scan specific ports
sudo ./cctvscan --ports 80,443,8080,554,1935 192.168.1.100

# Output: Focused scan on specific services
```

### Example 4: High-Speed Scanning

```bash
# Fast scan with high rate
sudo ./cctvscan --rate 10000 192.168.1.0/24

# Output: Quick network reconnaissance
```

### Example 5: Long-Running Scan

```bash
# Extended timeout for large networks
sudo ./cctvscan --comprehensive --timeout 4h 10.0.0.0/8

# Output: Comprehensive scan of large network
```

## Troubleshooting

### Common Issues

#### 1. Permission Denied

```bash
# Error: Permission denied for masscan
# Solution: Set capabilities
sudo setcap cap_net_raw+ep $(which masscan)
```

#### 2. Naabu Not Found

```bash
# Error: naabu: command not found
# Solution: Install naabu
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

#### 3. No Open Ports Found

```bash
# Issue: No ports detected
# Solutions:
# 1. Check if target is reachable
ping 192.168.1.100

# 2. Try unprivileged mode
./cctvscan --unprivileged 192.168.1.100

# 3. Check firewall settings
sudo ufw status
```

#### 4. Slow Scanning

```bash
# Issue: Scan is too slow
# Solutions:
# 1. Increase rate
./cctvscan --rate 5000 192.168.1.100

# 2. Use default mode instead of comprehensive
./cctvscan 192.168.1.100

# 3. Reduce timeout
./cctvscan --timeout 10m 192.168.1.100
```

#### 5. Memory Issues

```bash
# Issue: Out of memory
# Solutions:
# 1. Use default mode
./cctvscan 192.168.1.100

# 2. Reduce thread count
./cctvscan --threads 10 192.168.1.100

# 3. Scan smaller ranges
./cctvscan 192.168.1.0/28
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
# Debug mode
sudo ./cctvscan --debug 192.168.1.100

# Output includes:
# - Detailed scan configuration
# - Port discovery process
# - Detection method details
# - Error messages
```

### Performance Tuning

#### For Fast Scanning

```bash
# High rate, default ports
sudo ./cctvscan --rate 10000 192.168.1.0/24
```

#### For Thorough Scanning

```bash
# Comprehensive mode, extended timeout
sudo ./cctvscan --comprehensive --timeout 2h 192.168.1.0/24
```

#### For Large Networks

```bash
# High threads, custom rate
sudo ./cctvscan --threads 100 --rate 5000 10.0.0.0/8
```

## Best Practices

### 1. Start with Default Mode

```bash
# Quick reconnaissance first
sudo ./cctvscan 192.168.1.0/24

# Then comprehensive for interesting targets
sudo ./cctvscan --comprehensive 192.168.1.100
```

### 2. Use Appropriate Timeouts

```bash
# Small networks: 30 minutes
sudo ./cctvscan --timeout 30m 192.168.1.0/24

# Large networks: 2+ hours
sudo ./cctvscan --comprehensive --timeout 4h 10.0.0.0/8
```

### 3. Monitor Resource Usage

```bash
# Check CPU and memory usage
top -p $(pgrep cctvscan)

# Adjust threads if needed
sudo ./cctvscan --threads 50 192.168.1.0/24
```

### 4. Save Results

```bash
# Save to file
sudo ./cctvscan 192.168.1.0/24 > results.txt

# Save with timestamp
sudo ./cctvscan 192.168.1.0/24 > "scan_$(date +%Y%m%d_%H%M%S).txt"
```

### 5. Use Debug Mode for Troubleshooting

```bash
# Debug mode for issues
sudo ./cctvscan --debug 192.168.1.100 2>&1 | tee debug.log
```

## Security Considerations

### 1. Legal Compliance

- Only scan systems you own or have explicit permission to test
- Check local laws and regulations
- Obtain written authorization before testing

### 2. Network Impact

- Use appropriate scan rates to avoid overwhelming networks
- Monitor network performance during scans
- Consider scanning during off-peak hours

### 3. Data Protection

- Secure scan results and logs
- Follow data protection regulations
- Implement proper access controls

### 4. Responsible Disclosure

- Report vulnerabilities to vendors
- Follow responsible disclosure practices
- Provide detailed technical information

## Support

For issues, questions, or contributions:

1. Check this usage guide
2. Review the README.md
3. Check GitHub issues
4. Submit new issues with detailed information

## License

MIT License - See LICENSE file for details.
