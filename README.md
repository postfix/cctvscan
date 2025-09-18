# CCTVScan - Advanced IP Camera Security Assessment Tool

A comprehensive pentesting toolkit for **discovering, fingerprinting, and assessing IP cameras** across multiple protocols including HTTP/HTTPS, RTSP, ONVIF, RTMP, and MMS. Enhanced with Python CamXploit-inspired features for maximum detection accuracy.

## 🚀 Features

- **⚡ Hybrid Port Scanning**: Masscan for high-speed SYN discovery + Naabu for verification
- **🎯 Dual Port Modes**: 
  - **Default**: Fast 79 camera-specific ports
  - **Comprehensive**: 1000+ thorough camera port scan
- **🎯 Multi-Protocol Support**: HTTP/HTTPS, RTSP, RTMP, MMS, ONVIF protocol detection
- **🔍 Enhanced Brand Detection**: Advanced detection for 15+ camera brands with server headers, content analysis, and DVR/NVR patterns
- **🛡️ Expanded CVE Database**: 100+ CVEs across major camera brands with direct NVD links
- **🔐 Intelligent Credential Testing**: Multi-method authentication testing with form detection
- **📹 Comprehensive Stream Detection**: Multi-protocol stream detection (MJPEG, RTSP, RTMP, MMS, HLS)
- **🌍 Geographic Intelligence**: IP location lookup with ISP and coordinate information
- **🔍 Search Integration**: Direct links to Shodan, Censys, Zoomeye, and Google Dorking
- **📊 Advanced Reporting**: Detailed console output with enhanced detection results

## Supported Camera Brands

- **Hikvision** (18 CVEs) - Advanced server header detection
- **Dahua** (14 CVEs) - DVR/NVR pattern recognition
- **Axis** (17 CVEs) - Axis-specific endpoint detection
- **Bosch** (5 CVEs) - Security system integration
- **Samsung** (11 CVEs) - Samsung Techwin detection
- **Panasonic** (3 CVEs) - Network camera patterns
- **Vivotek** (4 CVEs) - IP camera detection
- **Sony** (2 CVEs) - IPela series detection
- **CP Plus** (3 CVEs) - UVR model detection
- **Foscam** - IP camera detection
- **D-Link** - Camera-specific patterns
- **EasyN** - Network camera detection
- **Edimax** - IP camera patterns
- **Intellinet** - Camera detection
- **TP-Link** - Camera-specific detection
- **Trendnet** - Network camera patterns
- **Mobotix** - Advanced camera detection
- **Generic** - Fallback camera detection

## Architecture

### Modular Architecture
- **`Maascan`**: High-speed SYN scanning for external targets with performance optimizations
- **`Nabu`**: Reliable port verification and localhost scanning with efficient string operations
- Concurrent HTTP/RTSP/ONVIF enumeration
- Concurrent credential brute force with connection pooling 
- Cached brand detection with optimized string matching

### Performance Optimizations
- **Concurrent Post-Scan Processing**: All fingerprinting, brute force, and enumeration run concurrently
- **Smart Caching**: Brand detection, HTTP metadata, and credential caching
- **Optimized String Operations**: Custom parsing with pre-compiled prefixes and efficient matching
- **Connection Pooling**: HTTP client reuse with keep-alive connections
- **Memory Management**: Pre-allocated buffers and efficient data structures
- **Thread-Safe Operations**: Minimal locking with concurrent-safe data structures
- **Buffer Management**: 1MB scanner buffers for large output processing

### Port Coverage

#### Default Mode (79 ports) - Fast Scanning
- **Web Ports**: 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 8080, 8443, 8000-8010, 8081-8099, 8100-8104
- **RTSP Ports**: 554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554
- **RTMP Ports**: 1935, 1936, 1937, 1938, 1939
- **ONVIF/Discovery**: 3702
- **Miscellaneous**: 37777, 5000, 7001, 8999, 9000-9002, 10000, 8181, 5001, 50000, 8880, 8889, 3001

#### Comprehensive Mode (1000+ ports) - Thorough Scanning
- **All Default Ports** plus extensive high-port ranges
- **Custom Camera Ports**: 37777-37800 (Hikvision, Dahua)
- **ONVIF Ports**: 3702-3710
- **High Port Ranges**: 10000-65010 (increments of 10)
- **MMS Ports**: 1755-1760
- **Extended Web Ports**: 5000-9010, 8888-9999
- **VLC Streaming**: 8080-8190

## Installation

### Prerequisites

- **Go 1.22+**
- **Masscan** (for SYN scanning)
- **Naabu** (for verification)

### Build from Source

```bash
git clone https://github.com/postfix/cctvscan.git
cd cctvscan
go build -o cctvscan ./cmd/cctvscan
```

### Install Dependencies

```bash
# Install masscan (Ubuntu/Debian)
sudo apt-get install masscan

# Install naabu
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Set masscan capabilities for SYN scanning
sudo setcap cap_net_raw+ep $(which masscan)
```

## Technical Details

### Scanning Strategy
1. **Target Analysis**: Automatically detects localhost vs external targets
2. **Discovery Phase**: 
   - External targets: Masscan SYN scan (10,000+ pps)
   - Localhost targets: Naabu CONNECT scan
3. **Verification Phase**: Naabu verification of discovered ports
4. **Protocol Analysis**: HTTP/HTTPS, RTSP, ONVIF probing
5. **Security Assessment**: Brand detection, CVE lookup, credential testing

### Performance Metrics
- **Scanning Speed**: 10,000+ packets/second with masscan
- **Memory Usage**: <50MB for typical scans
- **CPU Efficiency**: Optimized string parsing and caching
- **Network Efficiency**: Smart port selection and rate limiting

## Usage

### Basic Scanning

```bash
# Scan single IP (default 79 ports)
sudo ./cctvscan 192.168.1.100

# Scan CIDR range
sudo ./cctvscan 192.168.1.0/24

# Scan targets from file
sudo ./cctvscan targets.txt
```

### Advanced Scanning Options

```bash
# Comprehensive scan (1000+ ports)
sudo ./cctvscan --comprehensive 192.168.1.100

# Custom port range
sudo ./cctvscan --ports 80,443,8080,554 192.168.1.100

# Debug mode with verbose output
sudo ./cctvscan --debug 192.168.1.100

# Force SYN scan (requires root)
sudo ./cctvscan --privileged 192.168.1.100

# Force CONNECT scan (no root required)
sudo ./cctvscan --unprivileged 192.168.1.100

# Custom credentials file
sudo ./cctvscan --creds mycreds.txt 192.168.1.100

# Custom output directory
sudo ./cctvscan --output /tmp/results 192.168.1.100

# Adjust scan rate
sudo ./cctvscan --rate 5000 192.168.1.100

# Custom timeout
sudo ./cctvscan --timeout 1h 192.168.1.100
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--comprehensive` | Use 1000+ camera ports instead of default 79 | false |
| `--ports` | Custom port range (e.g., '80,443,8000-9000') | 0-65535 |
| `--rate` | Packets per second rate for naabu | 1000 |
| `--retry` | Number of retries for port scanning | 3 |
| `--wait` | Seconds to wait for late replies | 1 |
| `--adapter` | Network adapter name for naabu | auto |
| `--adapter-ip` | Source IP address for naabu | auto |
| `--timeout` | Overall scan timeout (e.g., '30m', '1h') | 30m |
| `--creds` | Credentials file for brute force | /etc/cctvscan/credentials.txt |
| `--output` | Output directory for results | . |
| `--debug` | Enable debug mode with verbose output | false |
| `--privileged` | Force privileged mode (SYN scan) | auto |
| `--unprivileged` | Force unprivileged mode (CONNECT scan) | auto |
| `--threads` | Number of threads for naabu | 25 |
| `--help` | Show help message | false |

### Enhanced Detection Features

The tool automatically provides:
- **Target expansion** from CIDR notation and file input
- **Intelligent port scanning** with naabu integration
- **Multi-protocol detection** (HTTP/HTTPS, RTSP, RTMP, MMS, ONVIF)
- **Advanced brand fingerprinting** with 15+ camera brands
- **Comprehensive CVE reporting** with direct NVD links
- **Intelligent credential testing** with multiple auth methods
- **Multi-protocol stream detection** (MJPEG, RTSP, RTMP, MMS, HLS)
- **Geographic intelligence** with IP location lookup
- **Search integration** with Shodan, Censys, Zoomeye, Google Dorking

## Workflow

1. **Target Processing**: Parse and expand targets from command line or files
2. **Port Discovery**: 
   - **Default Mode**: Fast 79 camera-specific ports
   - **Comprehensive Mode**: 1000+ thorough camera port scan
3. **Protocol Probing**: HTTP metadata extraction, RTSP service detection, ONVIF discovery
4. **Enhanced Brand Fingerprinting**: Multi-method detection using server headers, content analysis, DVR/NVR patterns
5. **Comprehensive Stream Detection**: Multi-protocol stream detection (MJPEG, RTSP, RTMP, MMS, HLS)
6. **CVE Analysis**: Vulnerability assessment based on detected brands
7. **Credential Testing**: Multi-method authentication testing on protected endpoints
8. **Geographic Intelligence**: IP location lookup with ISP and coordinate information
9. **Search Integration**: Generate links to Shodan, Censys, Zoomeye, Google Dorking
10. **Advanced Reporting**: Comprehensive console output with enhanced detection results

## Port Scanning Modes

### Default Mode (79 ports) - Fast Scanning
- **Use Case**: Quick reconnaissance and initial assessment
- **Speed**: ~5-10 seconds per target
- **Coverage**: Most common camera ports
- **Command**: `./cctvscan 192.168.1.100`

### Comprehensive Mode (1000+ ports) - Thorough Scanning
- **Use Case**: Complete security assessment and penetration testing
- **Speed**: ~30-60 seconds per target
- **Coverage**: Extensive port ranges including high ports
- **Command**: `./cctvscan --comprehensive 192.168.1.100`

### Custom Port Mode - Targeted Scanning
- **Use Case**: Specific port ranges or known services
- **Speed**: Variable based on port count
- **Coverage**: User-defined port ranges
- **Command**: `./cctvscan --ports 80,443,8080,554 192.168.1.100`

## Project Structure

```
cctvscan/
├── cmd/cctvscan/main.go          # Main application entry point
├── internal/
│   ├── cvedb/cvedb.go            # Comprehensive CVE database (100+ CVEs)
│   ├── fingerprint/
│   │   ├── brand.go              # Advanced brand detection (15+ brands)
│   │   └── optimized.go          # Optimized brand detection with caching
│   ├── probe/
│   │   ├── httpmeta.go           # HTTP metadata and login page detection
│   │   ├── camera_detection.go   # Enhanced camera detection with headers/content
│   │   ├── rtsp.go               # RTSP service probing and validation
│   │   └── onvif.go              # ONVIF discovery
│   ├── streams/
│   │   ├── mjpeg.go              # MJPEG stream detection (legacy)
│   │   └── comprehensive.go      # Multi-protocol stream detection
│   ├── geo/geo.go                # IP geographic location lookup
│   ├── search/search.go          # Search engine integration (Shodan, Censys, etc.)
│   ├── portscan/
│   │   ├── naabu.go              # Naabu integration wrapper
│   │   ├── masscan.go            # Masscan integration
│   │   └── hybrid.go             # Hybrid scanner combining both
│   ├── processor/optimized.go    # Concurrent post-scan processing
│   ├── credbrute/optimized.go    # Optimized credential brute force
│   ├── targets/expand.go         # Target parsing and expansion
│   └── util/util.go              # Utility functions
└── README.md
```

## Technical Details

### Enhanced Brand Detection

The tool uses comprehensive multi-method detection across:
- **HTTP Server headers** - Brand-specific server strings
- **HTTP response body content** - Page titles, form fields, keywords
- **RTSP Server headers** - RTSP service identification
- **RTSP Public command capabilities** - ONVIF and streaming capabilities
- **Content-Type analysis** - Camera-specific MIME types
- **DVR/NVR pattern recognition** - Specialized DVR/NVR detection
- **Model-specific indicators** - CP Plus UVR-0401E1, Hikvision DS- series, etc.

### Comprehensive Stream Detection

Multi-protocol stream detection supporting:
- **MJPEG Streams** - Real-time video streams
- **RTSP Streams** - Real-time streaming protocol
- **RTMP Streams** - Real-time messaging protocol
- **MMS Streams** - Microsoft media streaming
- **HLS Streams** - HTTP live streaming
- **Generic Streams** - Fallback detection

### Geographic Intelligence

IP location lookup provides:
- **ISP Information** - Internet service provider details
- **Geographic Coordinates** - Latitude/longitude with Google Maps links
- **Location Details** - City, region, country, postal code
- **Timezone Information** - Local timezone data

### Search Integration

Direct integration with security search engines:
- **Shodan** - Device and service discovery
- **Censys** - Host and certificate analysis
- **Zoomeye** - Network device search
- **Google Dorking** - Advanced search queries for camera discovery

### CVE Database

Contains **100+ CVEs** with direct links to NVD for detailed vulnerability information. The database is organized by brand for efficient lookup and reporting.

### Credential Testing

Intelligent credential testing that:
- Only tests endpoints requiring authentication (401/403 responses)
- Supports custom credential files
- Uses proper Basic auth encoding
- Respects timeouts and connection limits

## Example Output

### Enhanced Detection Results

```
=== Processing 192.168.1.100 ===
Open ports: [80 443 8080 554]
HTTP ports: [80 443 8080]
RTSP ports: [554]
HTTP Server: Hikvision-Webs
Login pages: [http://192.168.1.100/ http://192.168.1.100/login]

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

## CamXploit Integration

This tool incorporates advanced features inspired by the Python CamXploit tool:

### Enhanced Detection Capabilities
- **Comprehensive Port Lists**: 1000+ camera-specific ports for thorough scanning
- **Advanced Brand Detection**: 15+ camera brands with server headers and content analysis
- **DVR/NVR Pattern Recognition**: Specialized detection for recording devices
- **Multi-Protocol Stream Detection**: RTSP, RTMP, MMS, HTTP/HTTPS stream detection
- **Geographic Intelligence**: IP location lookup with ISP and coordinate information
- **Search Integration**: Direct links to Shodan, Censys, Zoomeye, Google Dorking

### Performance Improvements
- **Go Implementation**: Significantly faster than Python equivalent
- **Concurrent Processing**: Multi-threaded detection and scanning
- **Memory Efficiency**: Optimized for large-scale scanning
- **Network Optimization**: Smart port selection and rate limiting

### Feature Comparison

| Feature | CamXploit (Python) | CCTVScan (Go) |
|---------|-------------------|---------------|
| Port Scanning | 1000+ ports | 79 (default) / 1000+ (comprehensive) |
| Brand Detection | 10+ brands | 15+ brands |
| Stream Detection | Basic | Multi-protocol (RTSP, RTMP, MMS, HLS) |
| Geographic Info | Basic | Enhanced with coordinates |
| Search Integration | Basic | Advanced with multiple engines |
| Performance | Moderate | High (Go + concurrency) |
| Memory Usage | High | Low (optimized) |
| Dependencies | Many | Minimal |

## Legal and Ethical Use

⚠️ **WARNING**: This tool is intended for security assessment purposes only. Use only on systems you own or have explicit written permission to test. Unauthorized scanning may violate local laws and regulations.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit pull requests for:
- Additional camera brand detection patterns
- New CVE entries
- Protocol support improvements
- Bug fixes and performance enhancements