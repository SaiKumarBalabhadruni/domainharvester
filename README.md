# DomainHarvester (DH)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](https://github.com/saikumarbalabhadruni/domainharvester/blob/main/CONTRIBUTING.md)

> 🚀 **Production-Grade Defensive Security Scanner** for Ethical Hackers & Security Professionals

DomainHarvester is a comprehensive, modular reconnaissance tool designed for authorized security assessments. It performs passive and active enumeration to uncover potential vulnerabilities in domains, networks, and web applications.

## ✨ Features

| Module | Description | Key Capabilities |
|--------|-------------|------------------|
| 🔍 **DNS Enumeration** | Comprehensive DNS record analysis | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV, SPF, PTR, DNSSEC, Zone Transfer |
| 📋 **WHOIS Analysis** | Domain registration intelligence | Age, expiration, privacy protection, registrar analysis, suspicious emails |
| 🌐 **IP & ASN Profiling** | Geolocation & routing analysis | RDAP lookups, country/org detection, high-risk IP flagging |
| 🔒 **SSL/TLS Inspection** | Certificate security assessment | Validity, SAN matching, self-signed detection, deprecated protocol warnings |
| 🔌 **Port Scanning** | TCP port enumeration | Service identification, sensitive port exposure detection |
| 📧 **Email Security** | Mail server posture checks | MX, SPF, DMARC validation, policy analysis |
| 🌍 **Subdomain Discovery** | Attack surface mapping | Certificate Transparency, brute-force enumeration |
| 🛡️ **WAF Detection** | Web application firewall identification | Cloudflare, Akamai, Imperva, F5 detection |
| ☁️ **Cloud Storage Checks** | Misconfigured cloud assets | AWS S3 bucket enumeration |
| 🔄 **CORS Testing** | Cross-origin resource sharing analysis | Misconfiguration detection |
| 🌐 **Web Fingerprinting** | Technology stack identification | CMS detection, security headers, missing protections |
| 📂 **Asset Exposure** | Sensitive file/path discovery | .env, .git, backups, admin panels |
| 🕰️ **Wayback Analysis** | Historical web intelligence | Archived URL harvesting |
| 👥 **Social Media Intel** | OSINT on social presence | Platform existence checks |

## 🛠️ Installation

### Option 1: Direct Python Execution (Recommended)

1. **Create & Activate Virtual Environment**:
   ```bash
   python -m venv dh_env
   source dh_env/bin/activate  # On Windows: dh_env\Scripts\activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Scanner**:
   ```bash
   python domainharvester.py example.com
   ```

### Option 2: Install as Package

```bash
pip install .
# or
python setup.py install
```

Then run:
```bash
domainharvester example.com
```

## 🚀 Quick Start

### Interactive Mode
```bash
python domainharvester.py --interactive
```

### Full Scan (All Modules)
```bash
python domainharvester.py example.com
```

### Specific Modules
```bash
python domainharvester.py example.com --modules dns,whois,ip,web
```

### Passive Mode (No Active Scans)
```bash
python domainharvester.py example.com --passive
```

### Custom Configuration
```bash
python domainharvester.py example.com --timeout 6 --delay-min 0.05 --delay-max 0.3 --ports major --workers 100 --retries 3
```

## 📊 Port Presets

- `major` (default): 100+ common ports including web, mail, databases
- `top1000`: Top 1000 ports
- `all`: All 65535 ports (resource intensive)
- Custom: `--ports 1-1024,3306,5432,6379`

## 📝 Logging & Output

Enable verbose logging:
```bash
python domainharvester.py example.com --verbose --log-file dh.log
```

Reports are saved as:
- `dh_report_<domain>_<timestamp>.json`
- `dh_report_<domain>_<timestamp>.html`

Customize prefix: `--output-prefix my_scan`
Skip saving: `--no-save`

## ⚙️ Module Reference

Available modules: `dns`, `whois`, `ip`, `ssl`, `ports`, `email`, `subdomains`, `waf`, `cloud`, `cors`, `web`, `assets`, `wayback`, `social`

Run all: `--modules all`

## 🔧 Operational Flags

| Flag | Description |
|------|-------------|
| `--passive` | Skip active checks (ports, TLS sockets, zone transfers) |
| `--workers` | Concurrent threads (default: 60) |
| `--retries` | HTTP retry attempts (default: 2) |
| `--verbose` | Debug-level logging |
| `--log-file` | Write logs to file |
| `--timeout` | Request timeout in seconds (default: 5) |
| `--delay-min/max` | Stealth delay between requests |
| `--ports` | Port scan preset or custom ranges |
| `--output-prefix` | Custom report filename prefix |
| `--no-save` | Skip writing report files |

## ⚠️ Important Notes

- **Authorized Use Only**: This tool is for ethical security testing. Obtain explicit permission before scanning any systems.
- **Legal Compliance**: Unauthorized use may violate laws. Authors are not responsible for misuse.
- **Accuracy**: Results are heuristic; manually verify findings before remediation.
- **Rate Limiting**: Respect target systems; use delays to avoid detection.
- **Data Handling**: Store reports securely; do not share without authorization.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request
4. Follow ethical guidelines

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Built with ❤️ for the security community**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
