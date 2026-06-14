# PyScanOSINT 🛡️

A lightweight Python-based OSINT tool for automated domain reconnaissance, subdomain enumeration, and attack surface mapping.

[![Security: Bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![Tests: Pytest](https://img.shields.io/badge/tests-pytest-blue.svg)](https://docs.pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## 📋 Features

- **Subdomain Enumeration**: Passive discovery using `crt.sh` (Certificate Transparency logs).
- **Port Scanning**: Integrated `nmap` scanning for common ports (80, 443).
- **Protocol Identification**: Automatic detection of valid `http://` or `https://` schemas.
- **Directory Discovery**: Multi-threaded directory bruteforce (fuzzing) to find hidden assets.
- **Reporting**: Automated Markdown report generation for documentation and analysis.
- **DevSecOps Ready**: Includes SAST (Static Application Security Testing) and comprehensive Unit Tests.

## 🛠 Tech Stack

- **Language**: Python 3.10+
- **Libraries**: `requests`, `python-nmap`, `responses` (for testing).
- **Concurrency**: `ThreadPoolExecutor` for high-performance discovery.
- **Testing**: `pytest` with mocked API responses.
- **Security**: `Bandit` for vulnerability scanning.

## 🚀 Installation

### Prerequisites

Ensure you have `nmap` installed on your system:
```bash
# Debian/Ubuntu/Kali
sudo apt install nmap
```

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/pyscan-osint.git
   cd pyscan-osint
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

Run a basic scan with default settings:
```bash
python main.py -d example.com
```

Perform a full scan with a custom wordlist and output to Markdown:
```bash
python main.py -d example.com -w common_dirs.txt -o report.md
```

### CLI Arguments
| Flag | Long Flag | Description | Required |
|------|-----------|-------------|----------|
| `-d` | `--domain`| Target domain or IP | Yes |
| `-w` | `--wordlist`| Path to directory wordlist | No |
| `-o` | `--output`| Save results to .md file | No |

## 🧪 Testing & Quality Assurance

### Running Tests
To ensure the logic is correct (using `responses` to mock `crt.sh` and `http` calls):
```bash
pytest test_main_funcs.py
```

### Security Linting (SAST)
The project is regularly scanned for common security issues using `Bandit`:
```bash
bandit -r main.py
```

## 🛡️ Ethical Use & Disclaimer
This tool is provided for **educational and ethical security testing purposes only**. The developer is not responsible for any misuse or damage caused by this tool. Always obtain explicit permission before scanning targets.
