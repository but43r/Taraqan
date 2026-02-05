# Taraqan

SMB share scanner with Pass-the-Hash authentication support for penetration testing.

## Features

- Pass-the-Hash authentication using NT hash
- Subnet scanning with CIDR notation
- Pattern-based file detection
- Automatic file download
- Multi-threaded host and share scanning
- Built-in patterns for sensitive files

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
# PTH scan
./taraqan -t 192.168.1.0/24 -u admin -d CORP -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Download matched files
./taraqan -t 10.1.2.3 -u admin -d DOMAIN -H hash \
  --patterns "*.kdbx,*password*" --download -v

# Password authentication
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

Password files, key files (.kdbx, .pem, .pfx, id_rsa), config files (.ini, .conf, .env), scripts (.bat, .ps1), and common sensitive filenames.

## Disclaimer

For authorized penetration testing only.

## License

MIT
