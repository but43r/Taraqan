# Taraqan - SMB Share Scanner

## Features

- 🔐 **Pass-the-Hash** — аутентификация по NT-хешу
- 🌐 **Subnet scanning** — CIDR нотация (192.168.1.0/24)
- 🔍 **Pattern matching** — поиск файлов по glob-паттернам
- 📥 **File download** — автоматическая выкачка найденных файлов
- ⚡ **Multi-threaded** — параллельное сканирование хостов и шар
- 🇷🇺 **Russian patterns** — встроенные паттерны для СНГ окружения

## Installation

```bash
# Clone
git clone https://github.com/your-username/taraqan.git
cd taraqan

# Build
go build -o taraqan -ldflags="-s -w" .

# Or cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o taraqan -ldflags="-s -w" .
```

## Usage

```bash
# Basic PTH scan
./taraqan -t 192.168.1.0/24 -u admin -d CORP -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Download matched files
./taraqan -t 10.1.2.3 -u admin -d DOMAIN -H hash \
  --patterns "*учетк*,*пароль*,*.kdbx" \
  --download --max-size 50 -v

# Password auth, skip admin shares
./taraqan -t 10.0.0.10 -u admin -d DOMAIN -p "Password123" --skip-admin

# Export to JSON
./taraqan -t 10.0.0.0/24 -u admin -H hash -o results.json
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | - | Target IP/CIDR (required) |
| `-u, --username` | - | Username (required) |
| `-d, --domain` | `.` | Domain name |
| `-H, --hash` | - | NT hash for PTH |
| `-p, --password` | - | Password |
| `--patterns` | built-in | Patterns (file or comma-sep) |
| `--threads` | 10 | Host threads |
| `--share-threads` | 3 | Share threads per host |
| `--share-timeout` | 2m | Timeout per share |
| `--depth` | 5 | Max directory depth |
| `--download` | off | Download matched files |
| `--download-dir` | ./loot | Download directory |
| `--max-size` | 10 | Max file size in MB |
| `--skip-admin` | off | Skip admin shares (C$, ADMIN$) |
| `-o, --output` | - | Export file path |
| `--format` | json | Export format (json/csv) |
| `-v, --verbose` | off | Verbose output |

## Built-in Patterns

- Password files: `*password*`, `*credential*`, `*secret*`
- Key files: `*.kdbx`, `*.key`, `*.pem`, `*.pfx`, `id_rsa`, `*.ppk`
- Config files: `web.config`, `*.ini`, `*.conf`, `.env`
- Russian: `*пароль*`, `*учетк*`, `*ключ*`, `*логин*`, `*АРМ*`, `*ЭЦП*`

## Custom Patterns

Create a file with patterns (one per line):
```
# patterns.txt
*password*
*пароль*
*.kdbx
```

Use with `--patterns patterns.txt`

## Disclaimer

This tool is intended for authorized penetration testing only. Unauthorized access to computer systems is illegal.

## License

MIT
