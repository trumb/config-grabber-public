# config-grabber

SSH into network switches, run a list of commands, and save the output to timestamped text files — one file per device.

Available in **two implementations** — choose the one that fits your environment:

| | Python | PowerShell |
|---|---|---|
| **Script** | `config_grabber.py` | `config-grabber.ps1` |
| **Dependency** | `pip install paramiko` | `Install-Module Posh-SSH` |
| **Platform** | Windows / macOS / Linux | Windows (PowerShell 5.1+) |
| **Password auth** | ✅ Secure prompt | ✅ `Read-Host -AsSecureString` |
| **SSH key auth** | ✅ RSA / Ed25519 | ✅ via Posh-SSH |
| **Enable mode** | ✅ | ✅ |
| **Per-device ports** | ✅ `IP:PORT` | ✅ `IP:PORT` |

---

## Features (both versions)

- Connect to **one or many switches** via IP address or a text file list
- **Per-device port support** using `IP:PORT` notation for PAT/NAT environments
- **Password** or **SSH key** authentication
- Optional **enable / privileged EXEC mode** (Cisco-style)
- Output saved as **`<IP>_<YYYY-MM-DDTHHMMSS>.txt`** per device
- Graceful error handling — a failed device is logged and skipped

---

## Python Version

### Requirements

- Python 3.10 or later
- `paramiko` library

```bash
pip install -r requirements.txt
```

### Usage

```bash
python config_grabber.py (-i IP[,IP,...] | -f FILE) -c FILE -u USER
                         [-p PASS] [-k KEY_FILE] [-e]
                         [--port PORT] [-t SECONDS] [-o DIR] [-v]
```

### Quick examples

```bash
# Single switch — prompted for password
python config_grabber.py -i 192.168.1.1 -c examples/commands.txt -u admin

# Device file, save to ./output
python config_grabber.py -f examples/devices.txt -c examples/commands.txt -u admin -o output

# SSH key + enable mode
python config_grabber.py -f examples/devices.txt -c examples/commands.txt -u admin -k ~/.ssh/id_rsa -e -o output

# PAT/NAT — per-device ports
python config_grabber.py -i "203.0.113.1:2221,203.0.113.1:2222" -c examples/commands.txt -u admin
```

---

## PowerShell Version

### Requirements

- Windows PowerShell 5.1 or PowerShell 7+
- [Posh-SSH](https://www.powershellgallery.com/packages/Posh-SSH) module

```powershell
Install-Module -Name Posh-SSH -Scope CurrentUser
```

### Usage

```powershell
.\config-grabber.ps1 [-IP <string> | -DeviceFile <path>]
                     -CommandFile <path> -Username <string>
                     [-Password <SecureString>] [-KeyFile <path>]
                     [-Enable] [-Port <int>] [-Timeout <int>]
                     [-OutputDir <path>] [-Verbose]
```

### Quick examples

```powershell
# Single switch — prompted for password
.\config-grabber.ps1 -IP 192.168.1.1 -CommandFile examples\commands.txt -Username admin

# Device file, save to .\output
.\config-grabber.ps1 -DeviceFile examples\devices.txt -CommandFile examples\commands.txt -Username admin -OutputDir .\output

# SSH key + enable mode
.\config-grabber.ps1 -DeviceFile examples\devices.txt -CommandFile examples\commands.txt -Username admin -KeyFile C:\Users\me\.ssh\id_rsa -Enable -OutputDir .\output

# PAT/NAT — per-device ports
.\config-grabber.ps1 -IP "203.0.113.1:2221,203.0.113.1:2222" -CommandFile examples\commands.txt -Username admin
```

---

## Input File Formats

Both versions use the same file formats.

### devices.txt

```
# Lines starting with '#' are comments — ignored
# Blank lines are ignored

# Standard SSH port (uses --port / -Port default, typically 22)
192.168.1.1
192.168.1.2

# PAT'd devices with per-device ports
10.0.0.1:2221
10.0.0.2:2222
```

### commands.txt

```
# Cisco IOS example — one command per line
terminal length 0
show version
show ip interface brief
show running-config
```

---

## Output

Each device produces one output file per run:

```
output/
├── 192.168.1.1_2026-02-26T101930.txt
├── 10.0.0.1_2026-02-26T101936.txt
```

Each file starts with a metadata header:

```
# Config Grabber Output
# Device  : 192.168.1.1
# Captured: 2026-02-26T10:19:30
# ============================================================

Switch>terminal length 0
Switch>show version
...
```

---

## PAT / NAT Environments

Use `IP:PORT` notation anywhere a device is specified:

```
# devices.txt
192.168.1.1          ← uses default port (22)
203.0.113.1:2221     ← per-device port
203.0.113.1:2222     ← per-device port
```

```bash
# or inline
python config_grabber.py -i "203.0.113.1:2221,203.0.113.1:2222" ...
.\config-grabber.ps1  -IP "203.0.113.1:2221,203.0.113.1:2222" ...
```

---

## Security Notes

- Passwords are always **prompted securely** — never stored in shell history
- Enable passwords are handled securely in both versions
- SSH host keys are auto-accepted by default (suitable for trusted networks)
- Output files may contain sensitive device config — store them securely

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All devices processed successfully |
| `1` | One or more devices failed |

## Project Structure

```
config-grabber-public/
├── config_grabber.py       # Python implementation
├── config-grabber.ps1      # PowerShell implementation
├── requirements.txt        # Python dependencies
├── README.md
├── .gitignore
└── examples/
    ├── devices.txt         # Example IP list (shared by both)
    └── commands.txt        # Example Cisco IOS commands (shared)
```
