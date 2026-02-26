# config-grabber

A Python utility that SSH's into network switches, runs a list of commands, and saves
the output to timestamped text files — one file per device.

## Features

- Connect to **one or many switches** via IP address or a text file list
- **Per-device port support** using `IP:PORT` notation for PAT/NAT environments
- Support for **password** and **SSH key** authentication
- Optional **enable / privileged EXEC mode** (Cisco-style)
- Each device's output saved as **`<IP>_<YYYY-MM-DDTHHMMSS>.txt`**
- Graceful error handling — a failed device doesn't stop the rest
- Secure password prompting (no passwords stored in shell history)

## Requirements

- Python 3.10 or later
- [paramiko](https://www.paramiko.org/) SSH library

### Install dependencies

```bash
pip install -r requirements.txt
```

> **Tip:** Use a virtual environment to keep dependencies isolated:
> ```bash
> python -m venv .venv
> .venv\Scripts\activate      # Windows
> source .venv/bin/activate   # macOS / Linux
> pip install -r requirements.txt
> ```

## Usage

```
python config_grabber.py [-h] (-i IP[,IP,...] | -f FILE) -c FILE -u USER
                         [-p PASS] [-k KEY_FILE] [-e] [--port PORT]
                         [-t SECONDS] [-o DIR] [-v]
```

### Arguments

| Argument | Description |
|---|---|
| `-i IP[,IP,...]` | Single IP or comma-separated list of IPs. Supports `IP:PORT` notation per device. |
| `-f FILE` | Text file with one IP per line (mutually exclusive with `-i`). Supports `IP:PORT` per line. |
| `-c FILE` | **Required.** Text file with commands to run (one per line) |
| `-u USER` | **Required.** SSH username |
| `-p PASS` | SSH password (prompted securely if omitted) |
| `-k KEY_FILE` | SSH private key file for key-based authentication |
| `-e` | Enter privileged EXEC (enable) mode after login |
| `--port PORT` | Default SSH port when no per-device port is specified (default: `22`) |
| `-t SECONDS` | Connection timeout in seconds (default: `30`) |
| `-o DIR` | Output directory (default: current directory) |
| `-v` | Enable verbose/debug logging |

## Examples

### Connect to a single switch, prompt for password

```bash
python config_grabber.py -i 192.168.1.1 -c examples/commands.txt -u admin
```

### Connect to multiple switches from a file, save output to `./output`

```bash
python config_grabber.py -f examples/devices.txt -c examples/commands.txt -u admin -o output
```

### Use SSH key authentication

```bash
python config_grabber.py -f examples/devices.txt -c examples/commands.txt -u admin -k ~/.ssh/id_rsa -o output
```

### Enter enable mode (Cisco IOS)

```bash
python config_grabber.py -i 192.168.1.1 -c examples/commands.txt -u admin -e -o output
```

### Multiple IPs, custom port, verbose output

```bash
python config_grabber.py -i 10.0.0.1,10.0.0.2 -c examples/commands.txt -u netops --port 2222 -v -o output
```

### PAT/NAT environments — per-device ports on the CLI

```bash
# Each device has its own SSH port (PAT through a firewall)
python config_grabber.py -i 203.0.113.1:2221,203.0.113.1:2222 -c examples/commands.txt -u admin -o output
```

### PAT/NAT environments — per-device ports in a file

```bash
python config_grabber.py -f examples/devices.txt -c examples/commands.txt -u admin -o output
```

## Input File Formats

### devices.txt (IP list)

Bare IPs use the `--port` default. Add `:PORT` to override per device:

```
# Lines starting with '#' are comments - they are ignored
# Blank lines are also ignored

# Standard port (uses --port default, typically 22)
192.168.1.1
192.168.1.2

# PAT'd devices with custom per-device ports
10.0.0.1:2221
10.0.0.2:2222
```

### commands.txt (command list)

```
# Commands for Cisco IOS switches
# One command per line

terminal length 0
show version
show ip interface brief
show running-config
```

## Output

Each device produces one output file in the specified directory:

```
output/
├── 192.168.1.1_2026-02-26T101930.txt
├── 192.168.1.2_2026-02-26T101935.txt
└── 10.0.0.1_2026-02-26T101940.txt
```

Each file begins with a small header:

```
# Config Grabber Output
# Device  : 192.168.1.1
# Captured: 2026-02-26T10:19:30.123456
# ============================================================

Switch> terminal length 0
Switch> show version
Cisco IOS XE Software, Version 17.09.04a
...
```

## Security Notes

- **Never pass passwords on the command line in production** — use the prompt
  (`-p` omitted) or SSH key authentication (`-k`)
- The script uses `AutoAddPolicy` for host key verification (accepts all host keys
  automatically). For high-security environments, replace this with `RejectPolicy`
  and maintain a `known_hosts` file
- Output files may contain sensitive device configuration — store them securely

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All devices processed successfully |
| `1` | One or more devices failed (connection error, auth failure, etc.) |

## Project Structure

```
config-grabber/
├── config_grabber.py       # Main script
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── examples/
│   ├── devices.txt         # Example IP address list
│   └── commands.txt        # Example commands file
└── output/                 # Default output directory (git-ignored)
```
