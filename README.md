# SSH MCP Server (Secured)

[![npm version](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured.svg)](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured)
[![CI/CD](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml/badge.svg)](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **secured** fork of [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) with command whitelist/blacklist filtering, network device support, and bulk connection management for safe remote server management via MCP (Model Context Protocol).

## Key Features

* **Command Whitelist/Blacklist**: Control which commands can be executed
* **Dangerous Pattern Detection**: Blocks fork bombs, command injection, and destructive patterns
* **Network Device Support**: Cisco, Juniper, MikroTik with persistent shell sessions and enable mode
* **Jump Shell Support**: SSH into a host then enter a nested CLI (telnet to a host, FreeSWITCH fs_cli, etc.) — commands execute inside the nested shell
* **Bulk Connection Management**: Load dozens of connections from CSV/JSON files
* **Environment Variable Credentials**: Passwords auto-resolved from env vars by connectionId — no secrets in chat
* **Multi-Connection Execution**: Run commands across all or selected connections simultaneously
* **Connection Health Monitoring**: Keepalive tracking, dead connection detection, auto-cleanup
* **Configurable Security Policies**: Via config file or environment variables
* **Audit Logging**: Log all blocked command attempts

## Installation

### Quick Setup (Recommended)

```bash
# Add to Claude CLI
claude mcp add ssh-mcp-secured npx '@marian-craciunescu/ssh-mcp-server-secured@latest'
```

### Manual Installation

```bash
npm install -g @marian-craciunescu/ssh-mcp-server-secured
```

```json
{
  "mcpServers": {
    "ssh-mcp-secured": {
      "command": "ssh-mcp-server-secured"
    }
  }
}
```

## Usage

### 1. Single Connection

Connect to a host using `ssh_connect`. You only need to provide host, username, and connectionId — the password is automatically resolved from environment variables:

```
Connect to host 172.168.0.2 with user admin connectionId=router1
```

The LLM calls `ssh_connect` with:

```json
{
  "host": "172.168.0.2",
  "username": "admin",
  "deviceType": "cisco",
  "connectionId": "router1"
}
```

**No password in the tool call.** The server automatically looks up `ROUTER1_PASSWORD` from environment variables.

#### Credential Resolution Convention

The connectionId is converted to an env var prefix: uppercased, non-alphanumeric characters replaced with `_`.

| connectionId | Env var for password | Env var for enable password |
|---|---|---|
| `router1` | `ROUTER1_PASSWORD` | `ROUTER1_ENABLE_PASSWORD` |
| `my-connection` | `MY_CONNECTION_PASSWORD` | `MY_CONNECTION_ENABLE_PASSWORD` |
| `dc1.switch.3` | `DC1_SWITCH_3_PASSWORD` | `DC1_SWITCH_3_ENABLE_PASSWORD` |

Optionally, `<PREFIX>_USERNAME` is also resolved if username is not provided.

Set credentials in your MCP configuration:

```json
{
  "mcpServers": {
    "ssh-mcp-secured": {
      "command": "ssh-mcp-server-secured",
      "env": {
        "SSH_FILTER_MODE": "blacklist",
        "ROUTER1_PASSWORD": "admin123",
        "ROUTER1_ENABLE_PASSWORD": "enable123",
        "SERVER1_PASSWORD": "rootpass",
        "SERVER1_USERNAME": "root"
      }
    }
  }
}
```

Credentials live in the MCP config (or are injected via CI/CD, vault, etc.) and **never appear in chat or tool calls**. If a password is explicitly provided in the tool call, it takes precedence over the env var.

### 2. Bulk Connections from File

Load multiple connections from a CSV or JSON file using `ssh_load_connections`. Passwords are resolved from env vars using the same connectionId convention:

**CSV format** (`connections.csv`):

```csv
host,username,port,deviceType,connectionId
172.168.0.2,admin,22,cisco,router1
10.1.2.15,noc,22,cisco,router2
192.168.1.1,root,22,linux,server1
```

No passwords in the file. The server resolves `ROUTER1_PASSWORD`, `ROUTER2_PASSWORD`, `SERVER1_PASSWORD` from env vars.

**JSON format** (`connections.json`):

```json
[
  {
    "host": "172.168.0.2",
    "username": "admin",
    "deviceType": "cisco",
    "connectionId": "router1"
  },
  {
    "host": "10.1.2.15",
    "username": "noc",
    "deviceType": "cisco",
    "connectionId": "router2"
  }
]
```

**Usage:**

```
Load connections from /path/to/connections.csv and connect to all
```

> **Note:** You can still provide passwords directly in CSV/JSON if preferred — env var resolution only kicks in when the password field is missing or empty.

### 3. Network Device Types

The server supports different device types with appropriate connection handling:

| Device Type | Behavior | Use Case |
|-------------|----------|----------|
| `linux` | Standard SSH exec mode (default) | Linux/Unix servers |
| `cisco` | Persistent shell, enable mode support | Cisco IOS/IOS-XE routers and switches |
| `juniper` | Persistent shell | Juniper JunOS devices |
| `mikrotik` | Persistent shell | MikroTik RouterOS |
| `network` | Generic persistent shell | Other network devices |
| `jump_shell` | Persistent shell + nested CLI | Used internally by `ssh_connect_with_jump_command` |

Network devices use PTY-allocated persistent shell sessions instead of standard `exec()` because many network operating systems close the SSH channel after each exec command.

### 4. Cisco Enable Mode

Enter privileged EXEC mode on Cisco devices using `ssh_cisco_enable`:

```json
{
  "connectionId": "router1"
}
```

The tool handles the interactive enable password prompt automatically — it sends `enable`, waits for `Password:`, sends the stored `enablePassword`, and verifies the prompt changed to `#`.

### 5. Execute on Multiple Connections

Run a command on specific connections using `ssh_execute_on_multiple`:

```json
{
  "command": "show version",
  "connectionIds": ["router1", "router2", "switch1"]
}
```

Or run on ALL connections:

```json
{
  "command": "show ip interface brief",
  "connectionIds": ["*"]
}
```

### 6. Jump Shell (Nested CLI via SSH)

Use `ssh_connect_with_jump_command` when you need to SSH into a host and then enter a nested interactive shell before executing commands. This covers scenarios like:

* **Telnet to a Topex VoIP gateway** from an SSH jump host
* **FreeSWITCH `fs_cli`** on a remote server
* Any CLI that requires an interactive session after SSH

**How it works:**

```
SSH → open shell → send jump command (e.g. "telnet lh") → wait for nested prompt (e.g. "topexsw>") → ready
```

All subsequent `ssh_execute` commands on that connectionId run inside the nested shell.

**Topex gateway example (with preset):**

```json
{
  "host": "10.0.0.1",
  "username": "admin",
  "connectionId": "topex1",
  "preset": "topex",
  "jumpCommand": "telnet lh"
}
```

The `topex` preset auto-fills `jumpPromptPattern: "topexsw>\\s*$"` and `jumpExitCommand: "quit"`. You only need to supply `jumpCommand`.

Then execute commands inside the Topex CLI:

```json
{
  "command": "view portsoncard *",
  "connectionId": "topex1"
}
```

**FreeSWITCH example (preset fills everything):**

```json
{
  "host": "10.0.0.5",
  "username": "root",
  "connectionId": "fs1",
  "preset": "freeswitch"
}
```

The `freeswitch` preset auto-fills `jumpCommand: "fs_cli"`, `jumpPromptPattern: "freeswitch@...>"`, and `jumpExitCommand: "/exit"`. Then:

```json
{
  "command": "sofia status",
  "connectionId": "fs1"
}
```

**Fully custom (no preset):**

```json
{
  "host": "10.0.0.1",
  "username": "admin",
  "connectionId": "custom1",
  "jumpCommand": "telnet 192.168.1.100",
  "jumpPromptPattern": ">\\s*$",
  "jumpExitCommand": "quit",
  "jumpReadyTimeout": 8000
}
```

**Built-in presets:**

| Preset | jumpCommand | Prompt pattern | Exit command |
|--------|-------------|----------------|--------------|
| `freeswitch` | `fs_cli` | `freeswitch@...>` | `/exit` |
| `topex` | *(user provides)* | `topexsw>` | `quit` |

Presets can be overridden — any explicitly provided parameter takes precedence.

**Shell recovery:** If the shell drops, `ssh_execute` automatically reopens the shell and re-enters the jump shell.

**Disconnect:** `ssh_disconnect` gracefully sends the exit command to the nested CLI before closing the SSH connection.

### 7. Logging

Set log level via environment variable:

| Variable | Values | Default |
|----------|--------|---------|
| `SSH_LOG_LEVEL` | DEBUG, INFO, WARN, ERROR | INFO |
| `SSH_LOG_FILE` | Path to log file | (none) |

Log format:

```
[2026-01-22T20:26:02.044Z] [INFO ] ✓ SSH connection established to 172.168.0.2:22
[2026-01-22T20:26:02.046Z] [DEBUG] ♥ Keepalive #1 sent to 172.168.0.2 | {"uptime":"10s"}
[2026-01-22T20:26:12.047Z] [WARN ] ⚠ CONNECTION CLOSED BY REMOTE HOST: router1
```

## Configuration

### Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SSH_FILTER_MODE` | `whitelist`, `blacklist`, `disabled` | `blacklist` | Command filtering mode |
| `SSH_ALLOW_SUDO` | `true`, `false` | `true` | Allow sudo commands |
| `SSH_LOG_BLOCKED` | `true`, `false` | `true` | Log blocked commands to stderr |
| `SSH_MCP_CONFIG` | file path | - | Path to config JSON file |
| `SSH_WHITELIST` | comma-separated or JSON | - | Override whitelist commands |
| `SSH_BLACKLIST` | comma-separated or JSON | - | Override blacklist commands |
| `SSH_DANGEROUS_PATTERNS` | JSON array | - | Override dangerous regex patterns |
| `SSH_LOG_LEVEL` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` | Log verbosity |
| `SSH_LOG_FILE` | path | - | Log to file |

Any additional environment variables following the `<CONNECTIONID>_PASSWORD` convention are automatically used for credential resolution (see [Credential Resolution Convention](#credential-resolution-convention)).

### MCP Configuration Examples

**Blacklist mode with custom blocked commands:**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_BLOCKED": "true",
      "SSH_BLACKLIST": "rm,rmdir,mkfs,fdisk,shutdown,reboot,halt,poweroff,passwd,useradd,userdel,iptables,crontab,conf t,configure terminal"
    }
  }
}
```

**Whitelist mode (strict — only allow specific commands):**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "whitelist",
      "SSH_ALLOW_SUDO": "false",
      "SSH_LOG_BLOCKED": "true",
      "SSH_WHITELIST": "ls,cat,grep,tail,head,df,du,free,uptime,ps,systemctl,journalctl,docker,kubectl,ping,curl,dig,ss,netstat,show,display"
    }
  }
}
```

**Network operations with credential env vars:**

```json
{
  "ssh_mcp": {
    "command": "ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_LEVEL": "DEBUG",
      "SSH_BLACKLIST": "conf t,configure terminal,rm,shutdown,reboot",
      "ROUTER1_PASSWORD": "admin123",
      "ROUTER1_ENABLE_PASSWORD": "enable123",
      "ROUTER2_PASSWORD": "pass123",
      "SERVER1_PASSWORD": "pass1234"
    }
  }
}
```

Now in chat you simply say `connect to 172.168.0.2 as admin connectionId=router1` — no passwords exposed.

**Via npx (no global install):**

```json
{
  "ssh_mcp": {
    "command": "npx",
    "args": ["@marian-craciunescu/ssh-mcp-server-secured"],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true"
    }
  }
}
```

### Config File

Create `config.json` or `ssh-mcp-config.json`:

```json
{
  "commandFilter": {
    "mode": "whitelist",
    "allowSudo": false,
    "logBlocked": true,
    "whitelist": [
      "ls", "cat", "grep", "df", "ps", "systemctl", "docker", "show", "ping"
    ],
    "blacklist": [
      "rm", "shutdown", "reboot", "passwd", "conf t", "configure terminal"
    ],
    "dangerousPatterns": [
      ";\\s*rm\\s+-rf",
      "curl.*\\|\\s*bash"
    ]
  }
}
```

## Filter Modes

### Blacklist Mode (Default)

Commands in the blacklist are blocked. Everything else is allowed. Supports multi-word entries like `configure terminal` and `conf t`.

```
✓ ls -la
✓ docker ps
✓ show ip interface brief
✗ rm -rf /tmp/files       → Blocked: 'rm' is in blacklist
✗ configure terminal      → Blocked: 'configure terminal' is in blacklist
✗ shutdown now            → Blocked: 'shutdown' is in blacklist
```

### Whitelist Mode

Only commands in the whitelist are allowed. Everything else is blocked.

```
✓ ls -la                  → Allowed: 'ls' is whitelisted
✓ show version            → Allowed: 'show' is whitelisted
✗ vim /etc/hosts          → Blocked: 'vim' not in whitelist
✗ make install            → Blocked: 'make' not in whitelist
```

### Disabled Mode

No command filtering (use with caution).

### Command Validation Order

1. Check if filtering disabled
2. Check sudo permission
3. Check dangerous patterns (regex)
4. Check full command against blacklist (multi-word support)
5. Extract base commands from pipes/chains
6. Check each base command against blacklist/whitelist

## Dangerous Patterns

These patterns are **always blocked** regardless of filter mode:

| Pattern | Example | Risk |
|---------|---------|------|
| Fork bomb | `:(){ :\|:& };:` | System crash |
| Piped rm | `find . \| rm` | Data loss |
| Chained rm | `ls && rm -rf /` | Data loss |
| Device redirect | `> /dev/sda` | Disk corruption |
| System config overwrite | `> /etc/passwd` | System compromise |
| Remote code execution | `curl \| bash` | Arbitrary code execution |
| Recursive chmod 777 | `chmod -R 777 /` | Security compromise |

## Available Tools

| Tool | Description |
|------|-------------|
| `ssh_connect` | Connect to a single host (password auto-resolved from `<CONNECTIONID>_PASSWORD` env var) |
| `ssh_connect_with_jump_command` | SSH into a host, then enter a nested CLI (telnet, fs_cli, etc.) via a jump command. Supports presets. |
| `ssh_load_connections` | Load connections from CSV/JSON file (credentials resolved from env vars per connectionId) |
| `ssh_execute` | Execute a command on one connection |
| `ssh_cisco_enable` | Enter Cisco privileged EXEC mode (interactive enable password handling) |
| `ssh_execute_on_multiple` | Execute a command on selected connections (`["*"]` = all) |
| `ssh_disconnect` | Disconnect one connection |
| `ssh_disconnect_all` | Disconnect all connections |
| `ssh_list_connections` | List active connections with status |
| `ssh_check_connections` | Health check all connections (dead socket detection, shell status) |
| `ssh_upload_file` | Upload file via SFTP |
| `ssh_download_file` | Download file via SFTP |
| `ssh_list_files` | List remote directory via SFTP |

## Example Workflow

```
1. Load connections from CSV (passwords auto-resolved from env vars)
   → ssh_load_connections { filePath: "devices.csv", connectAll: true }
   (ROUTER1_PASSWORD, ROUTER2_PASSWORD resolved automatically)

2. Enter enable mode on Cisco routers
   → ssh_cisco_enable { connectionId: "router1" }
   → ssh_cisco_enable { connectionId: "router2" }

3. Execute show commands on all devices
   → ssh_execute_on_multiple {
       command: "show ip interface brief",
       connectionIds: ["*"]
     }

4. Execute privileged command on specific router
   → ssh_execute {
       command: "show running-config | include hostname",
       connectionId: "router1"
     }

5. Check connection health
   → ssh_check_connections {}

6. Connect to a Topex gateway via jump shell
   → ssh_connect_with_jump_command {
       host: "10.0.0.1",
       username: "admin",
       connectionId: "topex1",
       preset: "topex",
       jumpCommand: "telnet lh"
     }

7. Execute command inside the Topex CLI
   → ssh_execute {
       command: "view portsoncard *",
       connectionId: "topex1"
     }

8. Disconnect all
   → ssh_disconnect_all {}
```

## Architecture Notes

### Shell Buffer Management
Buffer is cleared before each command. Stability detection uses buffer unchanged for 3 × 500ms = command complete. Password prompts are detected in the last 200 chars of the buffer.

### Keepalive System
SSH2 sends keepalives every 10 seconds (`keepaliveInterval: 10000`). After 3 failed keepalives, the connection auto-closes (`keepaliveCountMax: 3`). A custom interval logs keepalive count for debugging.

### Connection Health Monitoring
The server detects dead connections (socket destroyed), tracks shell status for network devices, auto-cleans dead connections, and attempts shell reopen on network devices if the shell has closed.

### Jump Shell
When `ssh_connect_with_jump_command` is called, the server: (1) opens an SSH connection, (2) opens a PTY shell, (3) sends the jump command (e.g. `telnet lh`), (4) polls the shell buffer every 300ms for the expected prompt regex, (5) marks the connection as `jump_shell` with `jumpShellActive: true`. On disconnect, the nested CLI exit command is sent before closing the SSH session. On shell recovery, the jump command is automatically re-sent.

### Environment Variable Credential Resolution
When a connection is created (via `ssh_connect` or `ssh_load_connections`), if the password is not provided, the server automatically looks up `<PREFIX>_PASSWORD` from environment variables, where `<PREFIX>` is the connectionId uppercased with non-alphanumeric characters replaced by `_`. The same convention applies to `_ENABLE_PASSWORD` and `_USERNAME`. Explicitly provided values always take precedence.

## Comparison with Original

| Feature | zibdie/SSH-MCP-Server | This Fork |
|---------|----------------------|-----------|
| Basic SSH/SFTP | ✓ | ✓ |
| Command whitelist | ✗ | ✓ |
| Command blacklist | ✗ | ✓ |
| Multi-word blacklist entries | ✗ | ✓ |
| Dangerous pattern detection | ✗ | ✓ |
| Audit logging | ✗ | ✓ |
| Command validation tool | ✗ | ✓ |
| Config file support | ✗ | ✓ |
| Network device types (Cisco, Juniper, MikroTik) | ✗ | ✓ |
| Cisco enable mode | ✗ | ✓ |
| Jump shell (nested CLI via SSH) | ✗ | ✓ |
| Bulk connections from CSV/JSON | ✗ | ✓ |
| Multi-connection execution | ✗ | ✓ |
| Environment variable credentials | ✗ | ✓ |
| Connection health monitoring | ✗ | ✓ |
| Keepalive tracking | ✗ | ✓ |
| `host`/`hostname` compatibility | ✗ | ✓ |

## Development

```bash
# Clone
git clone https://github.com/marian-craciunescu/ssh-mcp-server-secured.git
cd ssh-mcp-server-secured

# Install dependencies
npm install

# Run in development mode
npm run dev

# Test with MCP Inspector
npx @modelcontextprotocol/inspector node index.js
```

## Security Considerations

* **Default is blacklist mode** — provides protection while remaining flexible
* **Dangerous patterns are always checked** — even in disabled mode
* **Audit logging enabled by default** — track blocked attempts
* **Sudo can be restricted** — set `SSH_ALLOW_SUDO=false` for high-security environments
* **Credential isolation** — passwords are resolved from env vars by connectionId, never typed in chat or visible in tool calls

## License

MIT — see [LICENSE](LICENSE) file

## Credits

* Original: [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) by Nour Zibdie
* Security fork: [marian-craciunescu](https://github.com/marian-craciunescu)

## Support

* [Issues](https://github.com/marian-craciunescu/ssh-mcp-server-secured/issues)
* [Discussions](https://github.com/marian-craciunescu/ssh-mcp-server-secured/discussions)
