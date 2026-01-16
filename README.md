# SSH MCP Server (Secured)

[![npm version](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured.svg)](https://badge.fury.io/js/@marian-craciunescu%2Fssh-mcp-server-secured)
[![CI/CD](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml/badge.svg)](https://github.com/marian-craciunescu/ssh-mcp-server-secured/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A **secured** fork of [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) with command whitelist/blacklist filtering for safe remote server management via MCP (Model Context Protocol).

## Key Security Features

- **Command Whitelist/Blacklist**: Control which commands can be executed
- **Dangerous Pattern Detection**: Blocks fork bombs, command injection, and destructive patterns
- **Configurable Security Policies**: Via config file or environment variables
- **Audit Logging**: Log all blocked command attempts
- **Sudo Control**: Optional restriction of sudo usage

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

Add to your Claude configuration:

**macOS/Linux**: `~/.config/claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ssh-mcp-secured": {
      "command": "ssh-mcp-server-secured"
    }
  }
}
```
### 1. Bulk Connections from File

Load multiple connections from a CSV or JSON file:

**CSV format** (`connections.csv`):
```csv
host,username,password,port,deviceType,connectionId,enablePassword
10.2.2.2,admin,admin123,22,cisco,router1,enable123
10.1.2.15,noc,noc123,22,cisco,router2,
192.168.1.1,root,password,22,linux,server1,
```

**JSON format** (`connections.json`):
```json
[
  {
    "host": "10.2.2.2",
    "username": "admin",
    "password": "admin123",
    "deviceType": "cisco",
    "connectionId": "router1",
    "enablePassword": "enable123"
  },
  {
    "host": "10.1.2.15",
    "username": "noc",
    "password": "noc123",
    "deviceType": "cisco",
    "connectionId": "router2"
  }
]
```

**Usage:**
```
Load connections from /path/to/connections.csv and connect to all
```




### 2. Execute on Multiple Connections

Run a command on specific connections:

Tool: `ssh_execute_on_multiple`
```json
{
  "command": "show version",
  "connectionIds": ["router1", "router2", "switch1"]
}
```

Or run on ALL connections:
```json
{
  "command": "show version",
  "connectionIds": ["*"]
}
```



### 4. Logging

Set log level via environment variable:

| Variable | Values | Default |
|----------|--------|---------|
| `SSH_LOG_LEVEL` | DEBUG, INFO, WARN, ERROR | INFO |
| `SSH_LOG_FILE` | Path to log file | (none) |

Log format:
```
[2024-01-15T10:30:45.123Z] [INFO ] Connected to 10.2.2.2:22 | {"connectionId":"router1"}
[2024-01-15T10:30:46.456Z] [DEBUG] Shell data received | {"length":256}
[2024-01-15T10:30:47.789Z] [WARN ] Command blocked: blacklisted | {"command":"rm -rf /"}
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

### MCP Configuration Examples

**Blacklist mode with custom blocked commands:**

```json
{
  "ssh_mcp": {
    "command": "/usr/local/bin/ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "blacklist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_BLOCKED": "true",
      "SSH_BLACKLIST": "rm,rmdir,mkfs,fdisk,shutdown,reboot,halt,poweroff,passwd,useradd,userdel,iptables,crontab"
    }
  }
}
```

**Whitelist mode (strict - only allow specific commands):**

```json
{
  "ssh_mcp": {
    "command": "/usr/local/bin/ssh-mcp-server-secured",
    "args": [],
    "env": {
      "SSH_FILTER_MODE": "whitelist",
      "SSH_ALLOW_SUDO": "true",
      "SSH_LOG_BLOCKED": "true",
      "SSH_WHITELIST": "ls,cat,grep,tail,head,df,du,free,uptime,ps,systemctl,journalctl,docker,kubectl,ping,curl,dig,ss,netstat"
    }
  }
}
```

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
      "ls", "cat", "grep", "df", "ps", "systemctl", "docker"
    ],
    "blacklist": [
      "rm", "shutdown", "reboot", "passwd"
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

Commands in the blacklist are blocked. Everything else is allowed.

```
✓ ls -la
✓ docker ps
✓ systemctl status nginx
✗ rm -rf /tmp/files     → Blocked: 'rm' is in blacklist
✗ shutdown now          → Blocked: 'shutdown' is in blacklist
```

### Whitelist Mode

Only commands in the whitelist are allowed. Everything else is blocked.

```
✓ ls -la                → Allowed: 'ls' is whitelisted
✓ df -h                 → Allowed: 'df' is whitelisted
✗ vim /etc/hosts        → Blocked: 'vim' not in whitelist
✗ make install          → Blocked: 'make' not in whitelist
```

### Disabled Mode

No command filtering (use with caution).

## Dangerous Patterns

These patterns are **always blocked** regardless of filter mode:

| Pattern | Example | Risk |
|---------|---------|------|
| Fork bomb | `:(){ :|:& };:` | System crash |
| Piped rm | `find . \| rm` | Data loss |
| Chained rm | `ls && rm -rf /` | Data loss |
| Device redirect | `> /dev/sda` | Disk corruption |
| System config overwrite | `> /etc/passwd` | System compromise |
| Remote code execution | `curl \| bash` | Arbitrary code execution |
| Recursive chmod 777 | `chmod -R 777 /` | Security compromise |


## Available Tools

| Tool | Description |
|------|-------------|
| `ssh_connect` | Connect to single host |
| `ssh_load_connections` | Load connections from CSV/JSON file |
| `ssh_execute` | Execute command on one connection |
| `ssh_execute_on_multiple` | Execute command on selected connections |
| `ssh_disconnect` | Disconnect one connection |
| `ssh_disconnect_all` | Disconnect all connections |
| `ssh_list_connections` | List active connections |
| `ssh_check_connections` | Check health of all connections |
| `ssh_upload_file` | Upload file via SFTP |
| `ssh_download_file` | Download file via SFTP |
| `ssh_list_files` | List remote directory |

## Environment Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SSH_FILTER_MODE` | whitelist, blacklist, disabled | blacklist | Command filtering |
| `SSH_ALLOW_SUDO` | true, false | true | Allow sudo |
| `SSH_WHITELIST` | comma-separated | - | Allowed commands |
| `SSH_BLACKLIST` | comma-separated | - | Blocked commands |
| `SSH_LOG_LEVEL` | DEBUG, INFO, WARN, ERROR | INFO | Log verbosity |
| `SSH_LOG_FILE` | path | - | Log to file |


### File Operations

| Tool | Description |
|------|-------------|
| `ssh_upload_file` | Upload file via SFTP |
| `ssh_download_file` | Download file via SFTP |
| `ssh_list_files` | List remote directory |

## Examples

### Basic Connection

```
Connect to 192.168.1.100 as admin with password secret123
```

```json
{
  "host": "192.168.1.100",
  "username": "admin",
  "password": "secret123"
}
```

### Execute Command

```
Check disk space on my server
```

```json
{
  "command": "df -h"
}
```

### Validate Before Execute

```
Check if 'rm -rf /tmp/old' would be allowed
```

```json
{
  "command": "rm -rf /tmp/old"
}
```

Response:
```json
{
  "command": "rm -rf /tmp/old",
  "allowed": false,
  "reason": "Command 'rm' is blocked by blacklist",
  "extractedCommands": ["rm"]
}
```

### Using sudo with -S

For commands requiring sudo on non-interactive sessions:

```bash
echo 'yourpassword' | sudo -S systemctl status nginx
```

Or configure passwordless sudo on the target server:

```bash
# On target server
echo "username ALL=(ALL) NOPASSWD: /usr/bin/systemctl *" | sudo tee /etc/sudoers.d/username-systemctl
```

## Comparison with Original

| Feature | zibdie/SSH-MCP-Server | This Fork |
|---------|----------------------|-----------|
| Basic SSH/SFTP | ✓ | ✓ |
| Command whitelist | ✗ | ✓ |
| Command blacklist | ✗ | ✓ |
| Dangerous pattern detection | ✗ | ✓ |
| Audit logging | ✗ | ✓ |
| Command validation tool | ✗ | ✓ |
| Config file support | ✗ | ✓ |
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

- **Default is blacklist mode** - provides protection while remaining flexible
- **Dangerous patterns are always checked** - even in disabled mode
- **Audit logging enabled by default** - track blocked attempts
- **Sudo can be restricted** - set `SSH_ALLOW_SUDO=false` for high-security environments

## License

MIT - see [LICENSE](LICENSE) file

## Credits

- Original: [zibdie/SSH-MCP-Server](https://github.com/zibdie/SSH-MCP-Server) by Nour Zibdie
- Security fork: [marian-craciunescu](https://github.com/marian-craciunescu)

## Support

- [Issues](https://github.com/marian-craciunescu/ssh-mcp-server-secured/issues)
- [Discussions](https://github.com/marian-craciunescu/ssh-mcp-server-secured/discussions)
