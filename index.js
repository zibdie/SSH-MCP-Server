#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Client } from 'ssh2';
import { readFileSync, writeFileSync, mkdirSync, existsSync, appendFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';
import cors from 'cors';

// Get package.json version
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJson = JSON.parse(readFileSync(resolve(__dirname, 'package.json'), 'utf8'));

// =============================================================================
// LOGGER
// =============================================================================
class Logger {
  constructor(options = {}) {
    this.level = (process.env.SSH_LOG_LEVEL || options.level || 'INFO').toUpperCase();
    this.logFile = process.env.SSH_LOG_FILE || options.logFile || null;
    this.levels = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
  }

  _shouldLog(level) {
    return this.levels[level] >= this.levels[this.level];
  }

  _format(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const dataStr = data ? ` | ${JSON.stringify(data)}` : '';
    return `[${timestamp}] [${level.padEnd(5)}] ${message}${dataStr}`;
  }

  _write(level, message, data) {
    if (!this._shouldLog(level)) return;

    const formatted = this._format(level, message, data);
    console.error(formatted);

    if (this.logFile) {
      try {
        appendFileSync(this.logFile, formatted + '\n');
      } catch (e) {
        // Ignore file write errors
      }
    }
  }

  debug(message, data) { this._write('DEBUG', message, data); }
  info(message, data) { this._write('INFO', message, data); }
  warn(message, data) { this._write('WARN', message, data); }
  error(message, data) { this._write('ERROR', message, data); }
}

const logger = new Logger();

// =============================================================================
// DEFAULT COMMAND FILTER CONFIGURATION
// =============================================================================
const DEFAULT_COMMAND_FILTER = {
  mode: 'blacklist',
  whitelist: [
    'ls', 'cat', 'head', 'tail', 'grep', 'awk', 'sed', 'find', 'wc', 'sort', 'uniq',
    'df', 'du', 'free', 'uptime', 'whoami', 'pwd', 'date', 'hostname', 'uname',
    'ps', 'top', 'htop', 'pgrep', 'pidof',
    'systemctl', 'journalctl', 'service',
    'docker', 'docker-compose', 'kubectl', 'helm',
    'ping', 'curl', 'wget', 'dig', 'nslookup', 'host', 'traceroute', 'netstat', 'ss',
    'git', 'npm', 'node', 'python', 'python3', 'pip', 'pip3',
    'echo', 'printf', 'test', 'true', 'false', 'env', 'printenv',
    // Cisco commands
    'show', 'enable', 'configure', 'exit', 'end', 'write', 'copy', 'ping', 'traceroute',
  ],
  blacklist: [
    'rm', 'rmdir', 'unlink', 'mkfs', 'fdisk', 'parted', 'dd',
    'shutdown', 'reboot', 'halt', 'poweroff', 'init',
    'useradd', 'userdel', 'usermod', 'passwd', 'chpasswd', 'groupadd', 'groupdel',
    'visudo', 'sudoedit', 'iptables', 'ip6tables', 'nft', 'firewall-cmd', 'ufw',
    'crontab', 'mount', 'umount', 'insmod', 'rmmod', 'modprobe',
  ],
  dangerousPatterns: [
    ':\\(\\)\\s*\\{\\s*:|:&\\s*\\}\\s*;',
    ';\\s*rm\\s+-rf',
    '\\|\\s*rm',
    '&&\\s*rm',
    '\\|\\|\\s*rm',
    '>\\s*/dev/',
    '>\\s*/etc/',
    'curl.*\\|\\s*bash',
    'wget.*\\|\\s*bash',
  ],
  allowSudo: true,
  logBlocked: true,
};

// =============================================================================
// JUMP SHELL PRESETS
// =============================================================================
// Built-in configurations for "SSH → enter nested CLI" scenarios.
// jumpCommand=null means user must supply it manually.
const JUMP_SHELL_PRESETS = {
  freeswitch: {
    jumpCommand: 'fs_cli',
    jumpPromptPattern: 'freeswitch@[^>]*>\\s*$',
    jumpExitCommand: '/exit',
    jumpReadyTimeout: 5000,
  },
  topex: {
    jumpCommand: null,  // user must supply (e.g. "telnet lh")
    jumpPromptPattern: 'topexsw>\\s*$',
    jumpExitCommand: 'quit',
    jumpReadyTimeout: 5000,
  },
};

// =============================================================================
// SSH MCP SERVER
// =============================================================================
class SSHMCPServer {
  constructor() {
    this.server = new Server(
        {
          name: 'ssh-mcp-server-secured',
          version: packageJson.version,
        },
        {
          capabilities: {
            tools: {},
          },
        }
    );

    this.connections = new Map(); // connectionId -> { conn, host, port, username, deviceType, shell, shellBuffer }
    this.commandFilter = this.loadCommandFilter();
    this.setupToolHandlers();

    logger.info('SSH MCP Server initialized', { version: packageJson.version });
  }

  // ===========================================================================
  // CONFIG LOADING
  // ===========================================================================
  loadCommandFilter() {
    const config = { ...DEFAULT_COMMAND_FILTER };

    const configPaths = [
      process.env.SSH_MCP_CONFIG,
      resolve(__dirname, 'config.json'),
      resolve(process.cwd(), 'ssh-mcp-config.json'),
    ].filter(Boolean);

    for (const configPath of configPaths) {
      if (configPath && existsSync(configPath)) {
        try {
          const fileConfig = JSON.parse(readFileSync(configPath, 'utf8'));
          if (fileConfig.commandFilter) {
            Object.assign(config, fileConfig.commandFilter);
            logger.info(`Loaded config from: ${configPath}`);
          }
        } catch (error) {
          logger.error(`Failed to load config: ${configPath}`, { error: error.message });
        }
        break;
      }
    }

    // Environment variable overrides
    if (process.env.SSH_FILTER_MODE) config.mode = process.env.SSH_FILTER_MODE;
    if (process.env.SSH_ALLOW_SUDO !== undefined) config.allowSudo = process.env.SSH_ALLOW_SUDO === 'true';
    if (process.env.SSH_LOG_BLOCKED !== undefined) config.logBlocked = process.env.SSH_LOG_BLOCKED === 'true';

    if (process.env.SSH_WHITELIST) {
      try {
        config.whitelist = process.env.SSH_WHITELIST.startsWith('[')
            ? JSON.parse(process.env.SSH_WHITELIST)
            : process.env.SSH_WHITELIST.split(',').map(s => s.trim()).filter(Boolean);
        logger.info(`Loaded whitelist from env: ${config.whitelist.length} commands`);
      } catch (e) {
        logger.error('Failed to parse SSH_WHITELIST', { error: e.message });
      }
    }

    if (process.env.SSH_BLACKLIST) {
      try {
        config.blacklist = process.env.SSH_BLACKLIST.startsWith('[')
            ? JSON.parse(process.env.SSH_BLACKLIST)
            : process.env.SSH_BLACKLIST.split(',').map(s => s.trim()).filter(Boolean);
        logger.info(`Loaded blacklist from env: ${config.blacklist.length} commands`);
      } catch (e) {
        logger.error('Failed to parse SSH_BLACKLIST', { error: e.message });
      }
    }

    // Normalize to lowercase and trim
    const normalizedWhitelist = config.whitelist.map(s => s.toLowerCase().trim());
    const normalizedBlacklist = config.blacklist.map(s => s.toLowerCase().trim());

    const result = {
      mode: config.mode,
      whitelist: new Set(normalizedWhitelist),
      whitelistArray: normalizedWhitelist, // Keep array for multi-word matching
      blacklist: new Set(normalizedBlacklist),
      blacklistArray: normalizedBlacklist, // Keep array for multi-word matching
      dangerousPatterns: config.dangerousPatterns.map(p => new RegExp(p, 'i')),
      allowSudo: config.allowSudo,
      logBlocked: config.logBlocked,
    };

    logger.info(`Command filter configured`, {
      mode: result.mode,
      whitelistCount: result.whitelist.size,
      blacklistCount: result.blacklist.size,
      blacklistSample: result.blacklistArray.slice(0, 10),
    });

    return result;
  }

  // ===========================================================================
  // CREDENTIAL RESOLUTION FROM ENV VARS
  // ===========================================================================

  /**
   * Convert a connectionId to an env var prefix.
   * "my-connection" → "MY_CONNECTION"
   * "dc1.switch.3"  → "DC1_SWITCH_3"
   * "router1"       → "ROUTER1"
   */
  connectionIdToEnvPrefix(connectionId) {
    return connectionId
        .toUpperCase()
        .replace(/[^A-Z0-9]+/g, '_')
        .replace(/^_|_$/g, '');
  }

  /**
   * Resolve credentials from environment variables based on connectionId.
   *
   * Convention:
   *   connectionId "router1" → ROUTER1_PASSWORD, ROUTER1_ENABLE_PASSWORD, ROUTER1_USERNAME
   *
   * Only fills in fields that are NOT already provided (explicit values always win).
   */
  resolveCredentialsFromEnv(args) {
    const connectionId = args.connectionId;
    if (!connectionId) return args;

    const prefix = this.connectionIdToEnvPrefix(connectionId);
    const resolved = { ...args };

    if (!resolved.password) {
      const envKey = `${prefix}_PASSWORD`;
      const envValue = process.env[envKey];
      if (envValue) {
        logger.info(`Resolved password from env: ${envKey}`);
        resolved.password = envValue;
      } else {
        logger.debug(`No env var found for password: ${envKey}`);
      }
    }

    if (!resolved.enablePassword) {
      const envKey = `${prefix}_ENABLE_PASSWORD`;
      const envValue = process.env[envKey];
      if (envValue) {
        logger.info(`Resolved enable password from env: ${envKey}`);
        resolved.enablePassword = envValue;
      }
    }

    if (!resolved.username) {
      const envKey = `${prefix}_USERNAME`;
      const envValue = process.env[envKey];
      if (envValue) {
        logger.info(`Resolved username from env: ${envKey}`);
        resolved.username = envValue;
      }
    }

    return resolved;
  }

  // ===========================================================================
  // JUMP SHELL HELPERS
  // ===========================================================================

  /**
   * Resolve jump config by merging a preset (if any) with explicit overrides.
   */
  resolveJumpShellConfig(args) {
    const preset = args.preset ? JUMP_SHELL_PRESETS[args.preset.toLowerCase()] : null;

    const jumpCommand       = args.jumpCommand       || (preset && preset.jumpCommand)       || null;
    const jumpPromptPattern = args.jumpPromptPattern  || (preset && preset.jumpPromptPattern) || null;
    const jumpExitCommand   = args.jumpExitCommand    || (preset && preset.jumpExitCommand)   || 'exit';
    const jumpReadyTimeout  = args.jumpReadyTimeout   || (preset && preset.jumpReadyTimeout)  || 5000;

    if (!jumpCommand) {
      const hint = args.preset
          ? `Preset "${args.preset}" requires jumpCommand (e.g. "telnet lh").`
          : 'Provide jumpCommand (e.g. "telnet lh", "fs_cli").';
      throw new Error(`jumpCommand is required. ${hint}`);
    }
    if (!jumpPromptPattern) {
      throw new Error('jumpPromptPattern is required. Provide a regex matching the nested shell prompt (e.g. "topexsw>\\\\s*$").');
    }

    return { jumpCommand, jumpPromptPattern, jumpExitCommand, jumpReadyTimeout };
  }

  /**
   * Send the jump command into an open SSH shell
   *   SSH prompt → jumpCommand → nested CLI prompt → ready
   */
  async enterJumpShell(connectionInfo, connectionId) {
    const { jumpCommand, jumpPromptPattern, jumpReadyTimeout } = connectionInfo.jumpConfig;
    const promptRegex = new RegExp(jumpPromptPattern);

    logger.info(`Entering jump shell: "${jumpCommand}"`, { connectionId, promptPattern: jumpPromptPattern });

    return new Promise((resolve, reject) => {
      connectionInfo.shellBuffer = '';
      connectionInfo.shell.write(jumpCommand + '\n');

      const timeoutId = setTimeout(() => {
        clearInterval(intervalId);
        reject(new Error(`Jump shell timeout after ${jumpReadyTimeout}ms. `
            + `Expected prompt matching /${jumpPromptPattern}/ but got: "${connectionInfo.shellBuffer.slice(-200)}"`
        ));
      }, jumpReadyTimeout);

      const intervalId = setInterval(() => {
        if (promptRegex.test(connectionInfo.shellBuffer.slice(-500))) {
          clearInterval(intervalId);
          clearTimeout(timeoutId);
          connectionInfo.jumpShellActive = true;
          const lastLine = connectionInfo.shellBuffer.trim().split('\n').pop() || '';
          logger.info(`✓ Jump shell ready: "${jumpCommand}"`, { connectionId, prompt: lastLine.trim() });
          resolve();
        }
      }, 300);
    });
  }

  /**
   * Exit the jump shell gracefully (sends the exit command).
   */
  async exitJumpShell(connectionInfo, connectionId) {
    if (!connectionInfo.jumpShellActive || !connectionInfo.jumpConfig) return;
    const exitCmd = connectionInfo.jumpConfig.jumpExitCommand;
    logger.info(`Exiting jump shell with: "${exitCmd}"`, { connectionId });
    try {
      connectionInfo.shell.write(exitCmd + '\n');
      await new Promise(r => setTimeout(r, 500));
      connectionInfo.jumpShellActive = false;
    } catch (e) {
      logger.debug('Jump shell exit error (non-fatal)', { connectionId, error: e.message });
    }
  }

  // ===========================================================================
  // CSV/JSON CONNECTION FILE LOADING
  // ===========================================================================
  parseConnectionsFile(filePath) {
    logger.info(`Loading connections from: ${filePath}`);

    const content = readFileSync(filePath, 'utf8').trim();
    const connections = [];

    // Try JSON first
    if (content.startsWith('[') || content.startsWith('{')) {
      try {
        const parsed = JSON.parse(content);
        const arr = Array.isArray(parsed) ? parsed : [parsed];
        for (const item of arr) {
          connections.push({
            host: item.host || item.hostname || item.ip,
            username: item.username || item.user,
            password: item.password || item.pass,
            port: item.port || 22,
            deviceType: item.deviceType || item.device_type || item.type || 'linux',
            connectionId: item.connectionId || item.connection_id || item.id || item.host,
            enablePassword: item.enablePassword || item.enable_password || item.enable,
          });
        }
        logger.info(`Parsed JSON file: ${connections.length} connections`);
        return connections;
      } catch (e) {
        logger.debug('Not valid JSON, trying CSV', { error: e.message });
      }
    }

    // Parse as CSV
    const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    if (lines.length === 0) {
      throw new Error('Empty connections file');
    }

    const firstLine = lines[0].toLowerCase();
    const hasHeader = firstLine.includes('host') || firstLine.includes('user') || firstLine.includes('ip');
    const dataLines = hasHeader ? lines.slice(1) : lines;

    for (const line of dataLines) {
      // Support both comma and semicolon separators
      const parts = line.includes(';') ? line.split(';') : line.split(',');
      const trimmed = parts.map(p => p.trim());

      if (trimmed.length >= 2) {
        connections.push({
          host: trimmed[0],
          username: trimmed[1],
          password: trimmed[2] || null,
          port: parseInt(trimmed[3]) || 22,
          deviceType: trimmed[4] || 'linux',
          connectionId: trimmed[5] || trimmed[0],
          enablePassword: trimmed[6] || null,
        });
      }
    }

    logger.info(`Parsed CSV file: ${connections.length} connections`);
    return connections;
  }

  // ===========================================================================
  // COMMAND FILTERING
  // ===========================================================================
  extractBaseCommand(command) {
    let cmd = command.trim();

    if (cmd.startsWith('sudo ')) {
      cmd = cmd.slice(5).trim();
      while (cmd.startsWith('-')) {
        const flagMatch = cmd.match(/^-(\S+)\s*/);
        if (flagMatch) {
          const flag = flagMatch[1];
          cmd = cmd.slice(flagMatch[0].length);
          if (/^[ugprtCh]/.test(flag) && cmd && !cmd.startsWith('-')) {
            cmd = cmd.replace(/^\S+\s*/, '');
          }
        } else {
          break;
        }
      }
    }

    while (/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/.test(cmd)) {
      cmd = cmd.replace(/^[A-Za-z_][A-Za-z0-9_]*=\S*\s+/, '');
    }

    const firstPart = cmd.split(/\s+/)[0];
    if (!firstPart) return '';

    return firstPart.split('/').pop() || '';
  }

  extractAllCommands(command) {
    const parts = command.split(/\s*(?:\|{1,2}|&&?|;)\s*/);
    const commands = [];
    for (const part of parts) {
      const baseCmd = this.extractBaseCommand(part.trim());
      if (baseCmd) commands.push(baseCmd);
    }
    return commands;
  }

  validateCommand(command) {
    if (this.commandFilter.mode === 'disabled') {
      return { allowed: true, reason: 'Filtering disabled' };
    }

    const trimmedCmd = command.trim();
    const lowerCmd = trimmedCmd.toLowerCase();

    // Check sudo permission
    if (!this.commandFilter.allowSudo && /^\s*sudo\s+/.test(trimmedCmd)) {
      logger.warn('Command blocked: sudo not allowed', { command });
      return { allowed: false, reason: 'sudo commands are not permitted' };
    }

    // Check dangerous patterns
    for (const pattern of this.commandFilter.dangerousPatterns) {
      if (pattern.test(trimmedCmd)) {
        logger.warn('Command blocked: dangerous pattern', { command, pattern: pattern.toString() });
        return { allowed: false, reason: `Dangerous pattern: ${pattern}` };
      }
    }

    // Check full command against blacklist first (for multi-word entries like 'configure terminal', 'conf t')
    if (this.commandFilter.mode === 'blacklist') {
      for (const blocked of this.commandFilter.blacklistArray) {
        // Check if command equals or starts with the blacklisted entry
        if (lowerCmd === blocked ||
            lowerCmd.startsWith(blocked + ' ') ||
            lowerCmd.startsWith(blocked + '\t') ||
            lowerCmd.startsWith(blocked + '\n')) {
          logger.warn('Command blocked: matches blacklist entry', { command, blockedEntry: blocked });
          return { allowed: false, reason: `'${blocked}' is blacklisted` };
        }
      }
    }

    // Check full command against whitelist (for multi-word entries)
    if (this.commandFilter.mode === 'whitelist') {
      let foundMatch = false;
      for (const allowed of this.commandFilter.whitelistArray) {
        if (lowerCmd === allowed ||
            lowerCmd.startsWith(allowed + ' ') ||
            lowerCmd.startsWith(allowed + '\t')) {
          foundMatch = true;
          break;
        }
      }
      if (foundMatch) {
        return { allowed: true, reason: 'Whitelisted (full match)' };
      }
    }

    // Also check individual base commands in pipes/chains
    const allCommands = this.extractAllCommands(trimmedCmd);

    if (this.commandFilter.mode === 'whitelist') {
      for (const cmd of allCommands) {
        const lowerBaseCmd = cmd.toLowerCase();
        if (!this.commandFilter.whitelist.has(lowerBaseCmd)) {
          logger.warn('Command blocked: not whitelisted', { command, blockedCmd: cmd });
          return { allowed: false, reason: `'${cmd}' not in whitelist` };
        }
      }
      return { allowed: true, reason: 'Whitelisted' };
    } else {
      // Blacklist mode - check base commands too
      for (const cmd of allCommands) {
        const lowerBaseCmd = cmd.toLowerCase();
        if (this.commandFilter.blacklist.has(lowerBaseCmd)) {
          logger.warn('Command blocked: blacklisted', { command, blockedCmd: cmd });
          return { allowed: false, reason: `'${cmd}' is blacklisted` };
        }
      }
      return { allowed: true, reason: 'Not blacklisted' };
    }
  }

  // ===========================================================================
  // TOOL HANDLERS SETUP
  // ===========================================================================
  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'ssh_connect',
          description: 'Connect to an SSH server. For Cisco/network devices, set deviceType to "cisco" for persistent shell mode.',
          inputSchema: {
            type: 'object',
            properties: {
              host: { type: 'string', description: 'SSH server hostname or IP' },
              hostname: { type: 'string', description: 'Alias for host' },
              port: { type: 'number', description: 'SSH port', default: 22 },
              username: { type: 'string', description: 'Username' },
              password: { type: 'string', description: 'Password' },
              privateKey: { type: 'string', description: 'Path to private key file' },
              passphrase: { type: 'string', description: 'Passphrase for private key' },
              connectionId: { type: 'string', description: 'Unique connection ID', default: 'default' },
              deviceType: { type: 'string', description: 'Device type: linux, cisco, mikrotik, juniper', default: 'linux' },
              enablePassword: { type: 'string', description: 'Enable password for Cisco devices' },
            },
            required: ['username'],
          },
        },
        {
          name: 'ssh_connect_with_jump_command',
          description:
              'SSH into a host, then execute a jump command to enter a nested interactive shell '
              + '(e.g. telnet to a Topex gateway, fs_cli for FreeSWITCH). '
              + 'All subsequent ssh_execute commands on this connectionId run INSIDE the nested shell. '
              + 'Use "preset" for built-in configs (freeswitch, topex) or supply jumpCommand + jumpPromptPattern manually.',
          inputSchema: {
            type: 'object',
            properties: {
              host: { type: 'string', description: 'SSH server hostname or IP' },
              hostname: { type: 'string', description: 'Alias for host' },
              port: { type: 'number', description: 'SSH port', default: 22 },
              username: { type: 'string', description: 'SSH username' },
              password: { type: 'string', description: 'SSH password' },
              privateKey: { type: 'string', description: 'Path to private key file' },
              passphrase: { type: 'string', description: 'Passphrase for private key' },
              connectionId: { type: 'string', description: 'Unique connection ID', default: 'default' },
              preset: { type: 'string', description: 'Built-in preset: freeswitch, topex. Auto-fills jump config where possible.' },
              jumpCommand: { type: 'string', description: 'Command to enter nested shell (e.g. "telnet lh", "fs_cli").' },
              jumpPromptPattern: { type: 'string', description: 'Regex matching the nested shell prompt (e.g. "topexsw>\\\\s*$").' },
              jumpExitCommand: { type: 'string', description: 'Command to exit the nested shell. Default from preset or "exit".' },
              jumpReadyTimeout: { type: 'number', description: 'Timeout in ms waiting for nested prompt.', default: 5000 },
            },
            required: ['host', 'username'],
          },
        },
        {
          name: 'ssh_load_connections',
          description: 'Load multiple connections from a CSV or JSON file. CSV format: host,username,password,port,deviceType,connectionId,enablePassword',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: { type: 'string', description: 'Path to CSV or JSON file with connections' },
              connectAll: { type: 'boolean', description: 'Immediately connect to all loaded connections', default: false },
            },
            required: ['filePath'],
          },
        },
        {
          name: 'ssh_execute',
          description: 'Execute a command. For Cisco devices, uses persistent shell session.',
          inputSchema: {
            type: 'object',
            properties: {
              command: { type: 'string', description: 'Command to execute' },
              connectionId: { type: 'string', description: 'Connection ID', default: 'default' },
              timeout: { type: 'number', description: 'Timeout in ms', default: 30000 },
            },
            required: ['command'],
          },
        },
        {
          name: 'ssh_execute_on_multiple',
          description: 'Execute a command on multiple connections by name',
          inputSchema: {
            type: 'object',
            properties: {
              command: { type: 'string', description: 'Command to execute' },
              connectionIds: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of connection IDs to execute on. Use "*" or empty array for all connections.'
              },
              timeout: { type: 'number', description: 'Timeout in ms', default: 30000 },
            },
            required: ['command', 'connectionIds'],
          },
        },
        {
          name: 'ssh_disconnect',
          description: 'Disconnect from an SSH server',
          inputSchema: {
            type: 'object',
            properties: {
              connectionId: { type: 'string', description: 'Connection ID', default: 'default' },
            },
          },
        },
        {
          name: 'ssh_disconnect_all',
          description: 'Disconnect from all SSH servers',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'ssh_list_connections',
          description: 'List all active SSH connections',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'ssh_check_connections',
          description: 'Check health status of all connections, detect if any were closed by remote host',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'ssh_upload_file',
          description: 'Upload a file via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              localPath: { type: 'string', description: 'Local file path' },
              remotePath: { type: 'string', description: 'Remote destination path' },
              connectionId: { type: 'string', default: 'default' },
            },
            required: ['localPath', 'remotePath'],
          },
        },
        {
          name: 'ssh_download_file',
          description: 'Download a file via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: { type: 'string', description: 'Remote file path' },
              localPath: { type: 'string', description: 'Local destination path' },
              connectionId: { type: 'string', default: 'default' },
            },
            required: ['remotePath', 'localPath'],
          },
        },
        {
          name: 'ssh_list_files',
          description: 'List files on remote server via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: { type: 'string', default: '.' },
              connectionId: { type: 'string', default: 'default' },
              detailed: { type: 'boolean', default: false },
            },
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      logger.debug(`Tool called: ${name}`, { args: { ...args, password: args?.password ? '***' : undefined } });

      try {
        switch (name) {
          case 'ssh_connect': return await this.handleSSHConnect(args);
          case 'ssh_connect_with_jump_command': return await this.handleSSHConnectWithJump(args);
          case 'ssh_load_connections': return await this.handleLoadConnections(args);
          case 'ssh_execute': return await this.handleSSHExecute(args);
          case 'ssh_execute_on_multiple': return await this.handleExecuteOnMultiple(args);
          case 'ssh_disconnect': return await this.handleSSHDisconnect(args);
          case 'ssh_disconnect_all': return await this.handleDisconnectAll();
          case 'ssh_list_connections': return await this.handleListConnections();
          case 'ssh_check_connections': return await this.handleCheckConnections();
          case 'ssh_upload_file': return await this.handleSSHUploadFile(args);
          case 'ssh_download_file': return await this.handleSSHDownloadFile(args);
          case 'ssh_list_files': return await this.handleSSHListFiles(args);
          default: throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        logger.error(`Tool error: ${name}`, { error: error.message });
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true,
        };
      }
    });
  }

  // ===========================================================================
  // CONNECTION HANDLERS
  // ===========================================================================
  async handleSSHConnect(args) {
    const resolved = this.resolveCredentialsFromEnv(args);

    const {
      host: hostParam,
      hostname,
      port = 22,
      username,
      password,
      privateKey,
      passphrase,
      connectionId = 'default',
      deviceType = 'linux',
      enablePassword,
    } = resolved;

    const host = hostParam || hostname;
    if (!host) throw new Error('host is required');

    if (this.connections.has(connectionId)) {
      throw new Error(`Connection '${connectionId}' already exists`);
    }

    logger.info(`Connecting to ${host}:${port}`, { connectionId, deviceType, username });

    // Resolve private key path BEFORE entering Promise scope
    // (Promise's resolve/reject params would shadow path.resolve inside)
    const resolvedKeyPath = privateKey ? resolve(privateKey) : null;

    return new Promise((resolve, reject) => {
      const conn = new Client();

      const config = {
        host: host.includes(':') && !host.startsWith('[') ? `[${host}]` : host,
        port,
        username,
        keepaliveInterval: 10000, // Send keepalive every 10 seconds
        keepaliveCountMax: 3,     // Disconnect after 3 failed keepalives
        readyTimeout: 30000,
      };

      logger.debug(`Connection config`, {
        connectionId,
        host: config.host,
        port,
        keepaliveInterval: '10s',
        keepaliveCountMax: 3,
        readyTimeout: '30s'
      });

      if (resolvedKeyPath) {
        try {
          config.privateKey = readFileSync(resolvedKeyPath);
          if (passphrase) config.passphrase = passphrase;
        } catch (error) {
          return reject(new Error(`Failed to read private key: ${error.message}`));
        }
      } else if (password) {
        config.password = password;
      } else {
        return reject(new Error('Either password or privateKey required. Set <CONNECTIONID>_PASSWORD env var or provide password directly.'));
      }

      conn.on('ready', async () => {
        logger.info(`✓ SSH connection established to ${host}:${port}`, { connectionId });

        const connectionInfo = {
          conn,
          host,
          port,
          username,
          connectionId,
          deviceType: deviceType.toLowerCase(),
          enablePassword,
          jumpConfig: null,
          jumpShellActive: false,
          shell: null,
          shellBuffer: '',
          shellReady: false,
          keepaliveCount: 0,
          connectedAt: Date.now(),
        };

        // Start keepalive logging interval
        connectionInfo.keepaliveInterval = setInterval(() => {
          connectionInfo.keepaliveCount++;
          logger.debug(`♥ Keepalive #${connectionInfo.keepaliveCount} sent to ${host}`, {
            connectionId,
            uptime: Math.round((Date.now() - connectionInfo.connectedAt) / 1000) + 's'
          });
        }, 10000);

        // For Cisco/network devices, open a persistent shell
        if (['cisco', 'mikrotik', 'juniper', 'network'].includes(deviceType.toLowerCase())) {
          try {
            await this.openShell(connectionInfo, connectionId);
            logger.info(`✓ Shell opened for ${connectionId}`, { deviceType });
          } catch (shellError) {
            logger.error(`✗ Failed to open shell for ${connectionId}`, { error: shellError.message });
            clearInterval(connectionInfo.keepaliveInterval);
            conn.end();
            return reject(new Error(`Failed to open shell: ${shellError.message}`));
          }
        }

        this.connections.set(connectionId, connectionInfo);

        resolve({
          content: [{
            type: 'text',
            text: `Connected to ${host}:${port} as ${username} (${connectionId}) [${deviceType}]${connectionInfo.shell ? ' - Shell mode active' : ''}`,
          }],
        });
      });

      conn.on('error', (error) => {
        logger.error(`✗ CONNECTION ERROR: ${host}:${port}`, {
          connectionId,
          error: error.message,
          code: error.code,
          level: error.level
        });
        reject(new Error(`SSH connection failed: ${error.message}`));
      });

      conn.on('close', (hadError) => {
        const connInfo = this.connections.get(connectionId);
        if (connInfo?.keepaliveInterval) {
          clearInterval(connInfo.keepaliveInterval);
        }
        const uptime = connInfo?.connectedAt
            ? Math.round((Date.now() - connInfo.connectedAt) / 1000)
            : 0;

        logger.warn(`══════════════════════════════════════════════════════════`);
        logger.warn(`⚠ CONNECTION CLOSED BY REMOTE HOST: ${connectionId}`);
        logger.warn(`  Host: ${host}:${port}`);
        logger.warn(`  Had Error: ${hadError ? 'YES' : 'NO'}`);
        logger.warn(`  Session Duration: ${uptime} seconds`);
        logger.warn(`  Keepalives Sent: ${connInfo?.keepaliveCount || 0}`);
        logger.warn(`══════════════════════════════════════════════════════════`);
        this.connections.delete(connectionId);
      });

      conn.on('end', () => {
        logger.warn(`⚠ Connection stream ended by remote host: ${connectionId}`, { host, port });
      });

      conn.on('timeout', () => {
        logger.error(`✗ Connection timeout - remote host not responding: ${connectionId}`, { host, port });
        conn.end();
      });

      // Note: ssh2 sends keepalives automatically based on keepaliveInterval config
      // If 3 consecutive keepalives fail, the connection will be closed automatically
      // and the 'close' event will fire

      conn.on('rekey', () => {
        logger.debug(`SSH rekey occurred: ${connectionId}`, { host });
      });

      // Handle TCP socket events for better close detection
      conn.on('tcp connection', (info, accept, reject) => {
        logger.debug(`TCP connection request`, { connectionId, info });
      });

      conn.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
        logger.debug('Keyboard-interactive auth', { connectionId, prompts: prompts.length });
        const responses = prompts.map(prompt => {
          if (prompt.prompt.toLowerCase().includes('password')) {
            return password;
          }
          return '';
        });
        finish(responses);
      });

      logger.debug(`Initiating connection to ${host}:${port}`);
      conn.connect(config);
    });
  }

  async openShell(connectionInfo, connectionId) {
    return new Promise((resolve, reject) => {
      connectionInfo.conn.shell({ term: 'vt100', rows: 24, cols: 80 }, (err, stream) => {
        if (err) {
          return reject(err);
        }

        connectionInfo.shell = stream;
        connectionInfo.shellBuffer = '';
        connectionInfo.shellReady = false;

        stream.on('data', (data) => {
          const text = data.toString();
          connectionInfo.shellBuffer += text;
          logger.debug(`📥 Shell data received`, {
            connectionId,
            length: text.length,
            preview: text.substring(0, 100).replace(/\n/g, '\\n')
          });
        });

        stream.on('close', (code, signal) => {
          logger.warn(`══════════════════════════════════════════════════════════`);
          logger.warn(`⚠ SHELL CLOSED BY REMOTE HOST: ${connectionId}`);
          logger.warn(`  Host: ${connectionInfo.host}`);
          logger.warn(`  Exit Code: ${code}`);
          logger.warn(`  Signal: ${signal || 'none'}`);
          logger.warn(`══════════════════════════════════════════════════════════`);
          connectionInfo.shell = null;
          connectionInfo.shellReady = false;
          connectionInfo.jumpShellActive = false;
        });

        stream.on('end', () => {
          logger.warn(`⚠ Shell stream ended by remote host`, {
            connectionId,
            host: connectionInfo.host
          });
        });

        stream.on('error', (err) => {
          logger.error(`✗ Shell stream error`, {
            connectionId,
            host: connectionInfo.host,
            error: err.message
          });
        });

        stream.on('exit', (code, signal) => {
          logger.warn(`⚠ Shell process exited`, {
            connectionId,
            host: connectionInfo.host,
            exitCode: code,
            signal: signal,
            reason: signal ? `Terminated by signal ${signal}` : `Exit code ${code}`
          });
        });

        // Wait for initial prompt
        setTimeout(() => {
          connectionInfo.shellReady = true;
          logger.debug(`✓ Shell ready`, { connectionId, host: connectionInfo.host });
          resolve();
        }, 2000);
      });
    });
  }

  // ===========================================================================
  // SSH CONNECT WITH JUMP COMMAND
  // ===========================================================================
  async handleSSHConnectWithJump(args) {
    const resolved = this.resolveCredentialsFromEnv(args);

    // Validate jump config before connecting
    const jumpConfig = this.resolveJumpShellConfig(resolved);

    const {
      host: hostParam,
      hostname,
      port = 22,
      username,
      password,
      privateKey,
      passphrase,
      connectionId = 'default',
    } = resolved;

    const host = hostParam || hostname;
    if (!host) throw new Error('host is required');

    if (this.connections.has(connectionId)) {
      throw new Error(`Connection '${connectionId}' already exists`);
    }

    // Resolve private key path BEFORE entering Promise scope
    const resolvedKeyPath = privateKey ? resolve(privateKey) : null;

    logger.info(`Connecting to ${host}:${port} with jump: "${jumpConfig.jumpCommand}"`, {
      connectionId, username, preset: resolved.preset || null,
    });

    return new Promise((resolve, reject) => {
      const conn = new Client();

      const config = {
        host: host.includes(':') && !host.startsWith('[') ? `[${host}]` : host,
        port,
        username,
        keepaliveInterval: 10000,
        keepaliveCountMax: 3,
        readyTimeout: 30000,
      };

      if (resolvedKeyPath) {
        try {
          config.privateKey = readFileSync(resolvedKeyPath);
          if (passphrase) config.passphrase = passphrase;
        } catch (error) {
          return reject(new Error(`Failed to read private key: ${error.message}`));
        }
      } else if (password) {
        config.password = password;
      } else {
        return reject(new Error('Either password or privateKey required. Set <CONNECTIONID>_PASSWORD env var or provide password directly.'));
      }

      conn.on('ready', async () => {
        logger.info(`✓ SSH connection established to ${host}:${port}`, { connectionId });

        const connectionInfo = {
          conn,
          host,
          port,
          username,
          connectionId,
          deviceType: 'jump_shell',
          enablePassword: null,
          jumpConfig,
          jumpShellActive: false,
          shell: null,
          shellBuffer: '',
          shellReady: false,
          keepaliveCount: 0,
          connectedAt: Date.now(),
        };

        // Start keepalive logging interval
        connectionInfo.keepaliveInterval = setInterval(() => {
          connectionInfo.keepaliveCount++;
          logger.debug(`♥ Keepalive #${connectionInfo.keepaliveCount} sent to ${host}`, {
            connectionId,
            uptime: Math.round((Date.now() - connectionInfo.connectedAt) / 1000) + 's'
          });
        }, 10000);

        // Step 1: Open SSH shell
        try {
          await this.openShell(connectionInfo, connectionId);
          logger.info(`✓ Shell opened for ${connectionId}`);
        } catch (shellError) {
          logger.error(`✗ Failed to open shell for ${connectionId}`, { error: shellError.message });
          clearInterval(connectionInfo.keepaliveInterval);
          conn.end();
          return reject(new Error(`Failed to open shell: ${shellError.message}`));
        }

        // Step 2: Enter nested CLI via jump command
        try {
          await this.enterJumpShell(connectionInfo, connectionId);
        } catch (jumpError) {
          logger.error(`✗ Failed to enter jump shell for ${connectionId}`, { error: jumpError.message });
          clearInterval(connectionInfo.keepaliveInterval);
          conn.end();
          return reject(new Error(`Jump shell failed: ${jumpError.message}`));
        }

        this.connections.set(connectionId, connectionInfo);

        resolve({
          content: [{
            type: 'text',
            text: `Connected to ${host}:${port} as ${username} (${connectionId}) [jump_shell] → "${jumpConfig.jumpCommand}" ready`,
          }],
        });
      });

      conn.on('error', (error) => {
        logger.error(`✗ CONNECTION ERROR: ${host}:${port}`, {
          connectionId,
          error: error.message,
          code: error.code,
          level: error.level
        });
        reject(new Error(`SSH connection failed: ${error.message}`));
      });

      conn.on('close', (hadError) => {
        const connInfo = this.connections.get(connectionId);
        if (connInfo?.keepaliveInterval) {
          clearInterval(connInfo.keepaliveInterval);
        }
        const uptime = connInfo?.connectedAt
            ? Math.round((Date.now() - connInfo.connectedAt) / 1000)
            : 0;

        logger.warn(`══════════════════════════════════════════════════════════`);
        logger.warn(`⚠ CONNECTION CLOSED BY REMOTE HOST: ${connectionId}`);
        logger.warn(`  Host: ${host}:${port}`);
        logger.warn(`  Had Error: ${hadError ? 'YES' : 'NO'}`);
        logger.warn(`  Session Duration: ${uptime} seconds`);
        logger.warn(`  Keepalives Sent: ${connInfo?.keepaliveCount || 0}`);
        logger.warn(`══════════════════════════════════════════════════════════`);
        this.connections.delete(connectionId);
      });

      conn.on('end', () => {
        logger.warn(`⚠ Connection stream ended by remote host: ${connectionId}`, { host, port });
      });

      conn.on('timeout', () => {
        logger.error(`✗ Connection timeout - remote host not responding: ${connectionId}`, { host, port });
        conn.end();
      });

      conn.on('keyboard-interactive', (name, instructions, instructionsLang, prompts, finish) => {
        logger.debug('Keyboard-interactive auth', { connectionId, prompts: prompts.length });
        const responses = prompts.map(prompt => {
          if (prompt.prompt.toLowerCase().includes('password')) {
            return password;
          }
          return '';
        });
        finish(responses);
      });

      logger.debug(`Initiating connection to ${host}:${port}`);
      conn.connect(config);
    });
  }

  async handleLoadConnections(args) {
    const { filePath, connectAll = false } = args;

    logger.info(`Loading connections from file: ${filePath}`);

    const absolutePath = resolve(filePath);
    if (!existsSync(absolutePath)) {
      throw new Error(`File not found: ${absolutePath}`);
    }

    const rawConnections = this.parseConnectionsFile(absolutePath);
    const results = [];

    if (connectAll) {
      for (const rawEntry of rawConnections) {
        const connConfig = this.resolveCredentialsFromEnv(rawEntry);
        try {
          logger.info(`Connecting to ${connConfig.host}`, { connectionId: connConfig.connectionId });
          await this.handleSSHConnect(connConfig);
          results.push({ host: connConfig.host, connectionId: connConfig.connectionId, status: 'connected' });
        } catch (error) {
          logger.error(`Failed to connect to ${connConfig.host}`, { error: error.message });
          results.push({ host: connConfig.host, connectionId: connConfig.connectionId, status: 'failed', error: error.message });
        }
      }
    } else {
      for (const rawEntry of rawConnections) {
        results.push({ host: rawEntry.host, connectionId: rawEntry.connectionId, status: 'loaded' });
      }
    }

    const summary = connectAll
        ? `Connected: ${results.filter(r => r.status === 'connected').length}/${results.length}`
        : `Loaded: ${results.length} connections`;

    return {
      content: [{
        type: 'text',
        text: `${summary}\n\n${results.map(r => `${r.connectionId}: ${r.host} - ${r.status}${r.error ? ' (' + r.error + ')' : ''}`).join('\n')}`,
      }],
    };
  }

  // ===========================================================================
  // COMMAND EXECUTION
  // ===========================================================================
  async handleSSHExecute(args) {
    const { command, connectionId = 'default', timeout = 30000 } = args;

    const validation = this.validateCommand(command);
    if (!validation.allowed) {
      throw new Error(`Command blocked: ${validation.reason}`);
    }

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No connection: ${connectionId}. Connection may have been closed by remote host.`);
    }

    if (!connection.conn || !connection.conn._sock || connection.conn._sock.destroyed) {
      logger.error(`Connection dead: ${connectionId}`, { host: connection.host });
      this.connections.delete(connectionId);
      throw new Error(`Connection ${connectionId} was closed by remote host. Please reconnect.`);
    }

    if (['cisco', 'mikrotik', 'juniper', 'network', 'jump_shell'].includes(connection.deviceType)) {
      if (!connection.shell || !connection.shellReady) {
        logger.warn(`⚠ Shell not ready for ${connectionId}, attempting to reopen`, { host: connection.host });
        try {
          await this.openShell(connection, connectionId);
          logger.info(`✓ Shell reopened for ${connectionId}`);
          // Re-enter jump shell if this was a jump_shell connection
          if (connection.jumpConfig) {
            await this.enterJumpShell(connection, connectionId);
            logger.info(`✓ Jump shell re-entered for ${connectionId}`);
          }
        } catch (shellError) {
          throw new Error(`Shell closed by remote host and failed to reopen: ${shellError.message}`);
        }
      }
    }

    logger.info(`Executing command`, { connectionId, command, deviceType: connection.deviceType });

    if (connection.shell && connection.shellReady) {
      return await this.executeViaShell(connection, command, timeout, connectionId);
    }

    return await this.executeViaExec(connection, command, timeout, connectionId);
  }

  async executeViaShell(connection, command, timeout, connectionId) {
    return new Promise((resolve, reject) => {
      const { shell } = connection;

      connection.shellBuffer = '';

      logger.debug(`Sending command via shell`, { connectionId, command });

      shell.write(command + '\n');

      let lastBufferLength = 0;
      let stableCount = 0;
      const checkInterval = 500;
      const stableThreshold = 3;

      const timeoutId = setTimeout(() => {
        clearInterval(intervalId);
        logger.warn(`Shell command timeout`, { connectionId, command });
        resolve({
          content: [{
            type: 'text',
            text: `[${connectionId}] Command: ${command}\n[TIMEOUT after ${timeout}ms]\nPartial output:\n${connection.shellBuffer}`,
          }],
        });
      }, timeout);

      const intervalId = setInterval(() => {
        if (connection.shellBuffer.length === lastBufferLength) {
          stableCount++;
          if (stableCount >= stableThreshold) {
            clearInterval(intervalId);
            clearTimeout(timeoutId);

            const output = connection.shellBuffer;
            logger.debug(`Shell command complete`, { connectionId, outputLength: output.length });

            resolve({
              content: [{
                type: 'text',
                text: `[${connectionId}] Command: ${command}\nOutput:\n${output}`,
              }],
            });
          }
        } else {
          lastBufferLength = connection.shellBuffer.length;
          stableCount = 0;
        }
      }, checkInterval);
    });
  }

  async executeViaExec(connection, command, timeout, connectionId) {
    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        logger.warn(`Exec command timeout`, { connectionId, command });
        reject(new Error(`Timeout after ${timeout}ms`));
      }, timeout);

      connection.conn.exec(command, { pty: true }, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          logger.error(`Exec error`, { connectionId, error: err.message });
          return reject(new Error(`Exec failed: ${err.message}`));
        }

        stream
            .on('close', (code, signal) => {
              clearTimeout(timeoutId);
              logger.debug(`Exec complete`, { connectionId, code, outputLength: output.length });
              resolve({
                content: [{
                  type: 'text',
                  text: `[${connectionId}] Command: ${command}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nStderr:\n${errorOutput}` : ''}`,
                }],
              });
            })
            .on('data', (data) => {
              output += data.toString();
            })
            .stderr.on('data', (data) => {
          errorOutput += data.toString();
        });
      });
    });
  }

  // ===========================================================================
  // CISCO ENABLE MODE
  // ===========================================================================
  async handleCiscoEnable(args) {
    const { connectionId = 'default', enablePassword: providedPassword, timeout = 10000 } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No connection: ${connectionId}`);
    }

    if (!connection.shell || !connection.shellReady) {
      throw new Error(`No shell session for ${connectionId}. Device type must be 'cisco' or 'network'.`);
    }

    let password = providedPassword || connection.enablePassword;

    if (!password) {
      const prefix = this.connectionIdToEnvPrefix(connectionId);
      const envKey = `${prefix}_ENABLE_PASSWORD`;
      password = process.env[envKey];
      if (password) {
        logger.info(`Resolved enable password from env: ${envKey}`);
      }
    }

    if (!password) {
      throw new Error(`No enable password. Set ${this.connectionIdToEnvPrefix(connectionId)}_ENABLE_PASSWORD env var or provide enablePassword.`);
    }

    logger.info(`Entering enable mode`, { connectionId });

    return new Promise((resolve, reject) => {
      connection.shellBuffer = '';
      connection.shell.write('enable\n');

      let passwordSent = false;
      let lastBufferLength = 0;
      let stableCount = 0;

      const timeoutId = setTimeout(() => {
        clearInterval(intervalId);
        reject(new Error(`Enable mode timeout after ${timeout}ms. Buffer: ${connection.shellBuffer.slice(-200)}`));
      }, timeout);

      const intervalId = setInterval(() => {
        const buffer = connection.shellBuffer;

        if (!passwordSent) {
          const lastChars = buffer.slice(-200).toLowerCase();
          if (lastChars.includes('password:') || lastChars.includes('password :')) {
            logger.debug(`🔐 Enable password prompt detected`, { connectionId });
            connection.shell.write(password + '\n');
            passwordSent = true;
            lastBufferLength = buffer.length;
            stableCount = 0;
            return;
          }
        }

        if (buffer.length === lastBufferLength) {
          stableCount++;
          if (stableCount >= 3) {
            clearInterval(intervalId);
            clearTimeout(timeoutId);

            const lastLine = buffer.trim().split('\n').pop() || '';
            const success = lastLine.includes('#');

            if (success) {
              logger.info(`✓ Enable mode activated`, { connectionId, prompt: lastLine.trim() });
              resolve({
                content: [{
                  type: 'text',
                  text: `[${connectionId}] Enable mode activated. Prompt: ${lastLine.trim()}`,
                }],
              });
            } else {
              logger.warn(`✗ Enable mode may have failed`, { connectionId, lastLine });
              resolve({
                content: [{
                  type: 'text',
                  text: `[${connectionId}] Enable mode result (check prompt):\n${buffer}`,
                }],
              });
            }
          }
        } else {
          lastBufferLength = buffer.length;
          stableCount = 0;
        }
      }, 500);
    });
  }

  // ===========================================================================
  // MULTI-CONNECTION EXECUTION
  // ===========================================================================
  async handleExecuteOnMultiple(args) {
    const { command, connectionIds = [], timeout = 30000 } = args;

    const validation = this.validateCommand(command);
    if (!validation.allowed) {
      throw new Error(`Command blocked: ${validation.reason}`);
    }

    let targetIds;

    if (connectionIds.length === 0 || (connectionIds.length === 1 && connectionIds[0] === '*')) {
      targetIds = Array.from(this.connections.keys());
    } else {
      targetIds = connectionIds;
      const missingIds = targetIds.filter(id => !this.connections.has(id));
      if (missingIds.length > 0) {
        throw new Error(`Connections not found: ${missingIds.join(', ')}`);
      }
    }

    if (targetIds.length === 0) {
      throw new Error('No connections to execute on');
    }

    logger.info(`Executing on multiple connections`, { command, targets: targetIds });

    const results = [];
    for (const connectionId of targetIds) {
      try {
        const result = await this.handleSSHExecute({ command, connectionId, timeout });
        results.push({ connectionId, success: true, output: result.content[0].text });
      } catch (error) {
        logger.error(`Execution failed on ${connectionId}`, { error: error.message });
        results.push({ connectionId, success: false, error: error.message });
      }
    }

    const successCount = results.filter(r => r.success).length;

    return {
      content: [{
        type: 'text',
        text: `Executed on ${successCount}/${results.length} connections\n\n${results.map(r =>
            r.success ? r.output : `[${r.connectionId}] ERROR: ${r.error}`
        ).join('\n\n---\n\n')}`,
      }],
    };
  }

  // ===========================================================================
  // DISCONNECT HANDLERS
  // ===========================================================================
  async handleSSHDisconnect(args) {
    const { connectionId = 'default' } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) {
      throw new Error(`No connection: ${connectionId}`);
    }

    logger.info(`Disconnecting: ${connectionId}`, { host: connection.host });

    // Exit jump shell gracefully before closing
    if (connection.jumpShellActive) {
      await this.exitJumpShell(connection, connectionId);
    }

    if (connection.keepaliveInterval) {
      clearInterval(connection.keepaliveInterval);
    }

    if (connection.shell) {
      connection.shell.end();
    }
    connection.conn.end();
    this.connections.delete(connectionId);

    return {
      content: [{ type: 'text', text: `Disconnected: ${connectionId}` }],
    };
  }

  async handleDisconnectAll() {
    const connectionIds = Array.from(this.connections.keys());

    logger.info(`Disconnecting all connections`, { count: connectionIds.length });

    for (const connectionId of connectionIds) {
      try {
        const connection = this.connections.get(connectionId);
        if (connection.jumpShellActive) {
          await this.exitJumpShell(connection, connectionId);
        }
        if (connection.keepaliveInterval) {
          clearInterval(connection.keepaliveInterval);
        }
        if (connection.shell) connection.shell.end();
        connection.conn.end();
        this.connections.delete(connectionId);
      } catch (e) {
        logger.error(`Error disconnecting ${connectionId}`, { error: e.message });
      }
    }

    return {
      content: [{ type: 'text', text: `Disconnected ${connectionIds.length} connections` }],
    };
  }

  async handleListConnections() {
    const list = Array.from(this.connections.entries()).map(([id, info]) => ({
      id,
      host: info.host,
      port: info.port,
      username: info.username,
      deviceType: info.deviceType,
      shellActive: !!info.shell,
      jumpShell: info.jumpShellActive ? info.jumpConfig?.jumpCommand : null,
    }));

    logger.debug(`Listing connections`, { count: list.length });

    return {
      content: [{
        type: 'text',
        text: list.length > 0
            ? `Active connections (${list.length}):\n${list.map(c => {
              let line = `  • ${c.id}: ${c.username}@${c.host}:${c.port} [${c.deviceType}]`;
              if (c.shellActive) line += ' (shell)';
              if (c.jumpShell) line += ` → ${c.jumpShell}`;
              return line;
            }).join('\n')}`
            : 'No active connections',
      }],
    };
  }

  async handleCheckConnections() {
    const results = [];
    const deadConnections = [];

    for (const [connectionId, connection] of this.connections.entries()) {
      const status = {
        id: connectionId,
        host: connection.host,
        port: connection.port,
        deviceType: connection.deviceType,
      };

      if (!connection.conn || !connection.conn._sock) {
        status.status = 'DEAD';
        status.reason = 'Connection object destroyed';
        deadConnections.push(connectionId);
      } else if (connection.conn._sock.destroyed) {
        status.status = 'DEAD';
        status.reason = 'Socket destroyed - closed by remote host';
        deadConnections.push(connectionId);
      } else if (connection.conn._sock.readyState !== 'open') {
        status.status = 'DEAD';
        status.reason = `Socket state: ${connection.conn._sock.readyState}`;
        deadConnections.push(connectionId);
      } else {
        status.status = 'ALIVE';
        if (['cisco', 'mikrotik', 'juniper', 'network', 'jump_shell'].includes(connection.deviceType)) {
          if (connection.shell && connection.shellReady) {
            status.shellStatus = 'ACTIVE';
            if (connection.jumpShellActive) {
              status.jumpShell = connection.jumpConfig?.jumpCommand;
            }
          } else {
            status.shellStatus = 'CLOSED';
            status.reason = 'Shell was closed by remote host';
          }
        }
      }

      results.push(status);
    }

    for (const deadId of deadConnections) {
      logger.warn(`Removing dead connection: ${deadId}`);
      this.connections.delete(deadId);
    }

    const aliveCount = results.filter(r => r.status === 'ALIVE').length;
    const deadCount = results.filter(r => r.status === 'DEAD').length;

    logger.info(`Connection health check`, { alive: aliveCount, dead: deadCount });

    let output = `Connection Health Check\n`;
    output += `═══════════════════════\n`;
    output += `Alive: ${aliveCount} | Dead: ${deadCount}\n\n`;

    for (const r of results) {
      const icon = r.status === 'ALIVE' ? '✓' : '✗';
      output += `${icon} [${r.status}] ${r.id}: ${r.host}:${r.port} [${r.deviceType}]\n`;
      if (r.shellStatus) {
        output += `    Shell: ${r.shellStatus}\n`;
      }
      if (r.jumpShell) {
        output += `    Jump: ${r.jumpShell}\n`;
      }
      if (r.reason) {
        output += `    Reason: ${r.reason}\n`;
      }
    }

    if (deadCount > 0) {
      output += `\n⚠️  ${deadCount} dead connection(s) removed. Please reconnect.`;
    }

    return {
      content: [{ type: 'text', text: output }],
    };
  }

  // ===========================================================================
  // FILE OPERATIONS
  // ===========================================================================
  async handleSSHUploadFile(args) {
    const { localPath, remotePath, connectionId = 'default' } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) throw new Error(`No connection: ${connectionId}`);

    const absolutePath = resolve(localPath);
    logger.info(`Uploading file`, { connectionId, localPath: absolutePath, remotePath });

    return new Promise((resolve, reject) => {
      const fileContent = readFileSync(absolutePath);

      connection.conn.sftp((err, sftp) => {
        if (err) return reject(new Error(`SFTP error: ${err.message}`));

        const writeStream = sftp.createWriteStream(remotePath);
        writeStream.write(fileContent);
        writeStream.end();

        writeStream.on('close', () => {
          logger.info(`Upload complete`, { connectionId, remotePath });
          resolve({
            content: [{ type: 'text', text: `Uploaded ${absolutePath} to ${remotePath}` }],
          });
        });

        writeStream.on('error', (err) => {
          reject(new Error(`Upload failed: ${err.message}`));
        });
      });
    });
  }

  async handleSSHDownloadFile(args) {
    const { remotePath, localPath, connectionId = 'default' } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) throw new Error(`No connection: ${connectionId}`);

    const absolutePath = resolve(localPath);
    logger.info(`Downloading file`, { connectionId, remotePath, localPath: absolutePath });

    return new Promise((resolve, reject) => {
      connection.conn.sftp((err, sftp) => {
        if (err) return reject(new Error(`SFTP error: ${err.message}`));

        const readStream = sftp.createReadStream(remotePath);
        let fileContent = Buffer.alloc(0);

        readStream.on('data', (chunk) => {
          fileContent = Buffer.concat([fileContent, chunk]);
        });

        readStream.on('end', () => {
          mkdirSync(dirname(absolutePath), { recursive: true });
          writeFileSync(absolutePath, fileContent);
          logger.info(`Download complete`, { connectionId, localPath: absolutePath });
          resolve({
            content: [{ type: 'text', text: `Downloaded ${remotePath} to ${absolutePath}` }],
          });
        });

        readStream.on('error', (err) => {
          reject(new Error(`Download failed: ${err.message}`));
        });
      });
    });
  }

  async handleSSHListFiles(args) {
    const { remotePath = '.', connectionId = 'default', detailed = false } = args;

    const connection = this.connections.get(connectionId);
    if (!connection) throw new Error(`No connection: ${connectionId}`);

    logger.debug(`Listing files`, { connectionId, remotePath });

    return new Promise((resolve, reject) => {
      connection.conn.sftp((err, sftp) => {
        if (err) return reject(new Error(`SFTP error: ${err.message}`));

        sftp.readdir(remotePath, (err, list) => {
          if (err) return reject(new Error(`List failed: ${err.message}`));

          let output = `Directory: ${remotePath}\n\n`;

          if (detailed) {
            output += 'Permissions  Size       Name\n';
            output += '-'.repeat(50) + '\n';
            for (const item of list) {
              const isDir = item.attrs.isDirectory() ? 'd' : '-';
              const perms = (item.attrs.mode & 0o777).toString(8).padStart(3, '0');
              const size = (item.attrs.size || 0).toString().padStart(10);
              output += `${isDir}${perms}   ${size}   ${item.filename}\n`;
            }
          } else {
            const dirs = list.filter(i => i.attrs.isDirectory()).map(i => i.filename + '/');
            const files = list.filter(i => !i.attrs.isDirectory()).map(i => i.filename);
            if (dirs.length) output += `Dirs:  ${dirs.join(', ')}\n`;
            if (files.length) output += `Files: ${files.join(', ')}\n`;
          }

          resolve({ content: [{ type: 'text', text: output }] });
        });
      });
    });
  }

  // ===========================================================================
  // RUN
  // ===========================================================================
  async run() {
    const ssePort = process.env.SSE_PORT || (process.argv.includes('--sse') ? '3001' : null);

    if (ssePort) {
      // SSE mode — HTTP server with /sse and /message endpoints
      await this.runSSE(parseInt(ssePort));
    } else {
      // Default — stdio mode
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      logger.info(`SSH MCP Server started [stdio]`, {
        version: packageJson.version,
        filterMode: this.commandFilter.mode,
        logLevel: logger.level,
      });
    }
  }

  async runSSE(port) {
    const app = express();
    app.use(cors());

    const transports = new Map();

    app.get('/sse', async (req, res) => {
      logger.info('New SSE client connected');
      const transport = new SSEServerTransport('/message', res);
      transports.set(transport.sessionId, transport);

      res.on('close', () => {
        logger.info('SSE client disconnected', { sessionId: transport.sessionId });
        transports.delete(transport.sessionId);
      });

      await this.server.connect(transport);
    });

    // No express.json() here — the SDK reads the raw body
    app.post('/message', async (req, res) => {
      const sessionId = req.query.sessionId;
      const transport = transports.get(sessionId);
      if (!transport) {
        res.status(400).json({ error: 'Unknown session' });
        return;
      }
      await transport.handlePostMessage(req, res);
    });

    app.listen(port, () => {
      logger.info(`SSH MCP Server started [SSE] on http://localhost:${port}/sse`, {
        version: packageJson.version,
        filterMode: this.commandFilter.mode,
        logLevel: logger.level,
      });
    });
  }
}

const server = new SSHMCPServer();
server.run().catch((err) => {
  logger.error('Server failed to start', { error: err.message });
  process.exit(1);
});
