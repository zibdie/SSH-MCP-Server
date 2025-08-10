#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { Client } from 'ssh2';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { resolve, basename, dirname } from 'path';

class SSHMCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'ssh-mcp',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.connections = new Map();
    this.setupToolHandlers();
  }

  setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'ssh_connect',
          description: 'Connect to an SSH server using password or SSH key authentication. Supports IPv4 and IPv6.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'SSH server hostname or IP address (IPv4 or IPv6)',
              },
              port: {
                type: 'number',
                description: 'SSH server port',
                default: 22,
              },
              username: {
                type: 'string',
                description: 'Username for SSH authentication',
              },
              password: {
                type: 'string',
                description: 'Password for authentication (if using password auth)',
              },
              privateKey: {
                type: 'string',
                description: 'Path to private SSH key file (if using key auth)',
              },
              passphrase: {
                type: 'string',
                description: 'Passphrase for encrypted private key (optional)',
              },
              connectionId: {
                type: 'string',
                description: 'Unique identifier for this connection',
                default: 'default',
              },
            },
            required: ['host', 'username'],
          },
        },
        {
          name: 'ssh_execute',
          description: 'Execute a command on an established SSH connection',
          inputSchema: {
            type: 'object',
            properties: {
              command: {
                type: 'string',
                description: 'Command to execute on the remote server',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              timeout: {
                type: 'number',
                description: 'Command timeout in milliseconds',
                default: 30000,
              },
            },
            required: ['command'],
          },
        },
        {
          name: 'ssh_disconnect',
          description: 'Disconnect from an SSH server',
          inputSchema: {
            type: 'object',
            properties: {
              connectionId: {
                type: 'string',
                description: 'Connection ID to disconnect',
                default: 'default',
              },
            },
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
          name: 'ssh_execute_script',
          description: 'Execute a multi-line script or code block on an SSH connection. Automatically handles code blocks with triple backticks.',
          inputSchema: {
            type: 'object',
            properties: {
              script: {
                type: 'string',
                description: 'Script or code block to execute. Can include triple backticks (```bash, ```python, etc.)',
              },
              interpreter: {
                type: 'string',
                description: 'Script interpreter to use (bash, sh, python, python3, node, etc.)',
                default: 'bash',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              timeout: {
                type: 'number',
                description: 'Script timeout in milliseconds',
                default: 60000,
              },
              workingDir: {
                type: 'string',
                description: 'Working directory to execute script in (optional)',
              },
            },
            required: ['script'],
          },
        },
        {
          name: 'ssh_upload_and_execute',
          description: 'Upload a script file and execute it on the remote server',
          inputSchema: {
            type: 'object',
            properties: {
              script: {
                type: 'string',
                description: 'Script content to upload and execute',
              },
              filename: {
                type: 'string',
                description: 'Filename for the script on remote server',
                default: 'mcp_script.sh',
              },
              interpreter: {
                type: 'string',
                description: 'Script interpreter (bash, python, etc.)',
                default: 'bash',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              cleanup: {
                type: 'boolean',
                description: 'Remove script file after execution',
                default: true,
              },
              timeout: {
                type: 'number',
                description: 'Execution timeout in milliseconds',
                default: 60000,
              },
            },
            required: ['script'],
          },
        },
        {
          name: 'ssh_upload_file',
          description: 'Upload a file to the remote server via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              localPath: {
                type: 'string',
                description: 'Local file path to upload',
              },
              remotePath: {
                type: 'string',
                description: 'Remote destination path',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              createDirs: {
                type: 'boolean',
                description: 'Create remote directories if they don\'t exist',
                default: true,
              },
            },
            required: ['localPath', 'remotePath'],
          },
        },
        {
          name: 'ssh_download_file',
          description: 'Download a file from the remote server via SFTP',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: {
                type: 'string',
                description: 'Remote file path to download',
              },
              localPath: {
                type: 'string',
                description: 'Local destination path',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              createDirs: {
                type: 'boolean',
                description: 'Create local directories if they don\'t exist',
                default: true,
              },
            },
            required: ['remotePath', 'localPath'],
          },
        },
        {
          name: 'ssh_list_files',
          description: 'List files and directories on the remote server',
          inputSchema: {
            type: 'object',
            properties: {
              remotePath: {
                type: 'string',
                description: 'Remote directory path to list',
                default: '.',
              },
              connectionId: {
                type: 'string',
                description: 'Connection ID to use',
                default: 'default',
              },
              detailed: {
                type: 'boolean',
                description: 'Show detailed file information (permissions, size, etc.)',
                default: false,
              },
            },
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'ssh_connect':
            return await this.handleSSHConnect(args);
          case 'ssh_execute':
            return await this.handleSSHExecute(args);
          case 'ssh_disconnect':
            return await this.handleSSHDisconnect(args);
          case 'ssh_list_connections':
            return await this.handleListConnections(args);
          case 'ssh_execute_script':
            return await this.handleSSHExecuteScript(args);
          case 'ssh_upload_and_execute':
            return await this.handleSSHUploadAndExecute(args);
          case 'ssh_upload_file':
            return await this.handleSSHUploadFile(args);
          case 'ssh_download_file':
            return await this.handleSSHDownloadFile(args);
          case 'ssh_list_files':
            return await this.handleSSHListFiles(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async handleSSHConnect(args) {
    const {
      host,
      port = 22,
      username,
      password,
      privateKey,
      passphrase,
      connectionId = 'default',
    } = args;

    if (this.connections.has(connectionId)) {
      throw new Error(`Connection '${connectionId}' already exists. Disconnect first or use a different ID.`);
    }

    return new Promise((resolve, reject) => {
      const conn = new Client();
      
      const config = {
        host,
        port,
        username,
      };

      // Handle IPv6 addresses
      if (host.includes(':') && !host.startsWith('[')) {
        config.host = `[${host}]`;
      }

      // Authentication setup
      if (privateKey) {
        try {
          const keyPath = resolve(privateKey);
          const keyData = readFileSync(keyPath);
          config.privateKey = keyData;
          if (passphrase) {
            config.passphrase = passphrase;
          }
        } catch (error) {
          return reject(new Error(`Failed to read private key: ${error.message}`));
        }
      } else if (password) {
        config.password = password;
      } else {
        return reject(new Error('Either password or privateKey must be provided'));
      }

      conn.on('ready', () => {
        this.connections.set(connectionId, conn);
        resolve({
          content: [
            {
              type: 'text',
              text: `Successfully connected to ${host}:${port} as ${username} (connection: ${connectionId})`,
            },
          ],
        });
      });

      conn.on('error', (error) => {
        reject(new Error(`SSH connection failed: ${error.message}`));
      });

      conn.on('close', () => {
        this.connections.delete(connectionId);
      });

      conn.connect(config);
    });
  }

  async handleSSHExecute(args) {
    const { command, connectionId = 'default', timeout = 30000 } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        reject(new Error(`Command timeout after ${timeout}ms`));
      }, timeout);

      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          return reject(new Error(`Failed to execute command: ${err.message}`));
        }

        stream
          .on('close', (code, signal) => {
            clearTimeout(timeoutId);
            resolve({
              content: [
                {
                  type: 'text',
                  text: `Command: ${command}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nError Output:\n${errorOutput}` : ''}`,
                },
              ],
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

  async handleSSHDisconnect(args) {
    const { connectionId = 'default' } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    conn.end();
    this.connections.delete(connectionId);

    return {
      content: [
        {
          type: 'text',
          text: `Disconnected from connection: ${connectionId}`,
        },
      ],
    };
  }

  async handleListConnections() {
    const connectionList = Array.from(this.connections.keys());
    
    return {
      content: [
        {
          type: 'text',
          text: connectionList.length > 0 
            ? `Active connections: ${connectionList.join(', ')}`
            : 'No active connections',
        },
      ],
    };
  }

  extractCodeFromBlock(script) {
    // Remove triple backticks and language specifiers
    const codeBlockRegex = /^```[\w]*\n?([\s\S]*?)\n?```$/;
    const match = script.trim().match(codeBlockRegex);
    return match ? match[1].trim() : script.trim();
  }

  async handleSSHExecuteScript(args) {
    const { 
      script, 
      interpreter = 'bash', 
      connectionId = 'default', 
      timeout = 60000,
      workingDir 
    } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    // Extract code from blocks if present
    const cleanScript = this.extractCodeFromBlock(script);

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        reject(new Error(`Script timeout after ${timeout}ms`));
      }, timeout);

      // Create a temporary script file and execute it
      const scriptName = `mcp_temp_${Date.now()}.${interpreter === 'python' || interpreter === 'python3' ? 'py' : 'sh'}`;
      const remotePath = `/tmp/${scriptName}`;
      
      // Prepare the script content with proper shebang
      let scriptContent = cleanScript;
      if (!scriptContent.startsWith('#!')) {
        const shebang = interpreter === 'python' || interpreter === 'python3' 
          ? '#!/usr/bin/env python3' 
          : '#!/bin/bash';
        scriptContent = `${shebang}\n${scriptContent}`;
      }

      // Upload script file
      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timeoutId);
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const writeStream = sftp.createWriteStream(remotePath);
        writeStream.write(scriptContent);
        writeStream.end();

        writeStream.on('close', () => {
          // Make script executable and run it
          const cdCommand = workingDir ? `cd "${workingDir}" && ` : '';
          const command = `${cdCommand}chmod +x ${remotePath} && ${remotePath} && rm -f ${remotePath}`;

          conn.exec(command, (err, stream) => {
            if (err) {
              clearTimeout(timeoutId);
              return reject(new Error(`Failed to execute script: ${err.message}`));
            }

            stream
              .on('close', (code, signal) => {
                clearTimeout(timeoutId);
                resolve({
                  content: [
                    {
                      type: 'text',
                      text: `Script executed with ${interpreter}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nError Output:\n${errorOutput}` : ''}`,
                    },
                  ],
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

        writeStream.on('error', (err) => {
          clearTimeout(timeoutId);
          reject(new Error(`Failed to upload script: ${err.message}`));
        });
      });
    });
  }

  async handleSSHUploadAndExecute(args) {
    const { 
      script, 
      filename = 'mcp_script.sh',
      interpreter = 'bash',
      connectionId = 'default',
      cleanup = true,
      timeout = 60000
    } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    // Extract code from blocks if present
    const cleanScript = this.extractCodeFromBlock(script);

    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';

      const timeoutId = setTimeout(() => {
        reject(new Error(`Upload and execute timeout after ${timeout}ms`));
      }, timeout);

      const remotePath = `/tmp/${basename(filename)}`;
      
      // Prepare the script content
      let scriptContent = cleanScript;
      if (!scriptContent.startsWith('#!')) {
        const shebang = interpreter === 'python' || interpreter === 'python3' 
          ? '#!/usr/bin/env python3' 
          : '#!/bin/bash';
        scriptContent = `${shebang}\n${scriptContent}`;
      }

      // Upload script file
      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timeoutId);
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const writeStream = sftp.createWriteStream(remotePath);
        writeStream.write(scriptContent);
        writeStream.end();

        writeStream.on('close', () => {
          // Make script executable and run it
          const cleanupCmd = cleanup ? ` && rm -f ${remotePath}` : '';
          const command = `chmod +x ${remotePath} && ${remotePath}${cleanupCmd}`;

          conn.exec(command, (err, stream) => {
            if (err) {
              clearTimeout(timeoutId);
              return reject(new Error(`Failed to execute uploaded script: ${err.message}`));
            }

            stream
              .on('close', (code, signal) => {
                clearTimeout(timeoutId);
                resolve({
                  content: [
                    {
                      type: 'text',
                      text: `Uploaded and executed: ${filename}\nInterpreter: ${interpreter}\nExit Code: ${code}\n${signal ? `Signal: ${signal}\n` : ''}Output:\n${output}${errorOutput ? `\nError Output:\n${errorOutput}` : ''}${cleanup ? '\nScript file removed after execution.' : `\nScript file preserved at: ${remotePath}`}`,
                    },
                  ],
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

        writeStream.on('error', (err) => {
          clearTimeout(timeoutId);
          reject(new Error(`Failed to upload script: ${err.message}`));
        });
      });
    });
  }

  async handleSSHUploadFile(args) {
    const { localPath, remotePath, connectionId = 'default', createDirs = true } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const absoluteLocalPath = resolve(localPath);

    return new Promise((resolve, reject) => {
      // Check if local file exists
      try {
        const fileContent = readFileSync(absoluteLocalPath);
        
        conn.sftp((err, sftp) => {
          if (err) {
            return reject(new Error(`SFTP error: ${err.message}`));
          }

          const uploadFile = () => {
            const writeStream = sftp.createWriteStream(remotePath);
            writeStream.write(fileContent);
            writeStream.end();

            writeStream.on('close', () => {
              resolve({
                content: [
                  {
                    type: 'text',
                    text: `Successfully uploaded ${absoluteLocalPath} to ${remotePath}`,
                  },
                ],
              });
            });

            writeStream.on('error', (err) => {
              reject(new Error(`Upload failed: ${err.message}`));
            });
          };

          if (createDirs) {
            const remoteDir = dirname(remotePath);
            if (remoteDir !== '.' && remoteDir !== '/') {
              sftp.mkdir(remoteDir, { recursive: true }, (err) => {
                // Ignore mkdir errors (directory might already exist)
                uploadFile();
              });
            } else {
              uploadFile();
            }
          } else {
            uploadFile();
          }
        });
      } catch (error) {
        reject(new Error(`Failed to read local file: ${error.message}`));
      }
    });
  }

  async handleSSHDownloadFile(args) {
    const { remotePath, localPath, connectionId = 'default', createDirs = true } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    const absoluteLocalPath = resolve(localPath);

    return new Promise((resolve, reject) => {
      conn.sftp((err, sftp) => {
        if (err) {
          return reject(new Error(`SFTP error: ${err.message}`));
        }

        const downloadFile = () => {
          const readStream = sftp.createReadStream(remotePath);
          let fileContent = Buffer.alloc(0);

          readStream.on('data', (chunk) => {
            fileContent = Buffer.concat([fileContent, chunk]);
          });

          readStream.on('end', () => {
            try {
              writeFileSync(absoluteLocalPath, fileContent);
              resolve({
                content: [
                  {
                    type: 'text',
                    text: `Successfully downloaded ${remotePath} to ${absoluteLocalPath}`,
                  },
                ],
              });
            } catch (error) {
              reject(new Error(`Failed to write local file: ${error.message}`));
            }
          });

          readStream.on('error', (err) => {
            reject(new Error(`Download failed: ${err.message}`));
          });
        };

        if (createDirs) {
          const localDir = dirname(absoluteLocalPath);
          try {
            mkdirSync(localDir, { recursive: true });
          } catch (error) {
            // Ignore mkdir errors if directory already exists
          }
        }

        downloadFile();
      });
    });
  }

  async handleSSHListFiles(args) {
    const { remotePath = '.', connectionId = 'default', detailed = false } = args;

    const conn = this.connections.get(connectionId);
    if (!conn) {
      throw new Error(`No active connection found for ID: ${connectionId}`);
    }

    try {
      const sftp = await new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) {
            return reject(new Error(`SFTP error: ${err.message}`));
          }
          resolve(sftp);
        });
      });

      const list = await new Promise((resolve, reject) => {
        sftp.readdir(remotePath, (err, list) => {
          if (err) {
            return reject(new Error(`Failed to list directory: ${err.message}`));
          }
          resolve(list);
        });
      });

      let output = `Directory listing for: ${remotePath}\n\n`;

      if (detailed) {
        output += 'Permissions  Size     Modified                Name\n';
        output += '-'.repeat(60) + '\n';
        
        list.forEach(item => {
          const isDir = item.attrs.isDirectory() ? 'd' : '-';
          const perms = item.attrs.mode ? (item.attrs.mode & parseInt('777', 8)).toString(8).padStart(3, '0') : '???';
          const size = item.attrs.size ? item.attrs.size.toString().padStart(8) : '???';
          const mtime = item.attrs.mtime ? new Date(item.attrs.mtime * 1000).toISOString() : 'Unknown';
          
          output += `${isDir}${perms}      ${size}   ${mtime}  ${item.filename}\n`;
        });
      } else {
        const dirs = list.filter(item => item.attrs.isDirectory()).map(item => item.filename + '/');
        const files = list.filter(item => !item.attrs.isDirectory()).map(item => item.filename);
        
        if (dirs.length > 0) {
          output += 'Directories:\n';
          dirs.forEach(dir => output += `  ${dir}\n`);
          output += '\n';
        }
        
        if (files.length > 0) {
          output += 'Files:\n';
          files.forEach(file => output += `  ${file}\n`);
        }
        
        if (dirs.length === 0 && files.length === 0) {
          output += 'Directory is empty';
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: output,
          },
        ],
      };
    } catch (error) {
      throw error;
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('SSH MCP Server running on stdio');
  }
}

const server = new SSHMCPServer();
server.run().catch(console.error);