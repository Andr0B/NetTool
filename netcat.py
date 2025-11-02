#!/usr/bin/env python3
"""
Simple Netcat-like tool for learning / demo purposes.

Features:
- Connect to a remote host and interact (client mode)
- Listen on a port and handle:
  * execute a single command and return output
  * accept a file upload and save to disk
  * interactive command shell (persistent)
This is for demo/education only. Do not use on networks where you don't have permission.
"""

import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd: str) -> str:
    """Execute a command on the local shell and return stdout+stderr as text."""
    cmd = cmd.strip()
    if not cmd:
        return ''
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
        return output.decode(errors='replace')
    except subprocess.CalledProcessError as e:
        # Return command output even if non-zero exit code
        return e.output.decode(errors='replace')
    except Exception as e:
        return f'Command execution failed: {e}\n'


class NetCat:
    def __init__(self, args, buffer: bytes = None):
        self.args = args
        self.buffer = buffer or b''
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow quick reuse during development
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        if self.args.listen:
            self.listen()
        else:
            self.send()

    # ---- Client mode ----
    def send(self):
        try:
            self.socket.connect((self.args.target, self.args.port))
        except Exception as e:
            print(f'Connection failed: {e}', file=sys.stderr)
            return

        if self.buffer:
            try:
                self.socket.sendall(self.buffer)
            except Exception as e:
                print(f'Failed to send buffer: {e}', file=sys.stderr)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    if not data:
                        break
                    response += data.decode(errors='replace')
                    if recv_len < 4096:
                        break
                if response:
                    print(response, end='')  # already includes newline if server sends it
                # Read user input and send
                try:
                    buffer = input('> ')
                except EOFError:
                    # Ctrl-D or no stdin
                    break
                buffer += '\n'
                try:
                    self.socket.sendall(buffer.encode())
                except Exception as e:
                    print(f'Failed to send: {e}', file=sys.stderr)
                    break
        except KeyboardInterrupt:
            print('\nUser terminated')
        finally:
            self.socket.close()

    # ---- Server mode ----
    def listen(self):
        bind_addr = self.args.target if self.args.target else '0.0.0.0'
        try:
            self.socket.bind((bind_addr, self.args.port))
            self.socket.listen(5)
            print(f'Listening on {bind_addr}:{self.args.port} ...')
        except Exception as e:
            print(f'Bind/listen failed: {e}', file=sys.stderr)
            return

        while True:
            client_socket, addr = self.socket.accept()
            print(f'Accepted connection from {addr}')
            client_thread = threading.Thread(target=self.handle, args=(client_socket, addr))
            client_thread.daemon = True
            client_thread.start()

    def handle(self, client_socket: socket.socket, addr):
        """Handle one connected client according to flags."""
        try:
            if self.args.execute:
                output = execute(self.args.execute)
                client_socket.sendall(output.encode())
                client_socket.close()
                return

            if self.args.upload:
                # receive file data until the socket is closed by the client
                file_buffer = b''
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    file_buffer += data
                try:
                    with open(self.args.upload, 'wb') as f:
                        f.write(file_buffer)
                    message = f'Saved file {self.args.upload}\n'
                except Exception as e:
                    message = f'Failed to save file: {e}\n'
                client_socket.sendall(message.encode())
                client_socket.close()
                return

            if self.args.command:
                # Interactive command shell
                try:
                    while True:
                        client_socket.sendall(b'BPH: #> ')
                        cmd_buffer = b''
                        # Read until newline
                        while b'\n' not in cmd_buffer:
                            chunk = client_socket.recv(64)
                            if not chunk:
                                # client disconnected
                                raise ConnectionResetError('Client disconnected')
                            cmd_buffer += chunk
                        command = cmd_buffer.decode(errors='replace').strip()
                        if not command:
                            continue
                        response = execute(command)
                        if response:
                            client_socket.sendall(response.encode())
                except Exception as e:
                    print(f'Client handler ({addr}) terminated: {e}')
                finally:
                    client_socket.close()
                    return

            # Default behavior: echo received data back
            try:
                while True:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    client_socket.sendall(data)
            except Exception:
                pass
            finally:
                client_socket.close()

        except Exception as e:
            print(f'Error handling client {addr}: {e}')
            try:
                client_socket.close()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Net Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''Example usage:
  # Start a command shell server listening on all interfaces port 5555
  netcat.py -l -p 5555 -t 0.0.0.0 -c

  # Start a server and accept a file upload and save as uploaded.txt
  netcat.py -l -p 5555 -u uploaded.txt

  # Start a server and execute a command then close
  netcat.py -l -p 5555 -e "uname -a"

  # Connect to a server and interact (client)
  echo 'Hello' | ./netcat.py -t 192.168.1.100 -p 5555
'''))
    parser.add_argument('-c', '--command', action='store_true', help='command shell')
    parser.add_argument('-e', '--execute', help='execute specified command and return output')
    parser.add_argument('-l', '--listen', action='store_true', help='listen on [target]:port for incoming connections')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='127.0.0.1', help='specified target IP (default client -> 127.0.0.1; server -> bind address)')
    parser.add_argument('-u', '--upload', help='upon receiving connection, write received bytes to this file')
    args = parser.parse_args()

    if args.listen:
        # When acting as a server, target is the bind address; default to 0.0.0.0
        if args.target == '127.0.0.1':
            args.target = '0.0.0.0'
        buffer = None
    else:
        # When client, read stdin as data to send (if any)
        try:
            buffer = sys.stdin.buffer.read()
        except Exception:
            buffer = b''

    nc = NetCat(args, buffer)
    nc.run()


if __name__ == '__main__':
    main()
