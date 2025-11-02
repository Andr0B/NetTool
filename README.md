# NetTool (toy netcat)

A small educational Netcat-like tool written in Python. Useful for demonstrating basic networking, threading, and simple remote command execution in a controlled lab environment.

> ⚠️ **Security notice:** This tool is for learning/demo purposes only. Do not run it on networks or hosts where you don't have explicit permission.

## Features
- Client mode: connect to a remote host and interact
- Server mode:
  - Execute a single command and return the output
  - Accept file uploads and save to disk
  - Interactive remote command shell
- Minimal dependencies: Python 3 standard library only

## Example usage
Start an interactive command shell server:
```bash
python3 netcat.py -l -p 5555 -t 0.0.0.0 -c
