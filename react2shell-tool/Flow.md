# react2shell-tool — Flow

**Entry:** `run_exploit.py` → `exploit_tool/main.py` (interactive REPL) · `exploit.py` (single-shot)  ·  **Artifact summary:** Python attacker-side exploit tool for CVE-2025-55182 — delivers JS deserialization payloads into RSC Flight protocol, executes commands/file ops on target Node.js process, exfiltrates output via redirect header

| # | Behavior (`actor action artifact`) | Artifact [class] → consumed by | Tactic / TID — Technique Name | Context (baseline) |
|---|---|---|---|---|
| 1 | tool establishes persistent HTTP session to target | HTTP session [network] → #3 | — | `requests.Session()`; TLS cert verification disabled (`verify=False`) |
| 2 | tool encodes JS payload as `String.fromCharCode()` charcode sequence | — [no-artifact] → #3 | — | Applied to all eval-mode and file-op JS; avoids quote-in-JSON conflicts in multipart body |
| 3 | tool injects JS into RSC Flight `_response._prefix` via multipart POST with `Next-Action: x` header | HTTP POST [network] → #4 | — | CVE-2025-55182; `$@0` reference triggers fake Chunk `then` deserialization gadget on target |
| 4 | tool extracts command output from `X-Action-Redirect: /login?a=<b64>` response header | decoded output [network] → operator | — | Target throws `NEXT_REDIRECT` error; base64 stdout embedded in redirect URI digest field |
| 5 | Node.js process spawns cmd.exe then command via injected `child_process.execSync` (default RCE mode) | child process [process] → #4 | — | Double spawn: node.exe → cmd.exe → `<command>`; Windows default for unrecognized shell commands |
| 6 | Node.js process evaluates JavaScript in-process via injected `eval()` without spawning child (eval mode) | in-process result [no-artifact] → #4 | — | `process.mainModule.require` accesses Node internals; no child_process event; used by all file ops |
| 7 | Node.js process spawns executable directly via injected `child_process.spawnSync` without cmd.exe (run mode) | child process [process] → #4 | — | No shell wrapper; executable and args array explicit; node.exe → `<exe>` in process tree |
| 8 | Node.js process spawns C2 agent detached via `spawn({detached:true, stdio:'ignore'}).unref()` (eval+spawn) | detached process [process] | — | Agent survives HTTP request close; no stdout captured; used to launch dnscat2/C2 implants |
| 9 | tool writes pre-encoded b64 file to target in 2000-char chunks via `fs.writeFileSync`/`appendFileSync` (upload) | b64 file on target [file] → #10 | — | Requires local `.b64` pre-encoded file; leaves `.b64` artifact on target disk |
| 10 | Node.js process decodes b64 file to binary on target via `fs.writeFileSync(Buffer.from(readFileSync,'base64'))` (decode) | binary file on target [file] → #7,#8 | — | Pure fs API; no child_process spawn; consumes `.b64` written by #9 |
| 11 | tool XOR-encodes PE bytes in Python memory before staging (stage `--encrypt` flag) | — [no-artifact] → #12 | — | `out[i] = in[i] ^ ((0xA3 + i * 0x5B) & 0xFF)`; matches `CWLImplant.cpp` runtime decoder; optional |
| 12 | tool streams PE in 2000-char b64 chunks into `global.__stageBuffer` on target then flushes to binary file (stage) | binary file on target [file] → #7,#8 | — | No `.b64` artifact on target disk; `global.__stageBuffer` deleted immediately after `writeFileSync` |
| 13 | Node.js process decompresses gzip file on target via `zlib.gunzipSync` without spawning child (decompress) | decompressed file on target [file] → #7,#8 | — | Built-in zlib module; no child_process spawn; consumes `.gz.b64` uploaded via #9 |
| 14 | Node.js process copies file on target via `fs.copyFileSync` (copyfile) | copied file on target [file] | — | Pure fs API; no spawn |
| 15 | Node.js process renames/moves file on target via `fs.renameSync` (rename) | renamed file on target [file] | — | Pure fs API; no spawn |
| 16 | Node.js process sets Windows hidden attribute on target file via `spawnSync('attrib', ['+h', ...])` (hide) | child process [process] + hidden file [file] | — | node.exe → attrib.exe directly (no cmd.exe wrapper); intentional observable process event |
| 17 | tool streams PE in-memory to `global.__stageBuffer` on target then spawns loader via stdin pipe (pipestage) | child process [process] | — | 4-byte LE size header prepended to decoded PE; `spawnSync(CertEnrollAgent, {input: sizeHdr+payload})`; no PE disk artifact |
| 18 | Node.js reads b64 PE from target disk, decodes in-memory, spawns loader via stdin pipe (pipeload) | child process [process] | — | Reads existing `.b64` file; same stdin-pipe spawn as #17; PE never written as binary to disk |
| 19 | tool downloads file from target in 8192-byte chunks via `fs.openSync`/`fs.readSync`, saves locally (download) | local file [file] | — | Binary-safe via base64-per-chunk; no child_process; saved as `downloaded_<filename>` |
