"""
Decrypt TONESHELL encrypted log files.
Usage: python aes_base64_log_decryptor.py -i <input> -o <output> --aes-256-ctr -k <hexkey>
"""
import argparse
import base64
import sys
from Crypto.Cipher import AES

KEY = bytes.fromhex("c47001f8de67d8fe23b76d7685fe75fbb0abec9b3bb23f4cf99d7f3ece345c18")

def decrypt_line(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    raw = base64.b64decode(line)
    if len(raw) < 16:
        return f"[DECODE_ERROR: too short {len(raw)}]"
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=b"", initial_value=iv)
    return cipher.decrypt(ct).decode("utf-8", errors="replace")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True)
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("-k", "--key", default=KEY.hex())
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        lines = f.read().split(b"\n")

    with open(args.output, "w", encoding="utf-8") as f:
        for line in lines:
            text = line.decode("ascii", errors="replace").strip()
            if text:
                f.write(decrypt_line(text) + "\n")

    print(f"Done. Decrypted {len(lines)} lines -> {args.output}")

if __name__ == "__main__":
    main()
