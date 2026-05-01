#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Decode Base64 payload (certutil compatible format)
Can decode files created by encode_payload.py or certutil
Supports any file type (text, binary, scripts, executables, etc)
"""

import argparse
import base64
import sys
import os


def decode_file(input_file, output_file=None, remove_headers=True):
    """
    Decode base64 file to original content
    
    Args:
        input_file: Path to base64 encoded file (.txt)
        output_file: Path to output file (any type), auto-generated if None
        remove_headers: Remove BEGIN/END CERTIFICATE markers if present
    """
    
    # Read input file
    try:
        with open(input_file, 'r', encoding='ascii') as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Failed to read input file: {e}")
        return False
    
    # Remove headers if present
    lines = content.split('\n')
    filtered_lines = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if remove_headers and ('BEGIN CERTIFICATE' in line or 'END CERTIFICATE' in line):
            continue
        filtered_lines.append(line)
    
    # Join all base64 lines
    base64_string = ''.join(filtered_lines)
    
    # Decode from base64
    try:
        decoded_bytes = base64.b64decode(base64_string)
    except Exception as e:
        print(f"[!] Failed to decode: {e}")
        return False
    
    # Determine output filename
    if output_file is None:
        base_name = os.path.splitext(input_file)[0]
        output_file = f"{base_name}_decoded"
    
    # Write output file (binary mode to support all file types)
    try:
        with open(output_file, 'wb') as f:
            f.write(decoded_bytes)
    except Exception as e:
        print(f"[!] Failed to write output file: {e}")
        return False
    
    # Stats
    encoded_size = len(base64_string)
    decoded_size = len(decoded_bytes)
    output_size = os.path.getsize(output_file)
    
    print(f"[+] Decoding successful!")
    print(f"[*] Base64 size: {encoded_size} bytes")
    print(f"[*] Decoded size: {decoded_size} bytes")
    print(f"[*] Output file: {output_file} ({output_size} bytes)")
    
    # Show file type hint
    output_basename = os.path.basename(output_file)
    ext = os.path.splitext(output_basename)[1].lower()
    
    print(f"\n[+] File decoded: {output_basename}")
    
    # Show usage hints based on file extension
    if ext == '.ps1':
        print(f"[*] Execute with:")
        print(f"    powershell -ExecutionPolicy Bypass -File {output_basename}")
    elif ext == '.exe':
        print(f"[*] Execute with:")
        print(f"    .\\{output_basename}")
    elif ext in ['.sh', '.bash']:
        print(f"[*] Execute with:")
        print(f"    bash {output_basename}")
    elif ext == '.py':
        print(f"[*] Execute with:")
        print(f"    python {output_basename}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Decode Base64 payload (certutil compatible)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decode PowerShell script
  python decode_payload.py payload.txt -o script.ps1
  
  # Decode executable
  python decode_payload.py encoded.txt -o malware.exe
  
  # Auto-detect filename
  python decode_payload.py payload.txt
  
  # Keep certificate headers
  python decode_payload.py cert.txt --keep-headers
        """
    )
    
    parser.add_argument('input', help='Input base64 file (.txt)')
    parser.add_argument('-o', '--output', help='Output file (any type)', default=None)
    parser.add_argument('--keep-headers', action='store_true',
                        help='Keep BEGIN/END CERTIFICATE markers')
    
    args = parser.parse_args()
    
    # Verify input file exists
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)
    
    # Decode
    success = decode_file(
        args.input,
        args.output,
        remove_headers=not args.keep_headers
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

