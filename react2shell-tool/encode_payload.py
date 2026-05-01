#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Encode payload to Base64 (certutil compatible)
Formats base64 with proper line breaks for certutil decode
Supports any file type (text, binary, scripts, executables, etc)
"""

import argparse
import base64
import sys
import os


def encode_file(input_file, output_file=None, line_length=64, add_header=False):
    """
    Encode file to base64 with certutil-compatible format
    
    Args:
        input_file: Path to input file (any type)
        output_file: Path to output file (.txt), auto-generated if None
        line_length: Characters per line (default: 64, certutil standard)
        add_header: Add BEGIN/END CERTIFICATE markers (optional)
    """
    
    # Read input file (binary mode to support all file types)
    try:
        with open(input_file, 'rb') as f:
            content_bytes = f.read()
    except Exception as e:
        print(f"[!] Failed to read input file: {e}")
        return False
    
    # Encode to base64
    base64_bytes = base64.b64encode(content_bytes)
    base64_string = base64_bytes.decode('ascii')
    
    # Split into lines (certutil expects max 64 chars per line)
    # If line_length <= 0, don't wrap (single line)
    if line_length <= 0:
        lines = [base64_string]
    else:
        lines = []
        for i in range(0, len(base64_string), line_length):
            lines.append(base64_string[i:i + line_length])
    
    # Build output
    output_lines = []
    
    if add_header:
        output_lines.append("-----BEGIN CERTIFICATE-----")
    
    output_lines.extend(lines)
    
    if add_header:
        output_lines.append("-----END CERTIFICATE-----")
    
    output_content = '\n'.join(output_lines)
    
    # Determine output filename
    if output_file is None:
        base_name = os.path.splitext(input_file)[0]
        output_file = f"{base_name}.txt"
    
    # Write output file
    try:
        with open(output_file, 'w', encoding='ascii') as f:
            f.write(output_content)
    except Exception as e:
        print(f"[!] Failed to write output file: {e}")
        return False
    
    # Stats
    original_size = len(content_bytes)
    encoded_size = len(base64_string)
    output_size = os.path.getsize(output_file)
    
    print(f"[+] Encoding successful!")
    print(f"[*] Original size: {original_size} bytes")
    print(f"[*] Base64 size: {encoded_size} bytes")
    print(f"[*] Output file: {output_file} ({output_size} bytes)")
    print(f"[*] Lines: {len(lines)} x {line_length} chars")
    
    # Show usage
    output_basename = os.path.basename(output_file)
    input_ext = os.path.splitext(input_file)[1]
    decoded_name = os.path.splitext(output_basename)[0] + "_decoded" + input_ext
    
    print(f"\n[+] Decode with certutil:")
    print(f"    certutil -decode {output_basename} {decoded_name}")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Encode payload to Base64 (certutil compatible)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encode PowerShell script
  python encode_payload.py payload.ps1
  
  # Encode executable
  python encode_payload.py malware.exe -o legit.txt
  
  # Encode with certificate headers (stealth)
  python encode_payload.py payload.ps1 --header
  
  # Encode shell script
  python encode_payload.py exploit.sh -o encoded.txt
  
  # Custom line length
  python encode_payload.py file.bin -l 76
        """
    )
    
    parser.add_argument('input', help='Input file (any type)')
    parser.add_argument('-o', '--output', help='Output base64 file (.txt)', default=None)
    parser.add_argument('-l', '--line-length', type=int, default=64,
                        help='Base64 line length (default: 64)')
    parser.add_argument('--header', action='store_true',
                        help='Add BEGIN/END CERTIFICATE markers (stealth)')
    
    args = parser.parse_args()
    
    # Verify input file exists
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)
    
    # Encode
    success = encode_file(
        args.input,
        args.output,
        args.line_length,
        args.header
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()

