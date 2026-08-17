# secure_partition_v2.py v2.1

'''
    This tool is used to sign (aka generate "secureinfo") and encrypt partition

    usage: secure_partition_v2.py [-h] -i IN_FILE [-r RSA_KEY] [-a AES_KEY] [-o OUT_FILE] [-s SIGN_FILE]

    options:
    -h, --help            show this help message and exit
    -i, --in IN_FILE      Input file name
    -r, --rsa RSA_KEY     RSA private key [.pem]. Default: "default_keys/RSAimage_priv.pem"
    -a, --aes AES_KEY     AES key (hex format, 16 bytes). Default: 0007FF4154534D92FC55AA0FFF0110E0
    -o, --out OUT_FILE    Output file name. Default: <Input file name>.aes
    -s, --sign SIGN_FILE  Signature file name. Default: <Input file name>Sign.bin

    Almost all new Mstar builds I saw have SECURITY_BOOT option enabled. Which means it uses AES to 
    encrypt boot.img and recovery.img and RSA to generate signature (Plus multiple internal security updates).

    This script will generate three files: encrypted image, Mstar signature file and RSA signature file

    The script designed as a 'stand-alone' tool so it can be placed in any directory.

'''

import os
import sys
import argparse
from pathlib import Path
import subprocess

AES_KEY = b'\x00\x07\xFF\x41\x54\x53\x4D\x92\xFC\x55\xAA\x0F\xFF\x01\x10\xE0'   # Mstar default AES key
CONTINUE_MODE_ID = b'\x53\x45\x43\x55\x52\x49\x54\x59'                          # 'SECURITY'
INTERLEAVE_MODE_ID = b'\x49\x4E\x54\x45\x52\x4C\x56\x45'                        # 'INTERLVE'
CHUNK_NUMBER = b'\x01\x00\x00\x00'                                              # Always equal to 1 for non-interleave mode
MSTAR_SIGN_SIZE = 0x220

def check_file_exists(path_str):
    path = Path(path_str)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f'File not found: "{path_str}"')
    return path

def check_hex_16_bytes(value):
    clean_val = value.lower()
    if clean_val.startswith('0x'):
        clean_val = clean_val[2:]
    if len(clean_val) != 32:
        raise argparse.ArgumentTypeError(f'Wrong AES key length. Must be 16 bytes, received {len(clean_val)}')
    try:
        return bytes.fromhex(clean_val)
    except ValueError:
        raise argparse.ArgumentTypeError(f'String contains non-hex symbols: "{value}"')

    # Aligns the file to the base
def align_file(file: Path, base = 0x1000):
    result = (base - file.stat().st_size % base) % base
    if result:
        with file.open('ab') as f:
            f.write(('\xff' * result).encode(encoding='iso-8859-1'))

    # Checks if OpenSSL is installed
def check_openssl_cli():
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, text=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

    #Creates RSA signature of in_files and stores it in out_file
def rsa_sign(in_file: Path, out_file: Path, private_key: str):
    if not check_openssl_cli():
        print('[!] To create RSA signature you need to install OpenSSL')
        return False
    command = 'openssl dgst -sha256 -sign ' + private_key + ' -out ' + str(out_file) + ' ' + str(in_file)
    os.system(command)
    return True

    #Creates Mstar image signature
def create_img_sign(out_file: Path, size: int, signature: str) :
    with out_file.open('wb') as f1:
        f1.write(CONTINUE_MODE_ID)
        f1.write(CHUNK_NUMBER)
        f1.write(size.to_bytes(4, byteorder='little'))
        with open (signature, 'rb') as f2:
            data = f2.read()
        f1.write(data)
        f1.write(INTERLEAVE_MODE_ID)
        f1.write(CHUNK_NUMBER)
        f1.write(size.to_bytes(4, byteorder='little'))
        f1.write(data)
    if (out_file.stat().st_size != MSTAR_SIGN_SIZE) :
        print(f'[!] Something went wrong. Generated signature file size: {hex(out_file.stat().st_size)} bytes')
        return False
    else:
        return True

    # Encrypts in_file data using OpenSSL
    # AES-128-CBC-NoPadding or AES-128-ECB-NoPadding algorithm
    # Saves encrypted data to out_file
def aes_encrypt(in_file: Path, out_file: Path, cbc_ecb: str, aes_key: bytes, iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
    if not check_openssl_cli():
        print('[!] To encrypt data you need to install OpenSSL')
        return False
    command = 'openssl aes-128-' + cbc_ecb.lower() + ' -e -nopad -K ' + aes_key.hex()
    if (cbc_ecb.lower() == 'cbc') : 
        command += ' -iv ' + iv.hex()
    command += ' -in ' + str(in_file) + ' -out ' + str(out_file)
    os.system(command)
    return True

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--in', dest='in_file', type=check_file_exists, required=True, help='Input file name')
parser.add_argument('-r', '--rsa', dest='rsa_key', type=check_file_exists, default = 'default_keys/RSAimage_priv.pem', help='RSA private key [.pem]. Default: "%(default)s" ')
parser.add_argument('-a', '--aes', dest='aes_key', type=check_hex_16_bytes, default = AES_KEY, help=f'AES key (hex format, 16 bytes). Default: {AES_KEY.hex().upper()}')
parser.add_argument('-o', '--out', dest='out_file', type=str, help='Output file name. Default: <Input file name>.aes')
parser.add_argument('-s', '--sign', dest='sign_file', type=str, help='Signature file name. Default: <Input file name>Sign.bin')

print(' *              Mstar SecureInfo creator v2.1              *')
print(' * part of mstar-bin-tool by dipcore, fork by sha-man-4pda *')
print(' *     https://github.com/sha-man-4pda/mstar-bin-tool      *')
print('')

args = parser.parse_args()

if args.out_file is None:
    args.out_file = args.in_file.with_suffix('.aes')
if args.sign_file is None:
    args.sign_file = args.in_file.with_name(args.in_file.stem + 'Sign')
    args.sign_file = args.sign_file.with_suffix('.bin')

print('[i] Input parameters:')
print(f'[i]     Input file name:"{args.in_file}"')
print(f'[i]     Output file name: "{args.out_file}"')
print(f'[i]     AES key: "{args.aes_key.hex().upper()}"')
print(f'[i]     RSA private key: "{args.rsa_key}"')
print(f'[i]     Signature file name: "{args.sign_file}"')
print('')

# File alignment (appends 0xFF bytes to the alignment boundary. Changes input file if it is not 16-bytes aligned)
print('[i] Aligning image file')
align_file(args.in_file, 0x10)

# RSA signature generation
print('[i] Generating RSA signature')
if not rsa_sign(args.in_file, args.in_file.with_name(args.in_file.stem + '_rsa.sig'), str(args.rsa_key)):
    print('[ERROR] Cannot generate RSA signature')
    quit()

# Mstar signature file assembling
print('[i] Assembling Mstar signature')
if not create_img_sign(args.sign_file, args.in_file.stat().st_size, args.in_file.with_name(args.in_file.stem + '_rsa.sig')):
    print('[ERROR] Cannot assemble Mstar signature')
    quit()

# Output file encryption
print('[i] Encrypting image file')
if not aes_encrypt(args.in_file, args.out_file, 'ecb', args.aes_key):
    print('[ERROR] Cannot encrypt img file')
    quit()

print ("[i] Done")