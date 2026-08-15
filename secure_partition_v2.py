# secure_partition_v2.py v2.0
'''
This tool is used to sign (aka generate "secureinfo") and encrypt partition

Almost all new Mstar builds I saw have SECURITY_BOOT option enabled. Which means it uses AES to 
encrypt boot.img and recovery.img and RSA to generate signature (Plus multiple internal security updates).

This script will generate three files: encrypted image, Mstar signature file and RSA signature file

'''

import os
import sys
import argparse
from pathlib import Path

import utils

AES_KEY = b'\x00\x07\xFF\x41\x54\x53\x4D\x92\xFC\x55\xAA\x0F\xFF\x01\x10\xE0'   # Mstar default AES key

def check_file_exists(path_str):
    path = Path(path_str)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f'File not found: "{path_str}"')
    return path
    
import argparse

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

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--in', dest='in_file', type=check_file_exists, required=True, help='Input file name')
parser.add_argument('-r', '--rsa', dest='rsa_key', type=check_file_exists, default = Path('default_keys/RSAimage_priv.pem'), help='RSA private key [.pem]. Default: %(default)s')
parser.add_argument('-a', '--aes', dest='aes_key', type=check_hex_16_bytes, default = AES_KEY, help=f'AES key (hex format, 16 bytes). Default: {AES_KEY.hex().upper()}')
parser.add_argument('-o', '--out', dest='out_file', type=str, help='Output file name. Default: <Input file name>.aes')
parser.add_argument('-s', '--sign', dest='sign_file', type=str, help='Signature file name. Default: <Input file name>Sign')

args = parser.parse_args()

if args.out_file is None:
    args.out_file = args.in_file.with_suffix('.aes')
if args.sign_file is None:
    args.sign_file = args.in_file.with_name(args.in_file.stem + 'Sign')

print('[i] Mstar image signature generation')
print('[i]')
print('[i] Input parameters:')
print(f'[i]     Input file name:"{args.in_file}"')
print(f'[i]     Output file name: "{args.out_file}"')
print(f'[i]     AES key: "{args.aes_key.hex().upper()}"')
print(f'[i]     RSA private key: "{args.rsa_key}"')
print(f'[i]     Signature file name: "{args.sign_file}"')
print('[i]')

# File alignment (appends 0xFF bytes to the alignment boundary. Changes input file if it is not 16-bytes aligned)
print('[i] Aligning image file')
utils.alignFile(args.in_file, 0x10)

# RSA signature generation
print('[i] Generating RSA signature')
if not utils.RSA_sign(str(args.in_file), str(args.in_file.with_name(args.in_file.stem + '_rsa.sig')), str(args.rsa_key)):
    print('[ERROR] Cannot generate RSA signature')
    quit()

# Mstar signature file assembling
print('[i] Assembling Mstar signature')
if not utils.create_img_sign(str(args.sign_file), args.in_file.stat().st_size, str(args.in_file.with_name(args.in_file.stem + '_rsa.sig'))):
    print('[ERROR] Cannot assemble Mstar signature')
    quit()

# Output file encryption
print('[i] Encrypting image file')
if not utils.aes_encrypt(str(args.in_file), str(args.out_file), 'ecb', args.aes_key):
    print('[ERROR] Cannot encrypt img file')
    quit()

print ("[i] Done")