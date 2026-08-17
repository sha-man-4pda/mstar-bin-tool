# extract_keys_v2.py v2.0

'''
    Tool to extract security keys from the MBOOT
    
    usage: extract_keys_v2.py [-h] [-i IN_FILE] [-o OFFSET] [-d OUT_DIR]

    options:
        -h, --help           show this help message and exit
        -i, --input IN_FILE  Input MBOOT file. Default: "mboot.bin"
        -o, --offset OFFSET  Mstar KeyBank offset. Default: 0x0 - search entire file
        -d, --dir OUT_DIR    Output directory. Default: "keys"

    By default the script is looking for mboot.bin file in current directory but any file can 
    be specified with '-i' option.
    
    It can be used on any file that possibly contains Mstar key bank - MBOOT or  any Mstar 
    firmware update file, there is no need to unpack it if it's not encrypted. 
    The script will search the entire file to find Mstar key bank and exract keys out of it, 
    but if you know the exact offset you can specify it with '-o' option.
    
    If default key bank is found it will not be extracted because all the default keys are 
    already stored in the default_keys directory.
    
    The script designed as a 'stand-alone' tool so it can be placed in any directory.



    ==== Key bank structures ===

    #define AES_IV_LEN      16
    #define AES_KEY_LEN     16
    #define HMAC_KEY_LEN    32

    #define SIGNATURE_LEN           256
    #define RSA_PUBLIC_KEY_N_LEN    256
    #define RSA_PUBLIC_KEY_E_LEN    4
    #define RSA_PUBLIC_KEY_LEN      (RSA_PUBLIC_KEY_N_LEN+RSA_PUBLIC_KEY_E_LEN)

    typedef struct
    {
        U32 u32Num;
        U32 u32Size;
    }IMAGE_INFO;

    typedef struct
    {
      U8 u8SecIdentify[8]; 
      IMAGE_INFO info;
      U8 u8Signature[SIGNATURE_LEN];
    }_SUB_SECURE_INFO;

    typedef struct
    {
      U8 N[RSA_PUBLIC_KEY_N_LEN];
      U8 E[RSA_PUBLIC_KEY_E_LEN];
    }RSA_PUBLIC_KEY;

    typedef struct
    {
        _SUB_SECURE_INFO customer;
        RSA_PUBLIC_KEY u8RSABootPublicKey;
        RSA_PUBLIC_KEY u8RSAUpgradePublicKey;
        RSA_PUBLIC_KEY u8RSAImagePublicKey;
        U8 u8AESBootKey[AES_KEY_LEN];   
        U8 u8AESUpgradeKey[AES_KEY_LEN];       
        U8 u8MagicID[16];
        U8 crc[4];
    }CUSTOMER_KEY_BANK;

    ==== End Key bank structures ===

'''

import ctypes
import os
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass
import argparse
from Crypto.PublicKey import RSA  

# Default values
DEFAULT_AES_KEY = b'\x00\x07\xFF\x41\x54\x53\x4D\x92\xFC\x55\xAA\x0F\xFF\x01\x10\xE0'   # Mstar default AES key
KEY_BANK_MAGIC = b'\x4D\x73\x74\x61\x72\x2E\x4B\x65\x79\x2E\x42\x61\x6E\x6B\x2E\x2E'    # 'Mstar.Key.Bank..'
SECURITY_MARK = b'\x53\x45\x43\x55\x52\x49\x54\x59'                                     # 'SECURITY'
DEFAULT_CRC = b'\x7A\xEB\x68\xD3'                                                       # Default key bank CRC32 = 0xD368EB7A
KEY_BANK_SIZE = 0x450                                                                   # Key bank size, including SubSecureInfo
BUF_SIZE = 0x800                                                                        # Size of buffer to find KeyBank

# Structures
AES_KEY_LEN             = 16
SIGNATURE_LEN           = 256
RSA_PUBLIC_KEY_N_LEN    = 256
RSA_PUBLIC_KEY_E_LEN    = 4
RSA_PUBLIC_KEY_LEN      = RSA_PUBLIC_KEY_N_LEN + RSA_PUBLIC_KEY_E_LEN

class ImageInfo(ctypes.Structure):
    _fields_ = [("chunk_num", ctypes.c_uint32),                     # Always equal to 1 for non-interleave mode
                ("size", ctypes.c_uint32)]                          # Size of signed part of key bank, usually 0x340

class SubSecureInfo(ctypes.Structure):
    _fields_ = [("sec_identify", ctypes.c_uint8 * 8),               # For key bank is always 'SECURITY'
                ("info", ImageInfo),
                ("signature", ctypes.c_uint8 * SIGNATURE_LEN)]      # RSA signature of MstarKeyBank structure

class RsaPublicKey(ctypes.Structure):
    _fields_ = [("N", ctypes.c_uint8 * RSA_PUBLIC_KEY_N_LEN),
                ("E", ctypes.c_uint8 * RSA_PUBLIC_KEY_E_LEN)]

class MstarKeyBank(ctypes.Structure):
    _fields_ = [("header", SubSecureInfo),
                ("rsa_boot_public_key", RsaPublicKey),
                ("rsa_upgrade_public_key", RsaPublicKey),
                ("rsa_image_public_key", RsaPublicKey),
                ("aes_boot_key", ctypes.c_uint8 * AES_KEY_LEN),
                ("aes_upgrade_key", ctypes.c_uint8 * AES_KEY_LEN),
                ("magic", ctypes.c_uint8 * 16),                     # 'Mstar.Key.Bank..'
                ("crc", ctypes.c_uint8 * 4)]                        # CRC32 of MstarKeyBank structure excluding this field

@dataclass
class KeyBankInfo:
  offset: int
  expected_size: int
  stored_size: int
  crc32 : bytes

def check_file_exists(path_str):
    path = Path(path_str)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f'File not found: "{path_str}"')
    return path

def check_hex(value):
    cleaned_value = value.strip()
    if cleaned_value.startswith('-'):
        raise argparse.ArgumentTypeError(f'Offset cannot be negative: "{value}"')
    if value.lower().startswith('0x'):
        value = value[2:]
    try:
        return int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f'String contains non-hex symbols: "{value}"')

def ensure_directory(value):
  out_dir = Path(value)
  if out_dir.is_file():
    raise argparse.ArgumentTypeError(f'Path "{value}" points on a file, not a directory!')
  try:
    out_dir.mkdir(parents=True, exist_ok=True)
  except Exception as e:
    raise argparse.ArgumentTypeError(f'Cannot create directory "{value}": {e}')
  return out_dir

def find_key_bank(file: Path, offset = 0):
    info = KeyBankInfo(offset = -1, stored_size = 0, expected_size = 0, crc32 = b'')
    # If offset is specified we are searching just in [offset:offset+BUF_SIZE] region,
    # else - looking for Keybank magic throughout the entire file starting from the end
    if (offset != 0):
        with file.open('rb') as f:
            f.seek(offset)
            buffer = f.read(BUF_SIZE)
    else:
        with file.open('rb') as f:
            buffer = f.read()
    end_position = len(buffer)
    while True:
        magic_position = buffer.rfind(KEY_BANK_MAGIC, 0, end_position)
        if magic_position == -1:
            break
        else :
            security_position = buffer.rfind(SECURITY_MARK, max(0, magic_position - BUF_SIZE), magic_position)
            if security_position != -1:
                if offset == 0 :
                    info.offset = security_position
                else:
                    info.offset = offset
                offset = security_position + 12
                info.stored_size = int.from_bytes(buffer[offset : offset + 4], byteorder='little', signed=False)
                info.expected_size = magic_position - security_position + 20
                info.crc32 = buffer[magic_position + 16: magic_position + 20]
                return info
        end_position = magic_position
    return info

def store_part(in_file: Path, out_file: Path, offset, size):
    with in_file.open('rb') as f1:
        f1.seek(offset)
        buffer = f1.read(size)
    with out_file.open('wb') as f2:
        f2.write(buffer)

def load_key_bank(file: Path, offset):
    with file.open('rb') as f:
        f.seek(offset)
        buffer = f.read(KEY_BANK_SIZE)
        return MstarKeyBank.from_buffer_copy(buffer)

def write_rsa_public_key(file:Path, key: RsaPublicKey):
    # BIN
    with file.with_suffix('.bin').open('wb') as f:
        f.write(key)
    # TXT
    key_txt = str.encode(f'N = {bytes(key.N).hex().upper()}\nE = {bytes(key.E).hex().upper()}')
    with file.with_suffix('.txt').open('wb') as f:
        f.write(key_txt)
    # PEM
    n = int.from_bytes(bytes(key.N), byteorder='big')
    e = int.from_bytes(bytes(key.E), byteorder='big')
    key_pem = RSA.construct((n, e))
    with file.with_suffix('.pem').open('wb') as f:
        f.write(key_pem.export_key('PEM'))

def write_file(file: Path, data):
    with file.open('wb') as f:
        f.write(data)

parser = argparse.ArgumentParser()

parser.add_argument('-i', '--input', dest='in_file', type=check_file_exists, default = 'MBOOT.bin', help='Input MBOOT file. Default: "%(default)s"')
parser.add_argument('-o', '--offset', dest='offset', type=check_hex, default = '0x00', help=f'Mstar key bank offset. Default: "%(default)s" - search entire file')
parser.add_argument('-d', '--dir', dest='out_dir', type=ensure_directory, default = 'keys', help=f'Output directory. Default: "keys"')

print(' *              Mstar key bank extractor v2.0              *')
print(' * part of mstar-bin-tool by dipcore, fork by sha-man-4pda *')
print(' *     https://github.com/sha-man-4pda/mstar-bin-tool      *')
print('')

args = parser.parse_args()

print('[i] Input parameters:')
print(f'[i]     Input file name:"{args.in_file}"')
print(f'[i]     Output folder: "{args.out_dir}"')
if args.offset == 0 :
    print(f'[i]     Offset not specified, searching entire file')
else:
    print(f'[i]     Offset: "{hex(args.offset)}"')
print('')
print('[i] Looking for Mstar key bank')

# Looking for key bank 
key_bank_info = find_key_bank(args.in_file, args.offset)
if (key_bank_info.offset == -1) :
    print('[i] Mstar key bank is not found')
    if args.out_dir.is_dir() and not any(args.out_dir.iterdir()):
        args.out_dir.rmdir()
    quit()
print(f'[i] Mstar key bank found at {hex(key_bank_info.offset)}, size: {hex(key_bank_info.expected_size)}, crc: {key_bank_info.crc32[::-1].hex().upper()}')

# Checking if the real size of the found block corresponds with the size stored in SubSecureInfo section
if  (key_bank_info.expected_size != (key_bank_info.stored_size + ctypes.sizeof(SubSecureInfo))):
    print(f'[!] Calculated key bank size ({hex(key_bank_info.stored_size + ctypes.sizeof(SubSecureInfo))}) is not as expected ({hex(key_bank_info.expected_size)})')
    store_part(args.in_file, args.out_dir/'unknown.bin', key_bank_info.offset, max(key_bank_info.expected_size, key_bank_info.stored_size + ctypes.sizeof(SubSecureInfo)))
    quit()

# Saving key bank to file
store_part(args.in_file, args.out_dir/'key_bank.bin', key_bank_info.offset, key_bank_info.expected_size)

# Checking if the found key bank is the default one
if (key_bank_info.crc32 == DEFAULT_CRC) :
    print('[i] Mstar default key bank found. No need to analyze.')
    quit()

# Checking if the found key bank has usual size. The ones of different size cannot be parsed automatically
if (key_bank_info.expected_size != KEY_BANK_SIZE) :
    print('[!] Key bank has unknown format. Cannot parse')
    quit()

# Parsing key bank data
key_bank = load_key_bank(args.in_file, key_bank_info.offset)

# Save keys
print ("[i] Saving keys")

# RSA Boot
write_rsa_public_key(args.out_dir/'RSAboot_pub', key_bank.rsa_boot_public_key)

# RSA Image
write_rsa_public_key(args.out_dir/'RSAimage_pub', key_bank.rsa_image_public_key)

# RSA Upgrade
write_rsa_public_key(args.out_dir/'RSAupgrade_pub', key_bank.rsa_upgrade_public_key)

# AES
write_file(args.out_dir/'AESboot.bin', key_bank.aes_boot_key)
write_file(args.out_dir/'AESupgrade.bin', key_bank.aes_upgrade_key)

print ("[i] Done")