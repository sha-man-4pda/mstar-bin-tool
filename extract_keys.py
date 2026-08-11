'''
	Tool to extract security keys from the MBOOT

	That tool can be used only if you have Mstar.Key.Bank section in the mboot
	To check that you need to enable debug mode in the mboot console, 
	and check for next lines during the boot:
		[DEBUG] isCustomerKeyBankCipher:926: keyBankOffset=0x168e00
		[DEBUG] isCustomerKeyBankCipher:927: keyBankSize=0x450

	keyBankOffset - is an offset of the key bank section in the mboot, if unspecified or 0x0, we check the MBOOT header
	keyBankSize - section size

	There will be similar lines for the key bank backup.

	Another way to check it is to open MBOOT binary in the hex editor and
	do search for u8MagicID, which is most of the time equals to "Mstar.Key.Bank" string. 
	You should get two equal sections, the key bank and the key bank backup.

	==== Key bank structures ===

	#define AES_IV_LEN 		16
	#define AES_KEY_LEN 	16
	#define HMAC_KEY_LEN 	32

	#define SIGNATURE_LEN        	256
	#define RSA_PUBLIC_KEY_N_LEN 	256
	#define RSA_PUBLIC_KEY_E_LEN 	4
	#define RSA_PUBLIC_KEY_LEN   	(RSA_PUBLIC_KEY_N_LEN+RSA_PUBLIC_KEY_E_LEN)

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

	typedef struct
	{
		_SUB_SECURE_INFO SecureInfo;
		U8 u8MSID[4];
		U32 u32TkbVersion;
		U8 u8RSATEEKey[RSA_PUBLIC_KEY_LEN];
		U8 u8AESTEEKey[AES_KEY_LEN];
	} TEE_KEY_BANK;

	typedef struct
	{
		_SUB_SECURE_INFO SecureInfo;
		U8 u8RSAKey[RSA_PUBLIC_KEY_LEN];
		U8 u8AESKey[AES_KEY_LEN];
	} REE_KEY_BANK;

	==== End Key bank structures ===

'''


from ctypes import *
import os
import sys
import utils
import struct

DEBUG = False

# Default values
defOutFolder = "keys"
#defOffet = "0x168e00"
defSize = "0x600"
#defKey="hex:E01001FF0FAA55FC924D535441FF0700"

# Structures
AES_IV_LEN 		= 16
AES_KEY_LEN 	= 16
HMAC_KEY_LEN 	= 32

SIGNATURE_LEN        	= 256
RSA_PUBLIC_KEY_N_LEN 	= 256
RSA_PUBLIC_KEY_E_LEN 	= 4
RSA_PUBLIC_KEY_LEN   	= RSA_PUBLIC_KEY_N_LEN + RSA_PUBLIC_KEY_E_LEN

class IMAGE_INFO(Structure):
	_fields_ = [("u32Num", c_uint32),
				("u32Size", c_uint32)]

class SUB_SECURE_INFO(Structure):
	_fields_ = [("u8SecIdentify", c_uint8 * 8),
				("info", IMAGE_INFO),
				("u8Signature", c_uint8 * SIGNATURE_LEN)]

class RSA_PUBLIC_KEY(Structure):
	_fields_ = [("N", c_uint8 * RSA_PUBLIC_KEY_N_LEN),
				("E", c_uint8 * RSA_PUBLIC_KEY_E_LEN)]

class CUSTOMER_KEY_BANK(Structure):
	_fields_ = [("customer", SUB_SECURE_INFO),
				("u8RSABootPublicKey", RSA_PUBLIC_KEY),
				("u8RSAUpgradePublicKey", RSA_PUBLIC_KEY),
				("u8RSAImagePublicKey", RSA_PUBLIC_KEY),
				("u8AESBootKey", c_uint8 * AES_KEY_LEN),
				("u8AESUpgradeKey", c_uint8 * AES_KEY_LEN),
				("u8MagicID", c_uint8 * 16),
				("crc", c_uint8 * 4)]


# Command line args
if len(sys.argv) == 1: 
	print ("Usage: extract_keys.py <path to mboot> [<folder to store keys>] [<key bank offset>]")
	print ("If you don't enter the offset (or you enter 0x0) the script gets the offset from the MBOOT header")
	print ("Defaults: ")
	print ("          <folder to store keys> 	keys")
	print ("          <key bank offset> 		0x0")
	print ("Example: extract_keys.py ./unpacked/MBOOT.img")
	print ("Example: extract_keys.py ./unpacked/MBOOT.img ./keys 0x169e00")
	quit()


mboot = sys.argv[1]
outFolder = sys.argv[2] if len(sys.argv) >= 3 else defOutFolder
offsetStr = sys.argv[3] if len(sys.argv) >= 4 else "0x0"
offset = int(offsetStr, 16)
sizeStr = sys.argv[4] if len(sys.argv) >= 5 else "0x0"
size = int(sizeStr, 16)
#hwKey = sys.argv[5] if len(sys.argv) >= 6 else defKey

#If the offset wasn't specified in the args
#Try to load the offset from the MBOOT header
with open(mboot, 'rb') as file:
	if offset == 0:
		file.seek(0, os.SEEK_END)
		fileSize = file.tell()
		file.seek(0x4c)
		rawOffset = file.read(4)
		offset = struct.unpack('<I', rawOffset)[0]
		if (DEBUG):
			print ( "[i] offset from header is:{}".format( hex(offset) ) )
		# Sanity check that the offset isn't null or past the end of the file
		if offset == 0 or offset > fileSize:
			print( "[e] offset not specified, and we weren't able to find one in the header")
			exit(-1)
	# Load secure info
	file.seek(offset)
	secIdentityBytes= file.read(sizeof(SUB_SECURE_INFO))
	secIdentity = utils.unpackStructure(SUB_SECURE_INFO, secIdentityBytes)
	# make sure it starts with SECURITY
	if (DEBUG):
		print ( "[i] u8SecIdentify:{}".format( bytes(secIdentity.u8SecIdentify).decode("utf-8") ) ) 
	if bytes(secIdentity.u8SecIdentify).decode("utf-8") != "SECURITY":
		print( "[e] u8SecIdentify is not SECURITY at: "+ hex(offset) )
		exit(-1)
	# get the size from our secure identity
	size = secIdentity.info.u32Size + sizeof(SUB_SECURE_INFO)
	if (DEBUG):
		print ( "[i] size from secure header is:{}".format( hex(size) ) )


if size == 0:
		print( "[w] couldn't find bank size from the header, defaulting to "+ defSize)
		size = defSize

# Create out directory 
print ("[i] Create output directory")
utils.createDirectory(outFolder)

# Get the key bank section and store it
outEncKeyBankFile = os.path.join(outFolder, 'key_bank.bin')
print ("[i] Save mstar key bank to {}".format(outEncKeyBankFile))
utils.copyPart(mboot, outEncKeyBankFile, offset, size)

# Unpack the key bank to key bank structure
print ("[i] Unpack key bank structure")
keyBankBytes = utils.loadPart(outEncKeyBankFile, 0, size)
keyBank = utils.unpackStructure(CUSTOMER_KEY_BANK, keyBankBytes)
try:
	magicStr = bytes(keyBank.u8MagicID).decode('utf-8')
	if(magicStr != "Mstar.Key.Bank.."):
		raise(RuntimeError("oops, not Mstar.Key.Bank.."))
except:
	print ( "[w] u8MagicID is wrong. Check that this is actually the keybank")

if (DEBUG):
	# Print all
	print ( "[i] u8SecIdentify:\n{}".format( utils.hexString(keyBank.customer.u8SecIdentify) ) )
	print ( "[i] u32Num: 0x{:08x}".format( keyBank.customer.info.u32Num ) )
	print ( "[i] u32Size: 0x{:08x}".format( keyBank.customer.info.u32Size ) )
	print ( "[i] u8Signature:\n{}".format( utils.hexString(keyBank.customer.u8Signature) ) )

	print ( "[i] u8RSABootPublicKey N:\n{}".format( utils.hexString(keyBank.u8RSABootPublicKey.N) ) )
	print ( "[i] u8RSABootPublicKey E:\n{}".format( utils.hexString(keyBank.u8RSABootPublicKey.E) ) )
	print ( "[i] u8RSAUpgradePublicKey N:\n{}".format( utils.hexString(keyBank.u8RSAUpgradePublicKey.N) ) )
	print ( "[i] u8RSAUpgradePublicKey E:\n{}".format( utils.hexString(keyBank.u8RSAUpgradePublicKey.E) ) )
	print ( "[i] u8RSAImagePublicKey N:\n{}".format( utils.hexString(keyBank.u8RSAImagePublicKey.N) ) )
	print ( "[i] u8RSAImagePublicKey E:\n{}".format( utils.hexString(keyBank.u8RSAImagePublicKey.E) ) )
	print ( "[i] u8AESBootKey:\n{}".format( utils.hexString(keyBank.u8AESBootKey) ) )
	print ( "[i] u8AESUpgradeKey:\n{}".format( utils.hexString(keyBank.u8AESUpgradeKey) ) )

	print ( "[i] u8MagicID:\n{}".format( utils.hexString(keyBank.u8MagicID) ) )
	print ( "[i] CRC:\n{}".format( utils.hexString(keyBank.crc) ) )

# Save keys
print ("[i] Save keys")

# RSA Boot
utils.writeFile(os.path.join(outFolder, 'RSAboot_pub.bin'), keyBank.u8RSABootPublicKey)
utils.writeRSAPublicKey(os.path.join(outFolder, 'RSAboot_pub.txt'), keyBank.u8RSABootPublicKey)

# RSA Upgrade
utils.writeFile(os.path.join(outFolder, 'RSAupgrade_pub.bin'), keyBank.u8RSAUpgradePublicKey)
utils.writeRSAPublicKey(os.path.join(outFolder, 'RSAupgrade_pub.txt'), keyBank.u8RSAUpgradePublicKey)

# RSA Image
utils.writeFile(os.path.join(outFolder, 'RSAimage_pub.bin'), keyBank.u8RSAImagePublicKey)
utils.writeRSAPublicKey(os.path.join(outFolder, 'RSAimage_pub.txt'), keyBank.u8RSAImagePublicKey)

# AES
utils.writeFile(os.path.join(outFolder, 'AESBoot.bin'), keyBank.u8AESBootKey)
utils.writeFile(os.path.join(outFolder, 'AESUpgrade.bin'), keyBank.u8AESUpgradeKey)

print ("Done")