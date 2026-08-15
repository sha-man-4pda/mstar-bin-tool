# mstar-bin-tool

Command line tools to pack/unpack MStar bin firmware

Currently available tools:
 - **unpack.py** - unpack MStar bin firmware
 - **pack.py** - pack MStar bin firmware
 - **extract_keys.py** - extract AES and RSA-public keys from MBOOT binary
 - **secure_partition.py** - encrypt image and generate signature file (Windows only)
 - **secure_partition_v2.py** - same as latter but works on any OS with Python3 and OpenSSL installed
  
## Installing on Windows

On Windows you just need to have Python3  and OpenSSL installed

## Installing on Linux

On Linux you need to have python3, openssl and lzop installed and some binaries in bin/linux folder.

There are binaries compiled for Ubuntu 25.04 x64 in bin/linux folder. 
You may need to replace them with the ones compiled for your system.

- tinyZZZ - compressor/decompressor for different formats, to decompress LZ4 and LZMA.
	$git clone https://github.com/WangXuan95/TinyZZZ.git
	$cd TinyZZZ
	$gcc src/*.c -O2 -std=c99 -Wall -o tinyZZZ
	Replace tinyZZZ binary file in mstar-bin-tool/bin/linux folder with the compiled one.
	
- android-simg2img - utilities to work with SPARSE file format.
	$git clone https://github.com/anestisb/android-simg2img.git
	$cd android-simg2img
	$make
	Replace simg2img, img2simg, simg2simg binaries in mstar-bin-tool/bin/linux folder.
	
## Unpack MStar bin firmware files

```
Usage: unpack.py <firmware> <output folder [default: ./unpacked/]>
        <firmware> - MStar bin firmware to unpack
        <output folder> - directory to store unpacked stuff. Default value: ./unpacked/
```


## Pack MStar bin firmware 

```
Usage: pack.py <config file>
Example: pack.py configs/letv-x355pro-full.ini
		<config file> - Configuration file. The config file structure will be described later.
                        For now you can take a look at configs/letv-x355pro-full.ini
                        and use it as an example
```


## Extract keys from MBOOT
That tool is used to get AES and public RSA keys from the MBOOT. AES keys are needed to encrypt/decrypt 
boot.img and recovery.img images. aescrypt2 tool is used.

```
Usage: extract_keys.py <path to mboot> [<folder to store keys>] [<key bank offset>] [<key bank size>]
Defaults:
          <folder to store keys>        keys
          <key bank offset>             0x168e00
          <key bank size>               0x450
Example: extract_keys.py ./unpacked/MBOOT.img
Example: extract_keys.py ./unpacked/MBOOT.img ./keys 0x169e00 0x450
```

## Encrypt/Decrypt partition
You can encrypt/decrypt partition with using *aescrypt2.exe* tool, which is located in bin/win32 folder

Default mstar key is *hex:0007FF4154534D92FC55AA0FFF0110E0* All mstar default keys are in default_keys folder. (These keys are in public access in github)

Last parameter can be hex value or path to AES key. If your vendor is using custom aes keys you can use extract_keys.py to extract them.

To encrypt image use:
```
aescrypt2 0 boot.img boot.img.aes hex:0007FF4154534D92FC55AA0FFF0110E0
or
aescrypt2 0 boot.img boot.img.aes keys/AESBootKey
```

So to decrypt image use:
```
aescrypt2 1 boot.img.aes boot.img hex:0007FF4154534D92FC55AA0FFF0110E0
or
aescrypt2 1 boot.img boot.img.aes keys/AESBootKey
```

Alternatively you can encrypt/decrypt files using OpenSSL:
```
openssl aes-128-ecb -nopad -e  -K 0007FF4154534D92FC55AA0FFF0110E0 -in <in_file> -out <out_file> - encrypt
openssl aes-128-ecb -nopad -d  -K 0007FF4154534D92FC55AA0FFF0110E0 -in <in_file> -out <out_file> - decrypt

``` 

## Encrypt partition and generate signature
All new MStar builds have SECURE_BOOT option enabled. In that case 
boot.img and recovery.img is encrypted (AES) and signed with RSA priv keys.
That script is used to encrypt image and generate sign file. 
Works only on Windows because uses external utilities and the only known versions are Windows executables.

```
Usage: secure_partition.py <file to encrypt> <AES key file> <RSA private key file> <RSA public key file> <output encrypted file> <output signature file>
Example: secure_partition.py ./pack/boot.img ./keys/AESbootKey ./keys/RSAboot_priv.txt ./keys/RSAboot_pub.txt ./pack/boot.img.aes ./pack/bootSign
```

New script added - `secure_partition_v2.py`
It does the same job but doesn't depend on external utilities, uses only OpenSSL functions and therefore can be used on Linux as well.
Run the script with `-h` argument to see usage info.

## Extract keys from Mstar.Key.Bank structure
AES keys can be extracted from MBOOT with extract_keys.py script. 
In many cases you need to locate the offset of Mstar.Key.Bank first. 
Read the instructions inside `extract_keys.py` file.
