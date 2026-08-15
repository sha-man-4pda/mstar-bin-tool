# unpack.py v1.5.1

import sys
import os
import re
import shutil
from pathlib import Path

import utils

DEBUG = False
HEADER_SIZE = 16 * utils.KB # Header size is always 16KB
HEADER_SIZE_MTK = 128 * utils.KB # MTK-Mstar script is 128RB
MTK_SCRIPT_OFFSET = 0x300; # Here Mstar script offset and FW size are stored
VARIABLE_OFFSET_NAME = "REE_OFFSET_START"
VARIABLE_LENGTH_NAME = "REE_OFFSET_LEN"
LZ4_MAGIC = b'\x02\x21\x4C\x18'
MSTAR_AES_KEY = b'\x00\x07\xFF\x41\x54\x53\x4D\x92\xFC\x55\xAA\x0F\xFF\x01\x10\xE0'
MSTAR_AES_IV = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

print ('mstar-bin-tool by dipcore fork by sha-man-4pda unpack.py v.1.5')

# Vars
headerScript = ""
headerScriptFound = False
counter = {}
env = {} # Environment variables, set by setenv command
encrypted_ecb = False
encrypted_cbc = False
compressed_block = False
warning_counter = 0
stored_CRC32 = 0

# Parse args
if len(sys.argv) == 1: 
    print ('Usage: unpack.py <firmware> <output folder [default: ./unpacked_<filename>/]>')
    quit()

inputFile = sys.argv[1]
if not os.path.exists(inputFile):
    print (f'No such file: {inputFile}')
    quit()

if len(sys.argv) == 3:
    outputDirectory = sys.argv[2]
else:
    outputDirectory = 'unpacked_' + Path(inputFile).stem

# Create output directory
utils.createDirectory(outputDirectory)

header_file = os.path.join(outputDirectory, "~header")
tempCompFile = os.path.join(outputDirectory, "~temp.comp")
tempDecompFile = os.path.join(outputDirectory, "~temp.decomp")

# Find header script
# Mstar header size is 16KB, non used part usually is filled with 0xFF
# MTK-Mstar header has different format and size, but uses similar script commands

# Looking for the script at the beginning of the file
print ("[i] Looking for Mstar header ...")
utils.copyPart(inputFile, header_file, 0, HEADER_SIZE_MTK)
headerScript = utils.is_mstar_script(inputFile, 0, HEADER_SIZE_MTK)
if headerScript is not None:
    print ('[i] Mstar script found')
    headerScriptFound = True
else:
    # Tryind to decrypt header with Mstar AESupgrade key and find the sript in decryped header
    if utils.aes_decrypt(header_file, header_file + '.bin', 'ecb', MSTAR_AES_KEY):
        headerScript = utils.is_mstar_script(header_file + '.bin', 0, HEADER_SIZE_MTK)
        if headerScript is not None:
            print ('[i] Encrypted Mstar script found')
            headerScriptFound = True
            encrypted_ecb = True
        else:
            os.remove(header_file + '.bin')

if not headerScriptFound :
    print ("[i] Failed.")
    print ("[i] Looking for MTK-Mstar header ...")
    # Trying to find script at another offset
    # Reading the MTK variables area at offset 0x300
    header = utils.loadPart(inputFile, MTK_SCRIPT_OFFSET, HEADER_SIZE)
    offset = utils.find_first_non_printable_index(header)
    if offset != -1 :
        mtk_script = header[:offset].decode()
        # Getting script offset from MTK variables
        offset = utils.get_variable_value(mtk_script, VARIABLE_OFFSET_NAME)
        length = utils.get_variable_value(mtk_script, VARIABLE_LENGTH_NAME)
        if offset is not None :
            # Looking for the script at the new position
            headerScript = utils.is_mstar_script(inputFile, offset, HEADER_SIZE_MTK)
            if headerScript is not None:
                print ('[i] MTK-Mstar script found')
                headerScriptFound = True
            else:
                # Trying to find script in decrypted header
                utils.copyPart(inputFile, header_file + '_mtk', offset, HEADER_SIZE_MTK)
                if utils.aes_decrypt(header_file + '_mtk', header_file + '_mtk.bin', 'cbc', MSTAR_AES_KEY, MSTAR_AES_IV):
                    headerScript = utils.is_mstar_script(header_file + '_mtk.bin', 0, HEADER_SIZE_MTK)
                    if headerScript is not None:
                        print ("[i] Encrypted MTK-Mstar script found")
                        headerScriptFound = True
                        encrypted_cbc = True
                        os.remove(header_file + '_mtk')
                    else:
                        os.remove(header_file + '_mtk')
                        os.remove(header_file + '_mtk.bin')

if not headerScriptFound:
    print ('[i] Failed.')
    print ('[ERROR] Could not find header script!')
    quit()

# Save the script
print ("[i] Saving header script to " + os.path.join(outputDirectory, "~header_script.sh"))
with open(os.path.join(outputDirectory, "~header_script.sh"), "w") as f:
    f.write(headerScript)

if DEBUG:
    print (headerScript)
#   quit()    

if encrypted_ecb :
    # Decrypting data
    print ('[i] Decrypting data, please wait...')
    utils.aes_decrypt(inputFile, inputFile + '.dec', 'ecb', MSTAR_AES_KEY, MSTAR_AES_IV)
    print (f'[i] Decrypted data saved in {inputFile}.dec file.')
    inputFile += '.dec'

if encrypted_cbc :
    # Decrypting data
    print ('[i] Decrypting data, please wait...')
    utils.copyPart(inputFile, '~data.aes', offset, length)
    utils.aes_decrypt('~data.aes', '~data.dec', 'cbc', MSTAR_AES_KEY, MSTAR_AES_IV)
    utils.copyPart(inputFile, inputFile + '.dec', 0, offset)
    utils.copyPart('~data.dec', inputFile + '.dec', 0, length, append = True)
    utils.copyPart(inputFile, inputFile + '.dec', offset + length, os.path.getsize(inputFile) - (offset + length), append = True)
    print (f'[i] Decrypted data saved in {inputFile}.dec file.')
    os.remove('~data.aes')
    os.remove('~data.dec')
    inputFile += '.dec'

# Parse script
print ("[i] Parsing script ...")
sparseList = list()
# Supporting filepartload, mmc, store_secure_info, store_nuttx_config
for line in headerScript.splitlines():

    if DEBUG:
        print (line)

    if re.match("^setenv", line):
        params = utils.processSetEnv(line)
        key = params["key"]     
        if not "value" in params:
            del env[key]
        else:
            value = params["value"]
            env[key] = value
            print (f'[i]     Parsing setenv {key} -> {value}')

    if re.match("^filepartload", line):
        line = utils.applyEnv(line, env)
        params = utils.processFilePartLoad(line)
        offset =  params["offset"]
        size =  params["size"]
        compressed_block = False

    if re.match("^store_secure_info", line):
        line = utils.applyEnv(line, env)        
        params = utils.processStoreSecureInfo(line)
        outputFile = os.path.join(outputDirectory, params["partition_name"] + '.bin')
        utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))
        print (f'[i] Secure info: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')

    if re.match("^store_nuttx_config", line):
        line = utils.applyEnv(line, env)
        params = utils.processStoreNuttxConfig(line)
        outputFile = os.path.join(outputDirectory, params["partition_name"] + '.bin')
        utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))
        print (f'[i] Nuttx config: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')

    if re.match("^multi2optee", line):
        line = utils.applyEnv(line, env)
        params = utils.processMulti2optee(line)
        outputFile = os.path.join(outputDirectory, params["partition_name"] + ".bin")
        utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))
        print (f'[i] Partition: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')

    if re.match('^lz4', line):
        if os.path.exists(tempDecompFile):
            os.remove(tempDecompFile)          
        params = utils.processLZ4(line)
        # save .comp
        print (f'[i]     LZ4 compressed block. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to temporary file')
        lz4_header = LZ4_MAGIC + int(params['in_size'], 16).to_bytes(4, byteorder='little')
        utils.writeFile(tempCompFile, lz4_header);
        lz4_buffer = utils.loadPart(inputFile, int(offset, 16), int(size, 16))
        utils.appendData(lz4_buffer, tempCompFile)
        # unpack .comp -> .decomp
        print ('[i]         Decompressing LZ4 (Please be patient)...')
        utils.unlz4(tempCompFile, tempDecompFile)
        real_size = os.path.getsize(tempDecompFile)
        print (f'[i]         Done. Decompressed size: {hex(real_size)} ({utils.sizeStr(real_size)})')
        if (real_size != int(params['out_size'],16)):
            print('[WARNING] Size mismatch of decompressed file. Possible data corruption.')
            warning_counter += 1
        size = params['out_size']
        # delete .comp
        os.remove(tempCompFile)
        compressed_block = True

        #mscompress7 is LZMA with two bytes 0xBEEF appended to the end of the file
    if re.match("^mscompress7", line):
        if os.path.exists(tempDecompFile):
            os.remove(tempDecompFile)          
        params = utils.processMscompress7(line)
        # save .comp
        print (f'[i]     LZMA compressed block. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to temporary file')
        utils.copyPart(inputFile, tempCompFile, int(offset, 16), int(size, 16) - 2)
        # unpack .comp -> .decomp
        print ('[i]         Decompressing LZMA (Please be patient)...')
        utils.unlzma(tempCompFile, tempDecompFile)
        real_size = os.path.getsize(tempDecompFile)
        calculated_CRC32 = utils.crc32(tempDecompFile)
        print (f'[i]         Done. Decompressed size: {hex(real_size)} ({utils.sizeStr(real_size)}). Calculated CRC-32: {hex(calculated_CRC32)}')
        size = hex(real_size)
        # delete .comp
        os.remove(tempCompFile)
        compressed_block = True

        #mw - memory write (fill)
        #   Usage:
        #   mw [.b, .w, .l] address value [count]
    if re.match('^mw', line):
        params = utils.processMw(line)
        if (int(params['count'], 16) == 4) :
            # Assume it is CRC-32
            stored_CRC32 = int(params['value'], 16)
            if (stored_CRC32 == calculated_CRC32):
                print(f'[i]         Stored CRC-32: {hex(stored_CRC32)}. OK')
            else :
                print(f'[WARNING] CRC-32 mismatch. Stored CRC-32: {hex(stored_CRC32)}, calculated CRC-32: {hex(calculated_CRC32)}.')
                warning_counter += 1
        else :
            if (int(params['value'], 16) == 0) :
                #Write file of desired size filled with zeros
                block_size = int(params['count'], 16)
                with open(tempDecompFile, 'wb') as f:
                    f.seek(block_size - 1)  
                    f.write(b'\x00') 
                print(f'[i]         Filling block with zeros. \t\tSize: {hex(block_size)} ({utils.sizeStr(block_size)})')
                compressed_block = True

    if re.match("^sparse_write", line):
        line = utils.applyEnv(line, env)
        params = utils.processSparseWrite(line)
        outputFile = utils.generateFileNameSparse(outputDirectory, params)
        if not params["partition_name"] in sparseList:
            sparseList.append(params["partition_name"]) 
            print (f'[i] Partition: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')
        else :
            print (f'[i]     Continue with: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')
        if compressed_block:
            utils.copyPart(tempDecompFile, outputFile, 0 , os.path.getsize(tempDecompFile))
        else:
            utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))

    if re.match("^mmc", line):
        line = utils.applyEnv(line, env)
        params = utils.processMmc(line)

        if params:

            # if params["action"] == "create":
            #   nothing here

            if params["action"] == "write.boot":
                outputFile = utils.generateFileName(outputDirectory, params, ".img")
                if compressed_block :
                    utils.copyPart(tempDecompFile, outputFile, 0 , os.path.getsize(tempDecompFile))
                    print (f'[i] Partition: {params["partition_name"]}. \tWriting {size} bytes ({utils.sizeStr(int(size, 16))}) to {outputFile}')
                else:                    
                    utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))
                    print (f'[i] Partition: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')

            if params["action"] == "write.p":
                outputFile = os.path.join(outputDirectory, params["partition_name"] + ".img")
                if compressed_block :
                    utils.copyPart(tempDecompFile, outputFile, 0 , os.path.getsize(tempDecompFile))
                    print (f'[i] Partition: {params["partition_name"]}. \tWriting {size} bytes ({utils.sizeStr(int(size, 16))}) to {outputFile}')
                else:
                    utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16))
                    print (f'[i] Partition: {params["partition_name"]}. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to {outputFile}')

            if params["action"] == "write.p.continue":
                outputFile = os.path.join(outputDirectory, params["partition_name"] + ".img")   
                if compressed_block :
                    utils.appendFile(tempDecompFile, outputFile)
                else: 
                    utils.copyPart(inputFile, outputFile, int(offset, 16), int(size, 16), append = True)
                print (f'[i]     Continue with: {params["partition_name"]}. \tAppending {size} bytes ({utils.sizeStr(int(size, 16))}) to {outputFile}')

            if params["action"] == "unlzo":
                if os.path.exists(tempDecompFile):
                    os.remove(tempDecompFile)                 
                outputFile = os.path.join(outputDirectory, params["partition_name"] + ".img")
                # save .comp
                print (f'[i]     LZO compressed block. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to temporary file')
                utils.copyPart(inputFile, tempCompFile, int(offset, 16), int(size, 16))
                # unpack .comp -> .decomp
                print ('[i]         Decompressing LZO (Please be patient)...')
                if not utils.unlzo(tempCompFile, tempDecompFile):
                    print ('[ERROR] Decompression failed')
                    quit()
                size = hex(os.path.getsize(tempDecompFile))
                print (f'[i]         Done. Decompressed size: {size} ({utils.sizeStr(int(size, 16))}).') 
                # rename .decomp to .img
                if not utils.renameFile(tempDecompFile, outputFile):
                    print(f'[ERROR] Cannot rename {tempDecompFile} to {outputFile}.')
                    quit()
                print (f'[i] Partition: {params["partition_name"]}. \tWriting {size} bytes ({utils.sizeStr(int(size, 16))}) to {outputFile}')
                # delete .comp
                os.remove(tempCompFile)

            if (params["action"] == "unlzo.continue") :
                if os.path.exists(tempDecompFile):
                    os.remove(tempDecompFile) 
                outputFile = os.path.join(outputDirectory, params["partition_name"] + ".img")
                # save .comp
                print (f'[i]     LZO compressed block. \tCopying {size} bytes ({utils.sizeStr(int(size, 16))}) from offset {offset} to temporary file')
                utils.copyPart(inputFile, tempCompFile, int(offset, 16), int(size, 16))
                # unpack .comp -> .decomp
                print ('[i]         Decompressing LZO (Please be patient)...')
                if not utils.unlzo(tempCompFile, tempDecompFile):
                    print ('[ERROR] Decompression failed')
                    quit()
                size = hex(os.path.getsize(tempDecompFile))
                print (f'[i]         Done. Decompressed size: {size} ({utils.sizeStr(int(size, 16))}).') 
                # append .decomp to .img
                utils.appendFile(tempDecompFile, outputFile)
                print (f'[i]     Continue with: {params["partition_name"]}. \tAppending {size} bytes ({utils.sizeStr(int(size, 16))}) to {outputFile}')
                # delete .comp & .decomp
                os.remove(tempCompFile)

if os.path.exists(tempDecompFile):
    os.remove(tempDecompFile)                

for partName in sparseList:
    print (f'[i] Sparse: converting {partName}_sparse.* to {partName}.img. Please wait...')
    sparseFiles = os.path.join(outputDirectory, partName + '_sparse.*')
    sparseFiles = sparseFiles.replace("\\", "/")
    outputImgFile = os.path.join(outputDirectory, partName + ".img")
    utils.sparse_to_img(sparseFiles, outputImgFile)
    utils.sparse_delete(sparseFiles)
    print ('[i] Done')

if warning_counter != 0 :
    print (f'[i] Finished with {warning_counter} warnings.')
else:
    print ('[i] Finished.')
