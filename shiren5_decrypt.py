INPUT = "romfs"
OUTPUT = "romfs.extract"
SAVEPATH = None # If set, writes the list of correctly extracted paths in that file

# The base buffer used for encryption
with open("buffer.bin", 'rb') as file:
    BUFFER = file.read()

# A list of all known paths for association (invalid/missing paths are ignored)
with open("path_input.txt", 'r') as file:
    PATH = [x for x in file.read().split("\n") if x]

# A list of all file paths that are exempt of encryption
with open("path_clear.txt", 'r') as file:
    CLEAR = [x for x in file.read().split("\n") if x]

import os
import hashlib

def decrypt(data, key):
    dec = bytearray(len(data))
    for i, b in enumerate(data):
        dec[i] = ((key)^BUFFER[((key&1)<<8)|b])&0xFF
        key = (key+3)&0xFF
    return dec
    
def hash_bkdr(s):                                                                                                                                
    csn = 0
    for x in s:
        csn = csn*0x83+ord(x.upper())
    return csn

HASHBITS = "NJIFCOPDMAELBKHG"
def hashkey(n):
    h = ((hash_bkdr(reversed(n))<<8)&0x7FFFFFFFFFFFFF00)|(len(n)&0xFF)
    so = ""
    for i in range(16):
        so += HASHBITS[h&0xF]
        h>>=4
    return so

def keytonumber(key):
    dc = 0xC
    for c in key:
        dc += HASHBITS.index(c)
    return dc&0x7F

okpath = []
keys = set(os.listdir(INPUT))
found = set()
for p in PATH:
    x = hashkey(p)
    if x in keys:
        print("Found path match '%s' -> '%s'"%(p, x))
        okpath.append(p)
        found.add(x)
        with open(INPUT+"/"+x, 'rb') as file:
            data = file.read()
        if p not in CLEAR:
            data = decrypt(data, keytonumber(x))
        px = OUTPUT+"/"+p
        os.makedirs(os.path.dirname(px), exist_ok=True)
        with open(px, 'wb') as file:
            file.write(data)
    else:
        print("Key not found for '%s'"%p)
print("~~~~~~~~~~~~~~~~~~")
for x in sorted(keys.difference(found)):
    print("Missing path equivalent for '%s'"%x)
    with open(INPUT+"/"+x, 'rb') as file:
        data = file.read()
    if x not in CLEAR:
        data = decrypt(data, keytonumber(x))
    px = OUTPUT+"/"+x
    os.makedirs(os.path.dirname(px), exist_ok=True)
    with open(px, 'wb') as file:
        file.write(data)
if SAVEPATH is not None:
    with open(SAVEPATH, 'w') as file:
        file.write("\n".join(sorted(okpath)))
