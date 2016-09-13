#!/usr/bin/env python

import fileinput
import re
import sys
import subprocess
import traceback
import uuid as _uuid

class BinaryImage:
    def __init__(self, lowAddr, hiAddr, name, uuid, path, arch='x86_64'):
        self.lowAddr = lowAddr
        self.hiAddr = hiAddr
        self.name = name
        self.uuid = uuid
        self.path = path
        self.arch = arch if arch != "x86-64" else "x86_64" # sigh
    
    def match(self, addr):
        return self.lowAddr <= addr and self.hiAddr >= addr
        
    def symbolicate(self, addresses):
        if not hasattr(self, 'dsymPath'):
            findArgs = ['/usr/bin/mdfind', 'com_apple_xcode_dsym_uuids == %s' % (str(_uuid.UUID(self.uuid)).upper())]
            try:
                findResult = subprocess.check_output(findArgs).split('\n')
                if len(findResult) >= 1 and len(findResult[0].strip()) > 0:
                    self.dsymPath = findResult[0] + "/Contents/Resources/DWARF/%s" % self.name
                else:
                    self.dsymPath = None
            except:
                self.dsymPath = None
    
        path = self.dsymPath if self.dsymPath is not None else self.path

        args =  ['/usr/bin/xcrun', 
                  'atos', 
                  '-o', path, 
                  '-arch', self.arch, 
                  '-l', ("0x%x"%self.lowAddr)]
        
        for addr in addresses:
            args.append("0x%x" % addr)
        
        result = subprocess.check_output(args)
        return result.split("\n")
    
    def __str__(self):
        return "0x%x - 0x%x %s <%s> %s %s" % (self.lowAddr, self.hiAddr, self.name, self.uuid, self.path, self.arch)

lines = []
for line in fileinput.input():
    lines.append(line)

def seek(pattern):
    i = 0
    for line in lines:
        i += 1
        if (re.match(pattern, line)):
            return i
    return None

# find architecture
loc = seek(r'Code Type:')
if not loc:
    sys.stderr.write("Cannot find architecture (Code Type:). Maybe this isn't a crash file?\n")
    sys.exit(1)
arch = re.match(r'Code Type:\s+([\w\d\_\-\.]+).*', lines[loc-1]).group(1).lower()
    
# find binary images section
loc = seek(r'Binary Images:')
if not loc:
    sys.stderr.write("Cannot find Binary Images:. Maybe this isn't a crash file?\n")
    sys.exit(1)        

imageRE = re.compile(r'\s*(0x[0-9a-f]+)\s*-\s*(0x[0-9a-f]+)\s*(.*?)\s*<([0-9A-Fa-f\-]+)>\s*(.*)\n')
images = []
for line in lines[loc:]:
    if len(line) == 0:
        break
    match = imageRE.match(line)
    if match:
        lowAddr = int(match.group(1), 16)
        hiAddr = int(match.group(2), 16)
        nameParts = match.group(3).split(" ")
        name = nameParts[0]
        imgArch = arch
        if len(nameParts) > 1 and not nameParts[1].startswith("("):
            imgArch = nameParts[1]
        uuid = match.group(4)
        path = match.group(5)
        image = BinaryImage(lowAddr, hiAddr, name, uuid, path, imgArch)
#        sys.stderr.write("Found image %s\n" % str(image))
        images.append(image)        
        
# loop over backtraces, find addresses to symbolicate

addrsByImage = {}
addrToSymbol = {}

btRE = re.compile(r'(\d+\s*[\w\d\-\_\.]+\s*)(0x[0-9a-f]+)\s(.*)\n')
for line in lines:
    match = btRE.match(line)
    if match:
        prefix = match.group(1)
        addr = int(match.group(2), 16)
        suffix = match.group(3)
        
        for image in images:
            symbolicated = None
            if image.match(addr):
                if image in addrsByImage:
                    addrsByImage[image].append(addr)
                else:
                    addrsByImage[image] = [addr]

for (image, addresses) in addrsByImage.items():
    try:
        symbols = image.symbolicate(addresses)
        i = 0
        for addr in addresses:
            addrToSymbol[addr] = symbols[i]
            i += 1
    except:
        sys.stderr.write("Cannot find symbols for %s\n" % image)

for line in lines:
    match = btRE.match(line)
    newLine = line
    if match:
        prefix = match.group(1)
        addr = int(match.group(2), 16)
        suffix = match.group(3)
        
        if addr in addrToSymbol:
            symbol = addrToSymbol[addr]
            newLine = "%s0x%x %s\n" % (prefix, addr, symbol)

    sys.stdout.write(newLine)

                                
    