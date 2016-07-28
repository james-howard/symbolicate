#!/usr/bin/env python

import fileinput
import re
import sys
import subprocess

class BinaryImage:
    def __init__(self, lowAddr, hiAddr, name, uuid, path, arch='x86_64'):
        self.lowAddr = lowAddr
        self.hiAddr = hiAddr
        self.name = name
        self.uuid = uuid
        self.path = path
        self.arch = arch
    
    def match(self, addr):
        return self.lowAddr <= addr and self.hiAddr >= addr
        
    def symbolicate(self, addresses):
        args =  ['/usr/bin/xcrun', 
                  'atos', 
                  '-o', self.path, 
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
    
    
# find binary images section
loc = seek(r'Binary Images:')
if not loc:
    sys.stderr.write("Cannot find Binary Images:. Maybe this isn't a crash file?\n")
    sys.exit(1)        

imageRE = re.compile(r'\s*(0x[0-9a-f]+)\s*-\s*(0x[0-9a-f]+)\s*(.*?)\s*<([0-9A-F\-]+)>\s*(.*)\n')
images = []
for line in lines[loc:]:
    if len(line) == 0:
        break
    match = imageRE.match(line)
    if match:
        lowAddr = int(match.group(1), 16)
        hiAddr = int(match.group(2), 16)
        name = match.group(3)
        uuid = match.group(4)
        path = match.group(5)
        image = BinaryImage(lowAddr, hiAddr, name, uuid, path)
#        sys.stderr.write("Found image %s\n" % str(image))
        images.append(image)        
        
# loop over backtraces, find addresses to symbolicate

addrsByImage = {}
addrToSymbol = {}

btRE = re.compile(r'(\d+\s*[\w\.]+\s*)(0x[0-9a-f]+)\s(.*)\n')
for line in lines:
    match = btRE.match(line)
    if match:
        prefix = match.group(1)
        addr = int(match.group(2), 16)
        suffix = match.group(3)
        
        for image in images:
            symbolicated = None
            if image.match(addr):
                if addrsByImage.has_key(image):
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
        
        if addrToSymbol.has_key(addr):
            symbol = addrToSymbol[addr]
            newLine = "%s0x%x %s\n" % (prefix, addr, symbol)
    
    sys.stdout.write(newLine)

                                
    