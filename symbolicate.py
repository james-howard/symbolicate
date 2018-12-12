#!/usr/bin/env python

import fileinput
import re
import sys
import subprocess
import os.path
import uuid as _uuid

class BinaryImage:
    def __init__(self, lowAddr, hiAddr, identifier, uuid, path, arch='x86_64'):
        self.lowAddr = lowAddr
        self.hiAddr = hiAddr
        self.identifier = identifier
        self.name = os.path.basename(path)
        self.uuid = uuid
        self.path = path
        self.arch = arch if arch != "x86-64" else "x86_64" # sigh
    
    def match(self, addr):
        return self.lowAddr <= addr and self.hiAddr >= addr

    def findDsym(self):
        if not hasattr(self, 'dsymPath'):
            self.dsymPath = None
            upperUUID = str(_uuid.UUID(self.uuid)).upper()
            findArgs = ['/usr/bin/mdfind', 'com_apple_xcode_dsym_uuids == %s' % upperUUID]
            try:
                findResult = subprocess.check_output(findArgs).split('\n')
                if len(findResult) >= 1 and len(findResult[0].strip()) > 0:
                    self.dsymPath = findResult[0] + "/Contents/Resources/DWARF/%s" % self.name
            except:
                pass
            if not self.dsymPath:
                # Keep looking. Spotlight may not have indexed this dsym, but it's out there somewhere ...
                findArgs = ['/usr/bin/mdfind', 'kMDItemFSName == %s.dSYM' % self.name]
                try:
                    findResults = subprocess.check_output(findArgs).split('\n')
                    for path in findResults:
                        filePath = path.strip() + "/Contents/Resources/DWARF/%s" % self.name
                        if len(path) > 0 and os.path.exists(filePath):
                            dwarfArgs = ['/usr/bin/dwarfdump', '-u', path]
                            try:
                                dwarfResults = subprocess.check_output(dwarfArgs).split('\n')
                                for result in dwarfResults:
                                    if result.startswith('UUID: %s' % upperUUID):
                                        self.dsymPath = filePath
                                        return
                            except:
                                pass
                except:
                    pass
        
    def symbolicate(self, addresses):
        self.findDsym()
    
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


class BacktraceLine:
    @staticmethod
    def match(line):
        types = [CrashLine, SampleLine]
        for type in types:
            obj = type.match(line)
            if obj:
                return obj
        return None

    def __init__(self, line, addr):
        self.original_line = line
        self.addr = addr

    def rewrite(self, symbol):
        pass


class CrashLine (BacktraceLine):
    btRE = re.compile(r'(\d+\s*[\w\d\-\_\.]+\s*)(0x[0-9a-f]+)\s(.*)\n')

    @staticmethod
    def match(line):
        if len(line) == 0:
            return None
        match = CrashLine.btRE.match(line)
        return CrashLine(line, match) if match else None

    def __init__(self, line, match):
        BacktraceLine.__init__(self, line, int(match.group(2), 16))
        self.match = match

    def rewrite(self, symbol):
        prefix = self.match.group(1)
        addr = self.addr
        suffix = self.match.group(3)
        newLine = "%s0x%x %s\n" % (prefix, addr, symbol)
        return newLine


class SampleLine (BacktraceLine):
    #     + !   :   |   + ! : |     + !   : | +   !   : | + 3 ???  (in Ship)  load address 0x1073ea000 + 0x65601  [0x10744f601]
    sampleRE = re.compile(r'([\s+|:!]*)(\d+)\s*\?\?\?.*?\[0x([A-Fa-f0-9]+)\]')

    @staticmethod
    def match(line):
        if len(line) == 0:
            return None
        match = SampleLine.sampleRE.match(line)
        return SampleLine(line, match) if match else None

    def __init__(self, line, match):
        addr = int(match.group(3), 16)
        BacktraceLine.__init__(self, line, addr)
        self.prefix = match.group(1)
        self.sample_count = match.group(2)

    def rewrite(self, symbol):
        return "%s%s %s\n" % (self.prefix, self.sample_count, symbol)


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
        identifierParts = match.group(3).split(" ")
        identifier = identifierParts[0]
        imgArch = arch
        if len(identifierParts) > 1 and not identifierParts[1].startswith("("):
            imgArch = identifierParts[1]
        uuid = match.group(4)
        path = match.group(5)
        image = BinaryImage(lowAddr, hiAddr, identifier, uuid, path, imgArch)
#        sys.stderr.write("Found image %s\n" % str(image))
        images.append(image)        
        
# loop over backtraces, find addresses to symbolicate

addrsByImage = {}
addrToSymbol = {}

for line in lines:
    match = BacktraceLine.match(line)
    if match:
        for image in images:
            symbolicated = None
            if image.match(match.addr):
                if image in addrsByImage:
                    addrsByImage[image].add(match.addr)
                else:
                    addrsByImage[image] = set([match.addr])

for (image, addresses) in addrsByImage.items():
    try:
        symbols = image.symbolicate(addresses)
        i = 0
        for addr in addresses:
            addrToSymbol[addr] = symbols[i]
            i += 1
    except:
        sys.stderr.write("Cannot find symbols for %s: %s\n" % (image, sys.exc_type))

for line in lines:
    match = BacktraceLine.match(line)
    newLine = line
    if match:
        if match.addr in addrToSymbol:
            symbol = addrToSymbol[match.addr]
            newLine = match.rewrite(symbol)

    sys.stdout.write(newLine)

