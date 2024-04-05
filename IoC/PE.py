from abc import ABC
from IoC.Binary import Binary
from enum import Enum
import archinfo
import pefile
import subprocess
import logging
import re

__all__ = ["PE"]


class BitType(Enum):
    _ = 0
    x32 = 267
    x64 = 523
    rom = 263

class PE(Binary, ABC):
    logger = None

    def __init__(self, path, offset):
        PE.logger = logging.getLogger("IoCAnalysis." + __name__)
        super().__init__(path)
        self.offset = offset
        self.base_of_code = None
        self.image_base = None
        self.size_optional_header = None
        self.pe_header_addr = None
        self.hook_symbols = []
        self.regexp = ['(^|\s)(?:[0-9]{1,3}\.){3}[0-9]{1,3}($|\s)',  # Ipv4
               '(^|\s)\w+:{1}(\/+\/+)[^\s]+($|\s)',  # Uri
               "(^|\s)[a-zA-Z]:(\\\\(\w)+)+",  # win path
               '(^|\s)(HKEY_){1}\w+(\\\(\w)+)+($|\s)',  # win key reg
                '^[a-zA-Z,\s]+[.!?]?$' #frase
               ]
        self.analyze(path)

    def apply_regexp(self, string):
        found = False
        for r in self.regexp:
            m = re.search(r, string)
            if m is not None:
                return True
        return found
    def generate_tmp_no_offset(self):
        with open(self.path, 'rb') as f:
            f.seek(self.offset)
            binary_data = f.read()
            f.close()

            self.tmp_binary = './tmp/' + self.filename
            with open(self.tmp_binary, "wb") as tmp_binary_file:
                tmp_binary_file.write(binary_data)
            tmp_binary_file.close()
    def get_pe_sign(self):
        result = subprocess.run(["peid", self.tmp_binary], capture_output=True)
        return result.stdout.decode("UTF-8").replace('\n', ' ')

    def get_imphash(self):
        pe = pefile.PE(self.tmp_binary)
        self.imphash = pe.get_imphash().upper()

    def analyze(self, path):
        # sections_offset = []
        self.generate_tmp_no_offset()
        PE.logger.info('Recuperando la información de fichero PE')
        self.fileType = 'PE'
        self.endianess = 'little' #PE siempre es little endian
        with open(path, 'rb') as f:

            PE.logger.info("Offset: %i" % self.offset)

            #PEHeader
            f.seek(self.offset + 0x3c) # salto a la posicion que guarda la dirección donde comienza PE Header
            self.pe_header_addr = self.offset + int.from_bytes(f.read(4), "little")
            PE.logger.info("Dirección Inicio PE header: %s" %hex(self.pe_header_addr))

            #mMachine - ArchInfo
            f.seek(self.pe_header_addr + 4)
            mType = int.from_bytes(f.read(2), "little")
            self.machine = archinfo.arch_from_id(pefile.MACHINE_TYPE[mType])
            PE.logger.info('PE Header - machine %s [%s] ' % (hex(mType),self.machine))

            #Optional Header Size
            f.seek(self.pe_header_addr + 20)
            self.size_optional_header = int.from_bytes(f.read(2), "little")
            PE.logger.info("Tamaño de la cabecera opcional [%d]" % self.size_optional_header)

            #Optional header - Magic
            f.seek(self.pe_header_addr + 24)
            bitOption = int.from_bytes(f.read(2), "little")
            self.bits = BitType(bitOption).name
            PE.logger.info("Magic [%x] - %s bits" % (bitOption,self.bits))

            #Entry Point Address
            f.seek(self.pe_header_addr + 40)
            self.entry_point = int.from_bytes(f.read(4), "little")
            self.entry_point_hex = hex(self.entry_point)
            PE.logger.info("Entry point posición [%d] - dirección [%x]" % (self.entry_point, self.entry_point))

            #Base of Code
            self.base_of_code = int.from_bytes(f.read(4), "little")
            PE.logger.info("Base of code posición [%d] - dirección [%x]" % (self.base_of_code, self.base_of_code))

            #Base Address
            f.seek(self.pe_header_addr + 56)
            self.base_addr = int.from_bytes(f.read(4), "little")
            self.base_addr_hex = hex(self.base_addr)
            PE.logger.info("Base address posición [%d] - dirección [%x]" % (self.base_addr, self.base_addr))

            #Sections header
            f.seek(self.pe_header_addr + 24 + self.size_optional_header)
            offset_sections = self.pe_header_addr + 24 + self.size_optional_header
            b = f.read(1)
            offset_sections = offset_sections + 1
            while b == b"\x00":  # skip null bytes
                b = f.read(1)
                offset_sections = offset_sections + 1
            offset_sections = offset_sections - 1
            PE.logger.debug('Secciones posición [%d] - dirección [%x]' % (offset_sections, offset_sections) )
        f.close()
        self.get_strings()
        self.get_imphash()
        self.get_ssdeep_hash()
        self.get_tlsh_hash()
        self.hashfile()
        self.packInfo = self.get_pe_sign()

