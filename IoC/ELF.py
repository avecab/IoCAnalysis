from abc import ABC
from IoC.Binary import Binary
from enum import Enum
from jinja2 import *
import xhtml2pdf.pisa as pisa
import subprocess
import logging
import re

__all__ = ["ELF"]


class BitType(Enum):
    invalid = 0
    x32 = 1
    x64 = 2


class MachineType(Enum):
    NO_MACHINE = 0
    ATAndT_WE_32100 = 1
    SPARC = 2
    INTEL_80386 = 3
    MOTOROLA_68000 = 4
    MOTOROLA_88000 = 5
    RESERVED_FOR_FUTURE_USE_WAS_EM_486 = 6
    INTEL_80860 = 7
    MIPS_I_ARCHITECTURE = 8
    IBM_SYSTEM_370_PROCESSOR = 9
    MIPS_RS3000_LITTLE_ENDIAN = 10
    HEWLETT_PACKARD_PA_RISC = 15
    RESERVED_FOR_FUTURE_USE = 16
    FUJITSU_VPP500 = 17
    ENHANCED_INSTRUCTION_SET_SPARC = 18
    INTEL_80960 = 19
    POWERPC = 20
    _64_BIT_POWERPC = 21
    IBM_SYSTEM_390_PROCESSOR = 22
    NEC_V800 = 36
    FUJITSU_FR20 = 37
    TRW_RH_32 = 38
    MOTOROLA_RCE = 39
    ADVANCED_RISC_MACHINES_ARM = 40
    DIGITAL_ALPHA = 41
    HITACHI_SH = 42
    SPARC_VERSION_9 = 43
    SIEMENS_TRICORE_EMBEDDED_PROCESSOR = 44
    ARGONAUT_RISC_CORE_ARGONAUT_TECHNOLOGIES_INC = 45
    HITACHI_H8_300 = 46
    HITACHI_H8_300H = 47
    HITACHI_H8S = 48
    HITACHI_H8_500 = 49
    INTEL_IA_64_PROCESSOR_ARCHITECTURE = 50
    STANFORD_MIPS_X = 51
    MOTOROLA_COLDFIRE = 52
    MOTOROLA_M68HC12 = 53
    FUJITSU_MMA_MULTIMEDIA_ACCELERATOR = 54
    SIEMENS_PCP = 55
    SONY_NCPU_EMBEDDED_RISC_PROCESSOR = 56
    DENSO_NDR1_MICROPROCESSOR = 57
    MOTOROLA_STAR_CORE_PROCESSOR = 58
    TOYOTA_ME16_PROCESSOR = 59
    STMICROELECTRONICS_ST100_PROCESSOR = 60
    ADVANCED_LOGIC_CORP_TINYJ_EMBEDDED_PROCESSOR_FAMILY = 61
    AMD_X86_64_ARCHITECTURE = 62
    SONY_DSP_PROCESSOR = 63
    DIGITAL_EQUIPMENT_CORP_PDP_10 = 64
    DIGITAL_EQUIPMENT_CORP_PDP_11 = 65
    SIEMENS_FX66_MICROCONTROLLER = 66
    STMICROELECTRONICS_ST9_8_16_BIT_MICROCONTROLLER = 67
    STMICROELECTRONICS_ST7_8_BIT_MICROCONTROLLER = 68
    MOTOROLA_MC68HC16_MICROCONTROLLER = 69
    MOTOROLA_MC68HC11_MICROCONTROLLER = 70
    MOTOROLA_MC68HC08_MICROCONTROLLER = 71
    MOTOROLA_MC68HC05_MICROCONTROLLER = 72
    SILICON_GRAPHICS_SVX = 73
    STMICROELECTRONICS_ST19_8_BIT_MICROCONTROLLER = 74
    DIGITAL_VAX = 75
    AXIS_COMMUNICATIONS_32_BIT_EMBEDDED_PROCESSOR = 76
    INFINEON_TECHNOLOGIES_32_BIT_EMBEDDED_PROCESSOR = 77
    ELEMENT_14_64_BIT_DSP_PROCESSOR = 78
    LSI_LOGIC_16_BIT_DSP_PROCESSOR = 79
    DONALD_KNUTHS_EDUCATIONAL_64_BIT_PROCESSOR = 80
    HARVARD_UNIVERSITY_MACHINE_INDEPENDENT_OBJECT_FILES = 81
    SITERA_PRISM = 82
    ATMEL_AVR_8_BIT_MICROCONTROLLER = 83
    FUJITSU_FR30 = 84
    MITSUBISHI_D10V = 85
    MITSUBISHI_D30V = 86
    NEC_V850 = 87
    MITSUBISHI_M32R = 88
    MATSUSHITA_MN10300 = 89
    MATSUSHITA_MN10200 = 90
    PICOJAVA = 91
    OPENRISC_32_BIT_EMBEDDED_PROCESSOR = 92
    ARC_CORES_TANGENT_A5 = 93
    TENSILICA_XTENSA_ARCHITECTURE = 94
    ALPHAMOSAIC_VIDEOCORE_PROCESSOR = 95
    THOMPSON_MULTIMEDIA_GENERAL_PURPOSE_PROCESSOR = 96
    NATIONAL_SEMICONDUCTOR_32000_SERIES = 97
    TENOR_NETWORK_TPC_PROCESSOR = 98
    TREBIA_SNP_1000_PROCESSOR = 99
    STMICROELECTRONICS__ST200_MICROCONTROLLER = 100


class ELF(Binary, ABC):
    logger = None

    def __init__(self, path, offset):
        ELF.logger = logging.getLogger("IoCAnalysis." + __name__)
        super().__init__(path)
        self.offset = offset
        self.hook_symbols = []
        self.regexp = ['(^|\s)(?:[0-9]{1,3}\.){3}[0-9]{1,3}($|\s)',  # Ipv4
                       '(^|\s)\w+:{1}(\/+\/+)[^\s]+($|\s)',  # Uri
                       '(^|\s)(\/(\w)+)+($|\s)', # unix path
                       '^[a-zA-Z,\s]+[.!?]?$'
                       ]
        self.analyze(path)

    def apply_regexp(self, string):
        found = False
        for r in self.regexp:
            m = re.search(r, string)
            if m is not None:
                return True
        return found

    def analyze(self, path):
        ELF.logger.info('Recuperando la información de fichero ELF')
        self.fileType = 'ELF'
        with open(path, 'rb') as f:
            ELF.logger.info("Offset: %i" % self.offset)

            # EI_CLASS: 0 - invalida, 1 - 32bits , 2 - 64bits
            f.seek(self.offset + 0x4)
            self.bitFormat = int.from_bytes(f.read(1), "little")
            self.bits = BitType(self.bitFormat).name

            #EI_DATA: 0 - invalid, 1 - little-endian, 2 - big endian
            self.endianess =  int.from_bytes(f.read(1), "little")
            if self.endianess == 1:
                self.endianess = 'little'
            else:
                self.endianess = 'big'
            f.seek(self.offset + 0x12)

            #Machine
            mType = int.from_bytes(f.read(2), self.endianess)
            self.machine = MachineType(mType).name
            ELF.logger.info('Machine %s [%s] ' % (hex(mType), self.machine))

            #Entry Point
            f.seek(self.offset + 0x18)

            entry_point_field_length = 4
            if self.bitFormat == 2:
                entry_point_field_length = 8
            self.entry_point = int.from_bytes(f.read(entry_point_field_length), self.endianess)
            self.entry_point_hex = hex(self.entry_point)
            ELF.logger.info("Entry point posición [%d] - dirección [%s]" % (self.entry_point, hex(self.entry_point)))

            self.get_strings()
            self.get_ssdeep_hash()
            self.get_tlsh_hash()
            self.hashfile()

