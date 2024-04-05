import os
import json
from enum import Enum
from jinja2 import *
import xhtml2pdf.pisa as pisa
import ppdeep
import tlsh
import logging
import subprocess
from abc import ABC, abstractproperty, abstractmethod
from cryptography.hazmat.primitives.hashes import Hash, MD5, SHA1, SHA256
from cryptography.hazmat.backends import default_backend

__all__ = ["Binary"]


class BitType(Enum):
    x32 = 267
    x64 = 523
    rom = 263


class Binary:
    logger = None

    def __init__(self, path):
        Binary.logger = logging.getLogger("IoCAnalysis." + __name__)
        Binary.logger.info('Cargando Binario')
        self.path = path
        self.filename = path.split(os.sep)[-1]
        self.offset = 0
        self.fileType = None
        self.endianess = None
        self.packInfo = []
        self.sections = []
        self.base_addr = 0
        self.base_addr_hex = 0
        self.entry_point = None
        self.entry_point_hex = None
        self.number_of_sections = None
        self.machine = None
        self.bits = None
        self.strings = []
        self.symbols = []
        self.functions = []
        self.tmp_binary = None
        self.cfg_type = None
        self.imphash  = None
        self.ssdeep_hash = None
        self.tlsh_hash = None
        self.cfg_img = None
        self.process={}

    @abstractmethod
    def get_sections(self, project):
        Binary.logger.info('Obteniendo secciones/segmentos del binario')
        for section in project.loader.main_object.sections:
            Binary.logger.info('            [ %s ] @ [%s]' % (section.name,hex(section.vaddr)))
            self.sections.append({"name":section.name,"addr":hex(section.vaddr)})
        self.number_of_sections = len(project.loader.main_object.sections)

    @abstractmethod
    def get_symbols(self, project):
        Binary.logger.info('Obteniendo simbolos del binario')
        for symbol in project.loader.symbols:
            if symbol.name not in self.symbols:
                Binary.logger.info('          [ %s ]' % symbol.name)
                self.symbols.append({"name":symbol.name,"addr":hex(symbol.relative_addr),"type":symbol._type})

    @abstractmethod
    def get_functions(self, project):
        Binary.logger.info('Obteniendo funciones del binario')
        for funcInfo in project.kb.functions.keys():
            func = project.kb.functions[funcInfo]
            Binary.logger.info('         [ %s ] @ [ %s ] ' % (func.name,hex(func.addr)))
            code_bloc = []
            hash_ssdeep = ''
            if not func.is_simprocedure:
                for block in func.blocks:
                    try:
                        instructions = block.capstone.insns
                        for insn in instructions:
                            code_bloc.append("%s\t%s" % (insn.mnemonic, insn.op_str))
                    except:
                        Binary.logger.error("Error cargando bloque. Skip bloque de funcion %s" % func.name)
                if len(code_bloc) >0:
                    discode = '\n'.join(code_bloc)
                    hash_ssdeep = ppdeep.hash(discode)
            self.functions.append({"name":func.name,"addr":hex(func.addr),"hash_ssdeep":hash_ssdeep})


    @abstractmethod
    def apply_regexp(self, string):
        pass

    @abstractmethod
    def set_regexp(self,regexp):
        self.regexp = regexp
    @abstractmethod
    def get_strings(self):
        Binary.logger.info('Obteniendo cadenas del binario')
        ascii_string = ''
        with open(self.path, 'rb') as f:
            data = f.read(1)
            while data:
                string = data.decode(encoding="UTF-8", errors='ignore')
                if all(31 < ord(c) < 127 for c in string):
                    ascii_string = ascii_string + string
                else:
                    if len(ascii_string) > 4:
                        if self.apply_regexp(ascii_string):
                            self.strings.append(ascii_string)
                            Binary.logger.info('          [ %s ]' % ascii_string)
                        ascii_string = ''
                data = f.read(1)

    @abstractmethod
    def analyze(self, path):
        pass

    @abstractmethod
    def write_json(self, output_dir=None):
        Binary.logger.debug('Escribiendo resultado JSON en %s' % output_dir)
        with open(os.path.join(output_dir, (self.filename + "_report.json")), "w") as jsonReport:
            json.dump(self.__dict__, jsonReport, indent=4, skipkeys=True, sort_keys=True)


    @abstractmethod
    def write_html(self, output_dir=None):
        Binary.logger.debug('Escribiendo resultado HTML en %s' % output_dir)
        env = Environment(
            loader=FileSystemLoader("./template"),
            autoescape=select_autoescape()
        )

        template = env.get_template("report.template")
        content = template.render(self.__dict__)
        htmlFile = os.path.join(output_dir, (self.filename + "_report.html"))

        with open(htmlFile, "w") as htmlReport:
            htmlReport.write(content)

    @abstractmethod
    def write_pdf(self, output_dir=None):
        Binary.logger.debug('Escribiendo resultado PDF en %s' % output_dir)
        env = Environment(
            loader=FileSystemLoader("./template"),
            autoescape=select_autoescape()
        )

        template = env.get_template("report.template")
        content = template.render(self.__dict__)
        pdf_file = os.path.join(output_dir,(self.filename + "_report.pdf"))

        result_file = open(pdf_file, "w+b")
        pisa.CreatePDF(content, dest=result_file)
        result_file.close()

    def get_ssdeep_hash(self):
        Binary.logger.info('Calculando hash SSDeep')
        self.ssdeep_hash = ppdeep.hash_from_file(self.path)  # .decode()

    def get_tlsh_hash(self):
        Binary.logger.info('Calculando hash TLSH')
        self.tlsh_hash = tlsh.hash(open(self.path, 'rb').read())

    def hashfile(self):

        file = open(self.path, "rb")
        data = file.read()

        digest = Hash(MD5(), backend=default_backend())
        digest.update(data)
        hashmd5 = digest.finalize().hex()

        digest = Hash(SHA1(), backend=default_backend())
        digest.update(data)
        hashsha1 = digest.finalize().hex()

        digest = Hash(SHA256(), backend=default_backend())
        digest.update(data)
        hashsha256 = digest.finalize().hex()

        file.close()
        self.hashes = {"MD5": hashmd5, "SHA1": hashsha1, "SHA256": hashsha256}
