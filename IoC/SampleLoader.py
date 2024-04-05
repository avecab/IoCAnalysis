from enum import Enum
from IoC.PE import PE
from IoC.ELF import ELF
import logging
__all__ = ["ExeType", "SampleLoader"]


class ExeType(Enum):
    PE = 1
    ELF = 2


magic_numbers = [b"MZ",b"\x7f\x45\x4c\x46"]


class SampleLoader:

    @staticmethod
    def load(path):
        logger = logging.getLogger("IoCAnalysis." + __name__)
        offset = 0
        i = 1
        with open(path, 'rb') as f:
            b = f.read(1)
            offset = offset + 1
            while b == b"\x00":  # skip null bytes
                b = f.read(1)
                offset = offset + 1
            offset = offset - 1

            for n in magic_numbers:
                f.seek(offset)
                x = f.read(int(len(n.decode('utf-8'))))
                if n == x:
                    logger.debug('Sample is %s' % ExeType(i).name)
                    break
                i = i + 1
        f.close()

        match i:
            case 1:
                return PE(path=path, offset=offset)
            case 2:
                return ELF(path=path, offset=offset)
            case _:
                return None
