import ppdeep
import tlsh

if __name__ == '__main__':
    print("Comparando Fuzzy Hash de dos ficheros pertenecientes a la misma familia de malware (Wannacry)")
    print("     SSDeep")
    hash1 = "49152:ontQqMSPbcBVQeK1INR9SqTdX1HkQo6SAA:Y2qPoBhK1aR9SUDk36SA"
    hash2 = "49152:VnjQqMSPbcBVQen8/oQUE92/xJAbfhjOBhuHYXr6jYdPJTF4hL:Z8qPoBhnBEs5JQZjOaYXr6jO2"
    print("     Resultado: %s" % ppdeep.compare(hash1, hash2))

    print("     TLSH")
    hash1 = "T1E266F601D1E51AA0DAF25EF726BADB10833A6E45C95BA66E1221510F0C77F0CDDE6F2C"
    hash2 = "T119067D10E74B817ADFAB017115FEEA1E4029AE9803789FD7C3542F1756399C36A33B89"
    print("     Resultado: %s" % tlsh.diff(hash1,hash2))

    print("Comparando Fuzzy Hash de dos ficheros cualesquiera (Wannacry / CrackMe01)")
    print("     SSDeep")
    hash1 = "49152:ontQqMSPbcBVQeK1INR9SqTdX1HkQo6SAA:Y2qPoBhK1aR9SUDk36SA"
    hash2 = "192:Xej799E4mwHjOM3IIv/rPoNN7E5pz67VSkGPk:Xu77nmqj17/2N78kGM"
    print("     Resultado: %s" % ppdeep.compare(hash1, hash2))

    print("     TLSH")
    hash1 = "T1E266F601D1E51AA0DAF25EF726BADB10833A6E45C95BA66E1221510F0C77F0CDDE6F2C"
    hash2 = "T181124B03FE514963CB998BF4253395EEC1BBB7234B916253B7BB95464B35160E00304F"
    print("     Resultado: %s" % tlsh.diff(hash1, hash2))

