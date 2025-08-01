import hashlib
from random import Random
import base64

def secureHash(a: str, b: str, c: str, stretch: int) -> str:
    result = (a + b + c).encode('utf-8')
    for _ in range(stretch // 2):
        result = hashlib.sha256(result).digest()
    return base64.b64encode(result).decode('utf-8')

def getPsswd(masterpsswd, service, psswdlen, upper, lower, dig, spec1, spec2, spec3):
    enMP = masterpsswd.encode().hex()
    enS = service.encode().hex()
    string = masterpsswd+service
    radius = len((secureHash(enMP, enS, enS+enMP, psswdlen*1000)).encode())
    upperLet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowerLet = "abcdefghijklmnopqrstuvwxyz"
    specChar1 = """!@#$%^&*()_+-="""
    specChar2 = """"'`,./;:[]}{<>\\|"""
    specChar3 = """~?"""
    digChar = "0123456789"
    lendig = len(digChar)
    lenchar3 = len(specChar3)
    lenchar2 = len(specChar2)
    lenchar1 = len(specChar1)
    lenlower = len(lowerLet)
    lenupper = len(upperLet)
    az = ''
    az += upperLet if upper == True else az
    az += lowerLet if lower == True else az
    az += specChar1 if spec1 == True else az
    az += specChar2 if spec2 == True else az
    az += specChar3 if spec3 == True else az
    az += digChar if dig == True else az
    salt = secureHash(enMP, service, string, psswdlen*1245)
    salted = secureHash(masterpsswd, service, salt, psswdlen*802)
    psswd = hashlib.sha256(salted.encode()).digest()
    iterations = radius

    def encrypt(psswd, charsIn, alphabet):
        newPsswd = ''
        for char in psswd:
            newPsswd += alphabet[(char)%charsIn]
        return newPsswd

    def get_deterministic_alphabet(master, service, az):
        az = list(az)
        Random(int.from_bytes(hashlib.sha256(master.encode()).digest(), 'big')).shuffle(az)
        Random(int.from_bytes(hashlib.sha256(service.encode()).digest(), 'big')).shuffle(az)
        return ''.join(az)
    def choice_random_chars(psswdlen, psswd, securepsswd):
        psswd = int.from_bytes(psswd, byteorder='big')
        seclen = len(securepsswd)
        ultrasecpsswd = ''
        for index in range(psswdlen):
            ultrasecpsswd += securepsswd[psswd%(seclen-index)]
        return ultrasecpsswd
    alphabet = get_deterministic_alphabet(masterpsswd, service=service, az=az)
    charsIn = len(alphabet)
    securepsswd = ''
    
    for d in range(6):
        for i in range(d, iterations):
            enMP = encrypt(secureHash(digChar, enS, salted, radius).encode(), lendig, alphabet=alphabet) if dig and d == 6 else enMP
            enMP = encrypt(secureHash(specChar3, enS, salted, radius).encode(), lenchar3, alphabet=alphabet) if spec3 and d == 5 else enMP
            enMP = encrypt(secureHash(specChar2, enS, salted, radius).encode(), lenchar2, alphabet=alphabet) if spec2 and d == 4 else enMP
            enMP = encrypt(secureHash(specChar1, enS, salted, radius).encode(), lenchar1, alphabet=alphabet) if spec1 and d == 3 else enMP
            enMP = encrypt(secureHash(lowerLet, enS, salted, radius).encode(), lenlower, alphabet=alphabet) if lower and d == 2 else enMP
            enMP = encrypt(secureHash(upperLet, enS, salted, radius).encode(), lenupper, alphabet=alphabet) if upper and d == 1 else enMP
            psswd = str(int.from_bytes(psswd, byteorder='big'))
            securepsswd += encrypt(psswd=secureHash(psswd, salt, enMP, psswdlen*130+i*d).encode(), charsIn=charsIn, alphabet=alphabet)
            psswd = hashlib.sha256(psswd.encode()).digest()
    securepsswd = choice_random_chars(psswdlen=psswdlen, psswd=psswd, securepsswd=securepsswd)
    return securepsswd

if __name__ == '__main__':
    masterpsswd = 'b:";;aHLLR_iPfwuN2yZ^25#zy{RtGaafVN){YL)twy?{6{>o_\\Q;ht!;pAA4"[~'
    service = input('Название сервиса: ')
    psswdlen = int(input('Длина пароля: '))
    upper = int(input('Верхний регистр[0,1]: '))
    lower = int(input('Нижний регистр[0,1]: '))
    dig = int(input('Цифры[0,1]: '))
    spec1 = int(input('Спец1[0,1]: '))
    spec2 = int(input('Спец2[0,1]: '))
    spec3 = int(input('Спец3[0,1]: '))
    print(getPsswd(masterpsswd, service, psswdlen, upper, lower, dig, spec1, spec2, spec3))
