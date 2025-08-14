from random import Random
from random import randint
from encryptobara import generateDetermenisticAlphabet
from config import YOURmaster

def choice_random_chars(psswdlen:int, salt:bytes, securepsswd:str) -> str:
    psswd:int = int.from_bytes(salt, byteorder='big')
    seclen:int = len(securepsswd)
    ultrasecpsswd:str = ''
    for index in range(psswdlen):
        ultrasecpsswd += securepsswd[(psswd+int.from_bytes(ultrasecpsswd.encode(), 'big'))%seclen-Random(psswd).randint(index, psswdlen)]
    return ultrasecpsswd

def getPsswd(masterpsswd:str, service:str, psswdlen:int, upper:bool, lower:bool, dig:bool, spec1:bool, spec2:bool, spec3:bool) -> str:
    rand = Random(int.from_bytes(masterpsswd.encode(), 'big'))
    upperLet:str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rand.shuffle(list(upperLet))
    lowerLet:str = "abcdefghijklmnopqrstuvwxyz"
    rand.shuffle(list(lowerLet))
    specChar1:str = """!@#$%^&*()_+-="""*3
    rand.shuffle(list(specChar1))
    specChar2:str = """"'`,./;:[]}{<>\\|"""*2
    rand.shuffle(list(specChar2))
    specChar3:str = """~?"""*13
    rand.shuffle(list(specChar3))
    digChar:str = "0123456789"*5
    rand.shuffle(list(digChar))
    lenupper, lenlower, lenchar1, lenchar2, lenchar3, lendig = [1 for i in range(6)]
    az:str = ''
    
    if upper: 
        lenupper = len(upperLet)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+upperLet)
    else:
        az
    if lower:
        lenlower = len(lowerLet)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+lowerLet)
    else:
        az
    if spec1:
        lenchar1 = len(specChar1)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+specChar1)
    else:
        az
    if spec2:
        lenchar2 = len(specChar2)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+specChar2)
    else:
        az
    if spec3:
        lenchar3 = len(specChar3)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+specChar3)
    else:
        az
    if dig:
        lendig = len(digChar)
        az += generateDetermenisticAlphabet(masterpsswd, YOURmaster, az+digChar)
    else:
        az
        
    az = generateDetermenisticAlphabet(service, masterpsswd, az)
    
    if az == '':
        return ''
    
    return choice_random_chars(psswdlen, Random(int.from_bytes((masterpsswd+service).encode(), 'big')).randbytes(64), generateDetermenisticAlphabet(masterpsswd, service, az))