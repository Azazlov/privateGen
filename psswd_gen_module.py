import hashlib
from random import Random
import base64
from encryptobara import encryptString, generateDetermenisticAlphabet

def choice_random_chars(psswdlen:int, salt:bytes, securepsswd:str) -> str:
    psswd:int = int.from_bytes(salt, byteorder='big')
    seclen = len(securepsswd)
    ultrasecpsswd = ''
    for index in range(psswdlen):
        ultrasecpsswd += securepsswd[(psswd+psswdlen)%(seclen-index)]
    return ultrasecpsswd

def getPsswd(masterpsswd:str, service:str, psswdlen:int, upper:bool, lower:bool, dig:bool, spec1:bool, spec2:bool, spec3:bool):
    enMP:str = masterpsswd.encode().hex()
    enS:str = service.encode().hex()
    string:str = masterpsswd+service
    upperLet:str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lowerLet:str = "abcdefghijklmnopqrstuvwxyz"
    specChar1:str = """!@#$%^&*()_+-="""
    specChar2:str = """"'`,./;:[]}{<>\\|"""
    specChar3:str = """~?"""
    digChar:str = "0123456789"
    lendig:int = len(digChar)
    lenchar3:int = len(specChar3)
    lenchar2:int = len(specChar2)
    lenchar1:int = len(specChar1)
    lenlower:int = len(lowerLet)
    lenupper:int = len(upperLet)
    az:str = ''
    
    az += upperLet if upper == True else az
    az += lowerLet if lower == True else az
    az += specChar1 if spec1 == True else az
    az += specChar2 if spec2 == True else az
    az += specChar3 if spec3 == True else az
    az += digChar if dig == True else az
    
    az = generateDetermenisticAlphabet(masterpsswd, az)
    if az == '':
        return
    
    return choice_random_chars(psswdlen, (enMP+enS+az).encode(), az)
    

if __name__ == '__main__':
    masterpsswd = 'b:";;aHLLR_iPfwuN2yZ^25#zy{RtGaafVN){YL)twy?{6{>o_\\Q;ht!;pAA4"[~'
    service = input('Название сервиса: ')
    psswdlen = bool(input('Длина пароля: '))
    upper = bool(input('Верхний регистр[0,1]: '))
    lower = bool(input('Нижний регистр[0,1]: '))
    dig = bool(input('Цифры[0,1]: '))
    spec1 = bool(input('Спец1[0,1]: '))
    spec2 = bool(input('Спец2[0,1]: '))
    spec3 = bool(input('Спец3[0,1]: '))
    print(getPsswd(masterpsswd, service, psswdlen, upper, lower, dig, spec1, spec2, spec3))
