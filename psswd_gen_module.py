import hashlib
from random import Random
import base64
from encryptobara import encryptString, generateDetermenisticAlphabet, decrypt, encrypt
import json

YOURpsswd:str = 'b:";;aHLLR_iPfwuN2yZ^25#zy{RtGaafVN){YL)twy?{6{>o_\\Q;ht!;pAA4"[~'

YOURkey:str = 'Gpfve7tq\\eO"G]yP1({]_r>OKL%+P\'-csvKg~VOg{*DVDIf7D(9e\\GppFD,9x*P~'

def choice_random_chars(psswdlen:int, salt:bytes, securepsswd:str) -> str:
    psswd:int = int.from_bytes(salt, byteorder='big')
    seclen:int = len(securepsswd)
    ultrasecpsswd:str = ''
    for index in range(psswdlen):
        ultrasecpsswd += securepsswd[(psswd+psswdlen)%(seclen-index)]
    return ultrasecpsswd

def getPsswd(masterpsswd:str, service:str, psswdlen:int, upper:bool, lower:bool, dig:bool, spec1:bool, spec2:bool, spec3:bool) -> str:
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
        return ''
    
    return choice_random_chars(psswdlen, (masterpsswd).encode(), az)
    
def decoding() -> str:
    crypto:str = input('Шифр конфига: ')
    crypt:list = crypto.split('.')
    try:
        decode:str = decrypt(crypt[2], YOURkey)
        config:dict = json.loads(decode)
    except Exception as ex:
        print(ex)
        return ''

    print(
        getPsswd(config['mp'], 
                 config['serv'], 
                 int(config['psswdlen']), 
                 config['upper'], 
                 config['lower'], 
                 config['dig'], 
                 config['spec1'], 
                 config['spec2'], 
                 config['spec3']
        )
    )
    return ''

def generate() -> None:
    masterpsswd:str = YOURpsswd
    service:str = input('Название сервиса: ')
    psswdlen:int = int(input('Длина пароля: '))
    upper:bool = bool(input('Верхний регистр["",1]: '))
    lower:bool = bool(input('Нижний регистр["",1]: '))
    dig:bool = bool(input('Цифры["",1]: '))
    spec1:bool = bool(input('Спец1["",1]: '))
    spec2:bool = bool(input('Спец2["",1]: '))
    spec3:bool = bool(input('Спец3["",1]: '))
    config:dict = {
        'mp':masterpsswd,
        'serv':service,
        'psswdlen':psswdlen,
        'upper':upper,
        'lower':lower,
        'dig':dig,
        'spec1':spec1,
        'spec2':spec2,
        'spec3':spec3
    }
    encrypted:str = encrypt(json.dumps(config), YOURkey)
    print(getPsswd(masterpsswd, service, psswdlen, upper, lower, dig, spec1, spec2, spec3))
    print()
    print(f'{service}.{hashlib.sha256(masterpsswd.encode('utf-16')).digest().hex()}.{encrypted}')

if __name__ == '__main__':
    choice:str = input('Ген/дек?[0,1]: ')
    if choice == '0':
        generate()
    if choice == '1':
        decoding()


