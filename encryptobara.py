import hashlib
from random import Random
import random
from os import urandom
from customRSA import encryptRSA, decryptRSA, getDPQ, getEN, conv, deconv, genSecretRSA, unGenSecretRSA
from config import alphabet, YOURsecurepsswd

alphabetlen = 2**15
i:int

def generateRandomMaster(alphabet:str=alphabet) -> str:
    master:list = list(generateDetermenisticAlphabet(key=urandom(32).hex(), master=urandom(32).hex(), alphabet=alphabet))
    Random(urandom(16)).shuffle(master)
    return ''.join(master)

def generateDetermenisticAlphabet(key: str, master:str, alphabet:str = ''.join(chr(i) for i in range(alphabetlen))) -> str:
    az:list = list(alphabet)
    Random(int.from_bytes(hashlib.sha256(master.encode()).digest(), 'big')).shuffle(az)
    Random(int.from_bytes(hashlib.sha256(key.encode()).digest(), 'big')).shuffle(az)
    
    return ''.join(az)

def generateSecureKey(key:str, alphabet:str) -> str:
    securekey:str = key
    lenkey:int = len(key)
    lenalphabet:int = len(alphabet)

    for i in range(lenkey):
        securekey += alphabet[securekey.encode()[i]%lenalphabet]

    return encryptString(string=securekey[lenkey:], alphabet=alphabet, key=key)

def encryptString(string:str, alphabet:str, key:str) -> str:
    lenkey:int = len(key)
    lenalpha:int = len(alphabet)
    encrypted:str = ''
    i:int
    char:str
    
    for i, char in enumerate(string):
        if char not in alphabet or key[i%lenkey] not in alphabet:

            print(f'{char} not in alphabet')
            continue

        index = alphabet.index(char) - alphabet.index(key[i%lenkey]) + lenalpha
        
        if index < 0:
            index += lenalpha
        if index > lenalpha:
            index -= lenalpha
        if index == lenalpha:
            index = 0
            
        # print(alphabet.index(char), index)

        encrypted += alphabet[index]

    return encrypted

def decryptString(string:str, alphabet:str, key:str) -> str:
    lenkey:int = len(key)
    lenalpha:int = len(alphabet)
    encrypted:str = ''
    i:int
    char:str
    index:int

    for i, char in enumerate(string):
        if char not in alphabet:

            print(f'{char} not in alphabet')
            continue
        index = (alphabet.index(char) + alphabet.index(key[i%lenkey]) - lenalpha)
        
        if index < 0:
            index += lenalpha
        if index > lenalpha:
            index -= lenalpha
        if index == lenalpha:
            index = 0
            
        encrypted += alphabet[index]

    return encrypted

def encrypt(mssg:str, key:str, master:str, alphabet=alphabet) -> str:
    saltKey:str = conv(int.from_bytes(urandom(128), 'big'), len(alphabet), alphabet)
    saltMaster:str = conv(int.from_bytes(urandom(128), 'big'), len(alphabet), alphabet)
    key = generateSecureKey(key+saltKey, generateDetermenisticAlphabet(key+saltKey, master+saltMaster))
    alphabet = generateDetermenisticAlphabet(key+saltKey, master+saltMaster, alphabet=alphabet)
    mssg = encryptString(mssg, generateDetermenisticAlphabet(key+saltKey, master+saltMaster), key+saltKey)
    encryptint:int = int.from_bytes(bytes(mssg[0:], 'utf-16'))
    encrypted:str = conv(encryptint, len(alphabet), alphabet)
    
    return f'{saltKey}.{saltMaster}.{encrypted}'

def decrypt(secret:str, key:str, master:str, alphabet:str=alphabet) -> str:
    saltKey:str
    saltMaster:str
    try:
        saltKey, saltMaster, secret = secret.split('.')
    except:
        raise ValueError('Неправильный формат шифра')
    key = generateSecureKey(key+saltKey, generateDetermenisticAlphabet(key+saltKey, master+saltMaster))
    alphabet = generateDetermenisticAlphabet(key+saltKey, master+saltMaster, alphabet=alphabet)
    secrint:int = deconv(secret, len(alphabet), alphabet)
    try:
        secret = secrint.to_bytes(secrint.bit_length()//8+1, 'big')[1:].decode('utf-16')
        secret = decryptString(secret, generateDetermenisticAlphabet(key+saltKey, master+saltMaster), key+saltKey)
    except:
        raise ValueError('Неверный шифртекст или какой-либо из ключей')

    return secret




if __name__ == '__main__':
    master:str 
    key:str
    mssg:str
    RSA:bool
    while True:
        choice = input('Code/decode/getKey[0, 1, 2]: ')
        
        if choice == '2':
            e, n = getEN(input('config: '))
            print(f'\n{e}.{n}\n')
            choice = input('Code/decode/getKey[0, 1, 2]: ')
        RSA = bool(input('RSA["", 1]: '))

        if choice == '0':
            if RSA:
                print(genSecretRSA(input('config: '), input('mssg: ')))
            else:
                mssg = input('mssg: ')
                master = input('master: ')
                securepsswd = master if master != '' else YOURsecurepsswd
                key = input('key: ')
                print(f'encrypted: "{encrypt(mssg, key, securepsswd)}"')

        if choice == '1':
            if RSA:
                print(unGenSecretRSA(input('config: '), input('secret: ')))
            else:
                secret = input('secret: ')
                master = input('master: ')
                securepsswd = master if master != '' else YOURsecurepsswd
                key = input('key: ')
                print(f'decrypted: {decrypt(secret, key, securepsswd)}')
                
        choice = input('exit?[0,1]: ')
        if choice == '1':
            break