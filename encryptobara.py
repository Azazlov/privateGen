import hashlib
import base64
from random import Random
import random

def generateDetermenisticAlphabet(key: str, alphabet:str = ''.join(chr(i) for i in range(32, 2**8))):
    az:list = list(alphabet)
    master:bytes = b'F$Qt[QB?}_!td4C-8G>VKJnPFJnNoMu$f1]ufM{la"/l!a8@P"$?@uiM#oVkks"MiVt9t!{L-vTMTn,>dvw[wNW0d!h;Esx0T^GfvSC@t8mI/A)@{mvSdy4xEf+^!_\\A'
    Random(int.from_bytes(hashlib.sha256(master).digest(), 'big')).shuffle(az)
    Random(int.from_bytes(hashlib.sha256(key.encode()).digest(), 'big')).shuffle(az)
    
    return ''.join(az)

def generateSecureKey(mssg:str, key:str, alphabet:str):
    lenmssg:int = len(mssg)
    securekey:str = key
    lenkey:int = len(key)
    lenalphabet:int = len(alphabet)

    for i in range(lenkey):
        securekey += alphabet[securekey.encode()[i]%lenalphabet]

    return encryptString(string=securekey[lenkey:], alphabet=alphabet, key=key)

def encryptString(string:str, alphabet:str, key:str):
    lenkey:int = len(key)
    lenalpha:int = len(alphabet)
    encrypted:str = ''
    i:int
    char:str
    
    for i, char in enumerate(string):
        if char not in alphabet or key[i%lenkey] not in alphabet:

            print(f'{char} not in alphabet')
            continue

        index = (alphabet.index(char)-alphabet.index(key[i%lenkey])+lenalpha)
        
        if index < 0:
            index += lenalpha
        if index > lenalpha:
            index -= lenalpha
        if index == lenalpha:
            index -= 1

        encrypted += alphabet[index]

    return encrypted

def decryptString(string:str, alphabet:str, key:str):
    lenkey:int = len(key)
    lenalpha:int = len(alphabet)
    encrypted:str = ''
    i:int
    char:str

    for i, char in enumerate(string):
        if char not in alphabet:

            print(f'{char} not in alphabet')
            continue
        index = alphabet.index(char)+alphabet.index(key[i%lenkey])-lenalpha
        
        if index < 0:
            index += lenalpha
        if index > lenalpha:
            index -= lenalpha
            
        encrypted += alphabet[index]

    return encrypted

def encrypt(mssg:str, key:str):
    alphabet:str = generateDetermenisticAlphabet(key)
    mssg = base64.b64encode(mssg.encode()).decode()
    key = generateSecureKey(mssg, key, alphabet)
    encrypted:str = encryptString(mssg, alphabet, key)
    encrypted = encrypted.encode('utf-8').hex()
    key = key.encode('utf-8').hex()
    encr:str = hex(int(key, 16) - int(encrypted, 16))
    
    return encr

def decrypt(secret:str, key:str):
    alphabet:str = generateDetermenisticAlphabet(key)
    key = generateSecureKey(secret, key, alphabet)
    encrypted = hex(int(key.encode('utf-8').hex(), 16) - int(secret, 16))[2:]
    secret = bytes.fromhex(encrypted).decode('utf-8')

    decrypted:str = decryptString(secret, alphabet, key)
    decrypted = base64.b64decode(decrypted).decode()
    
    return decrypted


if __name__ == '__main__':
    while True:
        choice:str = input('Code/decode[0,1]: ')

        if choice == '0':
            mssg:str = input('mssg: ')
            key:str = input('key: ')
            print(f'encrypted: "{encrypt(mssg, key)}"')

        if choice == '1':
            secret:str = input('secret: ')
            key = input('key: ')
            print(f'decrypted: {decrypt(secret, key)}')
        choice = input('exit?[0,1]: ')
        if choice == '1':
            break