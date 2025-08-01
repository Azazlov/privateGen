# cython: language_level=3
import hashlib
import base64
from random import Random
import time

def generateDetermenisticAlphabet(basecode: bytes):
    alphabet:str = ''.join(chr(i) for i in range(2**14))
    az:str = list(alphabet)
    master:bytes = b'F$Qt[QB?}_!td4C-8G>VKJnPFJnNoMu$f1]ufM{la"/l!a8@P"$?@uiM#oVkks"MiVt9t!{L-vTMTn,>dvw[wNW0d!h;Esx0T^GfvSC@t8mI/A)@{mvSdy4xEf+^!_\\A'
    print(f'int from bytes: {int.from_bytes(hashlib.sha256(master).digest())}')
    Random(int.from_bytes(hashlib.sha256(master).digest(), 'big')).shuffle(az)
    Random(int.from_bytes(hashlib.sha256(basecode).digest(), 'big')).shuffle(az)
    return ''.join(az)

def generateAlphabets(alphabet):

    return [alphabet[i+1:]+alphabet[:i+1] for i in range(len(alphabet)-1)]

def generateSecureKey(mssg:str, key:str, alphabet:str, alphabets:list):
    lenmssg:int = len(mssg)
    securekey:str = key
    lenalphabet:int = len(alphabet)
    
    for i in range(lenmssg):
        securekey += alphabet[securekey.encode()[i]%lenalphabet]

    return encryptString(string=securekey, alphabet=alphabet, alphabets=alphabets, key=key)

def encryptString(string:str, alphabet:str, alphabets:list, key:str):
    lenkey:int = len(key)
    encrypted:str = ''
    i:str
    char:str

    for i, char in enumerate(string):
        if char not in alphabet:
            encrypted += char
            print(f'{char} not in alphabet')
            continue
        for az in alphabets:
            if az[0] == key[i%lenkey]:
                encrypted += az[alphabet.index(char)]
                break

    return encrypted

def decryptString(string:str, alphabet:str, alphabets:str, key:str):
    lenkey:int = len(key)
    encrypted:str = ''
    i:int
    char:str

    for i, char in enumerate(string):
        if char not in alphabet:
            encrypted += char
            print(f'{char} not in alphabet')
            continue
        for az in alphabets:
            if az[0] == key[i%lenkey]:
                encrypted += alphabet[az.index(char)]
                break

    return encrypted

def encrypt(mssg:str, key:str):
    a:double = time.time()
    alphabet:str = generateDetermenisticAlphabet(key.encode())
    alphabets:list = generateAlphabets(alphabet)
    key = generateSecureKey(mssg, key, alphabet, alphabets)
    encrypted:str = encryptString(mssg, alphabet, alphabets, key)
    print(a-time.time())
    return base64.b64encode(encrypted.encode('utf-16')).decode('utf-16')

def decrypt(secret:str, key:str):
    secret = base64.b64decode(secret.encode('utf-16')).decode('utf-16')
    a:double = time.time()
    alphabet:str = generateDetermenisticAlphabet(key.encode())
    alphabets:list = generateAlphabets(alphabet)
    key = generateSecureKey(mssg, key, alphabet, alphabets)
    decrypted:str = decryptString(mssg, alphabet, alphabets, key)
    print(a-time.time())

    return decrypted


if __name__ == '__main__':
    while True:
        choice:str = input('Code/decode[0,1]: ')

        if choice == '0':
            mssg:str = input('mssg: ')
            key:str = input('key: ')
            print(key)
            print(f'encrypted: "{encrypt(mssg, key)}"')

        if choice == '1':
            secret:str = input('secret: ')
            key:str = input('key: ')
            print(key)
            print(f'decrypted: {decrypt(secret, key)}')
        choice = input('exit?[0,1]: ')
        if choice == '1':
            break
