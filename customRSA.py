import math
import random

def getEN(key:str, conv:bool=False) -> tuple:
    e = key.split('.')[-2]
    n = key.split('.')[-1]
    if not conv:
        return (e, n)
    return (int(e, 36), int(n, 36))

def getDPQ(key:str, conv:bool=False) -> tuple:
    d = key.split('.')[0]
    p = key.split('.')[1]
    try:
        q = key.split('.')[2]
    except:
        raise ValueError('Неправильный конфиг!')
    if not conv:
        return (d, p ,q)
    return (int(d, 36), int(p, 36), int(q, 36))

def encryptRSA(message:int, public_key:tuple) -> int:
    e, n = public_key
    return pow(message, e, n)

def decryptRSA(c:int, private_key:tuple) -> int:
    d, p, q = private_key
    dp = d % (p - 1)
    dq = d % (q - 1)
    qp_inv = pow(q, -1, p)  # обратное к q по модулю p
    
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (qp_inv * (m1 - m2)) % p
    m = m2 + h * q
    
    return m

def genSecretRSA(config:str, mssg:str):
    en:tuple = getEN(config, True)
    crint:int = int.from_bytes(mssg.encode('utf-8'), 'big')
    
    return f'{conv(en[0], 36)}.{conv(en[1], 36)}.{conv(encryptRSA(crint, en), 36)}'

def unGenSecretRSA(config:str, secret:str):
    dpq = getDPQ(config, True)
    secret = secret.split('.')[-1]
    crint = int(secret, 36)
    code = decryptRSA(crint, dpq)
    return code.to_bytes(getBitsNum(code), 'big').decode('utf-8')

def getBitsNum(integer:int):
    return integer.bit_length()//8+1 if integer.bit_length()%8 != 0 else integer.bit_length()

def conv(value:int, base:int, alphabet:str="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> str:
    res:str = ''
    sign:str = ['', '-'][value < 0]
    value = abs(value)
    while True:
        res = alphabet[value % base] + res
        value //= base
        if value == 0: 
            
            return sign + res
        
def deconv(value:str, base:int, alphabet:str="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") -> int:
    res = 0 
    
    for i in range(1, len(value)+1):
        res += alphabet.index(value[-i])*base**(i-1)
        
    return [res, -res][value[0] == '-']

SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199
)  

def is_probable_prime(n, k=10):
    """Проверка простоты числа методом Миллера-Рабина."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True



def generate_prime(bits):
    """Генерация простого числа заданного размера в битах."""
    while True:
        num = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(num):
            return num

def generate_keys():
    bits = 2048  # примерно 2 раза больше текущего n
    p = generate_prime(bits)
    q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, p, q)

    return f'{conv(private_key[0], 36)}.{conv(private_key[1], 36)}.{conv(private_key[2], 36)}.{conv(public_key[0], 36)}.{conv(public_key[1], 36)}'


def main():

    print(generate_keys())
    
# Пример использования
if __name__ == "__main__":
    main()