import random
import math

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
    crint:int = int.from_bytes(mssg.encode(), 'big')
    
    return f'{conv(en[0], 36)}.{conv(en[1], 36)}.{conv(encryptRSA(crint, en), 36)}'

def unGenSecretRSA(config:str, secret:str):
    dpq = getDPQ(config, True)
    secret = secret.split('.')[-1]
    crint = int(secret, 36)
    code = decryptRSA(crint, dpq)
    return code.to_bytes(getBitsNum(code), 'big').decode()

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





# Функция для проверки простоты числа
def is_prime(num):
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

# Генерация простых чисел
def generate_prime():
    while True:
        num = random.randint(2**32, 2**51)  # Генерируем случайное число
        if is_prime(num):
            return num

# Генерация ключей
def generate_keys():
    # Генерируем два простых числа
    p = generate_prime()
    q = generate_prime()
    
    # Вычисляем n и φ(n)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Выбираем открытый показатель e
    e = random.randrange(1, phi)
    while math.gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    
    # Вычисляем закрытый ключ d
    d = pow(e, -1, phi)
    
    # Возвращаем открытый и закрытый ключи
    public_key = (e, n)
    private_key = (d, p, q)
    
    return public_key, private_key


def main():
    # Генерируем ключи
    public_key, private_key = generate_keys()
    print(f'{conv(private_key[0], 36)}.{conv(private_key[1], 36)}.{conv(private_key[2], 36)}.{conv(public_key[0], 36)}.{conv(public_key[1], 36)}')
    
# Пример использования
if __name__ == "__main__":
    main()