from encryptobara import conv, deconv
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers


def generateConfig():
    # Генерация приватного ключа
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2**12
    )

    # Получение числовых параметров из приватного ключа
    private_numbers = private_key.private_numbers()

    # Извлечение параметров
    d = private_numbers.d  # закрытый показатель
    n = private_numbers.public_numbers.n  # модуль
    e = private_numbers.public_numbers.e  # открытый показатель

    # Вывод значений
    # print(f"Открытый показатель (e): {conv(e, 36)}")
    # print(f"Модуль (n): {conv(n, 36)}")
    # print(f"Закрытый показатель (d): {conv(d, 36)}")

    # Если нужно получить p и q (простые числа)
    p = private_numbers.p
    q = private_numbers.q
    # print(f"Простое число p: {p}")
    # print(f"Простое число q: {q}")
    return f'{conv(d, 36)}.{conv(p, 36)}.{conv(q, 36)}.{conv(e, 36)}.{conv(n, 36)}'

if __name__ == '__main__':
    print(generateConfig())
