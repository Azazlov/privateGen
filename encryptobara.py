import hashlib
import base64
from random import Random

# Полный алфавит: символы с кодами от 0 до 255


def get_deterministic_alphabet(basecode: bytes):
    alphabet = ''.join(chr(i) for i in range(256))
    az = list(alphabet)
    master = b'F$Qt[QB?}_!td4C-8G>VKJnPFJnNoMu$f1]ufM{la"/l!a8@P"$?@uiM#oVkks"MiVt9t!{L-vTMTn,>dvw[wNW0d!h;Esx0T^GfvSC@t8mI/A)@{mvSdy4xEf+^!_\\A'
    Random(int.from_bytes(hashlib.sha256(master).digest(), 'big')).shuffle(az)
    Random(int.from_bytes(hashlib.sha256(basecode).digest(), 'big')).shuffle(az)
    return ''.join(az)

def encrypt(msg: str, basecode: str) -> str:
    basecode = basecode.encode()
    alphabet = get_deterministic_alphabet(basecode)
    msg_bytes = msg.encode('utf-8')  # исходные байты
    encrypted = ''.join(alphabet[b] for b in msg_bytes)  # шифрованная строка
    encrypted_bytes = encrypted.encode('latin1')  # 1:1 байтовое представление
    return base64.b64encode(encrypted_bytes).decode('ascii')  # ASCII-строка

def decrypt(encoded_secret: str, basecode: str) -> str:
    basecode = basecode.encode()
    alphabet = get_deterministic_alphabet(basecode)
    reverse_map = {c: i for i, c in enumerate(alphabet)}

    # Декодируем base64 -> байты -> строка (latin1)
    encrypted_bytes = base64.b64decode(encoded_secret)
    encrypted = encrypted_bytes.decode('latin1')

    # Расшифровываем
    decrypted_bytes = bytes(reverse_map[c] for c in encrypted)
    return decrypted_bytes.decode('utf-8', errors='replace')


if __name__ == '__main__':
    while True:
        choice = input('Code/decode[0,1]: ')

        if choice == '0':
            msg = input('msg: ')
            key = input('key: ').encode()
            print(key)
            print(f'encrypted: "{encrypt(msg, key)}"')

        if choice == '1':
            secret = input('secret: ')
            key = input('key: ').encode()
            print(key)
            print(f'decrypted: {decrypt(secret, key)}')
        choice = input('exit?[0,1]: ')
        if choice == '1':
            break