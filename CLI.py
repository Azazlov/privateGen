import json
from random import randbytes, randint
from encryptobara import encrypt, decrypt, conv, deconv
from psswd_gen_module import getPsswd
from config import YOURkey, YOURmaster
from customRSA import genSecretRSA, unGenSecretRSA, getEN, generate_keys

class CLIApp:
    def __init__(self):
        self.running = True
        self.tabs = {
            "1": ("Encrypter", self.encrypter_menu),
            "2": ("Generator", self.generator_menu),
            "3": ("RSAgenerator", self.rsagenerator_menu),
            "0": ("Выход", self.exit_app)
        }

    def run(self):
        while self.running:
            print("\n=== Главное меню ===")
            for k, (name, _) in self.tabs.items():
                print(f"{k}. {name}")
            choice = input("Выберите раздел: ").strip()
            if choice in self.tabs:
                self.tabs[choice][1]()
            else:
                print("Неверный выбор!")

    def encrypter_menu(self):
        while True:
            print("\n=== Encrypter ===")
            print("1. Кодировать")
            print("2. Декодировать")
            print("0. Назад")
            choice = input("Выбор: ").strip()
            if choice == "0":
                return
            mssg = input("Сообщение/Код: ")
            key = input(f"Ключ (по умолчанию: {YOURkey}): ") or YOURkey
            master = input(f"Мастер-ключ (по умолчанию: {YOURmaster}): ") or YOURmaster
            try:
                if choice == "1":
                    print("Результат:", encrypt(mssg, key, master))
                elif choice == "2":
                    try:
                        print("Результат:", decrypt(mssg, key, master))
                    except Exception as ex:
                        print("Ошибка:", ex)
            except Exception as ex:
                print("Ошибка:", ex)

    def generator_menu(self):
        while True:
            print("\n=== Generator ===")
            print("1. Получить пароль (мастер-пароль или конфиг)")
            print("0. Назад")
            choice = input("Выбор: ").strip()
            if choice == "0":
                return

            mp_input = input("Мастер-пароль или конфиг: ")

            # Определяем: конфиг или обычный мастер-пароль
            crypt_parts = mp_input.split(".")
            if len(crypt_parts) == 4:
                # Декодируем конфиг
                gen_key = input(f"Ключ шифрования (по умолчанию {YOURkey}): ") or YOURkey
                gen_master = input(f"Мастер-ключ шифрования (по умолчанию {YOURmaster}): ") or YOURmaster
                try:
                    config_json = decrypt(f"{crypt_parts[1]}.{crypt_parts[2]}.{crypt_parts[3]}", gen_key, gen_master)
                    config = json.loads(config_json)
                    print("Конфиг успешно расшифрован:", config)
                    password = getPsswd(
                        config['mp'], config['serv'], config['psswdlen'],
                        config['upper'], config['lower'], config['dig'],
                        config['spec1'], config['spec2'], config['spec3']
                    )
                    print("Ваш пароль:", password)
                except Exception as ex:
                    print("Ошибка при декодировании:", ex)
            else:
                # Генерация пароля с нуля
                if not mp_input:
                    mp_input = conv(int.from_bytes(randbytes(randint(32, 64)), 'big'), 36)
                    print("Случайный мастер-пароль:", mp_input)

                gen_key = input(f"Ключ шифрования (по умолчанию {YOURkey}): ") or YOURkey
                gen_master = input(f"Мастер-ключ шифрования (по умолчанию {YOURmaster}): ") or YOURmaster
                srv = input("Название сервиса (без точки): ")
                try:
                    lenpsswd = int(input("Длина пароля (по умолчанию 8): ") or "8")
                except:
                    print("Ошибка: длина должна быть числом!")
                    continue
                upper = input("Верхний регистр? (y/n): ").lower() == "y"
                lower = input("Нижний регистр? (y/n): ").lower() == "y"
                dig = input("Цифры? (y/n): ").lower() == "y"
                spec1 = input("!@#$%^&*()_+-=? (y/n): ").lower() == "y"
                spec2 = input("'`,./;:[]}{<>\\| (y/n): ").lower() == "y"
                spec3 = input("~? (y/n): ").lower() == "y"
                try:
                    password = getPsswd(mp_input, srv, lenpsswd, upper, lower, dig, spec1, spec2, spec3)
                    encrypted = encrypt(json.dumps({
                        'mp': mp_input, 'serv': srv, 'psswdlen': lenpsswd,
                        'upper': upper, 'lower': lower, 'dig': dig,
                        'spec1': spec1, 'spec2': spec2, 'spec3': spec3
                    }), gen_key, gen_master)
                    print("Ваш пароль:", password)
                    print("Конфиг:", f"{srv}.{encrypted}")
                except Exception as ex:
                    print("Ошибка генерации:", ex)


    def rsagenerator_menu(self):
        while True:
            print("\n=== RSAgenerator ===")
            print("1. Сгенерировать RSA ключ")
            print("2. Получить открытый ключ")
            print("3. Кодировать")
            print("4. Декодировать")
            print("0. Назад")
            choice = input("Выбор: ").strip()
            if choice == "0":
                return
            if choice == "1":
                print("RSA ключ:", generate_keys())
            elif choice == "2":
                key = input("RSA ключ: ")
                try:
                    e, n = getEN(key)
                    print(f"Публичный ключ: {e}.{n}")
                except Exception as ex:
                    print("Ошибка:", ex)
            elif choice == "3":
                key = input("RSA ключ: ")
                msg = input("Сообщение (12 симв. макс.): ")
                try:
                    print("Результат:", genSecretRSA(key, msg))
                except Exception as ex:
                    print("Ошибка:", ex)
            elif choice == "4":
                key = input("RSA ключ: ")
                msg = input("Код: ")
                try:
                    print("Результат:", unGenSecretRSA(key, msg))
                except Exception as ex:
                    print("Ошибка:", ex)

    def exit_app(self):
        self.running = False

if __name__ == "__main__":
    CLIApp().run()
