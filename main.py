from psswd_gen_module import getPsswd as psswd
from encryptobara import encrypt, decrypt
import hashlib
import json

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout,
    QPushButton, QLineEdit, QLabel, QRadioButton,
    QGroupBox, QHBoxLayout
)

app = QApplication([])
window = QWidget()
layout = QVBoxLayout()


mpwgt = QWidget()
mplyt = QVBoxLayout()
mplbl = QLabel('Мастер-пароль')
mp = QLineEdit()
mp.setPlaceholderText("Мастер-пароль")
mp.setText('b:";;aHLLR_iPfwuN2yZ^25#zy{RtGaafVN){YL)twy?{6{>o_\\Q;ht!;pAA4"[~') #Здесь можно вставить свой пароль
mplyt.addWidget(mplbl)
mplyt.addWidget(mp)
mpwgt.setLayout(mplyt)
layout.addWidget(mpwgt)

keywgt = QWidget()
keylyt = QVBoxLayout()
keylbl = QLabel('Ключ шифрования')
key = QLineEdit()
key.setPlaceholderText("Ключ")
key.setText('Gpfve7tq\\eO"G]yP1({]_r>OKL%+P\'-csvKg~VOg{*DVDIf7D(9e\\GppFD,9x*P~') #Здесь можно вставить свой ключ
keylyt.addWidget(keylbl)
keylyt.addWidget(key)
keywgt.setLayout(keylyt)
layout.addWidget(keywgt)

servwgt = QWidget()
servlyt = QVBoxLayout()
servlbl = QLabel('Сервис')
serv = QLineEdit()
serv.setPlaceholderText("Название сервиса")
servlyt.addWidget(servlbl)
servlyt.addWidget(serv)
servwgt.setLayout(servlyt)
layout.addWidget(servwgt)

psswdlenwgt = QWidget()
psswdlenlyt = QVBoxLayout()
psswdlenlbl = QLabel('Длина пароля')
psswdlen = QLineEdit()
psswdlen.setText('16')
psswdlenlyt.addWidget(psswdlenlbl)
psswdlenlyt.addWidget(psswdlen)
psswdlenwgt.setLayout(psswdlenlyt)
layout.addWidget(psswdlenwgt)

upperwgt = QWidget()
upperlyt = QHBoxLayout()
upperlbl = QLabel('Верхний регистр')
upper = QRadioButton()
upper.setChecked(True)
upperlyt.addWidget(upperlbl)
upperlyt.addWidget(upper)
upperwgt.setLayout(upperlyt)
layout.addWidget(upperwgt)

lowerwgt = QWidget()
lowerlyt = QHBoxLayout()
lowerlbl = QLabel('Нижний регистр')
lower = QRadioButton()
lower.setChecked(True)
lowerlyt.addWidget(lowerlbl)
lowerlyt.addWidget(lower)
lowerwgt.setLayout(lowerlyt)
layout.addWidget(lowerwgt)

digwgt = QWidget()
diglyt = QHBoxLayout()
diglbl = QLabel('0123456789')
dig = QRadioButton()
dig.setChecked(True)
diglyt.addWidget(diglbl)
diglyt.addWidget(dig)
digwgt.setLayout(diglyt)
layout.addWidget(digwgt)

spec1wgt = QWidget()
spec1lyt = QHBoxLayout()
spec1lbl = QLabel('!@#$%^&*()_+-=')
spec1 = QRadioButton()
spec1.setChecked(True)
spec1lyt.addWidget(spec1lbl)
spec1lyt.addWidget(spec1)
spec1wgt.setLayout(spec1lyt)
layout.addWidget(spec1wgt)

spec2wgt = QWidget()
spec2lyt = QHBoxLayout()
spec2lbl = QLabel('\'`,./;:[]}{<>\\|')
spec2 = QRadioButton()
spec2.setChecked(False)
spec2lyt.addWidget(spec2lbl)
spec2lyt.addWidget(spec2)
spec2wgt.setLayout(spec2lyt)
layout.addWidget(spec2wgt)

spec3wgt = QWidget()
spec3lyt = QHBoxLayout()
spec3lbl = QLabel('~?')
spec3 = QRadioButton()
spec3.setChecked(False)
spec3lyt.addWidget(spec3lbl)
spec3lyt.addWidget(spec3)
spec3wgt.setLayout(spec3lyt)
layout.addWidget(spec3wgt)

# Кнопка
toGen = QPushButton("Сгенерировать")
layout.addWidget(toGen)

# Метка для вывода текста
outputpsswd = QLineEdit()
outputsecret = QLineEdit()
layout.addWidget(outputpsswd)
layout.addWidget(outputsecret)

def check():
    crypt = mp.text().split('.')
    if len(crypt) == 3 and len(crypt[1]) == 64:
        outputpsswd.setText('')
        decoding()
        return
    else:
        genpsswd()

# Обработчик нажатия кнопки
def genpsswd():
    mpsswd = mp.text()
    srv = serv.text()
    lenpsswd = psswdlen.text()
    isUpper = upper.isChecked()
    isLower = lower.isChecked()
    isDig = dig.isChecked()
    isSpec1 = spec1.isChecked()
    isSpec2 = spec2.isChecked()
    isSpec3 = spec3.isChecked()

    config = {
        'mp':mpsswd,
        'serv':srv,
        'psswdlen': int(lenpsswd),
        'upper':isUpper,
        'lower':isLower,
        'dig':isDig,
        'spec1':isSpec1,
        'spec2':isSpec2,
        'spec3':isSpec3
    }
    try:
        outputpsswd.setText(
            psswd(
                mpsswd, 
                srv, 
                int(lenpsswd), 
                isUpper, 
                isLower, 
                isDig, 
                isSpec1, 
                isSpec2, 
                isSpec3
            )
        )
        encrypted = encrypt(json.dumps(config), key.text())
        outputsecret.setText(f'{srv}.{hashlib.sha256(mpsswd.encode('utf-16')).digest().hex()}.{encrypted}')
    except Exception as ex:
        outputpsswd.setText(f'{ex}')
        outputsecret.setText('Где-то ошибка!')
        return

def decoding():
    crypt = mp.text()
    key.text()
    crypt = crypt.split('.')
    print(crypt)
    try:
        config = decrypt(crypt[2], key.text())
        config = json.loads(config)
    except Exception as ex:
        outputpsswd.setText(f'{ex}')
        outputsecret.setText('Где-то ошибка!')        
        return
    print(config)
    mp.setText(config['mp'])
    serv.setText(config['serv'])
    psswdlen.setText(str(config['psswdlen']))
    upper.setChecked(config['upper'])
    lower.setChecked(config['lower']  )
    dig.setChecked(config['dig']  )
    spec1.setChecked(config['spec1']  )
    spec2.setChecked(config['spec2']  )
    spec3.setChecked(config['spec3']  )

    genpsswd()

toGen.clicked.connect(check)

window.setLayout(layout)
window.show()
app.exec()
