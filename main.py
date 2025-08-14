import sys
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from encryptobara import encrypt, decrypt, conv, generateRandomMaster
from psswd_gen_module import getPsswd
import json
from config import YOURkey, YOURmaster, YOURsecurepsswd
from GenKey import generateConfig
from customRSA import genSecretRSA, unGenSecretRSA, getEN

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle('PrivateGen')
        self.setGeometry(100, 100, 300, 600)

        self.tab_widget = QTabWidget()
        
        self.encrypter()
        self.generator()
        self.RSAgenerator()
        
        main_layout = QVBoxLayout()
        main_layout.addWidget(self.tab_widget)
        self.setLayout(main_layout)
        
        
    def createBlock(self, labelText='', placeholderText='', text=''):
        label = QLabel(labelText)
        block = QLineEdit(text)
        block.setPlaceholderText(placeholderText)
        
        return label, block
        
    def createRadio(self, label='', state=True):
        radioLabel = QLabel(label)
        radioButton = QRadioButton()
        radioButton.setChecked(state)
        
        return radioLabel, radioButton
        
    def addTab(self, tab, block):
        [tab.addWidget(i) for i in block]
        
    def getVWidget(self, block):
        widget = QWidget()
        VBox = QVBoxLayout()
        self.addTab(VBox, block) if isinstance (block, tuple) else VBox.addWidget(block)
        widget.setLayout(VBox)
        return widget
    
    def getHWidget(self, block):
        widget = QWidget()
        HBox = QHBoxLayout()
        self.addTab(HBox, block) if isinstance (block, tuple) else HBox.addWidget(block)
        widget.setLayout(HBox)
        return widget
        
    def code(self):
        if self.key[1].text() == '' or self.mssg[1].text() == '':
            return
        self.decoded.setText(encrypt(self.mssg[1].text(), self.key[1].text(), self.master[1].text()))

    def decode(self):
        if (self.key[1].text() == '' or self.master[1].text() == '') and self.mssg[1].text() == '':
            return
        
        crypt = self.mssg[1].text().split('.')

        if len(crypt) == 4:
            try:
                self.decrypting()
                return
            except:
                pass
            
        try:
            self.decoded.setText(decrypt(self.mssg[1].text(), self.key[1].text(), self.master[1].text()))
        except Exception as ex:
            self.decoded.setText(f'{ex}')
        
        return
        
    def decrypting(self):
        crypt = self.mssg[1].text()
        crypt = crypt.split('.')[1:]
        
        config = decrypt(f'{crypt[0]}.{crypt[1]}.{crypt[2]}', self.key[1].text(), self.master[1].text())
        config = json.loads(config)
        self.decoded.setText(f'{config}')
            
        return
           
    def check(self):
        crypt = self.mp[1].text().split('.')

        if len(crypt) == 4:
            self.psswd[1].setText('')
            self.decoding()
            return
        else:
            self.genpsswd()
            return

    def genpsswd(self):
        mpsswd = self.mp[1].text()
        self.mp[1].setText(generateRandomMaster()) if self.rand[1].isChecked() else 0
        srv = self.serv[1].text()
        try:
            lenpsswd = int(self.psswdLen[1].text())
        except Exception as ex:
            self.psswd[1].setText(f'{ex}')
            self.secret[1].setText('Длина пароля должна быть числом!')
            return
        isUpper = self.upperLet[1].isChecked()
        isLower = self.lowerLet[1].isChecked()
        isDig = self.dig[1].isChecked()
        isSpec1 = self.specChar1[1].isChecked()
        isSpec2 = self.specChar2[1].isChecked()
        isSpec3 = self.specChar3[1].isChecked()

        config = {
            'mp':mpsswd,
            'serv':srv,
            'psswdlen': int(lenpsswd) if lenpsswd != '' else 0,
            'upper':isUpper,
            'lower':isLower,
            'dig':isDig,
            'spec1':isSpec1,
            'spec2':isSpec2,
            'spec3':isSpec3
        }
        try:
            self.psswd[1].setText(
                getPsswd(
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
            encrypted = encrypt(json.dumps(config), self.genKey[1].text(), self.genMasterKey[1].text())
            self.secret[1].setText(f'{srv}.{encrypted}')
        except Exception as ex:
            self.psswd[1].setText(f'{ex}')
            self.secret[1].setText('Где-то ошибка!')
            return

    def decoding(self):
        crypt = self.mp[1].text()
        crypt = crypt.split('.')
    
        try:
            config = decrypt(f'{crypt[1]}.{crypt[2]}.{crypt[3]}', self.genKey[1].text(), self.genMasterKey[1].text())
            config = json.loads(config)
        except Exception as ex:
            self.psswd[1].setText(f'{ex}')
            self.secret[1].setText('Где-то ошибка!')        
            return

        self.mp[1].setText(config['mp'])
        self.serv[1].setText(config['serv'])
        self.psswdLen[1].setText(str(config['psswdlen']))
        self.upperLet[1].setChecked(config['upper'])
        self.lowerLet[1].setChecked(config['lower']  )
        self.dig[1].setChecked(config['dig']  )
        self.specChar1[1].setChecked(config['spec1']  )
        self.specChar2[1].setChecked(config['spec2']  )
        self.specChar3[1].setChecked(config['spec3']  )

        self.genpsswd()
        self.mp[1].setText(config['mp'])
        
        return

    def getConfig(self):
        config = generateConfig()
        self.RSAkey[1].setText(config)
        
    def RSAdecode(self):
        try:
            self.RSAoutput[1].setText(unGenSecretRSA(self.RSAkey[1].text(), self.RSAinput[1].text()))
        except Exception as ex:
            self.RSAoutput[1].setText(f'{ex}')
    
    def RSAcode(self):
        try:
            self.RSAoutput[1].setText(genSecretRSA(self.RSAkey[1].text(), self.RSAinput[1].text()))
        except Exception as ex:
            self.RSAoutput[1].setText(f'{ex}')
    
    def shareConfig(self):
        try:
            e, n = getEN(self.RSAkey[1].text())
            self.RSAoutput[1].setText(f'{e}.{n}')
        except Exception as ex:
            self.RSAoutput[1].setText(f'{ex}')
        
    def encrypter(self):
        
        self.tab1 = QWidget()
        self.tab1_layout = QVBoxLayout()
        self.mssg = self.createBlock('Сообщение/Код', "любой текст")
        self.key = self.createBlock('Ключ', "любой текст", YOURkey)
        self.master = self.createBlock('Мастер-ключ', "любой текст", YOURmaster)
        
        self.codebtn = QPushButton("Кодировать")
        self.decodebtn = QPushButton("Декодировать")
        
        self.decoded = QLineEdit()
        
        self.codebtn.clicked.connect(self.code)
        self.decodebtn.clicked.connect(self.decode)
        
        self.addTab(self.tab1_layout, self.mssg)
        self.addTab(self.tab1_layout, self.key)
        self.addTab(self.tab1_layout, self.master)
        self.tab1_layout.addWidget(self.codebtn)
        self.tab1_layout.addWidget(self.decodebtn)
        self.tab1_layout.addWidget(self.decoded)
        
        self.tab1.setLayout(self.tab1_layout)
        
        self.tab_widget.addTab(self.tab1, 'Encrypter')
        
    def generator(self):
        
        self.tab2 = QWidget()
        self.tab2_layout = QVBoxLayout()
        
        self.mp = self.createBlock('Мастер-пароль/Зашифрованный конфиг', "Любой текст", YOURsecurepsswd)
        self.rand = self.createRadio("Рандомный мастер-пароль")
        self.genKey = self.createBlock("Ключ шифрования", "Любой текст", YOURkey)
        self.genMasterKey = self.createBlock("Мастер-ключ шифрования", "Любой текст", YOURmaster)
        self.serv = self.createBlock("Название сервиса (Без точки)", "Любой текст без точки")
        self.psswdLen = self.createBlock("Длина пароля", "Любое число", '8')
        
        self.upperLet = self.createRadio('Верхний регистр')
        self.lowerLet = self.createRadio('Нижний регистр')
        self.dig = self.createRadio('0123456789')
        self.specChar1 = self.createRadio('!@#$%^&*()_+-=')
        self.specChar2 = self.createRadio('\'`,./;:[]}{<>\\|')
        self.specChar3 = self.createRadio('~?')
        
        self.genButton = QPushButton('Сгенерировать')
        
        
        self.psswd = self.createBlock('Ваш пароль')
        self.secret = self.createBlock('Конфиг генерации пароля', "Сохраните его!")
        self.genButton.clicked.connect(self.check)
        
        self.addTab(self.tab2_layout, self.mp)
        self.tab2_layout.addWidget(self.getHWidget(self.rand))
        self.addTab(self.tab2_layout, self.genKey)
        self.addTab(self.tab2_layout, self.genMasterKey)
        self.addTab(self.tab2_layout, self.serv)
        self.addTab(self.tab2_layout, self.psswdLen)
        self.tab2_layout.addWidget(self.getHWidget(self.upperLet))
        self.tab2_layout.addWidget(self.getHWidget(self.lowerLet))
        self.tab2_layout.addWidget(self.getHWidget(self.dig))
        self.tab2_layout.addWidget(self.getHWidget(self.specChar1))
        self.tab2_layout.addWidget(self.getHWidget(self.specChar2))
        self.tab2_layout.addWidget(self.getHWidget(self.specChar3))
        self.tab2_layout.addWidget(self.genButton)

        self.tab2.setLayout(self.tab2_layout)
        
        self.addTab(self.tab2_layout, self.psswd)
        self.addTab(self.tab2_layout, self.secret)
        
        
        self.tab_widget.addTab(self.tab2, 'Generator')
        
    def RSAgenerator(self):
        self.tab3 = QWidget()
        self.tab3_layout = QVBoxLayout()
        
        self.RSAgenbtn = QPushButton('Сгенерировать RSA ключ')
        self.RSAgenbtn.clicked.connect(self.getConfig)
        self.RSAsharebtn = QPushButton('Получить открытый RSA ключ')
        self.RSAsharebtn.clicked.connect(self.shareConfig)
        self.RSAcodebtn = QPushButton('Кодировать')
        self.RSAcodebtn.clicked.connect(self.RSAcode)
        self.RSAdecodebtn = QPushButton('Декодировать')
        self.RSAdecodebtn.clicked.connect(self.RSAdecode)
        
        self.RSAinput = self.createBlock('Сообщение/код')
        self.RSAkey = self.createBlock('RSA-ключ')
        self.RSAoutput = self.createBlock('')
        
        self.tab3_layout.addWidget(self.RSAgenbtn)
        self.tab3_layout.addWidget(self.RSAsharebtn)
        self.addTab(self.tab3_layout, self.RSAinput)
        self.addTab(self.tab3_layout, self.RSAkey)
        self.tab3_layout.addWidget(self.RSAcodebtn)
        self.tab3_layout.addWidget(self.RSAdecodebtn)
        self.addTab(self.tab3_layout, self.RSAoutput)
        
        self.tab3.setLayout(self.tab3_layout)
        
        self.tab_widget.addTab(self.tab3, 'RSAgenerator')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
