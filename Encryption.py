import os
import base64
from random import randint
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from string import ascii_letters, digits, punctuation


class AESCipher:
    def __init__(self, password):
        """
        初始化
        :param password: 密码，长度必须为 16, 24, 32 之一
        """
        self.key = password if isinstance(password, bytes) else bytes(password, encoding='utf8')

    def encrypt_line(self, line):
        if not isinstance(line, bytes):
            line = bytes(line, encoding='utf8')
        iv = Random.new().read(AES.block_size)  # 初始化向量
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(line)

    def decrypt_line(self, line):
        if not isinstance(line, bytes):
            line = bytes(line, encoding='utf8')
        iv = line[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return cipher.decrypt(line[AES.block_size:])


class RSAEncryption:
    def __init__(self, priv_key_path='', pub_key_path=''):
        if priv_key_path and isinstance(priv_key_path, str) and os.path.exists(priv_key_path):
            with open(priv_key_path, 'r') as f:
                self.priv_key = RSA.importKey(f.read())
        else:
            self.priv_key = None
        if pub_key_path and isinstance(pub_key_path, str) and os.path.exists(pub_key_path):
            with open(pub_key_path, 'r') as f:
                self.pub_key = RSA.importKey(f.read())
        else:
            self.pub_key = None
        self.priv_key_path = priv_key_path
        self.pub_key_path = pub_key_path

    def generate_key(self, key_size=4096):
        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()
        with open(self.priv_key_path, 'wb') as f:
            f.write(private_key.exportKey())
        with open(self.pub_key_path, 'wb') as f:
            f.write(public_key.exportKey())
        return RSAEncryption(self.priv_key_path, self.pub_key_path)

    def encrypt_pwd(self, pwd):
        return self.pub_key.encrypt(pwd, None)[0] if self.pub_key else False

    def decrypt_pwd(self, pwd):
        return self.priv_key.decrypt(pwd) if self.priv_key else False

    def save_pwd(self, pwd, pwd_path):
        encrypted_pwd = self.encrypt_pwd(pwd)
        with open(pwd_path, 'wb') as f:
            f.write(encrypted_pwd)
        return True

    def get_pwd(self, pwd_path):
        with open(pwd_path, 'rb') as f:
            pwd = f.read()
        return self.decrypt_pwd(pwd)


def random_pwd(pwd_length):
    if pwd_length < 1:
        return False
    sample_string = ascii_letters + digits + punctuation
    sample_len = len(sample_string)
    return bytes(''.join([sample_string[randint(0, sample_len - 1)] for _ in range(pwd_length)]), encoding='utf8')


def b64encode(content):
    return base64.b64encode(content).decode()


def b64decode(content):
    return base64.b64decode(content)
