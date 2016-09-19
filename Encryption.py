import base64
from random import randint
from Crypto.Cipher import AES
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
