# 使用示例

import os
from Encryption import AESCipher, b64encode, b64decode, random_pwd


def get_files_list(ext):
    files_list = os.listdir(os.getcwd())
    return [file for file in files_list if file.endswith('.{}'.format(ext))]


def demo_1_decrypt(pwd):
    """
    解密当前文件夹下所有 txt 文件
    """
    aes = AESCipher(pwd)
    for txt_file in get_files_list('txt'):
        with open(txt_file, 'r', encoding='utf8') as f:
            contents = [aes.decrypt_line(b64decode(line)).decode() for line in f]
        with open(txt_file, 'w', encoding='utf8') as f:
            f.writelines(contents)
        print('{} 解密完成'.format(txt_file))


def demo_1_encrypt(pwd):
    """
    加密当前文件夹下所有 txt 文件
    """
    aes = AESCipher(pwd)
    for txt_file in get_files_list('txt'):
        with open(txt_file, 'r', encoding='utf8') as f:
            contents = [b64encode(aes.encrypt_line(line)) + '\n' for line in f]
        with open(txt_file, 'w', encoding='utf8') as f:
            f.writelines(contents)
        print('{} 加密完成'.format(txt_file))


if __name__ == '__main__':
    # 生成随机密码，对于 AES 加密，密码长度必须为 (16, 24, 32) 之一
    password = random_pwd(32)
    print(password)
    # 开始加密
    # demo_1_encrypt(password)
    # 开始解密
    # demo_1_decrypt(password)
