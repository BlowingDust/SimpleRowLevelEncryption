# 使用示例

import os
from Encryption import AESCipher, b64encode, b64decode, random_pwd, RSAEncryption


def get_files_list(ext):
    files_list = os.listdir(os.getcwd())
    return [file for file in files_list if file.endswith('.{}'.format(ext))]


def aes_decrypt(pwd):
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


def aes_encrypt(pwd):
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


def demo_1():
    # 生成随机密码，对于 AES 加密，密码长度必须为 (16, 24, 32) 之一
    password = random_pwd(32)
    print(password)
    # AES 加密
    # aes_encrypt(password)
    # AES 解密
    # aes_decrypt(password)


def demo_2():
    # RSA 私钥文件路径
    priv_key_path = os.getcwd() + '/priv.pem'
    # RSA 公钥文件路径
    pub_key_path = os.getcwd() + '/pub.pem'
    # 如果只用 RSA 解密，可以只提供私钥文件路径，加密同理。
    # 如果要生成 RSA 公私钥，则两者都要提供。
    # 计算生成密钥对需要一定的时间
    rsa = RSAEncryption(priv_key_path, pub_key_path).generate_key()

    # 生成随机密码，对于 AES 加密，密码长度必须为 (16, 24, 32) 之一
    password = random_pwd(32)
    print(password)
    # 保存用 RSA 加密的密码
    pwd_path = os.getcwd() + '/pwd'
    rsa.save_pwd(password, pwd_path)
    # 读取用 RSA 加密的密码
    password = rsa.get_pwd(pwd_path)
    print(password)

    # 重点是上面用 RSA 对密码加解密的操作，获得密码后，下面就是常规的 AES 加密操作了
    # AES 加密
    # aes_encrypt(password)
    # AES 解密
    # aes_decrypt(password)


def demos():
    # 1、AES 加密文本
    # demo_1()
    # 2、RSA 加密 AES 密码，AES 加密文本
    # demo_2()
    pass


if __name__ == '__main__':
    demos()
