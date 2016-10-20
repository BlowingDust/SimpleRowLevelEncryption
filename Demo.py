# 使用示例

import os
from Encryption import AESCipher, b64encode, b64decode, random_pwd, RSAEncryption

# 自行定义换行符 or 回车符
LINE_BREAK = '\n'


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
            contents = [b64encode(aes.encrypt_line(line)) + LINE_BREAK for line in f]
        with open(txt_file, 'w', encoding='utf8') as f:
            f.writelines(contents)
        print('{} 加密完成'.format(txt_file))


def incremental_aes_encrypt(pwd, mark='*'):
    """
    增量加密。
    :param pwd: 密码
    :param mark: 区分加密与否的标识
                 该标识应在文件中独占一行，表示在其上的文本行均已加密，其下的文本行均未加密
                 注意标识不应有与 base64 编码后的密文相同的可能性
    """
    aes = AESCipher(pwd)
    for txt_file in get_files_list('txt'):
        with open(txt_file, 'r', encoding='utf8') as f:
            contents = f.readlines()
        encrypt_contents = encrypt_new_contents(aes, contents, mark)
        if encrypt_contents is False:
            # 跳过无标识的文件
            print('{} 未找到标识'.format(txt_file))
            continue

        with open(txt_file, 'w', encoding='utf8') as f:
            f.writelines(encrypt_contents)
            # 追加加密标识行
            f.writelines(mark)
        print('{} 加密完成'.format(txt_file))


def encrypt_new_contents(aes, contents, mark):
    """
    查找并加密增加的新内容，如果未找到标志符，返回 False
    如果想要加密全新的文件，可以更改此函数，或手动在新文件首行加入 mark
    注意，在 Windows 记事本中编辑 utf8 文本后会自动在文件开头加上 BOM，将导致识别 mark 失败，解决方法很多，就不细说了
    """
    for i, line in enumerate(contents):
        if line.startswith(mark):
            encrypt_contents = contents[:i]
            new_contents = [b64encode(aes.encrypt_line(l)) + LINE_BREAK for l in contents[i + 1:]]
            encrypt_contents.extend(new_contents)
            return encrypt_contents
    return False


def incremental_aes_decrypt(pwd, mark='*'):
    """
    针对增量加密的全文解密。
    通常情况下没必要频繁解密之前已加密的内容，否则该使用场景并不适宜用增量加密。
    """
    aes = AESCipher(pwd)
    for txt_file in get_files_list('txt'):
        with open(txt_file, 'r', encoding='utf8') as f:
            contents = f.readlines()
        for i, line in enumerate(contents):
            if line.startswith(mark):
                decrypt_contents = [aes.decrypt_line(b64decode(line)).decode() for line in contents[:i]]
                decrypt_contents.extend(contents[i + 1:])
                break
        else:
            continue

        with open(txt_file, 'w', encoding='utf8') as f:
            f.writelines('*' + LINE_BREAK)
            f.writelines(decrypt_contents)
        print('{} 解密完成'.format(txt_file))


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


def demo_3():
    password = random_pwd(32)
    print(password)
    # 增量加密
    incremental_aes_encrypt(password)
    # 对增量加密的全文解密
    incremental_aes_decrypt(password)


def demos():
    # 1、AES 加密文本
    # demo_1()
    # 2、RSA 加密 AES 密码，AES 加密文本
    # demo_2()
    # 3、AES 增量加密、解密
    # demo_3()
    pass


if __name__ == '__main__':
    demos()
