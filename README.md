# Simple Row-Level Encryption

简单的行级加密。本程序的目的在于，使得加密后的文本文件可用版本管理工具在行级范围内对其改动进行记录和跟踪。
方法是，对文本的每行内容使用 AES 的 CFB 模式加密后再进行 base64 编码，并回写到原文件。

## Requirements
* Python 3
* PyCrypto

## Usage

参考 ``Demo.py``

## Todo
- [x] 增量加密
- [x] 使用 RSA 公钥加密 AES 密钥
