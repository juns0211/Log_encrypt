import logging
from Crypto.Cipher import AES
import base64
import hashlib


class EncryptedLogFormatter(logging.Formatter):

    def __init__(self, key='juns1984', fmt=None, datefmt=None):
        self._key = hashlib.md5(key.encode('utf-8')).hexdigest().encode()
        super(EncryptedLogFormatter, self).__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record):
        message = record.msg
        if message:
            cipher = AES.new(self._key, AES.MODE_CFB,self._key[:16])
            message_enc = cipher.encrypt(bytes(message, encoding = 'utf-8'))
            record.msg = '//Cut//' + base64.b64encode(message_enc).decode("utf-8")
        return super(EncryptedLogFormatter, self).format(record)


def log_decryptor(key, log, path:str):
    key = hashlib.md5(key.encode('utf-8')).hexdigest().encode()
    fp = open(path,'a')
    for i in log:
        if not i.strip():
            continue
        time_level, stream = i.split('//Cut//', 1)
        cryptor = AES.new(key, AES.MODE_CFB, key[:16])
        data = base64.b64decode(stream)
        data = cryptor.decrypt(data).decode()
        fp.write(time_level + data + '\n')
    fp.close()