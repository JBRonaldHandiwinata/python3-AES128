import base64
from hashlib import md5
from Crypto.Cipher import AES


class AesCrypto:

    def aes_encrypt(self, rawstr, key_hex):
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        mdkey = md5(base64.b64decode(key_hex.encode('ascii'))).digest()
        cipher = AES.AESCipher(mdkey, AES.MODE_ECB)
        return cipher.encrypt(pad(rawstr)).hex()

    def aes_decrypt(self, sign, key_hex):
        key = md5(base64.b64decode(key_hex.encode('ascii'))).digest()
        cipher = AES.AESCipher(key, AES.MODE_ECB)
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        return unpad(cipher.decrypt(bytes.fromhex(sign))).decode()