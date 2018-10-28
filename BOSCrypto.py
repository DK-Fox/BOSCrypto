from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP as cp
from Crypto.Signature import PKCS1_v1_5 as sp
from Crypto.Hash import SHA
import sys
import getopt

class UseCrypto():
    def __init__(self, str):
        self._str = str

    @staticmethod
    def ramdom16():
        return Random.new().read(16)

    @staticmethod
    def output_rsa():
        random_generator=Random.new().read
        # rsa算法生成实例
        rsa = RSA.generate(1024, random_generator)

        # master的密钥对的生成
        private_pem = rsa.exportKey()

        with open('master-private.pem', 'wb') as f:
            f.write(private_pem)

        public_pem = rsa.publickey().exportKey()
        with open('master-public.pem', 'wb') as f:
            f.write(public_pem)

    def encode_RSAcrypt(self,keyfile):
        with open(keyfile, 'rb') as f:
            key = f.read()
        rsakey = RSA.importKey(key)
        cipher = cp.new(rsakey)
        return cipher.encrypt(self._str)

    def decode_RSAcrypt(self,keyfile):
        with open(keyfile, 'rb') as f:
            key = f.read()
        rsakey = RSA.importKey(key)
        cipher = cp.new(rsakey)
        return cipher.decrypt(self._str)

    def sign_RSAcrypt(self,keyfile):
        with open(keyfile, 'rb') as f:
            key = f.read()
        rsakey = RSA.importKey(key)
        signer = sp.new(rsakey)
        digest = SHA.new()
        digest.update(self._str)
        return signer.sign(digest)

    def verify_RSAcrypt(self,keyfile):
        with open(keyfile, 'rb') as f:
            key = f.read()
        rsakey = RSA.importKey(key)
        verifier = sp.new(rsakey)
        digest = SHA.new()
        digest.update(self._str)
        return verifier.sign(digest)

    def align(self):
        zerocount=16-len(self._str)%16
        self._str=self._str+b'\0'*zerocount

    def encrypt_EBC(self,key):
        self.align()
        AESCipher=AES.new(key,AES.MODE_ECB)
        return AESCipher.encrypt(self._str)

    def decrypt_EBC(self,key):
        AESCipher=AES.new(key,AES.MODE_ECB)
        return AESCipher.decrypt(self._str)

class CryptoCenerateFile():
    def __init__(self,textfile=None,cryptofile=None,rsafile=None,authenticationfile=None):
        self._textfile=textfile
        self._cryptofile=cryptofile
        self._rsafile=rsafile
        self._authenticationfile=authenticationfile

    @staticmethod
    def gernerateRSA():
        UseCrypto.output_rsa()

    def encode(self):
        key=UseCrypto.ramdom16()
        #AES加密
        with open(self._cryptofile, 'wb') as cf:
            with open(self._textfile,'rb') as tf:
                count=tf.read(16)
                while len(count)>0:
                    cipherline=UseCrypto(count).encrypt_EBC(key)
                    cf.write(cipherline)
                    count=tf.read(16)

        with open(self._authenticationfile, 'wb') as af:
            # RSA加密
            print(key)
            rsakey=UseCrypto(key).encode_RSAcrypt('master-public.pem')
            print(len(rsakey))
            af.write(rsakey)

    def decode(self):
        with open(self._authenticationfile, 'rb') as af:
            aeskey=af.read(128)
            print(len(aeskey))
            key=UseCrypto(aeskey).decode_RSAcrypt('master-private.pem')
            print(key)

        #AES解密
        with open(self._cryptofile,'rb') as cf:
            with open(self._textfile, 'wb') as tf:
                count=cf.read(16)
                while len(count)>0:
                    print(len(count))
                    textline=UseCrypto(count).decrypt_EBC(key)
                    tf.write(textline)
                    count=cf.read(16)


if __name__ == '__main__':
    opt={}
    opts,_=getopt.getopt(sys.argv[1:],'f:r:o:a:m:')
    for o,v in opts:
        if o=='-f':
            opt['textfile']=v
        if o=='-r':
            opt['rsafile']=v
        if o=='-o':
            opt['cryptofile']=v
        if o=='-a':
            opt['authenticationfile']=v
        if o=='-m':
            opt['menu']=v

    if opt['menu']=='gen':
        CryptoCenerateFile().gernerateRSA()
    elif opt['menu']=='en':
        CryptoCenerateFile(opt['textfile'],opt['cryptofile'],opt['rsafile'],opt['authenticationfile']).encode()
    elif opt['menu']=='de':
        CryptoCenerateFile(opt['textfile'],opt['cryptofile'],opt['rsafile'],opt['authenticationfile']).decode()
    else:
        print('-f textfile,-r rsafile,-o cryptofile,-a authenticationfile')

    # UseCrypto('master-private.pem', 'text', 'signfile').sign_RSAcrypt()
    # UseCrypto('master-public.public_pem', 'sign_after', 'signfile').verify_RSAcrypt()
