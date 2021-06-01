import base64
import hashlib
from Cryptodome.Cipher import AES as domeAES
from Cryptodome.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES as cryptoAES
f = open("ex.txt", "r")
import PyPDF2
pdfFileObj = open('example.pdf', 'rb')
pdfReader = PyPDF2.PdfFileReader(pdfFileObj)
pageObj = pdfReader.getPage(0)
datapdf  = (pageObj.extractText())

BLOCK_SIZE = domeAES.block_size

key = "my_secret_key".encode()
__key__ = hashlib.sha256(key).digest()
print(__key__)

def encrypt(raw):
    BS = cryptoAES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(cryptoAES.block_size)
    cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
    a= base64.b64encode(iv + cipher.encrypt(raw))
    IV = Random.new().read(BLOCK_SIZE)
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    b = base64.b64encode(IV + aes.encrypt(a))
    return b

def decrypt(enc):
    passphrase = __key__
    encrypted = base64.b64decode(enc)
    IV = encrypted[:BLOCK_SIZE]
    aes = domeAES.new(passphrase, domeAES.MODE_CFB, IV)
    enc = aes.decrypt(encrypted[BLOCK_SIZE:])
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:cryptoAES.block_size]
    cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
    b=  unpad(base64.b64decode(cipher.decrypt(enc[cryptoAES.block_size:])).decode('utf8'))
    return b
#print(f.read())
encrypted_data =encrypt(f.read())
encrypted_datapdf =encrypt(datapdf)
dataen = str(encrypted_data)
dataenpdf = str(encrypted_datapdf)

Da =  dataen[2:130]

print(encrypted_data)
print((dataenpdf))
#print(len(encrypted_data))
#print(Da)
print("=============================")
decrypted_data = decrypt(encrypted_data)
decrypted_datapdf = decrypt(encrypted_datapdf)
print(decrypted_data)
#print(decrypted_datapdf)

f = open("encrypted_data.txt", "w")
f.write("%s"%Da)
f.close()

f = open("encrypted_datapdf.txt", "w")
f.write("%s"%dataenpdf)
f.close()

#print(datapdf)
