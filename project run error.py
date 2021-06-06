import tkinter as tk
import tkinter.font as tkFont
import base64
import hashlib
from Cryptodome.Cipher import AES as domeAES
from Cryptodome.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES as cryptoAES
import os
import os.path
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from art import *
import codecs
print("#############"*10)
Art=text2art("B6111090",font='block',chr_ignore=True) # Return ASCII text with block font
print(Art)
tprint("Poommin","rnd-xlarge")
print("#############"*10)
#tprint("Phinphimai","rnd-xlarge")
#clear terminal
#clear = lambda: os.system("cls")

#Gen Key RSA
key = RSA.generate(2048)

#private key
private_key = key.export_key()
with open("private.key", "wb") as f:
    f.write(private_key)

#pubic key
public_key = key.publickey().export_key()
with open("public.key", "wb") as f:
    f.write(public_key)

# Encrypt & DeCrypt TEXT
#block size
BS = cryptoAES.block_size

#gen key aes
def genkeyaes():
    key = get_random_bytes(32)
    print(key)
    k = codecs.decode(key, 'UTF-16')

    #k = __key__.decode('utf-16')
    print(type(k))
    print(k)
    with open("aes.txt", "w", encoding="utf-16") as f:
        f.write(k)
    #return(key)
genkeyaes()
#key = genkeyaes()
with open('aes.txt', 'r', encoding="utf-16") as f:
    kk = f.read()

key = codecs.encode(kk, 'UTF-16')
__key__ = hashlib.sha256(key).digest()
#__key__ = bytes(__key__, 'utf-16')
#__key__ = hashlib.sha256(key).digest()
print(__key__)

#function encrypt text
def ent(raw):
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = get_random_bytes(BS)
    cipher = cryptoAES.new(key= __key__, mode= cryptoAES.MODE_CFB,iv= iv)
    a= base64.b64encode(iv + cipher.encrypt(raw))
    IV = Random.new().read(BS)
    aes = domeAES.new(__key__, domeAES.MODE_CFB, IV)
    b = base64.b64encode(IV + aes.encrypt(a))
    return b

#function decrypt text
def det(enc):
    passphrase = __key__
    encrypted = base64.b64decode(enc)
    IV = encrypted[:BS]
    aes = domeAES.new(passphrase, domeAES.MODE_CFB, IV)
    enc = aes.decrypt(encrypted[BS:])
    unpad = lambda s: s[:-ord(s[-1:])]
    enc = base64.b64decode(enc)
    iv = enc[:cryptoAES.block_size]
    cipher = cryptoAES.new(__key__, cryptoAES.MODE_CFB, iv)
    b=  unpad(base64.b64decode(cipher.decrypt(enc[cryptoAES.block_size:])).decode('utf8'))
    return b

#encrypt + digittal signa
def en_text(data_s):
    #encrypt
    with open(data_s, 'r') as f:
        s = f.read()
    with open(data_s, 'wb+') as f:
        en_d = ent(s)
        f.write(en_d)

    #digitalSig
    key = RSA.import_key(open('private.key').read())

    mes = s.encode('utf_8')
    h = SHA512.new(mes)

    sg = pkcs1_15.new(key)
    signa = sg.sign(h)

    with open("signature.txt", "wb") as f:
        f.write(signa)

#decrypt + digital signa
def de_text(data_s):
    #decrypt
    with open(data_s, 'rb') as f:
        s = f.read()
    with open(data_s,"w+") as f:
        de_d = det(s)
        f.write(de_d)

    #digital veri
    key = RSA.import_key(open('public.key').read())
    with open("signature.txt", "rb") as f:
        signa = f.read()

    mes = de_d.encode('utf_8')
    h = SHA512.new(mes)

    try:
        pkcs1_15.new(key).verify(h, signa)
       # print("Digital Signa !!")
        tprint("Signa", "rnd-xlarge")
    except (ValueError, TypeError):
        print("Help Plaease")

#Encrypt & Decrypt File
class En:
    #key aes
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    #encrypt for file
    def en(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    #encrypt file
    def en_f(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.en(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    #decrypt for file
    def de(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    #decrypt file
    def de_f(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.de(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

#key aes
enc = En(key)
class App:

    def __init__(self, root):
        #setting title
        root.title("B6111090 Poommin Phinphimai")
        #setting window size
        width=600
        height=500
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        GMessage_366=tk.Message(root)
        GMessage_366["bg"] = "#8338ec"
        ft = tkFont.Font(family='Times',size=23)
        GMessage_366["font"] = ft
        GMessage_366["fg"] = "#fffbfd"
        GMessage_366["justify"] = "left"
        GMessage_366["text"] = ""
        GMessage_366.place(x=0,y=30,width=601,height=69)

        GMessage_862=tk.Message(root)
        GMessage_862["bg"] = "#fb5607"
        ft = tkFont.Font(family='Times',size=23)
        GMessage_862["font"] = ft
        GMessage_862["fg"] = "#ffffff"
        GMessage_862["justify"] = "center"
        GMessage_862["text"] = ""
        GMessage_862.place(x=0,y=410,width=599,height=56)

        GMessage_415=tk.Message(root)
        GMessage_415["bg"] = "#3a86ff"
        ft = tkFont.Font(family='Times',size=18)
        GMessage_415["font"] = ft
        GMessage_415["fg"] = "#ffffff"
        GMessage_415["justify"] = "center"
        GMessage_415["text"] = "Text"
        GMessage_415.place(x=90,y=130,width=135,height=54)

        GButton_983=tk.Button(root)
        GButton_983["bg"] = "#92bdfc"
        ft = tkFont.Font(family='Times',size=16)
        GButton_983["font"] = ft
        GButton_983["fg"] = "#000000"
        GButton_983["justify"] = "center"
        GButton_983["text"] = "Encrypt Text"
        GButton_983.place(x=80,y=210,width=162,height=64)
        GButton_983["command"] = self.GButton_983_command

        GButton_286=tk.Button(root)
        GButton_286["bg"] = "#92bdfc"
        ft = tkFont.Font(family='Times',size=16)
        GButton_286["font"] = ft
        GButton_286["fg"] = "#000000"
        GButton_286["justify"] = "center"
        GButton_286["text"] = "Decrypt Text"
        GButton_286.place(x=80,y=290,width=163,height=64)
        GButton_286["command"] = self.GButton_286_command

        GMessage_246=tk.Message(root)
        GMessage_246["bg"] = "#ff006e"
        ft = tkFont.Font(family='Times',size=16)
        GMessage_246["font"] = ft
        GMessage_246["fg"] = "#f9f9f9"
        GMessage_246["justify"] = "center"
        GMessage_246["text"] = "All File"
        GMessage_246.place(x=350,y=130,width=135,height=53)

        GButton_847=tk.Button(root)
        GButton_847["bg"] = "#ff74b0"
        ft = tkFont.Font(family='Times',size=16)
        GButton_847["font"] = ft
        GButton_847["fg"] = "#000000"
        GButton_847["justify"] = "center"
        GButton_847["text"] = "Encrypt File"
        GButton_847.place(x=340,y=210,width=161,height=63)
        GButton_847["command"] = self.GButton_847_command

        GButton_215=tk.Button(root)
        GButton_215["bg"] = "#ff74b0"
        ft = tkFont.Font(family='Times',size=16)
        GButton_215["font"] = ft
        GButton_215["fg"] = "#000000"
        GButton_215["justify"] = "center"
        GButton_215["text"] = "Decrypt File"
        GButton_215.place(x=340,y=290,width=163,height=64)
        GButton_215["command"] = self.GButton_215_command

    def GButton_983_command(self):
        print("Text Encrypt")
        def show_entry_fields():
            print("Data Name: %s" % (e1.get()))
            en_text(e1.get())

        master = tk.Tk()
        tk.Label(master,
                 text="DataName").grid(row=0)
        e1 = tk.Entry(master)
        e1.grid(row=0, column=1)
        tk.Button(master,text='OK', command=show_entry_fields).grid(row=3,column=1,sticky=tk.W, pady=4)
        tk.mainloop()


    def GButton_286_command(self):
        print("decrypt text")
        def show_entry_fields():
            print("Data Name: %s" % (e1.get()))
            de_text(e1.get())

        master = tk.Tk()
        tk.Label(master,
                 text="DataName").grid(row=0)
        e1 = tk.Entry(master)
        e1.grid(row=0, column=1)
        tk.Button(master,text='OK', command=show_entry_fields).grid(row=3,column=1,sticky=tk.W, pady=4)
        tk.mainloop()


    def GButton_847_command(self):
        print("En All files")
        def show_entry_fields():
            print("Data Name: %s" % (e1.get()))
            enc.en_f(e1.get())

        master = tk.Tk()
        tk.Label(master,
                 text="DataName").grid(row=0)
        e1 = tk.Entry(master)
        e1.grid(row=0, column=1)
        tk.Button(master, text='OK', command=show_entry_fields).grid(row=3, column=1, sticky=tk.W, pady=4)
        tk.mainloop()


    def GButton_215_command(self):
        print("De All files")
        def show_entry_fields():
            print("Data Name: %s" % (e1.get()))
            enc.de_f(e1.get())

        master = tk.Tk()
        tk.Label(master,
                 text="DataName").grid(row=0)
        e1 = tk.Entry(master)
        e1.grid(row=0, column=1)
        tk.Button(master, text='OK', command=show_entry_fields).grid(row=3, column=1, sticky=tk.W, pady=4)
        tk.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
