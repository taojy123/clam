# python3.7
# pip install cryptography==2.6.1
# pip install pyaes==1.6.1

import os
import hashlib
import hmac
import traceback

import pyaes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# default_backend：cryptography.hazmat.backends.openssl.backend

from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter.filedialog import askopenfilename


HKEY = b'clam'


def try_run(func):

    def f(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            err = traceback.format_exc()
            messagebox.showerror(title='遇到错误', message=err)

    return f


@try_run
def generate_keys():

    if not all([password_a.get(), password_b.get(), password_c.get()]):
        messagebox.showwarning(title='提示', message='请三人都填写密码')
        return

    if password_a.get() != password_a2.get() or password_b.get() != password_b2.get() or password_c.get() != password_c2.get():
        messagebox.showwarning(title='提示', message='两次输入密码不匹配，请重新输入!')
        password_a2.set('')
        password_b2.set('')
        password_c2.set('')
        return

    hkey = HKEY
    hkey = hmac.new(hkey, password_a.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, password_b.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, password_c.get().encode(), hashlib.sha256).digest()

    assert len(hkey) == 32

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_pem = public_pem.decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(hkey),
        # BestAvailableEncryption evp_cipher: self._lib.EVP_get_cipherbyname(b"aes-256-cbc")
        # encryption_algorithm=serialization.NoEncryption(),
    )
    private_pem = private_pem.decode()

    pubkey.delete(0.0, END)
    pubkey.insert(END, public_pem)
    prikey.delete(0.0, END)
    prikey.insert(END, private_pem)

    f_passwords.pack_forget()
    f_keys.pack()


@try_run
def select_encrypt_file():
    encrypt_path.set(askopenfilename())


@try_run
def encrypt():
    filename = encrypt_path.get().strip()
    if not filename:
        messagebox.showwarning(title='提示', message='请先选择要加密的文件')
        return

    public_pem = encrypt_pubkey.get(0.0, END).strip()
    if '-----' not in public_pem:
        messagebox.showwarning(title='提示', message='请正确填写加密公钥')
        return

    secret = os.urandom(32)
    assert len(secret) == 32

    content = open(filename, 'rb').read()

    aes = pyaes.AESModeOfOperationCTR(secret)
    content_en = aes.encrypt(content)

    public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
    secret_en = public_key.encrypt(secret, padding.PKCS1v15())
    assert len(secret_en) == 256

    content_en = secret_en + content_en

    filename += '.cen'
    open(filename, 'wb').write(content_en)
    messagebox.showinfo(title='提示', message='加密成功，已保存至 %s' % filename)


@try_run
def select_decrypt_file():
    decrypt_path.set(askopenfilename())


@try_run
def decrypt():

    if not all([decrypt_password_a.get(), decrypt_password_b.get(), decrypt_password_c.get()]):
        messagebox.showwarning(title='提示', message='请三人都填写密码')
        return

    filename = decrypt_path.get().strip()
    if not filename:
        messagebox.showwarning(title='提示', message='请先选择要解密的文件')
        return

    private_pem = decrypt_prikey.get(0.0, END).strip()
    if '-----' not in private_pem:
        messagebox.showwarning(title='提示', message='请正确填写解密私钥')
        return

    content_en = open(filename, 'rb').read()
    secret_en = content_en[:256]
    content_en = content_en[256:]
    
    hkey = HKEY
    hkey = hmac.new(hkey, decrypt_password_a.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, decrypt_password_b.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, decrypt_password_c.get().encode(), hashlib.sha256).digest()

    private_key = serialization.load_pem_private_key(private_pem.encode(), password=hkey, backend=default_backend())
    secret = private_key.decrypt(secret_en, padding.PKCS1v15())

    assert len(secret) == 32


    aes = pyaes.AESModeOfOperationCTR(secret)
    content_de = aes.decrypt(content_en)


    if filename.endswith('.cen'):
        filename = filename[:-4]
    else:
        filename += '.cde'
    open(filename, 'wb').write(content_de)
    messagebox.showinfo(title='提示', message='解密成功，已保存至 %s' % filename)


root = Tk()
root.title('联合授权加解密工具 clam v1.0 ')
password_a = StringVar()
password_b = StringVar()
password_c = StringVar()
password_a2 = StringVar()
password_b2 = StringVar()
password_c2 = StringVar()
encrypt_path = StringVar()
decrypt_password_a = StringVar()
decrypt_password_b = StringVar()
decrypt_password_c = StringVar()
decrypt_path = StringVar()

n = ttk.Notebook(root)
n.pack()

f1 = Frame(n)
f2 = Frame(n)
f3 = Frame(n)

n.add(f1, text='生成密钥')
n.add(f2, text='加密文件')
n.add(f3, text='解密文件')


f_passwords = Frame(f1)

Label(f_passwords, text='请三位依次输入密码：').grid(row=0, column=0, sticky=W)
Entry(f_passwords, textvariable=password_a, show='*', width=22).grid(row=1, column=0)
Entry(f_passwords, textvariable=password_b, show='*', width=22).grid(row=1, column=1)
Entry(f_passwords, textvariable=password_c, show='*', width=22).grid(row=1, column=2)

Label(f_passwords, text='请再次输入密码确认：').grid(row=2, column=0, sticky=W)
Entry(f_passwords, textvariable=password_a2, show='*', width=22).grid(row=3, column=0)
Entry(f_passwords, textvariable=password_b2, show='*', width=22).grid(row=3, column=1)
Entry(f_passwords, textvariable=password_c2, show='*', width=22).grid(row=3, column=2)

Button(f_passwords, text="生成密钥", command=generate_keys).grid(row=4, column=1)

f_passwords.pack()


f_keys = Frame(f1)

Label(f_keys, text='加密公钥:').pack()
pubkey = Text(f_keys, width=66, height=10)
pubkey.pack()
pubkey.delete(0.0, END)
pubkey.insert(END, 'pub')

Label(f_keys, text='解密私钥:').pack()
prikey = Text(f_keys, width=66, height=31)
prikey.pack()
prikey.delete(0.0, END)
prikey.insert(END, 'pri')

Label(f_keys, text='请务必牢记生成的密钥并保存！！').pack()


Button(f2, text="选择要加密的文件", command=select_encrypt_file).pack()
Entry(f2, textvariable=encrypt_path, width=66).pack()
Label(f2, text='填写加密公钥').pack()
encrypt_pubkey = Text(f2, width=66, height=10)
encrypt_pubkey.pack()
Button(f2, text="加密", command=encrypt).pack()


f_decrypt_passwords = Frame(f3)

Label(f_decrypt_passwords, text='请三位依次输入密码：').grid(row=0, column=0, sticky=W)
Entry(f_decrypt_passwords, textvariable=decrypt_password_a, show='*', width=22).grid(row=1, column=0)
Entry(f_decrypt_passwords, textvariable=decrypt_password_b, show='*', width=22).grid(row=1, column=1)
Entry(f_decrypt_passwords, textvariable=decrypt_password_c, show='*', width=22).grid(row=1, column=2)

f_decrypt_passwords.pack()


Button(f3, text="选择要解密的文件", command=select_decrypt_file).pack()
Entry(f3, textvariable=decrypt_path, width=66).pack()
Label(f3, text='填写解密私钥').pack()
decrypt_prikey = Text(f3, width=66, height=31)
decrypt_prikey.pack()
Button(f3, text="解密", command=decrypt).pack()


root.mainloop()





