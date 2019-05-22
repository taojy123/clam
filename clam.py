# python3.7
# pip install cryptography==2.6.1

import os
import hashlib
import hmac
import base64
import traceback

from cryptography.fernet import Fernet
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
        except Exception as e:
            err = traceback.format_exc()
            messagebox.showerror(title='遇到错误', message=err)
            print(e)

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
    public_pem = public_pem.decode().strip()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(hkey),
        # BestAvailableEncryption evp_cipher: self._lib.EVP_get_cipherbyname(b"aes-256-cbc")
        # encryption_algorithm=serialization.NoEncryption(),
    )
    private_pem = private_pem.decode().strip()

    assert len(private_pem) == len(private_pem.encode()) == 1873

    rsa_key_content = public_pem + '\n==========\n' + private_pem

    assert rsa_key_content.startswith('-----BEGIN PUBLIC KEY-----')
    assert rsa_key_content.endswith('-----END ENCRYPTED PRIVATE KEY-----')
    assert '-----END PUBLIC KEY-----\n==========\n-----BEGIN ENCRYPTED PRIVATE KEY-----' in rsa_key_content
    assert len(rsa_key_content.split('\n==========\n')) == 2

    rsa_key.delete(0.0, END)
    rsa_key.insert(END, rsa_key_content)

    # f_passwords.pack_forget()
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

    rsa_key_content = encrypt_key.get(0.0, END).strip()
    if not all([
        rsa_key_content.startswith('-----BEGIN PUBLIC KEY-----'),
        rsa_key_content.endswith('-----END ENCRYPTED PRIVATE KEY-----'),
        '-----END PUBLIC KEY-----\n==========\n-----BEGIN ENCRYPTED PRIVATE KEY-----' in rsa_key_content,
        len(rsa_key_content.split('\n==========\n')) == 2,
    ]):
        messagebox.showwarning(title='提示', message='请正确填写加密公钥')
        return

    public_pem, private_pem = rsa_key_content.split('\n==========\n')
    assert len(private_pem) == 1873

    content = open(filename, 'rb').read()

    secret = BytesBaseFernet.generate_key()
    bbf = BytesBaseFernet(secret)
    content_en = bbf.encrypt(content)

    public_key = serialization.load_pem_public_key(public_pem.encode(), backend=default_backend())
    secret_en = public_key.encrypt(secret, padding.PKCS1v15())
    assert len(secret_en) == 256

    content_en = private_pem.encode() + secret_en + content_en

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

    content_en = open(filename, 'rb').read()
    private_pem = content_en[:1873]
    secret_en = content_en[1873:1873 + 256]
    content_en = content_en[1873 + 256:]

    hkey = HKEY
    hkey = hmac.new(hkey, decrypt_password_a.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, decrypt_password_b.get().encode(), hashlib.sha256).digest()
    hkey = hmac.new(hkey, decrypt_password_c.get().encode(), hashlib.sha256).digest()

    private_key = serialization.load_pem_private_key(private_pem, password=hkey, backend=default_backend())
    secret = private_key.decrypt(secret_en, padding.PKCS1v15())

    assert len(secret) == 32

    bbf = BytesBaseFernet(secret)
    content_de = bbf.decrypt(content_en)

    if filename.endswith('.cen'):
        filename = filename[:-4]
    else:
        filename += '.cde'
    open(filename, 'wb').write(content_de)
    messagebox.showinfo(title='提示', message='解密成功，已保存至 %s' % filename)


class BytesBaseFernet(Fernet):
    """ algorithms：AES-CBC
    """

    @classmethod
    def generate_key(cls):
        key = os.urandom(32)
        assert len(key) == 32
        return key

    def __init__(self, key, backend=None):
        key = base64.urlsafe_b64encode(key)
        super().__init__(key, backend)

    def encrypt(self, data):
        result = super().encrypt(data)
        result = base64.urlsafe_b64decode(result)
        return result

    def decrypt(self, token, ttl=None):
        token = base64.urlsafe_b64encode(token)
        result = super().decrypt(token, ttl)
        return result


root = Tk()
root.title('联合授权加解密工具 clam v1.2')
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

rsa_key = Text(f_keys, width=66, height=41)
rsa_key.pack()
Label(f_keys, text='请务必牢记以上的密钥并保存！！').pack()

Button(f2, text="选择要加密的文件", command=select_encrypt_file).pack()
Entry(f2, textvariable=encrypt_path, width=66).pack()
Label(f2, text='填写完整的加密密钥').pack()
encrypt_key = Text(f2, width=66, height=41)
encrypt_key.pack()
Button(f2, text="加密", command=encrypt).pack()

f_decrypt_passwords = Frame(f3)

Label(f_decrypt_passwords, text='请三位依次输入密码：').grid(row=0, column=0, sticky=W)
Entry(f_decrypt_passwords, textvariable=decrypt_password_a, show='*', width=22).grid(row=1, column=0)
Entry(f_decrypt_passwords, textvariable=decrypt_password_b, show='*', width=22).grid(row=1, column=1)
Entry(f_decrypt_passwords, textvariable=decrypt_password_c, show='*', width=22).grid(row=1, column=2)

f_decrypt_passwords.pack()

Button(f3, text="选择要解密的文件", command=select_decrypt_file).pack()
Entry(f3, textvariable=decrypt_path, width=66).pack()
Button(f3, text="解密", command=decrypt).pack()

root.mainloop()
