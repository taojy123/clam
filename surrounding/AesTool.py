import os
import base64

from Crypto.Cipher import AES       #注：python3 安装 Crypto 是 pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple pycryptodome


def pkcs7padding(text):
    """
    明文使用PKCS7填充
    最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
    :param text: 待加密内容(明文)
    :return:
    """
    bs = AES.block_size  # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # tips：utf-8编码时，英文占1个byte，而中文占3个byte
    padding_size = length if(bytes_length == length) else bytes_length
    padding = bs - padding_size % bs
    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    padding_text = chr(padding) * padding
    return text + padding_text
 
 
def pkcs7unpadding(text):
    """
    处理使用PKCS7填充过的数据
    :param text: 解密后的字符串
    :return:
    """
    try:
        length = len(text)
        unpadding = ord(text[length-1])
        return text[0:length-unpadding]
    except Exception as e:
        pass
 
 
def aes_encode(key, content):
    """
    AES加密
    key,iv使用同一个
    模式ECB
    填充pkcs7
    :param key: 密钥
    :param content: 加密内容
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_ECB, iv)  # AES.MODE_CBC
    # 处理明文
    content_padding = pkcs7padding(content)
    # 加密
    aes_encode_bytes = cipher.encrypt(bytes(content_padding, encoding='utf-8'))
    # 重新编码
    result = str(base64.b64encode(aes_encode_bytes), encoding='utf-8')
    return result
 
 
def aes_decode(key, content):
    """
    AES解密
     key,iv使用同一个
    模式ECB
    去填充pkcs7
    :param key:
    :param content:
    :return:
    """
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_ECB, iv)  # AES.MODE_CBC
    # base64解码
    aes_encode_bytes = base64.b64decode(content)
    # 解密
    aes_decode_bytes = cipher.decrypt(aes_encode_bytes)
    # 重新编码
    result = str(aes_decode_bytes, encoding='utf-8')
    # 去除填充内容
    result = pkcs7unpadding(result)
    if result == None:
        return ""
    else:
        return result


KEY = 'debe3510fcca4fc7'

key = input('请输入密码(默认为 debe3510fcca4fc7):') or KEY

fnames = os.listdir('.')
for fname in fnames:
	if not fname.lower().endswith('.txt'):
		continue

	print(fname)
	f = open(fname[:-4] + '.csv', 'w')
	lines = open(fname).readlines()
	for line in lines:
		line = line.strip()
		if not line or ',' in line:
			content

		en = aes_encode(key, line)
		line += ',' + en + '\n'
		f.write(line)
	f.close()

 
# data = 'Hello!'
# mi = aes_encode(key, data)
# print(aes_decode(key, mi))
# print(mi)
 
 

# data = '你好'
# mi = aes_encode(key, data)
# print(aes_decode(key, mi))
# print(mi)


# data = '1234567890abcdefgHIJK'
# mi = aes_encode(key, data)
# print(aes_decode(key, mi))
# print(mi)


input('当前目录下的所有 txt 文件以完成加密！')


