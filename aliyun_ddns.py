#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import struct
import binascii
import socket
import os
import time
import urllib
import urllib2
import json


def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
def sha1(message):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        message: The input message string to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    # Initialize variables:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    message += b'\x80'
    
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += struct.pack(b'>Q', original_bit_len)
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack(b'>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
    
        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value （字节形式）
    return struct.pack('>IIIII', h0, h1, h2, h3, h4) 







def hmac_sha1(key, message):
    """
    计算给定密钥和消息的HMAC-SHA1值。
    
    :param key: HMAC密钥（字节形式）
    :param message: 要进行HMAC处理的消息（字节形式）
    :return: HMAC-SHA1结果（字节形式）
    """
    # 如果密钥长度超过64字节，则先用SHA1压缩它
    if len(key) > 64:
        key = sha1(key)

    # 补齐密钥到64字节长度
    if len(key) < 64:
        key += b'\x00' * (64 - len(key))



    if sys.version_info[0] == 2:
        # Python 2
        o_key_pad = ''.join([chr(ord(x) ^ 0x5c) for x in key])
        i_key_pad = ''.join([chr(ord(x) ^ 0x36) for x in key])
    else:
        # Python 3
        o_key_pad = bytes([x ^ 0x5c for x in key])
        i_key_pad = bytes([x ^ 0x36 for x in key])


    # 计算内部和外部HMAC部分
    inner_part = sha1(i_key_pad + message)
    outer_part = sha1(o_key_pad + inner_part)

    return outer_part





def get_curr_ip():

    # 创建一个套接字对象
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # 连接到ifconfig.me服务器
    s.connect(("ifconfig.me", 80))
    
    # 发送HTTP GET请求，注意在Python 3中需要将字符串转换为字节
    request = "GET /ip HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n"
    #if sys.version_info[0] >= 3:
        #request = request.encode('utf-8')  # Python 3中发送前需要编码
    s.send(request)
    
    # 接收响应，Python 3中接收到的是字节，需要解码成字符串
    response = s.recv(4096)
    #if sys.version_info[0] >= 3:
        #response = response.decode('utf-8')  # Python 3中接收后需要解码
    
    # 关闭套接字连接
    s.close()
    
    # 解析响应以获取IP地址
    ip = response.split("\r\n\r\n")[1].strip()
    return ip







            
            
            
def get_common_params(access_key):
    """
    获取公共参数
    参考文档：https://help.aliyun.com/document_detail/29745.html?spm=5176.doc29776.6.588.sYhLJ0
    """
    # 获取当前UTC时间戳
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # 获取当前时间的时间戳
    timestamp2 = time.time()
    
    return {
        'Format': 'json',
        'Version': '2015-01-09',
        'AccessKeyId': access_key,
        'SignatureMethod': 'HMAC-SHA1',
        'Timestamp': timestamp, 
        'SignatureVersion': '1.0',
        'SignatureNonce': timestamp2 
    }
    
def c_urlencode(params):
    """
    实现类似 urllib.urlencode 的功能，将字典或元组列表转换为URL编码的字符串
    """
    if not params:
        return ''
        
    encoded_params = []
    
    for key, value in params:
        # 确保键和值都转换为字符串
        key = str(key) if not isinstance(key, str) else key
        value = str(value) if not isinstance(value, str) else value
        
        # 编码键和值
        encoded_key = c_quote_plus(key)
        encoded_value = c_quote_plus(value)
        
        # 组合键值对
        encoded_params.append(encoded_key + '=' + encoded_value)
    
    # 用&连接所有参数
    return '&'.join(encoded_params)
    
def c_quote_plus(string):
    """
    实现类似 urllib.quote_plus 的功能，将字符串转换为URL编码格式
    空格转换为'+'，特殊字符转换为'%xx'格式
    """
    # 需要编码的特殊字符集合
    safe = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~'
    encoded = []
    
    for char in string:
        if char == ' ':
            encoded.append('+')
        elif char in safe:
            encoded.append(char)
        else:
            # 将字符转换为十六进制，并确保是两位数
            hex_str = hex(ord(char))[2:].upper()
            if len(hex_str) == 1:
                hex_str = '0' + hex_str
            encoded.append('%' + hex_str)
    
    return ''.join(encoded)
    
def get_signed_params(http_method, params, access_secret):
    """
    参考文档：https://help.aliyun.com/document_detail/29747.html?spm=5176.doc29745.2.1.V2tmbU
    """

    # 1、合并参数，不包括Signature
    params.update(get_common_params(access_key))
    # 2、按照参数的字典顺序排序
    sorted_params = sorted(params.items())
    # 3、encode 参数
    query_params = c_urlencode(sorted_params)
    # 4、构造需要签名的字符串
    str_to_sign = http_method + "&" + c_quote_plus("/") + "&" + c_quote_plus(query_params)
    # 5、计算签名
    signature = hmac_sha1(str(access_secret + '&'), str(str_to_sign)).encode('base64').strip('\n') #此处注意，必须用str转换，因为hmac不接受unicode，大坑！！！
    # 6、将签名加入参数中
    params['Signature'] = signature

    return params

def update_yun(ipv4='', ipv6=''):
    """
    修改云解析
    参考文档：
        获取解析记录：https://help.aliyun.com/document_detail/29776.html?spm=5176.doc29774.6.618.fkB0qE
        修改解析记录：https://help.aliyun.com/document_detail/29774.html?spm=5176.doc29774.6.616.qFehCg
    """


    if ipv4 != '':
        update_type = 'A'
        update_value = ipv4
    else:
        update_type = 'AAAA'
        update_value = ipv6


    # 首先获取解析列表
    get_params = get_signed_params('GET', {
        'Action': 'DescribeDomainRecords',
        'DomainName': domain,
        'TypeKeyWord': update_type
    }, access_secret)


    # 编码查询参数
    params = urllib.urlencode(get_params)

    # 构建完整的URL
    full_url = '%s?%s' % (REQUEST_URL, params)

    # 创建请求对象
    req = urllib2.Request(full_url)

    # 发送GET请求并获取响应
    response = urllib2.urlopen(req)

    # 读取响应内容
    get_resp = response.read()

    # 打印响应内容
    #print(get_resp)
    
    #print(type(get_resp))


    # 解析 JSON 字符串为 Python 对象
    python_obj = json.loads(get_resp)

    # 打印解析后的 Python 对象
    #print(python_obj)
    #print(python_obj['DomainRecords']['Record'])
    #print(python_obj['DomainRecords']['Record'][0])
    #print(python_obj['DomainRecords']['Record'][0]['RR'])

    i = 0
    while i < len(python_obj['DomainRecords']['Record']):
        if python_obj['DomainRecords']['Record'][i]['RR'] == record_name:
            print(python_obj['DomainRecords']['Record'][i])
            print(type(python_obj['DomainRecords']['Record'][i]['Value']))
            save_latest_local_ip(python_obj['DomainRecords']['Record'][i]['Value'])
            if python_obj['DomainRecords']['Record'][i]['Value'] != update_value:
                print('need to update\n')
                post_params = get_signed_params('POST', {
                    'Action': 'UpdateDomainRecord',
                    'RecordId': python_obj['DomainRecords']['Record'][i]['RecordId'],
                    'RR': record_name,
                    'Type': python_obj['DomainRecords']['Record'][i]['Type'],
                    'Value': update_value
                }, access_secret)
                
                # 将字典转换为查询字符串
                post_params = urllib.urlencode(post_params)

                # 创建请求对象
                request = urllib2.Request(REQUEST_URL, post_params)

                try:
                    # 发送 POST 请求
                    response = urllib2.urlopen(request)
                    
                    # 获取响应状态码和内容
                    status_code = response.getcode()
                    content = response.read()
                    
                    print("Status Code:", status_code)
                    print("Response Content:", content)
                except urllib2.URLError as e:
                    print("Error:", e.reason)
                        
        i += 1


def is_valid_ip(ip_address):
    """
    判断给定的字符串是否是有效的IPv4地址
    """
    # 检查字符串是否为空
    if not ip_address:
        return False

    # 按点分割字符串
    parts = ip_address.split('.')
    
    # 检查是否有四个部分
    if len(parts) != 4:
        return False

    for part in parts:
        # 检查每个部分是否为数字
        if not part.isdigit():
            return False
            
        # 检查每个部分是否在0到255之间
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True


def get_lastest_local_ip():
    """
    获取最近一次保存在本地的ip
    """
    with open(LOCAL_FILE, 'r') as f:
        data = f.read()
        try:
            return data
        except Exception as e:
            print(e.message)
            return {}

def save_latest_local_ip(ip_address = '1.2.3.4'):
    """
    将最新的IP地址保存到本地文件中，覆盖原有内容
    """
    try:
        with open(LOCAL_FILE, 'w') as file:
            file.write(ip_address)
        print("IP地址已成功保存。")
    except Exception as e:
        print(e.message)
        return {}




LOCAL_FILE = '/tmp/ip.txt'

REQUEST_URL = 'http://alidns.aliyuncs.com/'

access_key = 'xxx'
access_secret = 'xxx'
domain = 'xxx.com'
record_name = 'xxx'
        
if __name__ == '__main__':
    


    ip_data = get_curr_ip()
    if(is_valid_ip(ip_data)):
        # 检查是否存在上次ip文件
        if os.path.isfile(LOCAL_FILE):
            last_ip_data = get_lastest_local_ip()
            if ip_data != last_ip_data:
                print('Current_ip:' + ip_data)
                print(' Record_ip:' + last_ip_data)
                print("update_yun run")
                update_yun(ipv4=ip_data)
        else:
            print("update_yun run")
            update_yun(ipv4=ip_data)
    else:
        print('not a valid ip!')
