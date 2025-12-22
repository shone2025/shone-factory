#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SF Token Codec - ShoneFactory 专用 Token 编解码模块
使用 zlib 压缩 + XOR 加密 + 自定义 Base64
"""

import base64
import hashlib
import zlib

# 加密字典 - 自定义 Base64 字符表（打乱顺序，增加破解难度）
# 标准 URL-safe Base64: A-Z a-z 0-9 - _ (64字符)
_STD_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_SF_CHARSET  = "qQ1x-H6AVvWUkfhKa8eFDmS47lGJdc59L0nMp_ogPy3jutBsr2TYOiXzCNbZwEIR"

# 混淆密钥
_SF_KEY = b'ShoneFactory2024SecretKey!@#$%'

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR 加密/解密"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def _custom_b64_encode(data: bytes) -> str:
    """使用自定义字符表的 Base64 编码"""
    std_encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
    # 字符替换
    trans = str.maketrans(_STD_CHARSET, _SF_CHARSET)
    return std_encoded.translate(trans)

def _custom_b64_decode(encoded: str) -> bytes:
    """使用自定义字符表的 Base64 解码"""
    # 反向字符替换
    trans = str.maketrans(_SF_CHARSET, _STD_CHARSET)
    std_encoded = encoded.translate(trans)
    # 补齐 padding
    padding = 4 - len(std_encoded) % 4
    if padding != 4:
        std_encoded += '=' * padding
    return base64.urlsafe_b64decode(std_encoded)

def encode_token(token: str) -> str:
    """将 token 编码为短格式（带压缩）"""
    if not token:
        return ""
    # 先压缩
    compressed = zlib.compress(token.encode('utf-8'), 9)
    # XOR 加密
    encrypted = _xor_bytes(compressed, _SF_KEY)
    # 自定义 Base64 编码
    return _custom_b64_encode(encrypted)

def decode_token(encoded: str) -> str:
    """将短格式解码为原始 token（支持压缩和非压缩格式）"""
    if not encoded:
        return ""
    try:
        # 自定义 Base64 解码
        encrypted = _custom_b64_decode(encoded)
        # XOR 解密
        decrypted = _xor_bytes(encrypted, _SF_KEY)
        # 尝试解压缩（新格式）
        try:
            decompressed = zlib.decompress(decrypted)
            return decompressed.decode('utf-8')
        except zlib.error:
            # 旧格式（无压缩）
            return decrypted.decode('utf-8')
    except Exception:
        return ""

LINE_LENGTH = 62  # 每行有效字符数（不含 SF-XX 前缀，共68字符）

def encode_sf_key(access_token: str, refresh_token: str) -> str:
    """
    将 access_token 和 refresh_token 编码为多行 SF-Key 格式
    每行格式: SF-{2位行号}{62字符内容}，总长68字符
    行号: 01-99 表示第几行，00 表示最后一行
    """
    if not access_token or not refresh_token:
        return ""
    
    encoded_refresh = encode_token(refresh_token)
    encoded_access = encode_token(access_token)
    
    # 组合: 4位refresh长度 + refresh + access
    len_prefix = f"{len(encoded_refresh):04d}"
    full_content = len_prefix + encoded_refresh + encoded_access
    
    # 分割成多行，每行 LINE_LENGTH 字符
    lines = []
    for i in range(0, len(full_content), LINE_LENGTH):
        chunk = full_content[i:i+LINE_LENGTH]
        line_num = (i // LINE_LENGTH) + 1
        # 最后一行用 00 标记
        if i + LINE_LENGTH >= len(full_content):
            line_num = 0
        lines.append(f"SF-{line_num:02d}{chunk}")
    
    return "\n".join(lines)

def decode_sf_key(sf_key: str) -> tuple:
    """
    将多行 SF-Key 解码为 (access_token, refresh_token)
    只支持新格式（2位行号 SF-01xxx）
    返回: (access_token, refresh_token) 或 ("", "") 如果解码失败
    """
    if not sf_key:
        return "", ""
    
    sf_key = sf_key.strip()
    
    # 检查是否是 SF-Key 格式
    if not sf_key.startswith("SF-"):
        return "", ""
    
    try:
        # 解析所有行
        lines = [l.strip() for l in sf_key.split('\n') if l.strip().startswith("SF-")]
        if not lines:
            return "", ""
        
        # 检测格式：新格式第一行是 SF-01xxx（第4字符是0）
        first_line = lines[0]
        is_new_format = len(first_line) >= 6 and first_line[3] == '0' and first_line[4].isdigit()
        
        if not is_new_format:
            # 旧格式已不再支持，需要重新生成 SF-Key
            return "", ""
        
        # 按行号排序并提取内容
        line_contents = {}
        for line in lines:
            if len(line) < 6:
                continue
            
            after_prefix = line[3:]  # SF- 之后的内容
            
            # 新格式：固定2位行号 (SF-01xxx, SF-02xxx, ..., SF-00xxx)
            line_num_str = after_prefix[:2]
            content = after_prefix[2:]
            if line_num_str == '00':  # 最后一行
                line_contents[9999] = content
            elif line_num_str.isdigit():
                line_contents[int(line_num_str)] = content
        
        # 按顺序组合内容
        sorted_keys = sorted(line_contents.keys())
        full_content = ''.join(line_contents[k] for k in sorted_keys)
        
        if len(full_content) < 5:
            return "", ""
        
        # 读取长度前缀（4位数字）
        len_str = full_content[:4]
        refresh_len = int(len_str)
        
        # 分割 refresh 和 access 部分
        encoded_refresh = full_content[4:4+refresh_len]
        encoded_access = full_content[4+refresh_len:]
        
        refresh_token = decode_token(encoded_refresh)
        access_token = decode_token(encoded_access)
        
        if not refresh_token or not access_token:
            return "", ""
        
        return access_token, refresh_token
    except Exception:
        return "", ""

def is_sf_key(content: str) -> bool:
    """检查是否是 SF-Key 格式（支持单行或多行）"""
    content = content.strip()
    if not content:
        return False
    
    # 检查第一行是否以 SF- 开头
    first_line = content.split('\n')[0].strip()
    if not first_line.startswith("SF-"):
        return False
    
    # 检查第4个字符是否是数字（行号）
    if len(first_line) < 5:
        return False
    
    return first_line[3].isdigit()

# 测试
if __name__ == "__main__":
    # 测试数据
    test_access = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiZXhwIjoxNzM0MzAwMDAwfQ.test_signature"
    test_refresh = "refresh_token_abc123xyz"
    
    print("原始 Access Token:", test_access[:50] + "...")
    print("原始 Refresh Token:", test_refresh)
    print()
    
    # 编码
    sf_key = encode_sf_key(test_access, test_refresh)
    print("编码后 SF-Key (多行格式):")
    print("-" * 70)
    print(sf_key)
    print("-" * 70)
    
    # 统计
    lines = sf_key.split('\n')
    print(f"共 {len(lines)} 行，每行长度:")
    for i, line in enumerate(lines):
        print(f"  第{i+1}行: {len(line)} 字符")
    print()
    
    # 解码
    decoded_access, decoded_refresh = decode_sf_key(sf_key)
    print("解码 Access Token:", decoded_access[:50] + "..." if decoded_access else "解码失败")
    print("解码 Refresh Token:", decoded_refresh)
    print()
    
    # 验证
    print("验证结果:", "✅ 成功" if (decoded_access == test_access and decoded_refresh == test_refresh) else "❌ 失败")
