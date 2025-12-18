#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os,sys,json,base64,platform,webbrowser,urllib.request,urllib.error,ssl,time,hashlib,socket,uuid,zlib
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer,BaseHTTPRequestHandler
from urllib.parse import parse_qs,urlparse,urlencode
import threading,re

# 核心函数占位符 - 运行时从云端加载
def decode_sf_key(s):return"",""
def is_sf_key(s):return False

# 云端同步配置
_CLOUD_URL='https://shone.ggff.net'
_CLIENT_KEY='shonefactory_client_2024'

def _0xGCF():
    """从云端获取客户端配置"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        ts=str(int(time.time()))
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/config",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success'):
                return r.get('config',{})
    except:pass
    return None

def _0xGVR():
    """从云端获取版本信息"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/version",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json'
        },method='GET')
        with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            return r
    except urllib.error.URLError as e:
        return {"success":False,"message":f"网络错误: {e.reason}"}
    except Exception as e:
        return {"success":False,"message":f"检查失败: {e}"}

def _0xRRF(sfkey_id):
    """向云端提交刷新请求"""
    if not sfkey_id:
        return {"success":False,"message":"缺少 Key ID"}
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        ts=str(int(time.time()))
        data=json.dumps({"sfkey_id":sfkey_id[:35]}).encode('utf-8')
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/refresh-request",data=data,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'Content-Type':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='POST')
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            return r
    except Exception as e:
        return {"success":False,"message":f"提交失败: {str(e)}"}

def _0xGBA(sfkey_id):
    """从云端获取额度信息"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        ts=str(int(time.time()))
        qid=sfkey_id.strip()[:35]
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/balance/{qid}",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('balance'):
                return r.get('balance')
    except:pass
    return None

def _0xCQ(sfkey_id):
    """从云端快速查询Token - 使用优化的fast-query接口"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        qid=sfkey_id.strip()
        if not qid.startswith('SF-')and len(qid)>=32:qid='SF-'+qid
        qid=qid[:35]  # 确保只取前35字符
        url=f"{_CLOUD_URL}/api/fast-query/{qid}"
        ts=str(int(time.time()))
        rq=urllib.request.Request(url,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('found')and r.get('data'):
                enc=r.get('data','')
                if enc:
                    b64=enc.replace('_','=').replace('-','+').replace('.','/')
                    b64=b64[::-1]
                    js=base64.b64decode(b64).decode('utf-8')
                    return json.loads(js)
    except urllib.error.URLError as e:
        print(f"云端查询失败: {e}")
    except Exception as e:
        print(f"云端查询异常: {e}")
    return None

def _0xCQU(user_id):
    """从云端通过user_id查询Token - 备用查询方式"""
    if not user_id:return None
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        url=f"{_CLOUD_URL}/api/query-by-uid/{user_id}"
        ts=str(int(time.time()))
        rq=urllib.request.Request(url,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=20,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('found')and r.get('data'):
                enc=r.get('data','')
                if enc:
                    b64=enc.replace('_','=').replace('-','+').replace('.','/')
                    b64=b64[::-1]
                    js=base64.b64decode(b64).decode('utf-8')
                    return json.loads(js)
    except Exception as e:
        print(f"云端(user_id)查询异常: {e}")
    return None

def _0xCQC(sfkey_id):
    """从云端查询账号凭据(邮箱/密码/Cookie)"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        url=f"{_CLOUD_URL}/api/credentials/{sfkey_id}"
        ts=str(int(time.time()))
        rq=urllib.request.Request(url,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('data'):
                enc=r.get('data','')
                if enc:
                    b64=enc.replace('_','=').replace('-','+').replace('.','/')
                    b64=b64[::-1]
                    js=base64.b64decode(b64).decode('utf-8')
                    return json.loads(js)
    except Exception as e:
        print(f"云端凭据查询异常: {e}")
    return None

def _0xUTC(sfkey_id,at,rt,ex):
    """上传Token到云端"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        data=json.dumps({"sfkey_id":sfkey_id,"access_token":at,"refresh_token":rt,"exp":ex}).encode('utf-8')
        ts=str(int(time.time()))
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/update-token",data=data,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Content-Type':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='POST')
        with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
            return json.loads(rs.read().decode('utf-8'))
    except Exception as e:
        print(f"云端上传异常: {e}")
    return None

_0xT=time.time()
_0xCORE=None

def _0xAD1():
    import sys as _s
    if hasattr(_s,'gettrace') and _s.gettrace():return True
    try:
        import ctypes as _c
        if platform.system()=='Windows':
            if _c.windll.kernel32.IsDebuggerPresent():return True
    except:pass
    return False

def _0xAD2():
    _d=['ida64.exe','ida32.exe','ollydbg','x64dbg.exe','x32dbg.exe','windbg','immunity debugger','ghidra','radare2','hopper disassembler','frida-server','cycript','substrate','xposed']
    try:
        import subprocess
        if platform.system()=='Darwin':
            _r=subprocess.run(['ps','aux'],capture_output=True,text=True,timeout=2)
        elif platform.system()=='Windows':
            _r=subprocess.run(['tasklist'],capture_output=True,text=True,timeout=2)
        else:
            _r=subprocess.run(['ps','-e'],capture_output=True,text=True,timeout=2)
        _o=_r.stdout.lower()
        for _t in _d:
            if _t.lower()in _o:return True
    except:pass
    return False

def _0xAD3():
    global _0xT
    _c=time.time();_d=_c-_0xT;_0xT=_c
    if _d>60:return True
    return False

def _0xWARN():
    _ip="UNKNOWN";_mac="UNKNOWN";_vpn=False
    try:
        _s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);_s.connect(("8.8.8.8",80));_ip=_s.getsockname()[0];_s.close()
    except:pass
    try:_mac=':'.join(['{:02x}'.format((uuid.getnode()>>i)&0xff)for i in range(0,48,8)][::-1])
    except:pass
    _msg=f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  严重安全警告 / CRITICAL SECURITY WARNING ⚠️              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   检测到非法逆向工程/破解行为！                                                    ║
║   您的设备信息已被记录 / Your device information has been logged:                 ║
║   • IP 地址: {_ip:<20}                                                    ║
║   • MAC 地址: {_mac:<20}                                                  ║
║   • 时间戳: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<20}                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(_msg)

def _0xCHK():
    if _0xAD1()or _0xAD2():_0xWARN();os._exit(1)
    if _0xAD3():_0xWARN();os._exit(1)

def _0xLC():
    """动态加载核心代码 - 从云端获取，缓存到内存"""
    global _0xCORE
    if _0xCORE is not None:
        return _0xCORE
    ctx=ssl.create_default_context()
    ctx.check_hostname=False
    ctx.verify_mode=ssl.CERT_NONE
    ts=str(int(time.time()))
    try:
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/core",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('core'):
                enc=r.get('core','')
                # 三层解密：Base64 → Base64 → zlib
                try:
                    layer1=base64.b64decode(enc).decode('utf-8')
                    layer2=base64.b64decode(layer1)
                    code=zlib.decompress(layer2).decode('utf-8')
                    # 缓存到内存，避免每次切换账号都重新请求
                    _0xCORE=code
                    return code
                except:pass
    except:pass
    return None

_0xCHK()

_0k=lambda s,k=0x5F:''.join(chr(ord(c)^k)for c in s)
_0e=lambda s:base64.b64encode(s.encode()).decode()
_0d=lambda s:base64.b64decode(s).decode()
_S1=_0k('\x3e\x2e\x35\x3b\x71\x3f\x28\x38\x39')
_S2=_0k('\x3e\x30\x30\x3a\x28\x28\x70\x35\x38\x3c\x3a\x39')
_S3=_0k('\x27\x3a\x3b\x27\x3a\x28\x3b\x70\x35\x38\x3c\x3a\x39')
_S4=_0k('\x71\x3b\x3e\x30\x35\x38\x27\x2c')
_S5=_0k('\x14\x28\x3a\x27\x11\x27\x38\x3b\x3c\x3f\x3a')
_S6=_0d('aHR0cHM6Ly9hcHAuZmFjdG9yeS5haS9hcGkvb3JnYW5pemF0aW9uL21lbWJlcnMvY2hhdC11c2FnZQ==')
_S7=_0d('aHR0cHM6Ly9hcGkuZmFjdG9yeS5haS9jbGkvYXV0aC9yZWZyZXNo')
_S8=_0d('aHR0cHM6Ly9hcGkuZmFjdG9yeS5haS9hdXRoL3JlZnJlc2g=')

_P0=8765
_H0='127.0.0.1'

def _0xF1():return 0
def _0xF2(_a,_b):return _a if _a else _b
def _0xF3(_x):return hashlib.md5(str(_x).encode()).hexdigest()[:8]

class _0xTM:
    def __init__(s):
        _0xCHK()
        s._0pf=Path(__file__).parent/'token_pool.json';s._0mk=0;s._0bc={};s._0lmk();s._cw=None

    def _0lmk(s):
        po=s._0xlp()
        for a in po['accounts']:
            ki=a.get('key_id','')
            if ki.startswith('shonetokenkey'):
                try:
                    n=int(ki[13:])
                    if n>s._0mk:s._0mk=n
                except:pass

    def _0xfp(s):
        _0xCHK()
        if platform.system()=='Windows':return Path(os.environ.get(_S5,''))/_S4[1:]
        return Path.home()/_S4

    def _0xdj(s,t):
        try:
            p=t.strip().split('.')
            if len(p)!=3:return None
            pl=p[1];pd=4-len(pl)%4
            if pd!=4:pl+='='*pd
            return json.loads(base64.urlsafe_b64decode(pl))
        except:return None

    def _0xlp(s):
        if s._0pf.exists():
            with open(s._0pf,'r',encoding='utf-8')as f:return json.load(f)
        return{"accounts":[]}

    def _0xsp(s,po):
        with open(s._0pf,'w',encoding='utf-8')as f:json.dump(po,f,indent=2,ensure_ascii=False)

    def _0xgct(s):
        try:
            af=s._0xfp()/_S1
            if not af.exists():return None
            with open(af,'r',encoding='utf-8')as f:ad=json.load(f)
            # auth.json 使用标准字段名 access_token
            return ad.get('access_token',None)
        except:return None

    def _0xgcad(s):
        try:
            af=s._0xfp()/_S1
            if not af.exists():return None
            with open(af,'r',encoding='utf-8')as f:ad=json.load(f)
            # auth.json 使用标准字段名，需要转换为编码后的字段名以保持兼容
            if 'access_token' in ad and _S2 not in ad:
                ad[_S2]=ad.get('access_token','')
            if 'refresh_token' in ad and _S3 not in ad:
                ad[_S3]=ad.get('refresh_token','')
            return ad
        except:return None

    def _0xscl(s):
        ad=s._0xgcad()
        if not ad:return{"synced":False,"message":"未检测到登录账号"}
        at=ad.get(_S2,'');rt=ad.get(_S3,'')
        if not at or not rt:return{"synced":False,"message":"登录信息不完整"}
        pl=s._0xdj(at)
        if not pl:return{"synced":False,"message":"Token 格式无效"}
        po=s._0xlp()
        for a in po['accounts']:
            if a[_S2]==at:return{"synced":False,"message":"账号已在池中","exists":True}
        ki=s._0xgki();ex=pl.get('exp',0);em=pl.get('email','');sb=pl.get('sub','')
        rm=em if em else(f"用户: {sb[:8]}..."if sb else"自动导入")
        ac={"key_id":ki,_S2:at,_S3:rt,"remark":rm,"added_at":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"exp":ex}
        po['accounts'].append(ac);s._0xsp(po)
        return{"synced":True,"message":f"已自动导入当前登录账号: {ki}","key_id":ki}

    def _0xgcli(s):
        ad=s._0xgcad()
        if not ad:return None
        at=ad.get(_S2,'');rt=ad.get(_S3,'')
        if not at:return None
        pl=s._0xdj(at)
        if not pl:return None
        ex=pl.get('exp',0);nw=datetime.now().timestamp();sb=pl.get('sub','');em=pl.get('email','')
        po=s._0xlp();sfk='';in_pool=False
        # 第一优先：通过 access_token 完全匹配（切换账号后 token 会更新到账号池）
        for a in po['accounts']:
            if a.get(_S2,'')==at:
                sfk=a.get('sf_key_line1','')or a.get('key_id','')
                in_pool=True
                break
        # 第二优先：通过 refresh_token 匹配（refresh_token 比 access_token 更稳定）
        if not in_pool:
            for a in po['accounts']:
                if rt and a.get(_S3,'')==rt:
                    sfk=a.get('sf_key_line1','')or a.get('key_id','')
                    in_pool=True
                    break
        # 如果不在本地池中，自动上传到云端并生成 sfkey
        if not in_pool and at and rt:
            try:
                # 生成 sfkey_id (使用 user_id 的前35字符或生成新的)
                sfkey_id=f"SF-{sb[:32]}" if sb else f"SF-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                sfkey_id=sfkey_id[:35]
                # 上传到云端
                import urllib.request
                data=json.dumps({"sfkey_id":sfkey_id,"access_token":at,"refresh_token":rt,"email":em,"exp":ex,"user_id":sb}).encode('utf-8')
                req=urllib.request.Request(f"{_CU}/api/update",data=data,headers={'Content-Type':'application/json','X-API-Key':_AS},method='POST')
                with urllib.request.urlopen(req,timeout=15)as resp:
                    result=json.loads(resp.read().decode('utf-8'))
                    if result.get('success'):
                        sfk=sfkey_id
                        # 添加到本地池
                        rm=em if em else(f"用户: {sb[:8]}..."if sb else"自动导入")
                        ac={"key_id":sfkey_id,"sf_key_line1":sfkey_id,_S2:at,_S3:rt,"remark":rm,"added_at":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"exp":ex}
                        po['accounts'].append(ac);s._0xsp(po)
                        in_pool=True
            except Exception as e:
                print(f"自动上传云端失败: {e}")
        return{"email":em,"sub":sb,"exp":ex,"expired":ex<=nw,"in_pool":in_pool,"sf_key_line1":sfk}

    def _0xitp(s,at):
        po=s._0xlp()
        for a in po['accounts']:
            if a[_S2]==at:return True
        return False

    def _0xgki(s):s._0mk+=1;return f"shonetokenkey{s._0mk:03d}"

    def _0xpt(s,ct):
        at,rt,sfk='','',''
        ct=ct.strip()
        # 检查是否为短Key（查询码）- 单行35字符以SF-开头
        if ct.startswith('SF-')and len(ct)==35 and '\n'not in ct:
            print(f"正在从云端快速查询短Key: {ct}")
            cd=_0xCQ(ct)
            if cd:
                print(f"云端查询成功")
                return cd.get('access_token',''),cd.get('refresh_token',''),ct
            print(f"云端查询未找到结果")
            return'','',''
        # 本地解码 SF-Key（多行格式）- 不再依赖云端代码
        ls=[l.strip()for l in ct.split('\n')if l.strip().startswith('SF-')]
        if ls and len(ls)>=1:
            try:
                sfk=ls[0][:35]if ls[0]else''
                # 解码 SF-Key
                parts=[]
                for ln in ls:
                    if ln.startswith('SF-')and len(ln)>=5:
                        num=ln[3:5]
                        data=ln[5:]
                        parts.append((num,data))
                # 排序并合并
                parts.sort(key=lambda x:x[0]if x[0]!='00'else'99')
                enc=''.join(p[1]for p in parts)
                # 自定义 Base64 解码
                _CS="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_"
                _SB="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                tr=str.maketrans(_CS,_SB)
                b64=enc.translate(tr)
                pad=4-len(b64)%4
                if pad<4:b64+='='*pad
                raw=base64.b64decode(b64)
                # XOR 解密
                xk=0x5F
                dec=bytes(b^xk for b in raw)
                # zlib 解压
                js=zlib.decompress(dec).decode('utf-8')
                d=json.loads(js)
                at=d.get('access_token','')
                rt=d.get('refresh_token','')
                if at and rt:
                    return at,rt,sfk
            except Exception as e:
                print(f"SF-Key本地解码失败: {e}")
        # JSON 格式
        try:
            if '{'in ct and '}'in ct:
                st,ed=ct.find('{'),ct.rfind('}')+1;d=json.loads(ct[st:ed]);at=d.get(_S2,'');rt=d.get(_S3,'')
                if at and rt:return at,rt,''
        except:pass
        # 正则匹配
        am=re.search(r'["\']?'+_S2+r'["\']?\s*[:\s]\s*["\']?([^"\'}\s,]+(?:\.[^"\'}\s,]+)*)["\']?',ct)
        rm=re.search(r'["\']?'+_S3+r'["\']?\s*[:\s]\s*["\']?([^"\'}\s,]+)["\']?',ct)
        if am:at=am.group(1)
        if rm:rt=rm.group(1)
        if at and rt:return at,rt,''
        # 两行格式
        ls=[l.strip()for l in ct.split('\n')if l.strip()]
        if len(ls)>=2 and ls[0].count('.')==2:return ls[0],ls[1],''
        return'','',''

    def _0xwa(s,at,rt):
        """动态加载核心写入函数 - 从云端获取，不落盘"""
        _0xCHK()
        core_success=False
        try:
            code=_0xLC()
            if code:
                local_vars={}
                exec(code,local_vars)
                _wa=local_vars.get('_wa')
                if _wa:
                    fp=s._0xfp()
                    result=_wa(at,rt,fp,_S1)
                    if result:
                        core_success=True
                        return True
        except:pass
        # 备用方案 - 仅当核心模块失败时执行
        if not core_success:
            try:
                fp=s._0xfp();af=fp/_S1;fp.mkdir(parents=True,exist_ok=True)
                if af.exists():
                    bk=fp/(af.name+'.bak')
                    if bk.exists():bk.unlink()
                    import shutil
                    shutil.copy(af,bk)
                ad={_S2:at,_S3:rt}
                with open(af,'w',encoding='utf-8')as f:json.dump(ad,f,indent=2)
                return True
            except:pass
        return core_success

    def _0xat(s,ct):
        _0xCHK()
        ct=ct.strip()
        # 支持多行导入：每行一个 SF-Key
        lines=[l.strip()for l in ct.split('\n')if l.strip()]
        if len(lines)>1:
            # 多行导入模式
            return s._0xat_multi(lines)
        # 单行导入
        po=s._0xlp()
        sfk_input=''
        if ct.startswith('SF-'):
            # 提取 sfkey（短key或完整key的第一行前35字符）
            sfk_input=ct[:35]
            # 检查是否已存在
            for a in po['accounts']:
                a_sfk=a.get('sf_key_line1','')or a.get('key_id','')
                if a_sfk and a_sfk[:35]==sfk_input:
                    return{"success":False,"message":"此 SF-Key 已在账号池中，请点击切换使用","exists":True}
        # 解码 token
        at,rt,sfk=s._0xpt(ct)
        if not at or not rt:
            if ct.startswith('SF-')and len(ct)==35:
                return{"success":False,"message":"SF-Key 查询失败，请确认 Key 有效或稍后重试"}
            return{"success":False,"message":"无法识别 Key 格式，请粘贴完整的 SF-Key"}
        pl=s._0xdj(at)
        if not pl:return{"success":False,"message":"无效的 Token 格式"}
        # 再次检查（通过 access_token）
        for a in po['accounts']:
            if a[_S2]==at:return{"success":False,"message":"此 Key 已在账号池中，请点击切换使用","exists":True}
        ki=sfk if sfk else s._0xgki()
        ex=pl.get('exp',0)
        ac={"key_id":ki,_S2:at,_S3:rt,"remark":"","added_at":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"exp":ex,"sf_key_line1":sfk}
        po['accounts'].append(ac);s._0xsp(po)
        # 导入即切换：写入 auth.json
        s._0xwa(at,rt)
        return{"success":True,"message":f"已添加并切换到: {ki[:35]}..."}

    def _0xat_multi(s,lines):
        """多行 SF-Key 导入"""
        _0xCHK()
        po=s._0xlp()
        added=[];skipped=[];failed=[]
        last_at=None;last_rt=None;last_ki=None
        for line in lines:
            line=line.strip()
            if not line:continue
            # 检查是否已存在
            sfk_input=line[:35]if line.startswith('SF-')else''
            exists=False
            if sfk_input:
                for a in po['accounts']:
                    a_sfk=a.get('sf_key_line1','')or a.get('key_id','')
                    if a_sfk and a_sfk[:35]==sfk_input:
                        exists=True;break
            if exists:
                skipped.append(sfk_input);continue
            # 解码
            at,rt,sfk=s._0xpt(line)
            if not at or not rt:
                failed.append(line[:20]+'...'if len(line)>20 else line);continue
            pl=s._0xdj(at)
            if not pl:
                failed.append(line[:20]+'...');continue
            # 检查 access_token 是否已存在
            for a in po['accounts']:
                if a[_S2]==at:exists=True;break
            if exists:
                skipped.append(sfk[:35]if sfk else'token');continue
            ki=sfk if sfk else s._0xgki()
            ex=pl.get('exp',0)
            ac={"key_id":ki,_S2:at,_S3:rt,"remark":"","added_at":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"exp":ex,"sf_key_line1":sfk}
            po['accounts'].append(ac)
            added.append(ki[:35])
            last_at=at;last_rt=rt;last_ki=ki
        s._0xsp(po)
        # 切换到最后一个导入的账号
        if last_at and last_rt:
            s._0xwa(last_at,last_rt)
        # 构建消息
        msg=f"导入完成：成功 {len(added)} 个"
        if skipped:msg+=f"，跳过 {len(skipped)} 个(已存在)"
        if failed:msg+=f"，失败 {len(failed)} 个"
        if last_ki:msg+=f"，已切换到: {last_ki[:35]}..."
        return{"success":len(added)>0,"message":msg,"added":len(added),"skipped":len(skipped),"failed":len(failed)}

    def _0xgal(s):
        po=s._0xlp();nw=datetime.now().timestamp();ct=s._0xgct();al=[]
        for i,a in enumerate(po['accounts'],1):
            ex=a.get('exp',0);ki=a.get('key_id',f'shonetokenkey{i:03d}');ic=a.get(_S2,'')==ct if ct else False
            sfkl1=a.get('sf_key_line1','')
            # 如果 exp 为 0 或已过期但有 refresh_token，显示为"待刷新"而非"过期"
            if ex==0:st='pending';stx='待验证'
            elif ex>nw:st='valid';stx='有效'
            elif a.get(_S3):st='refresh';stx='待刷新'
            else:st='expired';stx='过期'
            bi=s._0bc.get(ki,{});cached=bi.get('cached',False);lu=bi.get('lastUpdated','')
            # 优先使用本地缓存的额度数据
            cb=a.get('cached_balance',{})
            if cb and cb.get('remaining') is not None:
                bi={'totalAllowance':cb.get('totalAllowance'),'totalUsed':cb.get('totalUsed'),'remaining':cb.get('remaining'),'usedRatio':cb.get('usedRatio'),'lastUpdated':cb.get('lastUpdated',''),'error':None,'estimated':False}
                cached=True;lu=cb.get('lastUpdated','')
            # 如果状态是"待刷新"，额度显示为短横线而不是"查询失败"
            if bi.get('error')and not bi.get('estimated'):
                if st=='refresh':bs='pending';btx='-';rs='-';us='-'
                else:bs='error';btx='查询失败';rs='-';us='-'
            elif bi.get('totalAllowance')is not None:
                re=bi.get('remaining',0);ur=bi.get('usedRatio',0);est=bi.get('estimated',False)
                if re<=0:bs='exhausted';btx='已耗尽'
                elif ur<0.5:bs='good';btx='充足'
                elif ur<0.8:bs='medium';btx='适中'
                else:bs='low';btx='偏低'
                if est:btx+='(预估)';bs='estimated'
                elif cached:btx+='(缓存)'
                rm=re/1000000;rs=f"{rm:.1f}M"+('*'if est else'');us=f"{ur*100:.1f}%"+('*'if est else'')
            else:bs='pending';btx='未查询';rs='-';us='-'
            al.append({"index":i,"key_id":ki,"status":st,"status_text":stx,"remark":a.get('remark',''),"added_at":a.get('added_at','N/A')[:16],"is_current":ic,"balance_status":bs,"balance_text":btx,"remaining":rs,"usage_ratio":us,"cached":cached,"last_updated":lu})
        return al

    def _0xsfc(s):
        """智能从云端同步账号数据
        逻辑：
        1. 遍历账号池，检查每个账号状态
        2. 状态为"待验证"(pending)或"待刷新"(refresh)的账号，从云端下载token
        3. 状态为"有效"的账号，仅加载基本信息（邮箱等），不重复下载token
        4. 逐个同步，返回同步结果
        """
        po=s._0xlp();nw=datetime.now().timestamp()
        synced=0;failed=0;skipped=0;results=[]
        
        for i,a in enumerate(po['accounts']):
            ki=a.get('key_id','')
            sfkl1=a.get('sf_key_line1','')
            ex=a.get('exp',0)
            at=a.get(_S2,'')
            rt=a.get(_S3,'')
            
            if not sfkl1 or len(sfkl1)<35:
                skipped+=1
                results.append({"key":ki[:20],"status":"skip","msg":"无SF-Key"})
                continue
            
            sfkey_id=sfkl1[:35]
            
            # 判断状态
            if ex==0:status='pending'  # 待验证（首次使用，无token信息）
            elif ex>nw:status='valid'  # 有效
            elif rt:status='refresh'   # 待刷新（过期但有refresh_token）
            else:status='expired'      # 已过期
            
            # 状态有效且有token，跳过云端同步（节省资源）
            if status=='valid' and at and rt:
                skipped+=1
                results.append({"key":ki[:20],"status":"skip","msg":"有效无需同步"})
                continue
            
            # 需要从云端获取token的情况：pending 或 refresh 或 无token
            try:
                cd=_0xCQ(sfkey_id)
                if cd and cd.get('access_token') and cd.get('refresh_token'):
                    new_at=cd.get('access_token','')
                    new_rt=cd.get('refresh_token','')
                    new_exp=0
                    # 解析新token的过期时间
                    new_pl=s._0xdj(new_at)
                    if new_pl:
                        new_exp=new_pl.get('exp',0)
                    
                    # 更新本地账号池
                    po['accounts'][i][_S2]=new_at
                    po['accounts'][i][_S3]=new_rt
                    po['accounts'][i]['exp']=new_exp
                    po['accounts'][i]['last_cloud_sync']=nw
                    
                    # 同时获取邮箱等基本信息
                    cred=_0xCQC(sfkey_id)
                    if cred:
                        if cred.get('email'):
                            po['accounts'][i]['email']=cred.get('email')
                        if cred.get('region'):
                            po['accounts'][i]['region']=cred.get('region')
                    
                    synced+=1
                    new_status='有效' if new_exp>nw else '待刷新'
                    results.append({"key":ki[:20],"status":"success","msg":f"同步成功({new_status})"})
                else:
                    # 云端无数据，尝试获取凭据信息
                    cred=_0xCQC(sfkey_id)
                    if cred and cred.get('email'):
                        po['accounts'][i]['email']=cred.get('email')
                        if cred.get('region'):
                            po['accounts'][i]['region']=cred.get('region')
                        skipped+=1
                        results.append({"key":ki[:20],"status":"skip","msg":"仅获取基本信息"})
                    else:
                        failed+=1
                        results.append({"key":ki[:20],"status":"fail","msg":"云端无数据"})
            except Exception as e:
                failed+=1
                results.append({"key":ki[:20],"status":"fail","msg":str(e)[:20]})
        
        # 保存更新后的账号池
        s._0xsp(po)
        
        return{
            "success":True,
            "message":f"同步完成: 成功 {synced}, 失败 {failed}, 跳过 {skipped}",
            "synced":synced,
            "failed":failed,
            "skipped":skipped,
            "results":results
        }

    def _0xswa(s,ix):
        _0xCHK()
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        a=po['accounts'][idx]
        at=a.get(_S2,'');rt=a.get(_S3,'');sfkl1=a.get('sf_key_line1','')
        
        # 检查 token 是否过期，如果过期尝试从云端获取新 token
        ex=a.get('exp',0);nw=datetime.now().timestamp()
        if ex<=nw and sfkl1:
            # Token 过期，尝试从云端获取最新 token
            cd=_0xCQ(sfkl1[:35])
            if cd and cd.get('access_token') and cd.get('refresh_token'):
                at=cd.get('access_token','')
                rt=cd.get('refresh_token','')
                # 更新本地存储
                po['accounts'][idx][_S2]=at
                po['accounts'][idx][_S3]=rt
                pl=s._0xdj(at)
                if pl:po['accounts'][idx]['exp']=pl.get('exp',0)
                s._0xsp(po)
        
        if not at or not rt:return{"success":False,"message":"账号信息不完整"}
        if s._0xwa(at,rt):
            # 切换成功后，自动刷新该账号的额度
            ki=a.get('key_id','')
            if at and ki:
                s._0xfb(at,ki)
            return{"success":True,"message":f"已切换到: {a['key_id']}"}
        return{"success":False,"message":"切换失败，请检查网络或重启客户端"}

    def _0xda(s,ix):
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        ki=po['accounts'][idx]['key_id'];del po['accounts'][idx];s._0xsp(po)
        return{"success":True,"message":f"已删除: {ki}"}

    def _0xur(s,ix,rm):
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        po['accounts'][idx]['remark']=rm;s._0xsp(po)
        return{"success":True,"message":"备注已更新"}

    def _0xsbo(s):
        """切换到最优账号（剩余额度最高的有效账号）"""
        po=s._0xlp();nw=datetime.now().timestamp()
        best_idx=-1;best_remaining=-1
        for i,a in enumerate(po['accounts']):
            ex=a.get('exp',0)
            # 只考虑有效或待刷新的账号
            if ex>nw or a.get(_S3):
                cb=a.get('cached_balance',{})
                rm=cb.get('remaining',0)
                if rm>best_remaining:
                    best_remaining=rm;best_idx=i
        if best_idx<0:return{"success":False,"message":"没有找到可用账号"}
        return s._0xswa(best_idx+1)

    def _0xgex(s):
        """获取已耗尽的账号列表
        只返回使用率 >= 100% 的账号，避免误删查询失败的账号
        """
        po=s._0xlp();exhausted=[]
        for i,a in enumerate(po['accounts'],1):
            cb=a.get('cached_balance',{})
            ur=cb.get('usedRatio',0)
            # 只有使用率 >= 100% (1.0) 才视为耗尽
            # 查询失败的账号 usedRatio 为 0，不会被误删
            if ur>=1.0:
                ki=a.get('key_id','')
                us_pct=f"{ur*100:.1f}%"
                exhausted.append({"index":i,"key_id":ki[:35]+'...'if len(ki)>35 else ki,"usage":us_pct})
        return{"success":True,"accounts":exhausted,"count":len(exhausted)}

    def _0xdex(s,indices):
        """删除已耗尽的账号"""
        po=s._0xlp()
        # 按索引从大到小排序，避免删除时索引偏移
        indices=sorted(indices,reverse=True)
        deleted=[]
        for ix in indices:
            idx=ix-1
            if 0<=idx<len(po['accounts']):
                ki=po['accounts'][idx].get('key_id','')
                deleted.append(ki[:35])
                del po['accounts'][idx]
        s._0xsp(po)
        return{"success":True,"message":f"已删除 {len(deleted)} 个耗尽账号","deleted":len(deleted)}

    def _0xgas(s):
        """获取自动切换设置"""
        po=s._0xlp()
        return{"auto_switch":po.get('auto_switch',False)}

    def _0xsas(s,enabled):
        """设置自动切换开关"""
        po=s._0xlp()
        po['auto_switch']=enabled
        s._0xsp(po)
        return{"success":True,"auto_switch":enabled,"message":f"自动切换已{'开启'if enabled else'关闭'}"}

    def _0xrat(s,force_all=False):
        """全部续期 - 使用 WorkOS API 刷新账号的 Token
        force_all: True=强制刷新所有账号, False=仅刷新即将过期或已过期的账号
        refresh_token 有效期约1个月，可用于刷新已过期的 access_token
        """
        WORKOS_API_URL="https://api.workos.com/user_management/authenticate"
        FACTORY_CLIENT_ID="client_01HNM792M5G5G1A2THWPXKFMXB"
        
        po=s._0xlp()
        success_count=0
        fail_count=0
        skip_count=0
        results=[]
        
        for i,a in enumerate(po['accounts']):
            ki=a.get('key_id','')[:20]
            rt=a.get(_S3,'')  # refresh_token
            ex=a.get('exp',0)
            nw=datetime.now().timestamp()
            
            # 如果没有 refresh_token，跳过
            if not rt:
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":"无refresh_token"})
                continue
            
            # 计算剩余时间
            remaining_hours=(ex-nw)/3600 if ex>nw else 0
            is_expired=ex<=nw
            
            # 非强制模式下，如果 token 还有超过 6 小时有效期，跳过
            if not force_all and remaining_hours>6:
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":f"有效({remaining_hours:.1f}h)"})
                continue
            
            # 调用 WorkOS API 刷新
            try:
                data=urlencode({
                    'grant_type':'refresh_token',
                    'client_id':FACTORY_CLIENT_ID,
                    'refresh_token':rt
                }).encode('utf-8')
                
                req=urllib.request.Request(
                    WORKOS_API_URL,
                    data=data,
                    headers={'Content-Type':'application/x-www-form-urlencoded'},
                    method='POST'
                )
                
                with urllib.request.urlopen(req,timeout=30)as resp:
                    result=json.loads(resp.read().decode('utf-8'))
                    new_at=result.get('access_token','')
                    new_rt=result.get('refresh_token','')
                    
                    if new_at:
                        po['accounts'][i][_S2]=new_at
                        if new_rt:
                            po['accounts'][i][_S3]=new_rt
                        # 解析新 token 的过期时间
                        new_pl=s._0xdj(new_at)
                        if new_pl:
                            po['accounts'][i]['exp']=new_pl.get('exp',0)
                        success_count+=1
                        status_msg="已过期->刷新成功" if is_expired else "刷新成功"
                        results.append({"key":ki,"status":"success","msg":status_msg})
                    else:
                        fail_count+=1
                        results.append({"key":ki,"status":"fail","msg":"无access_token"})
                        
            except urllib.error.HTTPError as e:
                error_body=e.read().decode('utf-8')
                try:
                    error_json=json.loads(error_body)
                    error_desc=error_json.get('error_description',error_json.get('error',''))
                    if 'already exchanged' in error_desc.lower():
                        results.append({"key":ki,"status":"fail","msg":"token已使用,需重新登录"})
                    elif 'expired' in error_desc.lower():
                        results.append({"key":ki,"status":"fail","msg":"refresh_token已过期"})
                    else:
                        results.append({"key":ki,"status":"fail","msg":error_desc[:30]})
                except:
                    results.append({"key":ki,"status":"fail","msg":f"HTTP{e.code}"})
                fail_count+=1
            except Exception as e:
                fail_count+=1
                results.append({"key":ki,"status":"fail","msg":str(e)[:30]})
        
        # 保存更新后的账号池
        s._0xsp(po)
        
        return{
            "success":True,
            "message":f"续期完成: 成功 {success_count}, 失败 {fail_count}, 跳过 {skip_count}",
            "success_count":success_count,
            "fail_count":fail_count,
            "skip_count":skip_count,
            "results":results
        }

    def _0xrsa(s,ix,force_cloud=True):
        """刷新单个账号的额度
        force_cloud: True=用户主动刷新时同步云端, False=仅用官方API查询额度
        """
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        a=po['accounts'][idx];ki=a.get('key_id','');at=a.get(_S2,'');ex=a.get('exp',0);nw=datetime.now().timestamp()
        sfkl1=a.get('sf_key_line1','')
        cloud_synced=False
        last_sync=a.get('last_cloud_sync',0)
        sync_interval=300  # 5分钟内不重复同步云端
        
        # 仅在 force_cloud=True 且距离上次同步超过间隔时才查询云端
        if force_cloud and (nw - last_sync > sync_interval):
            print(f"[云端同步] {ki} - 正在查询云端...")
            cd=None
            # 从本地 token 中提取 user_id 用于备用查询
            user_id=None
            if at:
                pl=s._0xdj(at)
                if pl:user_id=pl.get('id','')
            # 方式1: 用 sfkey_id 查询
            if sfkl1:
                cd=_0xCQ(sfkl1[:35])
            # 方式2: 如果 sfkey_id 查询失败，用 user_id 查询（备用）
            if not cd and user_id:
                print(f"[云端同步] {ki} - sfkey_id查询失败，尝试user_id查询...")
                cd=_0xCQU(user_id)
                # 如果通过 user_id 查到了新的 sfkey_id，更新本地
                if cd and cd.get('sfkey_id'):
                    new_sfkey=cd.get('sfkey_id')
                    print(f"[云端同步] {ki} - 通过user_id查到新sfkey: {new_sfkey}")
                    po['accounts'][idx]['sf_key_line1']=new_sfkey
            if cd and cd.get('access_token') and cd.get('refresh_token'):
                new_at=cd.get('access_token','')
                new_rt=cd.get('refresh_token','')
                new_pl=s._0xdj(new_at)
                new_exp=new_pl.get('exp',0) if new_pl else 0
                # 如果云端 token 比本地新，则更新
                if new_exp>ex:
                    print(f"[云端同步] {ki} - 发现更新! 本地exp:{ex} -> 云端exp:{new_exp}")
                    po['accounts'][idx][_S2]=new_at
                    po['accounts'][idx][_S3]=new_rt
                    po['accounts'][idx]['exp']=new_exp
                    po['accounts'][idx]['last_cloud_sync']=int(nw)
                    s._0xsp(po)
                    at=new_at
                    ex=new_exp
                    cloud_synced=True
                    po=s._0xlp()
                else:
                    print(f"[云端同步] {ki} - 无更新 (云端exp:{new_exp} <= 本地exp:{ex})")
                    po['accounts'][idx]['last_cloud_sync']=int(nw)
                    s._0xsp(po)
            else:
                print(f"[云端同步] {ki} - 云端无数据")
                po['accounts'][idx]['last_cloud_sync']=int(nw)
                s._0xsp(po)
        elif force_cloud:
            print(f"[云端同步] {ki} - 跳过 (距上次同步不足5分钟)")
        
        # 如果 Token 过期，尝试通过官方 API 刷新
        if ex<=nw and a.get(_S3):
            rr=s._0xrta_internal(idx)
            if rr.get('success'):
                po=s._0xlp();at=po['accounts'][idx].get(_S2,'')
        
        # 查询额度（始终使用官方API）
        if at:
            sc=s._0xfb(at,ki)
            if sc:
                msg=f"额度刷新成功: {ki}"
                if cloud_synced:msg=f"已从云端同步并刷新额度: {ki}"
                return{"success":True,"message":msg}
        return{"success":False,"message":"额度刷新失败，请稍后重试"}

    def _0xrta_internal(s,idx):
        """内部方法：刷新 Token"""
        po=s._0xlp()
        if idx<0 or idx>=len(po['accounts']):return{"success":False}
        a=po['accounts'][idx];rt=a.get(_S3,'')
        if not rt:return{"success":False}
        urls=[_S7,_S8]
        for u in urls:
            try:
                d=json.dumps({_S3:rt}).encode('utf-8');rq=urllib.request.Request(u,data=d,headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
                with urllib.request.urlopen(rq,timeout=8)as rs:
                    r=json.loads(rs.read().decode('utf-8'))
                    if _S2 in r:
                        po['accounts'][idx][_S2]=r[_S2]
                        if _S3 in r:po['accounts'][idx][_S3]=r[_S3]
                        pl=s._0xdj(r[_S2])
                        if pl:po['accounts'][idx]['exp']=pl.get('exp',0)
                        s._0xsp(po)
                        return{"success":True}
            except:continue
        return{"success":False}

    def _0xrta(s,ix):
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        a=po['accounts'][idx];rt=a.get(_S3,'')
        if not rt:return{"success":False,"message":"该账号没有 refresh_token"}
        urls=[_S7,_S8]
        for u in urls:
            try:
                d=json.dumps({_S3:rt}).encode('utf-8');rq=urllib.request.Request(u,data=d,headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
                with urllib.request.urlopen(rq,timeout=8)as rs:
                    r=json.loads(rs.read().decode('utf-8'))
                    if _S2 in r:
                        po['accounts'][idx][_S2]=r[_S2]
                        if _S3 in r:po['accounts'][idx][_S3]=r[_S3]
                        pl=s._0xdj(r[_S2])
                        if pl:po['accounts'][idx]['exp']=pl.get('exp',0)
                        s._0xsp(po)
                        return{"success":True,"message":f"刷新成功: {a['key_id']}"}
            except:continue
        # 刷新失败，尝试从云端获取
        sfkl1=a.get('sf_key_line1','')
        if sfkl1:
            cd=_0xCQ(sfkl1[:35])
            if cd and cd.get('access_token')and cd.get('refresh_token'):
                po['accounts'][idx][_S2]=cd['access_token']
                po['accounts'][idx][_S3]=cd['refresh_token']
                pl=s._0xdj(cd['access_token'])
                if pl:po['accounts'][idx]['exp']=pl.get('exp',0)
                s._0xsp(po)
                return{"success":True,"message":f"已从云端同步: {a['key_id']}"}
        return{"success":False,"message":"刷新失败，建议使用 'droid auth login' 重新登录"}

    def _0xfb(s,at,ki):
        try:
            ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            rq=urllib.request.Request(_S6,headers={'Authorization':f'Bearer {at}','Accept':'*/*','User-Agent':'Mozilla/5.0'},method='GET')
            with urllib.request.urlopen(rq,timeout=8,context=ctx)as rs:
                d=json.loads(rs.read().decode('utf-8'));us=d.get('usage',{});sd=us.get('standard',{})
                ta=sd.get('totalAllowance',0);tu=sd.get('orgTotalTokensUsed',0);re=max(0,ta-tu);ur=tu/ta if ta>0 else 0
                lu=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                s._0bc[ki]={'totalAllowance':ta,'totalUsed':tu,'remaining':re,'usedRatio':ur,'lastUpdated':lu,'error':None,'cached':False}
                # 保存缓存到 JSON
                s._0sbc(ki,{'totalAllowance':ta,'totalUsed':tu,'remaining':re,'usedRatio':ur,'lastUpdated':lu})
                return True
        except Exception as e:
            # 查询失败，尝试读取缓存
            cb=s._0gbc(ki)
            if cb:
                s._0bc[ki]={'totalAllowance':cb.get('totalAllowance'),'totalUsed':cb.get('totalUsed'),'remaining':cb.get('remaining'),'usedRatio':cb.get('usedRatio'),'lastUpdated':cb.get('lastUpdated','未知'),'error':None,'cached':True}
                return True
            s._0bc[ki]={'totalAllowance':None,'totalUsed':None,'remaining':None,'usedRatio':None,'lastUpdated':datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'error':str(e),'cached':False}
            return False

    def _0sbc(s,ki,data):
        """保存缓存到 JSON"""
        try:
            po=s._0xlp()
            for a in po['accounts']:
                if a.get('key_id')==ki:
                    a['cached_balance']=data
                    break
            s._0xsp(po)
        except:pass

    def _0gbc(s,ki):
        """从 JSON 读取缓存"""
        try:
            po=s._0xlp()
            for a in po['accounts']:
                if a.get('key_id')==ki:
                    return a.get('cached_balance')
        except:pass
        return None

    def _0xrab(s,force_cloud=False):
        """刷新所有账号额度
        force_cloud: True=同步云端后刷新（用户手动触发）, False=仅刷新当前账号（后台自动刷新用）
        """
        po=s._0xlp();rs=[];nw=datetime.now().timestamp()
        ct=s._0xgct()  # 当前登录的 access_token
        
        if force_cloud:
            # 用户手动刷新：刷新所有账号
            for i,a in enumerate(po['accounts']):
                ki=a.get('key_id','')
                rr=s._0xrsa(i+1,force_cloud=True)
                rs.append({'key_id':ki,'success':rr.get('success',False)})
        else:
            # 后台自动刷新：只刷新当前登录账号
            for i,a in enumerate(po['accounts']):
                if ct and a.get(_S2,'')==ct:
                    ki=a.get('key_id','')
                    rr=s._0xrsa(i+1,force_cloud=False)
                    rs.append({'key_id':ki,'success':rr.get('success',False)})
                    break
        return rs

    def _0xgbi(s,ki):return s._0bc.get(ki,{})

    def _0xSRCC(s):
        """清空Chrome的Google账户信息"""
        import subprocess,shutil
        system=platform.system()
        try:
            if system=='Darwin':
                subprocess.run(['pkill','-f','Google Chrome'],capture_output=True)
                time.sleep(1)
                chrome_dir=Path.home()/'Library'/'Application Support'/'Google'/'Chrome'
                if chrome_dir.exists():
                    for item in ['Default','Profile 1','Profile 2','Profile 3']:
                        p=chrome_dir/item
                        if p.exists():
                            for sub in ['Cookies','Login Data','Web Data','Google Profile']:
                                sp=p/sub
                                if sp.exists():
                                    if sp.is_dir():shutil.rmtree(sp,ignore_errors=True)
                                    else:sp.unlink(missing_ok=True)
                    return{"success":True,"message":"Chrome Google信息已清空"}
                return{"success":False,"message":"未找到Chrome目录"}
            elif system=='Windows':
                subprocess.run(['taskkill','/F','/IM','chrome.exe'],capture_output=True)
                time.sleep(1)
                chrome_dir=Path(os.environ.get('LOCALAPPDATA',''))/'Google'/'Chrome'/'User Data'
                if chrome_dir.exists():
                    for item in ['Default','Profile 1','Profile 2']:
                        p=chrome_dir/item
                        if p.exists():
                            for sub in ['Cookies','Login Data','Web Data']:
                                sp=p/sub
                                if sp.exists():sp.unlink(missing_ok=True)
                    return{"success":True,"message":"Chrome Google信息已清空"}
                return{"success":False,"message":"未找到Chrome目录"}
            return{"success":False,"message":f"不支持的系统: {system}"}
        except Exception as e:
            return{"success":False,"message":f"清空失败: {e}"}

    def _0xSRCL(s,key_id):
        """Cookie登录 - 从云端获取Cookie并注入Chrome"""
        if not key_id:return{"success":False,"message":"未指定账号"}
        po=s._0xlp()
        sfkl1=None
        for a in po['accounts']:
            if a.get('key_id','')==key_id or a.get('sf_key_line1','').startswith(key_id[:35]):
                sfkl1=a.get('sf_key_line1','')
                break
        if not sfkl1:return{"success":False,"message":"未找到账号"}
        # 从云端获取Cookie
        cd=_0xCQC(sfkl1[:35])
        if not cd or not cd.get('cookie'):
            return{"success":False,"message":"云端无Cookie数据，请联系管理员"}
        cookie=cd.get('cookie','')
        # 注入Cookie到Chrome (macOS)
        if platform.system()=='Darwin':
            try:
                import subprocess
                # 打开Google账户页面
                script=f'''
                tell application "Google Chrome"
                    activate
                    open location "https://accounts.google.com/"
                end tell
                delay 2
                tell application "Google Chrome"
                    execute front window's active tab javascript "document.cookie='{cookie}'; location.reload();"
                end tell
                '''
                subprocess.run(['osascript','-e',script],capture_output=True)
                return{"success":True,"message":"Cookie已注入，请检查登录状态"}
            except Exception as e:
                return{"success":False,"message":f"注入失败: {e}"}
        return{"success":False,"message":"当前系统暂不支持Cookie注入"}

    def _0xSROL(s,target_system=None):
        """打开登录页 - 使用后台线程避免阻塞
        target_system: 'mac' 或 'windows'，如果为空则自动检测
        """
        import subprocess
        import threading
        
        # 如果指定了目标系统，使用指定的；否则自动检测
        if target_system=='mac':
            run_system='Darwin'
        elif target_system=='windows':
            run_system='Windows'
        else:
            run_system=platform.system()
        
        def clear_auth_json():
            """清理auth.json"""
            auth_file=Path.home()/'.factory'/'auth.json'
            if auth_file.exists():
                try:
                    auth_file.unlink()
                    return True
                except:pass
            return True
        
        def run_login_flow_mac():
            """Mac后台执行登录流程"""
            try:
                clear_auth_json()
                # 完整流程：启动droid -> 输入/login -> 回车 -> 等待列表 -> 回车确认
                script='''
                tell application "Terminal"
                    activate
                    do script "droid"
                end tell
                delay 6
                tell application "System Events"
                    tell process "Terminal"
                        keystroke "/login"
                        delay 0.5
                        keystroke return
                        delay 2
                        keystroke return
                    end tell
                end tell
                '''
                result=subprocess.run(['osascript','-e',script],capture_output=True,text=True,timeout=30)
                if result.returncode!=0:
                    print(f"AppleScript执行失败: {result.stderr}")
            except Exception as e:
                print(f"登录流程执行失败: {e}")
        
        def run_login_flow_windows():
            """Windows后台执行登录流程"""
            try:
                clear_auth_json()
                # 完整流程：启动droid -> 输入/login -> 回车 -> 等待列表 -> 回车确认
                ps_script='''
                Start-Process cmd -ArgumentList '/k "droid"' -PassThru
                Start-Sleep -Seconds 6
                $wshell = New-Object -ComObject WScript.Shell
                $wshell.AppActivate('droid')
                Start-Sleep -Seconds 1
                $wshell.SendKeys('/login')
                Start-Sleep -Milliseconds 500
                $wshell.SendKeys('{ENTER}')
                Start-Sleep -Seconds 2
                $wshell.SendKeys('{ENTER}')
                '''
                subprocess.run(['powershell','-Command',ps_script],capture_output=True,text=True,timeout=30)
            except Exception as e:
                print(f"Windows登录流程执行失败: {e}")
        
        try:
            if run_system=='Darwin':
                thread=threading.Thread(target=run_login_flow_mac,daemon=True)
                thread.start()
                return{"success":True,"message":"正在启动登录流程 (Mac)...\n请等待终端打开并自动执行/login命令\n然后在浏览器中点击「连接设备」"}
            
            elif run_system=='Windows':
                thread=threading.Thread(target=run_login_flow_windows,daemon=True)
                thread.start()
                return{"success":True,"message":"正在启动登录流程 (Windows)...\n请等待命令提示符打开并自动执行/login命令\n然后在浏览器中点击「连接设备」"}
            
            return{"success":False,"message":f"不支持的系统: {run_system}"}
        except Exception as e:
            return{"success":False,"message":f"启动失败: {e}"}

    def _0xGAR(s,key_id):
        """获取账号地区信息 - 从云端查询"""
        if not key_id:return{"success":False,"message":"未指定账号"}
        po=s._0xlp()
        sfkl1=None
        for a in po['accounts']:
            if a.get('key_id','')==key_id or a.get('sf_key_line1','').startswith(key_id[:35]):
                sfkl1=a.get('sf_key_line1','')
                break
        if not sfkl1:return{"success":False,"message":"未找到账号"}
        # 从云端获取地区信息
        cd=_0xCQC(sfkl1[:35])
        if cd and cd.get('region'):
            return{"success":True,"region":cd.get('region','')}
        return{"success":False,"message":"未设置地区信息"}

    def _0xSRGC(s,key_id):
        """获取账号凭据 - 从云端获取邮箱和密码"""
        if not key_id:return{"success":False,"message":"未指定账号"}
        po=s._0xlp()
        sfkl1=None
        for a in po['accounts']:
            if a.get('key_id','')==key_id or a.get('sf_key_line1','').startswith(key_id[:35]):
                sfkl1=a.get('sf_key_line1','')
                break
        if not sfkl1:return{"success":False,"message":"未找到账号"}
        # 从云端获取凭据
        cd=_0xCQC(sfkl1[:35])
        if not cd:return{"success":False,"message":"云端无凭据数据"}
        return{"success":True,"email":cd.get('email',''),"password":cd.get('password','')}

    def _0xSRUA(s,key_id):
        """更新账号 - 检查auth.json并上传到云端"""
        if not key_id:return{"success":False,"message":"未指定账号"}
        auth_file=Path.home()/'.factory'/'auth.json'
        if not auth_file.exists():
            return{"success":False,"message":"auth.json不存在，请先完成登录"}
        try:
            with open(auth_file,'r')as f:
                auth=json.load(f)
            at=auth.get('access_token','')
            rt=auth.get('refresh_token','')
            if not at or not rt:
                return{"success":False,"message":"auth.json中没有有效Token"}
            pl=s._0xdj(at)
            if not pl:return{"success":False,"message":"Token格式无效"}
            ex=pl.get('exp',0)
            nw=datetime.now().timestamp()
            if ex<=nw:return{"success":False,"message":"Token已过期，请重新登录"}
            # 更新本地token_pool
            po=s._0xlp()
            updated=False
            for i,a in enumerate(po['accounts']):
                if a.get('key_id','')==key_id or a.get('sf_key_line1','').startswith(key_id[:35]):
                    po['accounts'][i][_S2]=at
                    po['accounts'][i][_S3]=rt
                    po['accounts'][i]['exp']=ex
                    updated=True
                    sfkl1=a.get('sf_key_line1','')
                    break
            if not updated:return{"success":False,"message":"账号池中未找到此账号"}
            s._0xsp(po)
            # 上传到云端
            if sfkl1:
                r=_0xUTC(sfkl1[:35],at,rt,ex)
                if r and r.get('success'):
                    return{"success":True,"message":"账号已更新并同步到云端"}
            return{"success":True,"message":"账号已更新（本地），云端同步需管理员操作"}
        except Exception as e:
            return{"success":False,"message":f"更新失败: {e}"}

_H1='''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShoneFactory Token Key</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d3a 100%);
            min-height: 100vh;
            color: #f8f8f2;
            padding: 20px;
        }
        .container { max-width: 1200px; width: 95%; margin: 0 auto; }
        h1 { text-align: center; color: #bd93f9; margin-bottom: 30px; font-size: 28px; }
        .card { background: #282a36; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); }
        .card-title { color: #bd93f9; font-size: 16px; font-weight: bold; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #44475a; }
        textarea { width: 100%; height: 100px; background: #1e1e2e; border: 1px solid #44475a; border-radius: 8px; color: #f8f8f2; padding: 12px; font-family: monospace; font-size: 13px; resize: vertical; }
        textarea:focus { outline: none; border-color: #bd93f9; }
        .hint { color: #6272a4; font-size: 13px; margin-top: 8px; }
        .hint-orange { color: #ffb86c; }
        .btn-row { display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; transition: all 0.2s; }
        .btn:hover { transform: translateY(-1px); }
        .btn-primary { background: #bd93f9; color: #1e1e2e; }
        .btn-primary:hover { background: #caa4ff; }
        .btn-secondary { background: #44475a; color: #f8f8f2; }
        .btn-secondary:hover { background: #565970; }
        .btn-danger { background: #ff5555; color: #fff; }
        .btn-danger:hover { background: #ff6e6e; }
        .btn-success { background: #50fa7b; color: #1e1e2e; }
        .btn-success:hover { background: #6bfb8f; }
        .info-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-top: 15px; }
        .info-row a { color: #8be9fd; text-decoration: none; }
        .info-row a:hover { text-decoration: underline; }
        .info-row span { color: #6272a4; font-size: 13px; }
        .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        table { width: 100%; border-collapse: collapse; min-width: 900px; }
        th, td { padding: 10px 8px; text-align: left; border-bottom: 1px solid #44475a; white-space: nowrap; }
        th { color: #bd93f9; font-weight: 600; font-size: 13px; }
        td { font-size: 13px; }
        tr:hover { background: #2d2d44; }
        .status-current { color: #50fa7b; }
        .status-valid { color: #8be9fd; }
        .status-expired { color: #ff5555; }
        .status-refresh { color: #f1fa8c; }
        .status-pending { color: #6272a4; }
        .balance-good { color: #50fa7b; }
        .balance-medium { color: #f1fa8c; }
        .balance-low { color: #ffb86c; }
        .balance-exhausted { color: #ff5555; }
        .balance-error { color: #ff5555; }
        .balance-pending { color: #6272a4; }
        .balance-estimated { color: #bd93f9; font-style: italic; }
        .cached-badge { font-size: 10px; color: #ffb86c; margin-left: 4px; }
        .action-btn { padding: 5px 10px; font-size: 12px; margin-right: 5px; }
        .btn-request-refresh { display: block; background: linear-gradient(135deg, #ff79c6, #bd93f9); border: none; color: #fff; padding: 3px 8px; font-size: 10px; border-radius: 4px; cursor: pointer; margin-bottom: 4px; transition: all 0.2s; }
        .btn-request-refresh:hover { background: linear-gradient(135deg, #ff92d0, #caa8ff); transform: scale(1.05); }
        .toast { position: fixed; top: 20px; right: 20px; padding: 15px 25px; border-radius: 8px; color: #fff; font-weight: 500; z-index: 1000; animation: slideIn 0.3s ease; }
        .toast-success { background: #50fa7b; color: #1e1e2e; }
        .toast-error { background: #ff5555; }
        .toast-info { background: #8be9fd; color: #1e1e2e; }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 999; justify-content: center; align-items: center; }
        .modal.active { display: flex; }
        .modal-content { background: #282a36; padding: 25px; border-radius: 12px; width: 90%; max-width: 400px; }
        .modal-title { color: #bd93f9; margin-bottom: 15px; }
        .modal input, .modal textarea { width: 100%; margin-bottom: 15px; }
        .modal input { background: #1e1e2e; border: 1px solid #44475a; border-radius: 6px; color: #f8f8f2; padding: 10px; }
        .empty-state { text-align: center; padding: 40px; color: #6272a4; }
        .login-status { padding: 15px; border-radius: 8px; background: #1e1e2e; }
        .login-status .status-row { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; }
        .login-status .user-info { display: flex; align-items: center; gap: 10px; }
        .login-status .status-badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .login-status .badge-active { background: #50fa7b; color: #1e1e2e; }
        .login-status .badge-expired { background: #ff5555; color: #fff; }
        .login-status .badge-none { background: #6272a4; color: #fff; }
        .login-status .badge-synced { background: #8be9fd; color: #1e1e2e; }
        .toolbar { margin-bottom: 15px; }
        .paste-section { display: flex; gap: 20px; }
        .paste-left { flex: 0 0 auto; display: flex; flex-direction: column; }
        .paste-left textarea { width: 580px; height: 200px; resize: none; }
        .paste-right { flex: 1; display: flex; flex-direction: column; }
        .credits-box { background: #1e1e2e; border: 1px solid #44475a; border-radius: 8px; padding: 15px; height: 100%; min-height: 200px; }
        .credits-title { color: #bd93f9; font-size: 14px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #44475a; }
        .credits-item { color: #8be9fd; font-size: 13px; margin-bottom: 8px; }
        .hint-row { display: flex; gap: 20px; margin-top: 8px; }
        .loading { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }
        .loading.active { display: flex; }
        .loading-content { background: #282a36; padding: 30px; border-radius: 12px; text-align: center; min-width: 200px; }
        .progress-ring { width: 80px; height: 80px; margin: 0 auto 15px; position: relative; }
        .progress-ring svg { transform: rotate(-90deg); }
        .progress-ring circle { fill: none; stroke-width: 6; }
        .progress-ring .bg { stroke: #44475a; }
        .progress-ring .progress { stroke: #bd93f9; stroke-linecap: round; transition: stroke-dashoffset 0.3s; }
        .progress-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 14px; font-weight: bold; color: #bd93f9; }
        .loading-message { color: #f8f8f2; font-size: 14px; margin-top: 10px; }
        .spinner { border: 4px solid #44475a; border-top: 4px solid #bd93f9; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 15px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .switch input:checked + .slider { background-color: #50fa7b; }
        .switch .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; }
        .switch input:checked + .slider:before { transform: translateX(20px); }
        .exhausted-list { max-height: 300px; overflow-y: auto; margin: 15px 0; }
        .exhausted-item { display: flex; align-items: center; padding: 10px; background: #1e1e2e; border-radius: 6px; margin-bottom: 8px; }
        .exhausted-item input { margin-right: 10px; }
        .exhausted-item .key-id { font-family: monospace; font-size: 12px; color: #ff5555; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ShoneFactory Token Key</h1>
        <div class="card">
            <div class="card-title">粘贴 Key</div>
            <div class="paste-section">
                <div class="paste-left">
                    <textarea id="tokenInput" placeholder="粘贴完整的 SF-Key Token..."></textarea>
                    <div class="hint-row">
                        <p class="hint hint-orange">首次添加满1000万额度</p>
                    </div>
                    <div class="btn-row">
                        <button class="btn btn-secondary" onclick="clearInput()">清空输入</button>
                        <button class="btn btn-primary" onclick="addToken()">点击添加</button>
                    </div>
                </div>
                <div class="paste-right">
                    <div class="credits-box">
                        <div class="credits-title">致谢</div>
                        <div id="creditsContent">
                            <div class="credits-item">前端程序员：YO！</div>
                            <div class="credits-item">后端程序员：bingw</div>
                        </div>
                        <div id="announcementBox" style="margin-top: 10px; padding-top: 10px; border-top: 1px solid #44475a; display: none;">
                            <div style="color: #ffb86c; font-size: 12px;" id="announcementText"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="info-row">
                <span id="contactInfo">联系作者: haooicq@gmail.com</span>
                <a href="#" target="_blank" id="purchaseLink" style="display:none;"></a>
                <span style="color: #6272a4; font-size: 11px; cursor: pointer;" onclick="checkVersion()">🔄 检查更新</span>
            </div>
        </div>
        <div class="card">
            <div class="card-title">当前登录状态</div>
            <div id="loginStatus" class="login-status">检测中...</div>
        </div>
        <div class="card">
            <div class="card-title">账号池</div>
            <div class="toolbar" style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
                <button class="btn btn-secondary" onclick="loadAccounts()">刷新列表</button>
                <button class="btn btn-info" onclick="syncFromCloud()">☁️ 云端同步</button>
                <button class="btn btn-primary" onclick="refreshAllBalances()">💰 刷新额度</button>
                <button class="btn btn-success" onclick="renewAllTokens()">🔄 全部续期</button>
                <div style="display: flex; align-items: center; gap: 5px; margin-left: 15px; padding: 5px 10px; background: #1e1e2e; border-radius: 6px;">
                    <span style="font-size: 12px; color: #8be9fd;">🔄 自动切换:</span>
                    <label class="switch" style="position: relative; display: inline-block; width: 40px; height: 20px;">
                        <input type="checkbox" id="autoSwitchToggle" onchange="toggleAutoSwitch()" style="opacity: 0; width: 0; height: 0;">
                        <span class="slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #44475a; transition: .3s; border-radius: 20px;"></span>
                    </label>
                    <span id="autoSwitchStatus" style="font-size: 11px; color: #6272a4;">关闭</span>
                </div>
                <button class="btn" style="background: linear-gradient(135deg, #8be9fd, #50fa7b); color: #282a36;" onclick="switchToBest()">⚡ 手动切换最优</button>
                <button class="btn btn-danger" onclick="showExhaustedAccounts()">🗑️ 删除已耗尽</button>
            </div>
            <div id="accountList"></div>
        </div>
    </div>
    <div class="modal" id="renewModal">
        <div class="modal-content" style="max-width: 420px;">
            <h3 class="modal-title">🔄 全部续期</h3>
            <div style="background: #1e1e2e; border-radius: 8px; padding: 12px; margin-bottom: 15px; font-size: 12px; color: #cdd6f4;">
                <p style="margin-bottom: 8px;">• 智能续期：仅刷新已过期的账号</p>
                <p style="margin-bottom: 0;">• 强制续期：刷新所有账号（包括有效的）</p>
            </div>
            <div style="background: #2d1f1f; border-radius: 8px; padding: 10px; margin-bottom: 15px; font-size: 11px; color: #f9e2af;">
                <p style="margin-bottom: 5px;">⚠️ 续期后仍失效？可能原因：</p>
                <p style="margin-bottom: 3px;">1. Key额度已耗尽</p>
                <p style="margin-bottom: 0;">2. 服务器刷新失败 → 请使用「自主刷新」</p>
            </div>
            <div class="btn-row" style="gap: 8px;">
                <button class="btn btn-success" onclick="doRenewTokens(false)">智能续期</button>
                <button class="btn btn-warning" onclick="doRenewTokens(true)">强制续期</button>
                <button class="btn btn-secondary" onclick="closeRenewModal()">关闭</button>
            </div>
        </div>
    </div>
    <div class="modal" id="remarkModal">
        <div class="modal-content">
            <h3 class="modal-title">编辑备注</h3>
            <input type="hidden" id="remarkIndex">
            <textarea id="remarkInput" rows="3" placeholder="输入备注..."></textarea>
            <div class="btn-row">
                <button class="btn btn-primary" onclick="saveRemark()">保存</button>
                <button class="btn btn-secondary" onclick="closeModal()">取消</button>
            </div>
        </div>
    </div>
    <div class="modal" id="selfRefreshModal">
        <div class="modal-content" style="max-width: 580px;">
            <h3 class="modal-title">🔄 自主刷新账号</h3>
            <p style="color: #8be9fd; font-size: 12px; margin-bottom: 5px;">Key: <span id="refreshKeyIdDisplay" style="font-family: monospace;"></span></p>
            <p style="color: #ffb86c; font-size: 11px; margin-bottom: 10px;">地区节点: <span id="refreshRegionDisplay">-</span></p>
            <div style="background: #1e1e2e; border-radius: 8px; padding: 12px; margin-bottom: 15px; font-size: 11px; color: #cdd6f4; max-height: 180px; overflow-y: auto;">
                <div style="color: #f9e2af; font-weight: bold; margin-bottom: 8px;">📋 刷新步骤：</div>
                <div style="margin-bottom: 4px;">1️⃣ 设置 Chrome 为默认浏览器（刷新完之后可以改回去）</div>
                <div style="margin-bottom: 4px;">2️⃣ 将您的干净节点切换至「<span style="color:#50fa7b;" id="refreshRegionHint">对应地区</span>」</div>
                <div style="margin-bottom: 4px;">3️⃣ 点击下方「🍪 Cookie注入」将云端Cookie注入到Chrome</div>
                <div style="margin-bottom: 4px;">4️⃣ 点击下方「🌐 打开登录页」选择您的系统后启动登录流程</div>
                <div style="margin-bottom: 4px;">5️⃣ 如果账户未自动登录，请点击「复制账号」「复制密码」手动登录</div>
                <div style="margin-bottom: 4px;">6️⃣ 登录成功后，在浏览器中点击「连接设备」</div>
                <div style="margin-bottom: 8px;">7️⃣ 最后点击「✅ 更新账号」保存Token</div>
                <div style="color: #6272a4; font-size: 10px; border-top: 1px dashed #44475a; padding-top: 8px;">
                    💡 备注：不自主刷新账号功能仍可使用，但无法查询余额。如果流程繁琐，可点击「📨 申请刷新」，服务器会在闲时进行刷新同步。
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                <button class="btn" style="background: linear-gradient(135deg, #ff79c6, #bd93f9); color: white; padding: 10px 8px;" onclick="selfRefreshCookieInject()">🍪 Cookie注入</button>
                <button class="btn" style="background: linear-gradient(135deg, #bd93f9, #8be9fd); color: white; padding: 10px 8px;" onclick="showSystemSelect()">🌐 打开登录页</button>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-bottom: 10px;">
                <button class="btn" style="background: linear-gradient(135deg, #f1fa8c, #ffb86c); color: #282a36; padding: 8px 6px; font-size: 12px;" onclick="selfRefreshCopyEmail()">📧 复制账号</button>
                <button class="btn" style="background: linear-gradient(135deg, #ffb86c, #ff5555); color: white; padding: 8px 6px; font-size: 12px;" onclick="selfRefreshCopyPassword()">🔑 复制密码</button>
                <button class="btn btn-secondary" style="padding: 8px 6px; font-size: 12px;" onclick="selfRefreshClearChrome()">🗑️ 清空Chrome</button>
            </div>
            <div style="display: grid; grid-template-columns: 1fr; gap: 8px; margin-bottom: 12px;">
                <button class="btn" style="background: linear-gradient(135deg, #50fa7b, #8be9fd); color: #282a36; padding: 12px; font-size: 14px; font-weight: bold;" onclick="selfRefreshUpdateAccount()">✅ 更新账号（登录成功后点击）</button>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="btn btn-secondary" style="flex: 1; font-size: 11px;" onclick="selfRefreshSubmitRequest()">📨 申请刷新</button>
                <button class="btn btn-secondary" style="flex: 1; font-size: 11px;" onclick="closeSelfRefreshModal()">关闭</button>
            </div>
        </div>
    </div>
    <div class="modal" id="systemSelectModal">
        <div class="modal-content" style="max-width: 350px;">
            <h3 class="modal-title">🖥️ 选择您的系统</h3>
            <p style="color: #6272a4; font-size: 12px; margin-bottom: 15px;">请选择您当前使用的操作系统：</p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                <button class="btn" style="background: linear-gradient(135deg, #6272a4, #44475a); color: white; padding: 20px; font-size: 14px;" onclick="selfRefreshOpenLoginMac()">🍎 Mac 系统</button>
                <button class="btn" style="background: linear-gradient(135deg, #8be9fd, #6272a4); color: #282a36; padding: 20px; font-size: 14px;" onclick="selfRefreshOpenLoginWindows()">🪟 Windows</button>
            </div>
            <div style="margin-top: 15px;">
                <button class="btn btn-secondary" style="width: 100%;" onclick="closeSystemSelect()">取消</button>
            </div>
        </div>
    </div>
    <div class="modal" id="exhaustedModal">
        <div class="modal-content" style="max-width: 500px;">
            <h3 class="modal-title">🗑️ 删除已耗尽账号</h3>
            <p style="color: #6272a4; font-size: 12px; margin-bottom: 10px;">以下账号使用率 ≥ 100%，勾选后点击删除</p>
            <div class="exhausted-list" id="exhaustedList">加载中...</div>
            <div class="btn-row">
                <button class="btn btn-danger" onclick="confirmDeleteExhausted()">确认删除</button>
                <button class="btn btn-secondary" onclick="closeExhaustedModal()">取消</button>
            </div>
        </div>
    </div>
    <div class="loading" id="loadingOverlay">
        <div class="loading-content">
            <div class="progress-ring">
                <svg width="80" height="80">
                    <circle class="bg" cx="40" cy="40" r="34"></circle>
                    <circle class="progress" id="progressCircle" cx="40" cy="40" r="34" stroke-dasharray="213.6" stroke-dashoffset="213.6"></circle>
                </svg>
                <div class="progress-text" id="progressText">0%</div>
            </div>
            <div class="loading-message" id="loadingMessage">API Key 正在读取中...</div>
        </div>
    </div>
    <script>
        let loadingTimer = null;
        let progressInterval = null;
        let currentTimeout = 30000;
        function showLoading(message = 'API Key 正在读取中...', timeout = 30000) {
            currentTimeout = timeout;
            document.getElementById('loadingMessage').textContent = message;
            document.getElementById('loadingOverlay').classList.add('active');
            setProgress(0);
            let progress = 0;
            const startTime = Date.now();
            if (progressInterval) clearInterval(progressInterval);
            progressInterval = setInterval(() => {
                const elapsed = Date.now() - startTime;
                progress = Math.min(95, (elapsed / currentTimeout) * 100);
                setProgress(progress);
            }, 100);
            if (loadingTimer) clearTimeout(loadingTimer);
            loadingTimer = setTimeout(() => {
                hideLoading();
                showToast('操作超时，请重试', 'error');
            }, currentTimeout);
        }
        function hideLoading() {
            if (loadingTimer) { clearTimeout(loadingTimer); loadingTimer = null; }
            if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
            setProgress(100);
            setTimeout(() => {
                document.getElementById('loadingOverlay').classList.remove('active');
                setProgress(0);
            }, 200);
        }
        function setProgress(percent) {
            const circle = document.getElementById('progressCircle');
            const text = document.getElementById('progressText');
            const circumference = 213.6;
            const offset = circumference - (percent / 100) * circumference;
            circle.style.strokeDashoffset = offset;
            text.textContent = Math.round(percent) + '%';
        }
        function showToast(message, type = 'info') {
            const toast = document.createElement('div');
            toast.className = 'toast toast-' + type;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }
        function clearInput() { document.getElementById('tokenInput').value = ''; }
        
        // 服务状态检测和自动重连
        let serverOnline = true;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 100;
        
        async function checkServerStatus() {
            try {
                const response = await fetch('/api', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'ping' }),
                    signal: AbortSignal.timeout(3000)
                });
                if (response.ok) {
                    if (!serverOnline) {
                        serverOnline = true;
                        reconnectAttempts = 0;
                        showToast('服务已恢复连接', 'success');
                        loadLoginStatus();
                        loadAccounts();
                    }
                    return true;
                }
            } catch (e) {
                if (serverOnline) {
                    serverOnline = false;
                    showToast('服务连接断开，正在尝试重连...', 'error');
                }
            }
            return false;
        }
        
        // 每5秒检测一次服务状态
        setInterval(async () => {
            if (!serverOnline) {
                reconnectAttempts++;
                if (reconnectAttempts <= maxReconnectAttempts) {
                    await checkServerStatus();
                }
            } else {
                await checkServerStatus();
            }
        }, 5000);
        
        async function api(action, data = {}) {
            try {
                const response = await fetch('/api', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action, ...data })
                });
                serverOnline = true;
                return response.json();
            } catch (e) {
                serverOnline = false;
                showToast('服务连接失败，请检查客户端是否运行', 'error');
                return { success: false, message: '服务未响应' };
            }
        }
        async function addToken() {
            const content = document.getElementById('tokenInput').value.trim();
            if (!content) { showToast('请先粘贴 Key', 'error'); return; }
            showLoading('您的 SF-Key 正在加载中，请稍后...', 20000);
            const result = await api('add', { content });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                clearInput();
                loadAccounts();
                loadLoginStatus();
            } else if (result.exists) {
                showToast(result.message, 'info');
            } else { 
                showToast(result.message, 'error'); 
            }
        }
        let isFirstLoad = true;  // 标记是否首次加载
        async function loadAccounts() {
            const result = await api('list');
            const container = document.getElementById('accountList');
            if (!result.accounts || result.accounts.length === 0) {
                container.innerHTML = '<div class="empty-state">暂无账号，请添加 Key</div>';
                return;
            }
            
            // 检查是否有需要同步的账号（状态为 pending 或 refresh）
            const needSync = result.accounts.some(acc => acc.status === 'pending' || acc.status === 'refresh' || acc.balance_status === 'pending');
            
            // 首次加载且有需要同步的账号，自动触发云端同步
            if (isFirstLoad && needSync) {
                isFirstLoad = false;
                showToast('检测到新账号，正在从云端同步数据...', 'info');
                setTimeout(() => syncFromCloud(), 500);
            }
            
            let html = '<div class="table-wrapper"><table><thead><tr><th>#</th><th>Key 编号</th><th>状态</th><th>额度状态</th><th>剩余</th><th>使用率</th><th>备注</th><th>添加时间</th><th>操作</th></tr></thead><tbody>';
            for (const acc of result.accounts) {
                const statusClass = 'status-' + acc.status;
                const statusIcon = acc.is_current ? '🟢' : (acc.status === 'valid' ? '✅' : (acc.status === 'refresh' ? '🔄' : (acc.status === 'pending' ? '⏳' : '❌')));
                const balanceClass = 'balance-' + acc.balance_status;
                const balanceIcon = (acc.status === 'refresh' && acc.balance_text === '-') ? '' : (acc.balance_status === 'good' ? '🟢' : acc.balance_status === 'medium' ? '🟡' : acc.balance_status === 'low' ? '🔴' : acc.balance_status === 'exhausted' ? '⚠️' : acc.balance_status === 'error' ? '❌' : '⏳');
                const keyDisplay = acc.key_id.startsWith('SF-') && acc.key_id.length > 35 ? acc.key_id.substring(0, 35) + '...' : acc.key_id;
                const cachedTip = acc.cached && acc.last_updated ? ` title="缓存数据，更新于: ${acc.last_updated}"` : '';
                const statusTip = acc.status === 'refresh' ? ' title="Token已过期，点击☁️云端同步获取最新数据"' : (acc.status === 'pending' ? ' title="待验证状态，请点击☁️云端同步获取数据"' : '');
                const balanceTip = acc.balance_status === 'error' ? ' title="注意：查询失败并不代表key失效，如果key额度高于20%请在几小时后重新查询，在额度使用完之前，此提示并不影响使用"' : cachedTip;
                // 状态为 refresh 或 pending 时显示同步按钮
                const syncBtn = (acc.status === 'refresh' || acc.status === 'pending') ? `<button class="btn-request-refresh" onclick="syncFromCloud()" title="从云端同步最新数据">☁️ 同步</button>` : '';
                const refreshRequestBtn = acc.status === 'refresh' ? `<button class="btn-request-refresh" onclick="requestRefresh('${acc.key_id}')" title="向管理员申请刷新此Key">📨 申请</button>` : '';
                const actionBtn = acc.is_current 
                    ? '<span class="btn btn-success action-btn" style="cursor:default;opacity:0.8;">已登录</span>' 
                    : `<button class="btn btn-success action-btn" onclick="switchAccount(${acc.index})">切换</button>`;
                html += `<tr><td>${acc.index}</td><td style="font-family: monospace; font-size: 11px;">${syncBtn}${refreshRequestBtn}${keyDisplay}</td><td class="${statusClass}"${statusTip}>${statusIcon} ${acc.is_current ? '登录中' : acc.status_text}</td><td class="${balanceClass}"${balanceTip}>${balanceIcon} ${acc.balance_text}</td><td>${acc.remaining}</td><td>${acc.usage_ratio}</td><td>${acc.remark || '-'}</td><td>${acc.added_at}</td><td>${actionBtn}<button class="btn btn-secondary action-btn" onclick="editRemark(${acc.index}, '${(acc.remark || '').replace(/'/g, "\\\\'")}')">备注</button><button class="btn btn-danger action-btn" onclick="deleteAccount(${acc.index})">删除</button></td></tr>`;
            }
            html += '</tbody></table></div>';
            container.innerHTML = html;
        }
        async function syncFromCloud() {
            showLoading('正在从云端同步账号数据...', 60000);
            const result = await api('sync_from_cloud');
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                loadAccounts();
                loadLoginStatus();
            } else {
                showToast(result.message || '同步失败', 'error');
            }
        }
        async function refreshAllBalances() {
            showToast('正在查询所有账号额度...', 'info');
            const result = await api('refresh_balances');
            if (result.success) { showToast('额度查询完成', 'success'); loadAccounts(); }
            else { showToast(result.message || '查询失败', 'error'); }
        }
        function renewAllTokens() {
            document.getElementById('renewModal').classList.add('active');
        }
        function closeRenewModal() {
            document.getElementById('renewModal').classList.remove('active');
        }
        async function doRenewTokens(forceAll) {
            closeRenewModal();
            const msg = forceAll ? '正在强制续期所有账号...' : '正在智能续期...';
            showLoading(msg, 60000);
            const result = await api('renew_all_tokens', { force_all: forceAll });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                loadAccounts();
                loadLoginStatus();
            } else {
                showToast(result.message || '续期失败', 'error');
            }
        }
        async function loadLoginStatus() {
            const container = document.getElementById('loginStatus');
            try {
                const result = await api('login_info');
                if (result.success && result.info) {
                    const info = result.info;
                    // 只显示有效/过期状态
                    let statusBadge;
                    if (info.expired) {
                        statusBadge = '<span class="status-badge badge-expired">已过期</span>';
                    } else {
                        statusBadge = '<span class="status-badge badge-active">有效</span>';
                    }
                    // 优先显示 sfkey，其次邮箱
                    let userDisplay = info.sf_key_line1 || info.email || (info.sub ? `用户ID: ${info.sub.substring(0, 12)}...` : '未知用户');
                    if (userDisplay.startsWith('SF-') && userDisplay.length > 35) userDisplay = userDisplay.substring(0, 35) + '...';
                    container.innerHTML = `<div class="status-row"><div class="user-info"><span style="font-family: monospace; font-size: 12px;">🔐 ${userDisplay}</span>${statusBadge}</div></div>`;
                } else { container.innerHTML = '<span style="color: #6272a4;">❌ 未检测到登录账号（请先运行 droid auth login）</span>'; }
            } catch (e) { container.innerHTML = '<span style="color: #ff5555;">检测失败</span>'; }
        }
        async function switchAccount(index) {
            showLoading('正在切换账号...', 35000);
            const result = await api('switch', { index });
            hideLoading();
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { loadAccounts(); loadLoginStatus(); }
        }
        async function deleteAccount(index) {
            if (!confirm('确定要删除这个账号吗？')) return;
            const result = await api('delete', { index });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) loadAccounts();
        }
        async function refreshToken(index) {
            showToast('正在刷新...', 'info');
            const result = await api('refresh', { index });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) loadAccounts();
        }
        function editRemark(index, currentRemark) {
            document.getElementById('remarkIndex').value = index;
            document.getElementById('remarkInput').value = currentRemark;
            document.getElementById('remarkModal').classList.add('active');
        }
        function closeModal() { document.getElementById('remarkModal').classList.remove('active'); }
        async function saveRemark() {
            const index = parseInt(document.getElementById('remarkIndex').value);
            const remark = document.getElementById('remarkInput').value.trim();
            const result = await api('remark', { index, remark });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { closeModal(); loadAccounts(); }
        }
        let currentRefreshKeyId = '';
        let currentRefreshRegion = '';
        async function requestRefresh(keyId) {
            currentRefreshKeyId = keyId;
            document.getElementById('selfRefreshModal').classList.add('active');
            document.getElementById('refreshKeyIdDisplay').textContent = keyId.substring(0, 35) + '...';
            // 获取账号的地区信息
            const result = await api('get_account_region', { key_id: keyId });
            if (result.success && result.region) {
                currentRefreshRegion = result.region;
                document.getElementById('refreshRegionDisplay').textContent = result.region;
                document.getElementById('refreshRegionHint').textContent = result.region;
            } else {
                currentRefreshRegion = '';
                document.getElementById('refreshRegionDisplay').textContent = '未设置';
                document.getElementById('refreshRegionHint').textContent = '对应地区';
            }
        }
        function closeSelfRefreshModal() {
            document.getElementById('selfRefreshModal').classList.remove('active');
            currentRefreshKeyId = '';
            currentRefreshRegion = '';
        }
        async function selfRefreshClearChrome() {
            showToast('正在清空Chrome Google信息...', 'info');
            const result = await api('self_refresh_clear_chrome');
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshCookieInject() {
            if (!currentRefreshKeyId) { showToast('请先选择账号', 'error'); return; }
            showToast('正在从云端获取Cookie并注入...', 'info');
            const result = await api('self_refresh_cookie_login', { key_id: currentRefreshKeyId });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        function showSystemSelect() {
            document.getElementById('systemSelectModal').classList.add('active');
        }
        function closeSystemSelect() {
            document.getElementById('systemSelectModal').classList.remove('active');
        }
        async function selfRefreshOpenLoginMac() {
            closeSystemSelect();
            showToast('正在打开登录页 (Mac)...', 'info');
            const result = await api('self_refresh_open_login', { system: 'mac' });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshOpenLoginWindows() {
            closeSystemSelect();
            showToast('正在打开登录页 (Windows)...', 'info');
            const result = await api('self_refresh_open_login', { system: 'windows' });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshCopyEmail() {
            if (!currentRefreshKeyId) { showToast('请先选择账号', 'error'); return; }
            const result = await api('self_refresh_get_credentials', { key_id: currentRefreshKeyId });
            if (result.success && result.email) {
                navigator.clipboard.writeText(result.email);
                showToast('邮箱已复制到剪贴板', 'success');
            } else {
                showToast(result.message || '获取邮箱失败', 'error');
            }
        }
        async function selfRefreshCopyPassword() {
            if (!currentRefreshKeyId) { showToast('请先选择账号', 'error'); return; }
            const result = await api('self_refresh_get_credentials', { key_id: currentRefreshKeyId });
            if (result.success && result.password) {
                navigator.clipboard.writeText(result.password);
                showToast('密码已复制到剪贴板', 'success');
            } else {
                showToast(result.message || '获取密码失败', 'error');
            }
        }
        async function selfRefreshUpdateAccount() {
            if (!currentRefreshKeyId) { showToast('请先选择账号', 'error'); return; }
            showToast('正在检查并更新账号...', 'info');
            const result = await api('self_refresh_update_account', { key_id: currentRefreshKeyId });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { loadAccounts(); loadLoginStatus(); }
        }
        async function selfRefreshSubmitRequest() {
            if (!currentRefreshKeyId) { showToast('请先选择账号', 'error'); return; }
            showToast('正在提交申请...', 'info');
            const result = await api('request_refresh', { key_id: currentRefreshKeyId });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        loadAccounts();
        loadLoginStatus();
        loadCloudConfig();
        let autoRefreshTimer = null;
        async function autoRefreshBalances() { 
            try { 
                await api('auto_refresh'); 
                loadAccounts(); 
            } catch(e) { console.error('Auto refresh error:', e); } 
        }
        function startAutoRefresh() { 
            // 首次延迟10秒后执行，之后每5分钟刷新一次
            setTimeout(async () => { 
                await autoRefreshBalances(); 
                autoRefreshTimer = setInterval(autoRefreshBalances, 300000); 
            }, 10000); 
        }
        startAutoRefresh();
        
        async function loadCloudConfig() {
            try {
                const result = await api('cloud_config');
                if (result.success && result.config) {
                    updateUIConfig(result.config);
                }
            } catch (e) {}
        }
        
        function updateUIConfig(config) {
            // 更新致谢列表
            if (config.credits && config.credits.length > 0) {
                const creditsHtml = config.credits.map(c => 
                    `<div class="credits-item">${c.role}：${c.name}</div>`
                ).join('');
                document.getElementById('creditsContent').innerHTML = creditsHtml;
            }
            // 更新购买链接（只有配置了才显示）
            if (config.purchase_text) {
                const link = document.getElementById('purchaseLink');
                const url = config.purchase_url || '';
                // 如果有有效链接则显示为链接，否则显示为普通文本
                if (url && url.length > 10 && url !== 'https://...' && url !== 'https://') {
                    link.href = url;
                    link.style.cursor = 'pointer';
                } else {
                    link.removeAttribute('href');
                    link.style.cursor = 'default';
                }
                link.textContent = config.purchase_text;
                link.style.display = 'inline';  // 配置了才显示
            }
            // 更新联系方式
            if (config.contact) {
                document.getElementById('contactInfo').textContent = '联系作者: ' + config.contact;
            }
            // 更新公告
            if (config.announcement) {
                document.getElementById('announcementText').textContent = config.announcement;
                document.getElementById('announcementBox').style.display = 'block';
            }
        }
        
        async function checkVersion() {
            showToast('检查更新中...', 'info');
            try {
                const result = await api('check_version');
                if (result.success && result.version) {
                    const v = result.version;
                    const msg = `当前版本: ${v.current || '1.0.0'}\\n\\n更新日志:\\n${v.changelog || '无'}`;
                    if (confirm(msg + '\\n\\n点击确定下载最新版本')) {
                        window.open(v.download_url || 'https://github.com/shone2025/shone-factory/releases/latest', '_blank');
                    }
                } else {
                    showToast(result.message || '检查更新失败', 'error');
                }
            } catch (e) {
                showToast('检查更新失败: ' + e, 'error');
            }
        }
        
        // 自动切换功能
        async function loadAutoSwitchStatus() {
            const result = await api('get_auto_switch');
            const enabled = result.auto_switch || false;
            document.getElementById('autoSwitchToggle').checked = enabled;
            document.getElementById('autoSwitchStatus').textContent = enabled ? '开启' : '关闭';
            document.getElementById('autoSwitchStatus').style.color = enabled ? '#50fa7b' : '#6272a4';
        }
        async function toggleAutoSwitch() {
            const enabled = document.getElementById('autoSwitchToggle').checked;
            const result = await api('set_auto_switch', { enabled });
            showToast(result.message, result.success ? 'success' : 'error');
            document.getElementById('autoSwitchStatus').textContent = enabled ? '开启' : '关闭';
            document.getElementById('autoSwitchStatus').style.color = enabled ? '#50fa7b' : '#6272a4';
        }
        async function switchToBest() {
            showLoading('正在切换到最优账号...', 35000);
            const result = await api('switch_best');
            hideLoading();
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { loadAccounts(); loadLoginStatus(); }
        }
        
        // 删除已耗尽账号功能
        let exhaustedAccounts = [];
        async function showExhaustedAccounts() {
            const result = await api('get_exhausted');
            exhaustedAccounts = result.accounts || [];
            const list = document.getElementById('exhaustedList');
            if (exhaustedAccounts.length === 0) {
                list.innerHTML = '<div style="text-align: center; color: #50fa7b; padding: 20px;">🎉 没有已耗尽的账号</div>';
            } else {
                list.innerHTML = exhaustedAccounts.map(acc => 
                    `<div class="exhausted-item">
                        <input type="checkbox" class="exhaust-check" data-index="${acc.index}" checked>
                        <span class="key-id">${acc.key_id}</span>
                        <span style="margin-left: auto; color: #ff5555; font-size: 11px;">${acc.usage || '已耗尽'}</span>
                    </div>`
                ).join('');
            }
            document.getElementById('exhaustedModal').classList.add('active');
        }
        function closeExhaustedModal() {
            document.getElementById('exhaustedModal').classList.remove('active');
        }
        async function confirmDeleteExhausted() {
            const checks = document.querySelectorAll('.exhaust-check:checked');
            const indices = Array.from(checks).map(c => parseInt(c.dataset.index));
            if (indices.length === 0) {
                showToast('请至少选择一个账号', 'error');
                return;
            }
            if (!confirm(`确定要删除 ${indices.length} 个已耗尽账号吗？`)) return;
            const result = await api('delete_exhausted', { indices });
            showToast(result.message, result.success ? 'success' : 'error');
            closeExhaustedModal();
            if (result.success) loadAccounts();
        }
        
        // 页面加载时初始化自动切换状态
        loadAutoSwitchStatus();
    </script>
</body>
</html>
'''

class _0xRH(BaseHTTPRequestHandler):
    _0m=_0xTM()
    def log_message(s,f,*a):pass
    def _0xsj(s,d,st=200):
        s.send_response(st);s.send_header('Content-Type','application/json; charset=utf-8');s.send_header('Access-Control-Allow-Origin','*');s.end_headers()
        s.wfile.write(json.dumps(d,ensure_ascii=False).encode('utf-8'))
    def _0xsh(s,h):
        s.send_response(200);s.send_header('Content-Type','text/html; charset=utf-8');s.end_headers();s.wfile.write(h.encode('utf-8'))
    def do_GET(s):
        _0xCHK()
        if s.path=='/'or s.path=='/index.html':s._0xsh(_H1)
        else:s.send_response(404);s.end_headers()
    def do_POST(s):
        _0xCHK()
        if s.path=='/api':
            cl=int(s.headers.get('Content-Length',0));bd=s.rfile.read(cl).decode('utf-8')
            try:
                d=json.loads(bd);ac=d.get('action','')
                if ac=='add':r=s._0m._0xat(d.get('content',''))
                elif ac=='list':r={"accounts":s._0m._0xgal()}
                elif ac=='sync_from_cloud':r=s._0m._0xsfc()
                elif ac=='switch':r=s._0m._0xswa(d.get('index',0))
                elif ac=='delete':r=s._0m._0xda(d.get('index',0))
                elif ac=='remark':r=s._0m._0xur(d.get('index',0),d.get('remark',''))
                elif ac=='refresh':r=s._0m._0xrsa(d.get('index',0),force_cloud=True)
                elif ac=='refresh_balances':s._0m._0xrab(force_cloud=True);r={"success":True,"message":"额度查询完成"}
                elif ac=='auto_refresh':s._0m._0xrab(force_cloud=False);r={"success":True,"message":"自动刷新完成"}
                elif ac=='sync_login':r=s._0m._0xscl()
                elif ac=='login_info':i=s._0m._0xgcli();r={"success":True,"info":i}
                elif ac=='cloud_config':c=_0xGCF();r={"success":True,"config":c}if c else{"success":False}
                elif ac=='check_version':r=_0xGVR()
                elif ac=='request_refresh':r=_0xRRF(d.get('key_id',''))
                elif ac=='self_refresh_clear_chrome':r=s._0m._0xSRCC()
                elif ac=='self_refresh_cookie_login':r=s._0m._0xSRCL(d.get('key_id',''))
                elif ac=='self_refresh_open_login':r=s._0m._0xSROL(d.get('system'))
                elif ac=='get_account_region':r=s._0m._0xGAR(d.get('key_id',''))
                elif ac=='self_refresh_get_credentials':r=s._0m._0xSRGC(d.get('key_id',''))
                elif ac=='self_refresh_update_account':r=s._0m._0xSRUA(d.get('key_id',''))
                elif ac=='switch_best':r=s._0m._0xsbo()
                elif ac=='get_exhausted':r=s._0m._0xgex()
                elif ac=='delete_exhausted':r=s._0m._0xdex(d.get('indices',[]))
                elif ac=='get_auto_switch':r=s._0m._0xgas()
                elif ac=='set_auto_switch':r=s._0m._0xsas(d.get('enabled',False))
                elif ac=='renew_all_tokens':r=s._0m._0xrat(d.get('force_all',False))
                elif ac=='ping':r={"success":True,"message":"pong","timestamp":time.time()}
                else:r={"success":False,"message":"未知操作"}
                s._0xsj(r)
            except Exception as e:s._0xsj({"success":False,"message":str(e)},500)
        else:s.send_response(404);s.end_headers()

def _0xM():
    _0xCHK()
    print("="*50)
    print("  ShoneFactory Token Key - Web 版")
    print("="*50)
    print()
    sv=HTTPServer((_H0,_P0),_0xRH);url=f"http://{_H0}:{_P0}"
    print(f"  服务已启动: {url}")
    print();print("  正在打开浏览器...");print();print("  按 Ctrl+C 停止服务");print()
    def _ob():webbrowser.open(url)
    threading.Timer(0.5,_ob).start()
    try:sv.serve_forever()
    except KeyboardInterrupt:print("\n  服务已停止");sv.shutdown()

if __name__=='__main__':
    _0xCHK()
    _0xM()
