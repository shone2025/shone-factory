#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os,sys,json,base64,platform,webbrowser,urllib.request,urllib.error,ssl,time,hashlib,socket,uuid,zlib,subprocess
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

# 设备唯一标识
_DEVICE_ID = None
_DEVICE_ID_FILE = Path(__file__).parent / '.device_id'

def _get_mac_address():
    """获取设备 MAC 地址"""
    try:
        mac = uuid.getnode()
        # 格式化为标准 MAC 地址格式
        mac_str = ':'.join(('%012x' % mac)[i:i+2] for i in range(0, 12, 2))
        return mac_str
    except:
        return None

def _generate_device_id():
    """生成设备唯一标识"""
    global _DEVICE_ID
    
    # 如果已有 ID，直接返回
    if _DEVICE_ID:
        return _DEVICE_ID
    
    # 尝试从文件读取
    if _DEVICE_ID_FILE.exists():
        try:
            with open(_DEVICE_ID_FILE, 'r') as f:
                data = json.load(f)
                _DEVICE_ID = data.get('device_id')
                if _DEVICE_ID:
                    return _DEVICE_ID
        except:
            pass
    
    # 生成新的设备 ID
    mac = _get_mac_address() or str(uuid.uuid4())
    hostname = socket.gethostname()
    system = platform.system()
    
    # 组合并哈希
    raw = f"{mac}:{hostname}:{system}:{uuid.uuid4().hex[:8]}"
    device_id = hashlib.sha256(raw.encode()).hexdigest()[:32]
    device_id = f"SF-D-{device_id}"
    
    # 保存到文件
    try:
        with open(_DEVICE_ID_FILE, 'w') as f:
            json.dump({
                'device_id': device_id,
                'mac': mac,
                'hostname': hostname,
                'system': system,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }, f, indent=2)
    except:
        pass
    
    _DEVICE_ID = device_id
    return device_id

def _register_client():
    """向云端注册客户端"""
    device_id = _generate_device_id()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        data = json.dumps({
            'device_id': device_id,
            'hostname': socket.gethostname(),
            'system': platform.system(),
            'version': '1.0'
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/client/register",
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-Client-Key': _CLIENT_KEY
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"客户端注册失败: {e}")
        return None

def _send_heartbeat():
    """发送心跳"""
    device_id = _generate_device_id()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        data = json.dumps({
            'device_id': device_id
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/client/heartbeat",
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-Client-Key': _CLIENT_KEY
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except:
        return None

def _get_share_info():
    """获取分享信息"""
    device_id = _generate_device_id()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/client/share-info/{device_id}",
            headers={
                'X-Client-Key': _CLIENT_KEY
            },
            method='GET'
        )
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"获取分享信息失败: {e}")
        return None

def _report_sfkey_import(referrer_id=None):
    """上报 SF-Key 导入（用于分享追踪）"""
    device_id = _generate_device_id()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        data = json.dumps({
            'device_id': device_id,
            'referrer_id': referrer_id
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/share/confirm-import",
            data=data,
            headers={
                'Content-Type': 'application/json',
                'X-Client-Key': _CLIENT_KEY
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except:
        return None

def _0xGCF():
    """从云端获取客户端配置（绕过系统代理）"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        no_proxy_handler=urllib.request.ProxyHandler({})
        opener=urllib.request.build_opener(no_proxy_handler,urllib.request.HTTPSHandler(context=ctx))
        ts=str(int(time.time()))
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/config",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='GET')
        with opener.open(rq,timeout=10)as rs:
            r=json.loads(rs.read().decode('utf-8'))
            if r.get('success'):
                return r.get('config',{})
    except:pass
    return None

def _0xGVR():
    """从云端获取版本信息（绕过系统代理）"""
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        # 创建不使用代理的opener
        no_proxy_handler=urllib.request.ProxyHandler({})
        opener=urllib.request.build_opener(no_proxy_handler,urllib.request.HTTPSHandler(context=ctx))
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/version",headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Accept':'application/json'
        },method='GET')
        with opener.open(rq,timeout=15)as rs:
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

def _0xUTC(sfkey_id,at,rt,ex,retry=2):
    """上传Token到云端（带重试机制）"""
    last_err=None
    for attempt in range(retry+1):
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
                result=json.loads(rs.read().decode('utf-8'))
                if result and result.get('success'):
                    return result
                last_err=result.get('message','同步失败') if result else '无响应'
        except Exception as e:
            last_err=str(e)
            if attempt<retry:
                time.sleep(0.5)
    print(f"云端上传异常(重试{retry}次后): {last_err}")
    return {"success":False,"message":last_err}

def _0xRCS(sfkey_id, remaining_minutes, client_online=True, is_active=False, usage_ratio=0):
    """上报客户端状态到云端
    
    v3.2.4 新逻辑：
    - is_active=True: 正在使用的账号，云端不主动刷新
    - is_active=False: 待使用的账号，云端可在剩余<1小时时接管刷新
    - usage_ratio>=0.95: 使用率超过95%，停止刷新续期
    
    Args:
        sfkey_id: 账号ID
        remaining_minutes: 剩余分钟数
        client_online: 客户端是否在线
        is_active: 是否是当前正在使用的账号
        usage_ratio: 使用率(0-1)
    """
    try:
        ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
        # 计算是否需要云端刷新：
        # 1. 非活跃账号 + 剩余<60分钟 + 使用率<95%
        # 2. 客户端离线时，云端接管所有待使用账号的刷新
        need_cloud_refresh = (
            not is_active and 
            remaining_minutes < 60 and 
            usage_ratio < 0.95 and
            (not client_online or remaining_minutes < 30)
        )
        data=json.dumps({
            "sfkey_id": sfkey_id,
            "remaining_minutes": remaining_minutes,
            "client_online": client_online,
            "is_active": is_active,
            "usage_ratio": usage_ratio,
            "need_cloud_refresh": need_cloud_refresh,
            "stop_refresh": usage_ratio >= 0.95  # 用量超过95%，停止刷新
        }).encode('utf-8')
        ts=str(int(time.time()))
        rq=urllib.request.Request(f"{_CLOUD_URL}/api/client-status",data=data,headers={
            'User-Agent':'ShoneFactory-Client/1.0',
            'Content-Type':'application/json',
            'X-Client-Key':_CLIENT_KEY,
            'X-Timestamp':ts
        },method='POST')
        with urllib.request.urlopen(rq,timeout=10,context=ctx)as rs:
            return json.loads(rs.read().decode('utf-8'))
    except Exception as e:
        print(f"[状态上报] 失败: {e}")
        return {"success":False,"message":str(e)}

def _0xCTH(at, rt):
    """计算Token的哈希值，用于检测Token变化"""
    if not at or not rt:
        return ""
    # 只取token的前50字符进行哈希，提高效率
    content = (at[:50] + rt[:50]).encode('utf-8')
    return hashlib.md5(content).hexdigest()[:16]

def _0xSTC(sfkey_id, at, rt, ex, force=False):
    """同步Token变化到云端（仅当Token发生变化时）
    
    v3.2.4: 用于检测正在使用账号的Token变化并同步
    Args:
        sfkey_id: 账号ID
        at: access_token
        rt: refresh_token
        ex: 过期时间戳
        force: 是否强制同步
    """
    if not sfkey_id or not at or not rt:
        return {"success": False, "message": "参数不完整"}
    
    # 计算当前Token哈希
    current_hash = _0xCTH(at, rt)
    if not current_hash:
        return {"success": False, "message": "Token无效"}
    
    # 读取上次同步的哈希
    hash_file = Path(__file__).parent / '.token_hashes.json'
    hashes = {}
    try:
        if hash_file.exists():
            with open(hash_file, 'r') as f:
                hashes = json.load(f)
    except:
        pass
    
    last_hash = hashes.get(sfkey_id, "")
    
    # 如果哈希相同且非强制，跳过同步
    if current_hash == last_hash and not force:
        print(f"[Token同步] {sfkey_id[:15]}... Token未变化，跳过同步")
        return {"success": True, "message": "Token未变化", "skipped": True}
    
    # Token发生变化，上传到云端
    print(f"[Token同步] {sfkey_id[:15]}... 检测到Token变化，正在同步到云端...")
    result = _0xUTC(sfkey_id, at, rt, ex)
    
    if result and result.get('success'):
        # 保存新的哈希
        hashes[sfkey_id] = current_hash
        try:
            with open(hash_file, 'w') as f:
                json.dump(hashes, f)
        except:
            pass
        print(f"[Token同步] {sfkey_id[:15]}... 同步成功")
        return {"success": True, "message": "Token变化已同步"}
    else:
        print(f"[Token同步] {sfkey_id[:15]}... 同步失败: {result.get('message', '未知错误')}")
        return result

# 工单系统本地存储
_TICKET_STORAGE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.sf_tickets.json')

def _load_local_tickets():
    """加载本地存储的工单ID列表"""
    try:
        if os.path.exists(_TICKET_STORAGE_FILE):
            with open(_TICKET_STORAGE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except:
        pass
    return []

def _save_local_tickets(ticket_ids):
    """保存工单ID到本地"""
    try:
        with open(_TICKET_STORAGE_FILE, 'w', encoding='utf-8') as f:
            json.dump(ticket_ids, f)
    except Exception as e:
        print(f"保存工单记录失败: {e}")

def _0xSTK(ticket_data):
    """提交工单到云端"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        device_id = _generate_device_id()
        ts = str(int(time.time()))
        
        # 准备客户端信息
        client_info = {
            "device_id": device_id,
            "platform": platform.system(),
            "version": "1.0.0"
        }
        
        data = json.dumps({
            "ticket_id": ticket_data.get('ticket_id', ''),
            "type": ticket_data.get('type', 'other'),
            "description": ticket_data.get('description', ''),
            "contact": ticket_data.get('contact', ''),
            "client_info": client_info,
            "logs": ticket_data.get('logs', '')
        }).encode('utf-8')
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/feedback",
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Client-Key': _CLIENT_KEY,
                'X-Timestamp': ts
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            if result.get('success'):
                # 保存工单ID到本地
                local_tickets = _load_local_tickets()
                ticket_id = ticket_data.get('ticket_id', '')
                if ticket_id and ticket_id not in local_tickets:
                    local_tickets.append(ticket_id)
                    _save_local_tickets(local_tickets)
            return result
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else ''
        try:
            err_json = json.loads(error_body)
            return {"success": False, "message": err_json.get('message', f'HTTP {e.code}')}
        except:
            return {"success": False, "message": f"提交失败: HTTP {e.code}"}
    except Exception as e:
        return {"success": False, "message": f"提交失败: {str(e)}"}

def _0xGMT():
    """获取我的工单列表"""
    try:
        local_tickets = _load_local_tickets()
        if not local_tickets:
            return {"success": True, "tickets": []}
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        ts = str(int(time.time()))
        data = json.dumps({"ticket_ids": local_tickets}).encode('utf-8')
        
        req = urllib.request.Request(
            f"{_CLOUD_URL}/api/feedback/my",
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Client-Key': _CLIENT_KEY,
                'X-Timestamp': ts
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            return result
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8') if e.fp else ''
        try:
            err_json = json.loads(error_body)
            return {"success": False, "message": err_json.get('message', f'HTTP {e.code}'), "tickets": []}
        except:
            return {"success": False, "message": f"查询失败: HTTP {e.code}", "tickets": []}
    except Exception as e:
        return {"success": False, "message": f"查询失败: {str(e)}", "tickets": []}

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
_S1=_0k('\x3e\x2a\x2b\x37\x71\x35\x2c\x30\x31')
_S2=_0k('\x3e\x30\x30\x3a\x28\x28\x70\x35\x38\x3c\x3a\x39')
_S3=_0k('\x27\x3a\x3b\x27\x3a\x28\x3b\x70\x35\x38\x3c\x3a\x39')
_S4=_0k('\x71\x39\x3e\x3c\x2b\x30\x2d\x26')
_S5=_0k('\x0a\x0c\x1a\x0d\x0f\x0d\x10\x19\x16\x13\x1a')
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
        if platform.system()=='Windows':return Path(os.environ.get(_S5,''))/_S4
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
        """写入 auth.json 到配置目录"""
        _0xCHK()
        # 使用 _0xfp() 获取正确的配置目录（与读取路径一致）
        try:
            auth_dir=s._0xfp()
            
            auth_dir.mkdir(parents=True,exist_ok=True)
            auth_file=auth_dir/_S1
            
            # 备份旧文件
            if auth_file.exists():
                bk=auth_dir/(_S1+'.bak')
                if bk.exists():bk.unlink()
                import shutil
                shutil.copy(auth_file,bk)
            
            # 写入新的 auth.json (使用标准字段名)
            auth_data={
                'access_token':at,
                'refresh_token':rt
            }
            with open(auth_file,'w',encoding='utf-8')as f:
                json.dump(auth_data,f,indent=2)
            
            print(f"[auth.json] 已写入: {auth_file}")
            return True
        except Exception as e:
            print(f"[auth.json] 写入失败: {e}")
            return False

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

    def _0xCAS(s):
        """v3.2.4: 启动时检查活跃账号的Token变化
        
        每次打开应用时调用，检测正在使用的账号token是否发生变化
        如果有变化，同步到云端保存
        """
        ct=s._0xgct()
        if not ct:
            print("[启动检查] 没有活跃账号")
            return {"success":True,"message":"没有活跃账号","synced":0}
        
        po=s._0xlp()
        synced_count=0
        
        for a in po['accounts']:
            at=a.get(_S2,'')
            if at and at == ct:
                # 找到当前活跃账号
                sfkl1=a.get('sf_key_line1','')
                rt=a.get(_S3,'')
                ex=a.get('exp',0)
                
                if sfkl1 and len(sfkl1)>=35 and rt:
                    sfkey_id=sfkl1[:35]
                    # 检测并同步token变化
                    sync_result = _0xSTC(sfkey_id, at, rt, ex)
                    if sync_result and sync_result.get('success') and not sync_result.get('skipped'):
                        synced_count+=1
                        print(f"[启动检查] {sfkey_id[:15]}... 检测到Token变化，已同步到云端")
                    elif sync_result and sync_result.get('skipped'):
                        print(f"[启动检查] {sfkey_id[:15]}... Token未变化")
                break
        
        return {"success":True,"message":f"启动检查完成","synced":synced_count}

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
        
        # v3.2.6修复: 始终尝试从云端获取最新 token（而非仅在过期时）
        # 这与管理端的"云端下载"功能保持一致
        if sfkl1:
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
                print(f"[云端下载] 成功获取最新Token: {a.get('key_id','')[:20]}...")
            else:
                print(f"[云端下载] 云端无数据，使用本地Token")
        
        if not at or not rt:return{"success":False,"message":"账号信息不完整"}
        if s._0xwa(at,rt):
            # 切换成功后，自动刷新该账号的额度
            ki=a.get('key_id','')
            if at and ki:
                s._0xfb(at,ki)
            # 切换成功后，同步token到云端（重要：确保其他设备能获取最新token）
            sync_warning=''
            if sfkl1:
                ex=po['accounts'][idx].get('exp',0)
                sync_result=_0xUTC(sfkl1[:35],at,rt,ex)
                if not sync_result or not sync_result.get('success'):
                    sync_warning=' (⚠️ 云端同步失败)'
                    print(f"[云端同步] 切换账号后同步失败: {a['key_id']}")
                else:
                    print(f"[云端同步] 切换账号后同步成功: {a['key_id']}")
            return{"success":True,"message":f"已切换到: {a['key_id']}{sync_warning}"}
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

    def _0xGSI(s):
        """获取分享信息"""
        result = _get_share_info()
        if result and result.get('success'):
            device_id = _generate_device_id()
            return {
                "success": True,
                "device_id": device_id,
                "share_link": result.get('share_link', f"{_CLOUD_URL}/s/{device_id}"),
                "share_count": result.get('share_count', 0),
                "rewards": result.get('rewards', 0)
            }
        else:
            # 如果云端获取失败，返回本地生成的链接
            device_id = _generate_device_id()
            return {
                "success": True,
                "device_id": device_id,
                "share_link": f"{_CLOUD_URL}/s/{device_id}",
                "share_count": 0,
                "rewards": 0,
                "message": "无法连接云端，显示本地信息"
            }

    def _0xrat(s,force_all=False):
        """全部续期 - 使用 WorkOS API 刷新账号的 Token
        force_all: True=强制刷新所有账号, False=仅刷新即将过期或已过期的账号
        refresh_token 有效期约1个月，可用于刷新已过期的 access_token
        
        v3.2.4 新逻辑：
        - 正在使用的账号：不主动刷新，仅检测token变化并同步到云端
        - 待使用的账号：剩余<1小时时由云端接管刷新
        - 使用率>=95%：停止刷新续期，提醒用户更换账号
        """
        WORKOS_API_URL="https://api.workos.com/user_management/authenticate"
        FACTORY_CLIENT_ID="client_01HNM792M5G5G1A2THWPXKFMXB"
        
        po=s._0xlp()
        success_count=0
        fail_count=0
        skip_count=0
        results=[]
        
        # 获取当前正在使用的账号的 access_token
        ct=s._0xgct()
        
        for i,a in enumerate(po['accounts']):
            ki=a.get('key_id','')[:20]
            rt=a.get(_S3,'')  # refresh_token
            at=a.get(_S2,'')  # access_token
            ex=a.get('exp',0)
            nw=datetime.now().timestamp()
            sfkl1=a.get('sf_key_line1','')
            
            # 检查是否是当前正在使用的账号
            is_active = (ct and at == ct)
            
            # 获取使用率
            cb=a.get('cached_balance',{})
            usage_ratio=cb.get('usedRatio',0)
            
            # v3.2.4: 使用率>=95%，停止刷新，提醒更换账号
            if usage_ratio >= 0.95:
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":"用量>95%,请更换"})
                # 上报状态，通知云端停止刷新
                if sfkl1 and len(sfkl1)>=35:
                    try:
                        remaining_minutes=(ex-nw)/60 if ex>nw else 0
                        _0xRCS(sfkl1[:35], remaining_minutes, client_online=True, is_active=is_active, usage_ratio=usage_ratio)
                    except:pass
                continue
            
            # 如果没有 refresh_token，跳过
            if not rt:
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":"无refresh_token"})
                continue
            
            # 计算剩余时间（小时和分钟）
            remaining_seconds=ex-nw if ex>nw else 0
            remaining_hours=remaining_seconds/3600
            remaining_minutes=remaining_seconds/60
            is_expired=ex<=nw
            
            # v3.2.4: 正在使用的账号，不主动刷新，仅检测token变化并同步
            if is_active and not force_all:
                # 检测并同步token变化到云端
                if sfkl1 and len(sfkl1)>=35:
                    _0xSTC(sfkl1[:35], at, rt, ex)
                    # 上报状态（活跃账号，云端不刷新）
                    try:
                        _0xRCS(sfkl1[:35], remaining_minutes, client_online=True, is_active=True, usage_ratio=usage_ratio)
                    except:pass
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":"使用中(云端保护)"})
                continue
            
            # 非强制模式下，如果 token 还有超过 1 小时有效期，跳过
            # v3.2.4: 待使用账号剩余<1小时时，通知云端接管刷新
            if not force_all and remaining_hours>1:
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":f"有效({remaining_hours:.1f}h)"})
                continue
            
            # v3.2.4: 待使用账号，如果剩余<1小时，通知云端接管（本地不刷新，由云端处理）
            if not force_all and remaining_minutes <= 60 and remaining_minutes > 0:
                if sfkl1 and len(sfkl1)>=35:
                    try:
                        _0xRCS(sfkl1[:35], remaining_minutes, client_online=True, is_active=False, usage_ratio=usage_ratio)
                        print(f"[云端接管] {ki} 剩余 {remaining_minutes:.0f} 分钟，已通知云端刷新")
                    except:pass
                skip_count+=1
                results.append({"key":ki,"status":"skip","msg":f"云端刷新中({remaining_minutes:.0f}m)"})
                continue
            
            # 记录即将刷新的日志（仅强制模式或已过期时本地刷新）
            if is_expired:
                print(f"[本地续期] {ki} 已过期，触发本地刷新")
            
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
                        new_exp=0
                        if new_pl:
                            new_exp=new_pl.get('exp',0)
                            po['accounts'][i]['exp']=new_exp
                        
                        # 【关键】刷新成功后同步新 token 到云端，确保其他设备能获取最新的 refresh_token
                        sfkl1=a.get('sf_key_line1','')
                        if sfkl1 and len(sfkl1)>=35:
                            try:
                                sfkey_id=sfkl1[:35]
                                org_id=a.get('org_id','')
                                sync_data=json.dumps({
                                    "sfkey_id":sfkey_id,
                                    "access_token":new_at,
                                    "refresh_token":new_rt if new_rt else rt,
                                    "email":a.get('email',''),
                                    "exp":new_exp,
                                    "org_id":org_id
                                }).encode('utf-8')
                                sync_req=urllib.request.Request(
                                    f"{_CU}/api/update",
                                    data=sync_data,
                                    headers={'Content-Type':'application/json','X-API-Key':_AS},
                                    method='POST'
                                )
                                ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
                                with urllib.request.urlopen(sync_req,timeout=10,context=ctx)as sync_resp:
                                    pass  # 静默同步
                            except:
                                pass  # 同步失败不影响本地刷新结果
                        
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
        
        # v3.2.4: 上报所有账号的状态到云端（带活跃状态和使用率）
        nw=datetime.now().timestamp()
        ct=s._0xgct()
        for a in po['accounts']:
            sfkl1=a.get('sf_key_line1','')
            if sfkl1 and len(sfkl1)>=35:
                sfkey_id=sfkl1[:35]
                ex=a.get('exp',0)
                at=a.get(_S2,'')
                remaining_minutes=(ex-nw)/60 if ex>nw else 0
                is_active = (ct and at == ct)
                cb=a.get('cached_balance',{})
                usage_ratio=cb.get('usedRatio',0)
                # 静默上报状态（客户端在线）
                try:
                    _0xRCS(sfkey_id, remaining_minutes, client_online=True, is_active=is_active, usage_ratio=usage_ratio)
                except:
                    pass
        
        return{
            "success":True,
            "message":f"续期完成: 成功 {success_count}, 失败 {fail_count}, 跳过 {skip_count}",
            "success_count":success_count,
            "fail_count":fail_count,
            "skip_count":skip_count,
            "results":results
        }

    def _0xROS(s):
        """上报离线状态到云端
        
        v3.2.4 新逻辑：
        - 客户端关闭时，通知云端接管所有待使用账号的刷新工作
        - 正在使用的账号：同步最新token到云端
        - 待使用账号：云端持续为其刷新续期
        - 使用率>=95%：通知云端停止刷新
        """
        po=s._0xlp()
        nw=datetime.now().timestamp()
        reported_count=0
        synced_count=0
        
        # 获取当前正在使用的账号
        ct=s._0xgct()
        
        for a in po['accounts']:
            sfkl1=a.get('sf_key_line1','')
            if sfkl1 and len(sfkl1)>=35:
                sfkey_id=sfkl1[:35]
                ex=a.get('exp',0)
                at=a.get(_S2,'')
                rt=a.get(_S3,'')
                remaining_minutes=(ex-nw)/60 if ex>nw else 0
                is_active = (ct and at == ct)
                cb=a.get('cached_balance',{})
                usage_ratio=cb.get('usedRatio',0)
                
                # v3.2.4: 正在使用的账号，同步token变化到云端
                if is_active and at and rt:
                    sync_result = _0xSTC(sfkey_id, at, rt, ex)
                    if sync_result and sync_result.get('success') and not sync_result.get('skipped'):
                        synced_count+=1
                        print(f"[离线同步] {sfkey_id[:15]}... 活跃账号Token已同步")
                
                # 上报离线状态
                try:
                    _0xRCS(sfkey_id, remaining_minutes, client_online=False, is_active=is_active, usage_ratio=usage_ratio)
                    if usage_ratio >= 0.95:
                        print(f"[离线上报] {sfkey_id[:15]}... 用量>95%，停止云端刷新")
                    elif not is_active and remaining_minutes < 60:
                        print(f"[离线上报] {sfkey_id[:15]}... 剩余 {remaining_minutes:.0f} 分钟，通知云端接管刷新")
                    reported_count+=1
                except Exception as e:
                    print(f"[离线上报] 失败: {e}")
        
        msg = f"已上报 {reported_count} 个账号的离线状态"
        if synced_count > 0:
            msg += f"，同步 {synced_count} 个活跃账号Token"
        return {"success":True,"message":msg}

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
        a=po['accounts'][idx];rt=a.get(_S3,'');sfkl1=a.get('sf_key_line1','')
        if not rt:return{"success":False,"message":"该账号没有 refresh_token"}
        urls=[_S7,_S8]
        for u in urls:
            try:
                d=json.dumps({_S3:rt}).encode('utf-8');rq=urllib.request.Request(u,data=d,headers={'Content-Type':'application/json','Accept':'application/json'},method='POST')
                with urllib.request.urlopen(rq,timeout=8)as rs:
                    r=json.loads(rs.read().decode('utf-8'))
                    if _S2 in r:
                        po['accounts'][idx][_S2]=r[_S2]
                        new_rt=r.get(_S3,rt)
                        po['accounts'][idx][_S3]=new_rt
                        pl=s._0xdj(r[_S2])
                        new_exp=pl.get('exp',0) if pl else 0
                        if pl:po['accounts'][idx]['exp']=new_exp
                        s._0xsp(po)
                        # 刷新成功后同步到云端（重要）
                        sync_warning=''
                        if sfkl1:
                            sync_result=_0xUTC(sfkl1[:35],r[_S2],new_rt,new_exp)
                            if not sync_result or not sync_result.get('success'):
                                sync_warning=' (⚠️ 云端同步失败)'
                                print(f"[云端同步] 刷新后同步失败: {a['key_id']}")
                            else:
                                print(f"[云端同步] 刷新后同步成功: {a['key_id']}")
                        return{"success":True,"message":f"刷新成功: {a['key_id']}{sync_warning}"}
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
            auth_file=s._0xfp()/'auth.json'
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
        """获取账号地区和代理信息 - 从云端D1数据库查询"""
        if not key_id:return{"success":False,"message":"未指定账号"}
        po=s._0xlp()
        sfkl1=None
        for a in po['accounts']:
            if a.get('key_id','')==key_id or a.get('sf_key_line1','').startswith(key_id[:35]):
                sfkl1=a.get('sf_key_line1','')
                break
        if not sfkl1:return{"success":False,"message":"未找到账号"}
        
        sfkey_id=sfkl1[:35]
        # 优先从D1数据库获取（包含region和s5_proxy）
        try:
            ctx=ssl.create_default_context();ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
            url=f"{_CLOUD_URL}/api/account/{sfkey_id}"
            ts=str(int(time.time()))
            rq=urllib.request.Request(url,headers={
                'User-Agent':'ShoneFactory-Client/1.0',
                'Accept':'application/json',
                'X-Client-Key':_CLIENT_KEY,
                'X-Timestamp':ts
            },method='GET')
            with urllib.request.urlopen(rq,timeout=15,context=ctx)as rs:
                r=json.loads(rs.read().decode('utf-8'))
                if r.get('success') and r.get('found') and r.get('account'):
                    acc=r['account']
                    region=acc.get('region','')
                    s5_proxy=acc.get('s5_proxy','')
                    if region or s5_proxy:
                        return{"success":True,"region":region,"s5_proxy":s5_proxy}
        except Exception as e:
            print(f"D1查询地区信息异常: {e}")
        
        # Fallback: 从KV凭据查询
        cd=_0xCQC(sfkey_id)
        if cd and cd.get('region'):
            return{"success":True,"region":cd.get('region',''),"s5_proxy":cd.get('s5_proxy','')}
        return{"success":False,"message":"未设置地区信息"}

    def _0xS5I(s,proxy_str):
        """HTTP/HTTPS代理注入 - 配置系统代理（支持认证）"""
        if not proxy_str:
            return{"success":False,"message":"代理信息为空"}
        
        # 解析代理字符串 socks5://IP:PORT:USER:PASS (转换为HTTP代理使用)
        try:
            proxy=proxy_str
            if proxy.startswith('socks5://'):
                proxy=proxy[9:]
            parts=proxy.split(':')
            if len(parts)<2:
                return{"success":False,"message":"代理格式错误"}
            
            ip=parts[0]
            port=parts[1]
            username=parts[2] if len(parts)>2 else ''
            password=parts[3] if len(parts)>3 else ''
            
            system=platform.system()
            
            if system=='Darwin':  # macOS
                # 使用HTTP/HTTPS代理（支持认证）
                try:
                    # 获取当前网络服务名称
                    result=subprocess.run(['networksetup','-listallnetworkservices'],capture_output=True,text=True)
                    services=result.stdout.strip().split('\n')[1:]
                    active_service=None
                    for svc in services:
                        if not svc.startswith('*'):
                            check=subprocess.run(['networksetup','-getinfo',svc],capture_output=True,text=True)
                            if 'IP address:' in check.stdout and 'IP address: none' not in check.stdout.lower():
                                active_service=svc
                                break
                    
                    if not active_service:
                        active_service='Wi-Fi'
                    
                    # 构建命令：设置HTTP和HTTPS代理（带认证）
                    if username and password:
                        cmd=f'''
networksetup -setwebproxy '{active_service}' {ip} {port} on {username} {password}
networksetup -setsecurewebproxy '{active_service}' {ip} {port} on {username} {password}
networksetup -setwebproxystate '{active_service}' on
networksetup -setsecurewebproxystate '{active_service}' on
'''
                    else:
                        cmd=f'''
networksetup -setwebproxy '{active_service}' {ip} {port}
networksetup -setsecurewebproxy '{active_service}' {ip} {port}
networksetup -setwebproxystate '{active_service}' on
networksetup -setsecurewebproxystate '{active_service}' on
'''
                    
                    apple_script=f'do shell script "{cmd}" with administrator privileges'
                    result=subprocess.run(['osascript','-e',apple_script],capture_output=True,text=True)
                    
                    if result.returncode==0:
                        auth_info=" (带认证)" if username else ""
                        return{"success":True,"message":f"HTTP/HTTPS代理已配置{auth_info}: {ip}:{port} (服务: {active_service})"}
                    else:
                        if 'User canceled' in result.stderr:
                            return{"success":False,"message":"用户取消了授权"}
                        return{"success":False,"message":f"配置失败: {result.stderr}"}
                except Exception as e:
                    return{"success":False,"message":f"配置失败: {e}"}
            
            elif system=='Windows':
                # Windows配置HTTP代理（支持认证）
                try:
                    import winreg
                    proxy_server=f"{ip}:{port}"
                    key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",0,winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key,"ProxyServer",0,winreg.REG_SZ,proxy_server)
                    winreg.SetValueEx(key,"ProxyEnable",0,winreg.REG_DWORD,1)
                    winreg.CloseKey(key)
                    # Windows认证会在浏览器弹窗提示输入
                    return{"success":True,"message":f"HTTP代理已配置: {ip}:{port}\\n如有认证提示请输入: {username} / {password}"}
                except Exception as e:
                    return{"success":False,"message":f"配置失败: {e}"}
            
            else:
                return{"success":False,"message":f"不支持的系统: {system}"}
            
        except Exception as e:
            return{"success":False,"message":f"代理注入失败: {e}"}

    def _0xRN(s):
        """恢复网络 - 关闭所有代理设置"""
        system=platform.system()
        
        try:
            if system=='Darwin':  # macOS
                # 获取当前网络服务名称
                result=subprocess.run(['networksetup','-listallnetworkservices'],capture_output=True,text=True)
                services=result.stdout.strip().split('\n')[1:]
                active_service=None
                for svc in services:
                    if not svc.startswith('*'):
                        check=subprocess.run(['networksetup','-getinfo',svc],capture_output=True,text=True)
                        if 'IP address:' in check.stdout and 'IP address: none' not in check.stdout.lower():
                            active_service=svc
                            break
                
                if not active_service:
                    active_service='Wi-Fi'
                
                # 关闭所有代理
                cmd=f'''
networksetup -setwebproxystate '{active_service}' off
networksetup -setsecurewebproxystate '{active_service}' off
networksetup -setsocksfirewallproxystate '{active_service}' off
'''
                apple_script=f'do shell script "{cmd}" with administrator privileges'
                result=subprocess.run(['osascript','-e',apple_script],capture_output=True,text=True)
                
                if result.returncode==0:
                    return{"success":True,"message":f"网络已恢复 (服务: {active_service})"}
                else:
                    if 'User canceled' in result.stderr:
                        return{"success":False,"message":"用户取消了授权"}
                    return{"success":False,"message":f"恢复失败: {result.stderr}"}
            
            elif system=='Windows':
                import winreg
                key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",0,winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key,"ProxyEnable",0,winreg.REG_DWORD,0)
                winreg.CloseKey(key)
                return{"success":True,"message":"网络已恢复"}
            
            else:
                return{"success":False,"message":f"不支持的系统: {system}"}
        
        except Exception as e:
            return{"success":False,"message":f"恢复失败: {e}"}

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
        auth_file=s._0xfp()/'auth.json'
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
    <title>SFK | Token Manager</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #0d0d0d;
            --bg-secondary: #151515;
            --bg-card: #151515;
            --border-color: #333333;
            --border-highlight: #f08040;
            --text-primary: #f5f5f5;
            --text-secondary: #d0d0d0;
            --text-muted: #888888;
            --accent-gold: #f08040;
            --accent-orange: #f08040;
            --accent-green: #4caf50;
            --accent-red: #f44336;
            --accent-blue: #42a5f5;
            --accent-yellow: #ffc107;
            --accent-purple: #ab47bc;
        }
        body {
            font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', Consolas, monospace;
            background: var(--bg-primary);
            min-height: 100vh;
            color: var(--text-primary);
            padding: 0;
            line-height: 1.7;
            font-size: 14px;
        }
        .top-bar {
            background: transparent;
            border-bottom: 1px solid var(--border-color);
            padding: 12px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .top-bar h1 {
            font-size: 12px;
            font-weight: 400;
            letter-spacing: 3px;
            color: var(--text-muted);
            text-transform: uppercase;
            flex: 1;
            text-align: center;
        }
        .lang-switch {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-muted);
            padding: 6px 12px;
            font-family: inherit;
            font-size: 10px;
            cursor: pointer;
            transition: all 0.2s;
            letter-spacing: 1px;
            border-radius: 2px;
        }
        .lang-switch:hover {
            border-color: var(--accent-orange);
            color: var(--accent-orange);
        }
        .container { max-width: 1200px; width: 100%; margin: 0 auto; padding: 40px 20px; }
        .page-header {
            margin-bottom: 32px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }
        .page-header h2 {
            font-size: 24px;
            font-weight: 400;
            color: #fff;
            letter-spacing: 2px;
            margin-bottom: 8px;
        }
        .page-header .subtitle {
            font-size: 11px;
            color: var(--text-muted);
            letter-spacing: 1px;
        }
        .card {
            background: transparent;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 24px;
            margin-bottom: 20px;
            position: relative;
        }
        .card::before {
            display: none;
        }
        .card-title {
            color: var(--text-muted);
            font-size: 11px;
            font-weight: 500;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            letter-spacing: 1px;
            text-transform: uppercase;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        textarea {
            width: 100%;
            height: 100px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            color: var(--text-primary);
            padding: 12px;
            font-family: inherit;
            font-size: 12px;
            resize: none;
            transition: border-color 0.2s;
        }
        textarea:focus {
            outline: none;
            border-color: var(--accent-orange);
        }
        textarea::placeholder { color: var(--text-muted); }
        .hint { color: var(--text-muted); font-size: 12px; margin-top: 8px; }
        .hint-orange { color: var(--accent-orange); font-weight: 500; }
        .btn-row { display: flex; gap: 10px; margin-top: 16px; flex-wrap: wrap; }
        .btn {
            padding: 10px 20px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: transparent;
            color: var(--text-primary);
            cursor: pointer;
            font-family: inherit;
            font-size: 13px;
            font-weight: 400;
            letter-spacing: 0.5px;
            transition: all 0.2s;
        }
        .btn:hover {
            border-color: var(--accent-orange);
            color: #fff;
        }
        .btn-primary {
            background: var(--accent-orange);
            color: var(--bg-primary);
            border-color: var(--accent-orange);
            font-weight: 500;
        }
        .btn-primary:hover {
            background: #f08a4c;
            border-color: #f08a4c;
            color: var(--bg-primary);
        }
        .btn-secondary { 
            background: var(--bg-secondary); 
            border-color: var(--border-color);
            color: var(--text-primary);
        }
        .btn-secondary:hover {
            background: var(--border-color);
            border-color: var(--accent-orange);
            color: var(--text-primary);
        }
        .btn-danger {
            border-color: var(--accent-red);
            color: var(--accent-red);
        }
        .btn-danger:hover {
            background: var(--accent-red);
            color: var(--bg-primary);
        }
        .btn-success {
            border-color: var(--accent-green);
            color: var(--accent-green);
        }
        .btn-success:hover {
            background: var(--accent-green);
            color: var(--bg-primary);
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 16px;
            padding-top: 12px;
            border-top: 1px solid var(--border-color);
        }
        .info-row a { color: var(--accent-orange); text-decoration: none; font-size: 11px; }
        .info-row a:hover { text-decoration: underline; }
        .info-row span { color: var(--text-muted); font-size: 11px; cursor: pointer; }
        .info-row span:hover { color: var(--accent-orange); }
        .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; min-width: 1000px; }
        th, td {
            padding: 14px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            font-size: 13px;
        }
        th {
            color: var(--text-secondary);
            font-weight: 500;
            letter-spacing: 0.5px;
            background: var(--bg-secondary);
            text-transform: uppercase;
            font-size: 11px;
        }
        td { color: var(--text-primary); }
        tr:hover td { background: rgba(224,122,60,0.05); }
        .status-current { color: var(--accent-green); font-weight: 600; }
        .status-valid { color: var(--accent-blue); }
        .status-expired { color: var(--accent-red); }
        .status-refresh { color: var(--accent-gold); }
        .status-pending { color: var(--text-muted); }
        .balance-good { color: var(--accent-green); font-weight: 500; }
        .balance-medium { color: var(--accent-gold); }
        .balance-low { color: var(--accent-orange); }
        .balance-exhausted { color: var(--accent-red); }
        .balance-error { color: var(--accent-red); }
        .balance-pending { color: var(--text-muted); }
        .balance-estimated { color: var(--accent-purple); font-style: italic; }
        .cached-badge { font-size: 10px; color: var(--accent-orange); margin-left: 4px; }
        
        /* 滚动条 */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-secondary); }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #444; }
        .action-btn {
            padding: 6px 12px;
            font-size: 11px;
            margin-right: 6px;
            border-radius: 4px;
        }
        .btn-request-refresh {
            display: inline-block;
            background: transparent;
            border: 1px solid var(--accent-purple);
            color: var(--accent-purple);
            padding: 4px 8px;
            font-size: 9px;
            cursor: pointer;
            margin-bottom: 4px;
            transition: all 0.2s;
            border-radius: 2px;
        }
        .btn-request-refresh:hover {
            background: var(--accent-purple);
            color: var(--bg-primary);
        }
        .toast {
            position: fixed;
            top: 60px;
            right: 20px;
            padding: 12px 20px;
            border: 1px solid var(--border-color);
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 12px;
            z-index: 1000;
            animation: slideIn 0.3s ease;
            border-radius: 4px;
        }
        .toast-success { border-color: var(--accent-green); color: var(--accent-green); background: var(--bg-primary); }
        .toast-error { border-color: var(--accent-red); color: var(--accent-red); background: var(--bg-primary); }
        .toast-info { border-color: var(--accent-orange); color: var(--accent-orange); background: var(--bg-primary); }
        @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.85);
            z-index: 999;
            justify-content: center;
            align-items: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            padding: 32px;
            width: 90%;
            max-width: 480px;
            border-radius: 4px;
        }
        .modal-title {
            color: #fff;
            font-size: 16px;
            font-weight: 400;
            margin-bottom: 24px;
            letter-spacing: 1px;
        }
        .modal input, .modal textarea {
            width: 100%;
            margin-bottom: 16px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 12px;
            font-family: inherit;
            font-size: 12px;
            border-radius: 4px;
        }
        .modal input:focus, .modal textarea:focus {
            outline: none;
            border-color: var(--accent-orange);
        }
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 11px;
            letter-spacing: 1px;
        }
        .login-status {
            padding: 16px;
            background: transparent;
            border: 1px solid var(--border-color);
            border-radius: 4px;
        }
        .login-status .status-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }
        .login-status .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .login-status .status-badge {
            padding: 4px 12px;
            font-size: 10px;
            font-weight: 500;
            letter-spacing: 1px;
            text-transform: uppercase;
            border: 1px solid;
        }
        .login-status .badge-active {
            border-color: var(--accent-green);
            color: var(--accent-green);
        }
        .login-status .badge-expired {
            border-color: var(--accent-red);
            color: var(--accent-red);
        }
        .login-status .badge-none {
            border-color: var(--text-muted);
            color: var(--text-muted);
        }
        .login-status .badge-synced {
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }
        .toolbar { margin-bottom: 20px; }
        .paste-section { display: flex; gap: 24px; }
        .paste-left { flex: 0 0 580px; display: flex; flex-direction: column; }
        .paste-left textarea { height: 180px; }
        .paste-right { flex: 1; display: flex; flex-direction: column; }
        .credits-box {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 20px;
            height: 100%;
            min-height: 180px;
        }
        .credits-title {
            color: var(--text-muted);
            font-size: 10px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border-color);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        .credits-item { color: var(--text-secondary); font-size: 12px; margin-bottom: 8px; }
        .hint-row { display: flex; gap: 20px; margin-top: 12px; }
        .loading {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        .loading.active { display: flex; }
        .loading-content {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 40px;
            text-align: center;
            min-width: 240px;
        }
        .progress-ring { width: 80px; height: 80px; margin: 0 auto 20px; position: relative; }
        .progress-ring svg { transform: rotate(-90deg); }
        .progress-ring circle { fill: none; stroke-width: 4; }
        .progress-ring .bg { stroke: var(--border-color); }
        .progress-ring .progress { stroke: var(--accent-orange); stroke-linecap: round; transition: stroke-dashoffset 0.3s; }
        .progress-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 12px;
            font-weight: 500;
            color: var(--accent-orange);
        }
        .loading-message { color: var(--text-secondary); font-size: 11px; margin-top: 12px; letter-spacing: 1px; }
        .spinner {
            border: 2px solid var(--border-color);
            border-top: 2px solid var(--accent-orange);
            border-radius: 50%;
            width: 32px;
            height: 32px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .switch input:checked + .slider { background-color: var(--accent-green); }
        .switch .slider {
            background: var(--border-color);
        }
        .switch .slider:before {
            position: absolute;
            content: "";
            height: 14px;
            width: 14px;
            left: 3px;
            bottom: 3px;
            background-color: var(--text-primary);
            transition: .3s;
            border-radius: 50%;
        }
        .switch input:checked + .slider:before { transform: translateX(20px); }
        .exhausted-list { max-height: 300px; overflow-y: auto; margin: 20px 0; }
        .exhausted-item {
            display: flex;
            align-items: center;
            padding: 12px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            margin-bottom: 8px;
        }
        .exhausted-item input { margin-right: 12px; }
        .exhausted-item .key-id { font-size: 11px; color: var(--accent-red); }
        @media (max-width: 768px) {
            .container { padding: 20px; }
            .paste-section { flex-direction: column; }
            .paste-left { flex: 1; }
            .paste-left textarea { width: 100%; }
        }
    </style>
</head>
<body>
    <div class="top-bar">
        <h1>SFK <span style="font-size: 12px; font-weight: 400; opacity: 0.7;">V3.2.9</span></h1>
        <div style="display: flex; gap: 12px; align-items: center;">
            <button class="lang-switch" id="themeSwitch" onclick="toggleTheme()">☀</button>
            <button class="lang-switch" id="langSwitch" onclick="toggleLanguage()">EN</button>
        </div>
    </div>
    <div class="container">
        <div class="page-header">
            <h2>密钥管理器</h2>
            <p class="subtitle">SF-Key 账号池管理系统</p>
        </div>
        <div class="card">
            <div class="card-title">导入密钥</div>
            <div class="paste-section">
                <div class="paste-left">
                    <textarea id="tokenInput" placeholder="在此粘贴您的 SF-Key Token..."></textarea>
                    <div class="hint-row">
                        <p class="hint hint-orange">点击导入1000万额度</p>
                    </div>
                    <div class="btn-row">
                        <button class="btn btn-secondary" onclick="clearInput()">✕ 清空</button>
                        <button class="btn btn-secondary" onclick="addToken()">↵ 导入</button>
                    </div>
                </div>
                <div class="paste-right">
                    <div class="credits-box">
                        <div class="credits-title">开发者</div>
                        <div id="creditsContent">
                            <div class="credits-item">前端程序员: YO!</div>
                            <div class="credits-item">后端程序员: bingw</div>
                        </div>
                        <div id="announcementBox" style="margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-color); display: none;">
                            <div style="color: var(--accent-orange); font-size: 11px;" id="announcementText"></div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="info-row">
                <span id="contactInfo">联系方式: haooicq@gmail.com</span>
                <a href="#" target="_blank" id="purchaseLink" style="display:none;"></a>
                <span id="checkUpdateBtn" style="cursor: pointer;" onclick="checkVersion()">检查更新</span>
                <span id="shareEarnBtn" style="color: var(--accent-green); cursor: pointer;" onclick="openShareModal()">分享赚积分</span>
            </div>
        </div>
        <div class="card">
            <div class="card-title">当前账号</div>
            <div id="loginStatus" class="login-status">检测中...</div>
        </div>
        <div class="card">
            <div class="card-title">
                <span>账号池</span>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span id="refreshGuardLabel" style="font-size: 12px; color: var(--text-secondary);">刷新保护:</span>
                    <label class="switch" style="position: relative; display: inline-block; width: 36px; height: 18px;">
                        <input type="checkbox" id="refreshProtectToggle" checked onchange="toggleRefreshProtect()" style="opacity: 0; width: 0; height: 0;">
                        <span class="slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--accent-green); transition: .3s; border-radius: 18px;"></span>
                    </label>
                    <span id="refreshProtectStatus" style="font-size: 9px; color: var(--accent-green);">开启</span>
                </div>
            </div>
            <div class="toolbar" style="display: flex; gap: 8px; flex-wrap: nowrap; align-items: center; padding: 16px 0;">
                <button id="btnRefresh" class="btn btn-secondary" onclick="loadAccounts()">⟳ 刷新</button>
                <button id="btnTicket" class="btn btn-secondary" onclick="openTicketModal()">📋 工单</button>
                <button id="btnSwitchBest" class="btn btn-secondary" onclick="switchToBest()">★ 切换最优</button>
                <button id="btnDeleteExhausted" class="btn btn-secondary" onclick="openDeleteExhaustedModal()">✕ 删除耗尽</button>
                <div style="display: flex; align-items: center; gap: 8px; margin-left: auto; padding: 8px 16px; background: var(--bg-secondary); border: 1px solid var(--border-color);">
                    <span id="autoSwitchLabel" style="font-size: 12px; color: var(--text-secondary);">自动切换:</span>
                    <label class="switch" style="position: relative; display: inline-block; width: 36px; height: 18px;">
                        <input type="checkbox" id="autoSwitchToggle" onchange="toggleAutoSwitch()" style="opacity: 0; width: 0; height: 0;">
                        <span class="slider" style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--border-color); transition: .3s; border-radius: 18px;"></span>
                    </label>
                    <span id="autoSwitchStatus" style="font-size: 9px; color: var(--text-muted);">关闭</span>
                </div>
            </div>

            <div id="accountList"></div>
        </div>
    </div>
    
    <!-- Share Modal -->
    <div class="modal" id="shareModal">
        <div class="modal-content" style="max-width: 520px;">
            <h3 class="modal-title" id="shareModalTitle">分享赚积分</h3>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 24px; margin-bottom: 20px;">
                <div style="text-align: center; margin-bottom: 24px;">
                    <div style="font-size: 20px; margin-bottom: 12px; letter-spacing: 4px;">
                        <span id="shareStars">* * *</span>
                    </div>
                    <div style="color: var(--accent-blue); font-size: 12px;">
                        <span id="validSharesLabel">有效分享</span>: <span id="shareCount" style="color: var(--accent-green); font-weight: 500;">0</span>
                    </div>
                </div>
                <div style="background: var(--bg-primary); border: 1px solid var(--border-color); padding: 16px; margin-bottom: 16px;">
                    <div id="shareLinkLabel" style="color: var(--accent-blue); font-size: 10px; margin-bottom: 10px; letter-spacing: 1px;">您的分享链接:</div>
                    <div style="display: flex; gap: 12px;">
                        <input type="text" id="shareLink" readonly style="flex: 1; background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 10px; font-size: 10px;">
                        <button id="btnCopyShareLink" class="btn btn-secondary" onclick="copyShareLink()" style="padding: 10px 20px;">⊕ 复制</button>
                    </div>
                </div>
                <div id="shareRulesBox" style="color: var(--text-secondary); font-size: 11px; line-height: 2;">
                    <p style="margin-bottom: 8px; color: var(--text-muted); letter-spacing: 1px;">规则:</p>
                    <p>1. 分享链接给朋友</p>
                    <p>2. 朋友导入SF-Key = 有效分享</p>
                    <p>3. 每3次分享 = 1个奖励Key</p>
                    <p>4. 10次分享 = 额外奖励</p>
                </div>
            </div>
            <div style="background: var(--bg-secondary); border: 1px solid var(--accent-purple); padding: 14px; margin-bottom: 20px;">
                <div style="color: var(--accent-purple); font-size: 11px;">
                    <span id="progressLabel">进度</span>: <span id="rewardProgress">加载中...</span>
                </div>
            </div>
            <div class="btn-row" style="justify-content: flex-end;">
                <button id="btnCloseShare" class="btn btn-secondary" onclick="closeShareModal()">✕ 关闭</button>
            </div>
        </div>
    </div>
    
    <div class="modal" id="renewModal">
        <div class="modal-content" style="max-width: 460px;">
            <h3 class="modal-title" id="renewModalTitle">全部续期</h3>
            <div id="renewDescBox" style="background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 16px; margin-bottom: 16px; font-size: 13px; color: var(--text-secondary);">
                <p style="margin-bottom: 8px;">智能续期：仅刷新已过期账号</p>
                <p style="margin-bottom: 0;">强制续期：刷新所有账号</p>
            </div>
            <div id="renewWarningBox" style="background: var(--bg-secondary); border: 1px solid var(--accent-yellow); padding: 14px; margin-bottom: 20px; font-size: 10px; color: var(--accent-yellow);">
                <p style="margin-bottom: 6px;">续期后仍然无效？</p>
                <p style="margin-bottom: 3px;">1. Key额度已耗尽</p>
                <p style="margin-bottom: 0;">2. 服务器刷新失败 - 使用自主刷新</p>
            </div>
            <div class="btn-row" style="gap: 10px;">
                <button id="btnSmartRenew" class="btn btn-secondary" onclick="doRenewTokens(false)">◎ 智能续期</button>
                <button id="btnForceRenew" class="btn btn-secondary" onclick="doRenewTokens(true)">↻ 强制续期</button>
                <button id="btnCloseRenew" class="btn btn-secondary" onclick="closeRenewModal()">✕ 关闭</button>
            </div>
        </div>
    </div>
    <div class="modal" id="remarkModal">
        <div class="modal-content">
            <h3 class="modal-title" id="remarkModalTitle">编辑备注</h3>
            <input type="hidden" id="remarkIndex">
            <textarea id="remarkInput" rows="3" placeholder="输入备注..."></textarea>
            <div class="btn-row">
                <button id="btnSaveRemark" class="btn btn-secondary" onclick="saveRemark()">✓ 保存</button>
                <button id="btnCancelRemark" class="btn btn-secondary" onclick="closeModal()">✕ 取消</button>
            </div>
        </div>
    </div>
    <div class="modal" id="selfRefreshModal">
        <div class="modal-content" style="max-width: 600px;">
            <h3 class="modal-title" id="selfRefreshTitle">自主刷新账号</h3>
            <p style="color: var(--accent-blue); font-size: 11px; margin-bottom: 6px;">Key: <span id="refreshKeyIdDisplay"></span></p>
            <p style="color: var(--accent-orange); font-size: 10px; margin-bottom: 8px;"><span id="regionLabel">地区</span>: <span id="refreshRegionDisplay">-</span></p>
            <!-- S5代理信息 -->
            <div id="s5ProxyInfoBox" style="display: none; background: var(--bg-secondary); border: 1px solid var(--accent-green); padding: 12px; margin-bottom: 16px; font-size: 10px; border-radius: 6px;">
                <div style="color: var(--accent-green); font-weight: 500; margin-bottom: 8px;">🌐 SOCKS5代理:</div>
                <div id="s5ProxyInfo" style="color: var(--text-secondary); line-height: 1.6; font-family: monospace;"></div>
            </div>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border-color); padding: 16px; margin-bottom: 20px; font-size: 10px; color: var(--text-secondary); max-height: 180px; overflow-y: auto;">
                <div id="stepsLabel" style="color: var(--accent-yellow); font-weight: 500; margin-bottom: 12px; letter-spacing: 1px;">步骤:</div>
                <div id="step1" style="margin-bottom: 6px;">1. 设置Chrome为默认浏览器</div>
                <div style="margin-bottom: 6px;"><span id="step2">2. 切换VPN到</span> <span style="color: var(--accent-green);" id="refreshRegionHint">对应地区</span></div>
                <div id="step3" style="margin-bottom: 6px;">3. 点击下方Cookie注入</div>
                <div id="step4" style="margin-bottom: 6px;">4. 点击打开登录页并选择系统</div>
                <div id="step5" style="margin-bottom: 6px;">5. 如果未自动登录，手动复制账号密码</div>
                <div id="step6" style="margin-bottom: 6px;">6. 登录后点击浏览器中的连接设备</div>
                <div id="step7" style="margin-bottom: 10px;">7. 最后点击更新账号</div>
                <div id="selfRefreshNote" style="color: var(--text-muted); font-size: 9px; border-top: 1px solid var(--border-color); padding-top: 10px;">
                    备注：不自主刷新账号功能仍可使用，但无法查询余额。
                </div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                <button id="btnS5Inject" class="btn btn-secondary" onclick="selfRefreshS5Inject()" style="background: var(--accent-green); color: #000;">🌐 代理注入</button>
                <button id="btnRestoreNetwork" class="btn btn-secondary" onclick="restoreNetwork()" style="background: var(--accent-red); color: #fff;">✕ 恢复网络</button>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                <button id="btnCookieInject" class="btn btn-secondary" onclick="selfRefreshCookieInject()">◈ Cookie注入</button>
                <button id="btnOpenLogin" class="btn btn-secondary" onclick="showSystemSelect()">⇗ 打开登录页</button>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                <button id="btnCopyEmail" class="btn btn-secondary" onclick="selfRefreshCopyEmail()">⊕ 复制账号</button>
                <button id="btnCopyPassword" class="btn btn-secondary" onclick="selfRefreshCopyPassword()">⊕ 复制密码</button>
                <button id="btnClearChrome" class="btn btn-secondary" onclick="selfRefreshClearChrome()">⊗ 清空Chrome</button>
            </div>
            <div style="margin-bottom: 16px;">
                <button id="btnUpdateAccount" class="btn btn-secondary" style="width: 100%; padding: 14px;" onclick="selfRefreshUpdateAccount()">↻ 更新账号</button>
            </div>
            <div style="display: flex; gap: 10px;">
                <button id="btnRequestRefresh" class="btn btn-secondary" style="flex: 1;" onclick="selfRefreshSubmitRequest()">✉ 申请刷新</button>
                <button id="btnCloseSelfRefresh" class="btn btn-secondary" style="flex: 1;" onclick="closeSelfRefreshModal()">✕ 关闭</button>
            </div>
        </div>
    </div>
    <div class="modal" id="systemSelectModal">
        <div class="modal-content" style="max-width: 380px;">
            <h3 class="modal-title" id="selectSystemTitle">选择系统</h3>
            <p id="selectSystemDesc" style="color: var(--text-muted); font-size: 11px; margin-bottom: 20px;">请选择您的操作系统:</p>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <button class="btn" style="border-color: var(--text-secondary); padding: 24px; font-size: 12px;" onclick="selfRefreshOpenLoginMac()">macOS</button>
                <button class="btn" style="border-color: var(--accent-blue); color: var(--accent-blue); padding: 24px; font-size: 12px;" onclick="selfRefreshOpenLoginWindows()">Windows</button>
            </div>
            <div style="margin-top: 20px;">
                <button id="btnCancelSystem" class="btn btn-secondary" style="width: 100%;" onclick="closeSystemSelect()">取消</button>
            </div>
        </div>
    </div>
    <div class="modal" id="exhaustedModal">
        <div class="modal-content" style="max-width: 520px;">
            <h3 class="modal-title" id="exhaustedModalTitle">删除已耗尽账号</h3>
            <p id="exhaustedModalDesc" style="color: var(--text-muted); font-size: 11px; margin-bottom: 16px;">以下账号使用率≥100%，勾选后点击删除</p>
            <div class="exhausted-list" id="exhaustedList">加载中...</div>
            <div class="btn-row">
                <button id="btnConfirmDelete" class="btn btn-secondary" onclick="confirmDeleteExhausted()">✓ 确认删除</button>
                <button id="btnCancelExhausted" class="btn btn-secondary" onclick="closeExhaustedModal()">✕ 取消</button>
            </div>
        </div>
    </div>
    <!-- 工单系统模态框 -->
    <div class="modal" id="ticketModal">
        <div class="modal-content" style="max-width: 580px; max-height: 85vh; display: flex; flex-direction: column;">
            <h3 class="modal-title" style="color: var(--accent-red); flex-shrink: 0;">📋 问题反馈</h3>
            <div style="display: flex; gap: 10px; margin-bottom: 15px; flex-shrink: 0;">
                <button id="tabSubmit" class="btn btn-primary" style="flex: 1;" onclick="showTicketTab('submit')">☁ 提交反馈</button>
                <button id="tabMyTickets" class="btn btn-secondary" style="flex: 1;" onclick="showTicketTab('mytickets')">🔒 我的工单</button>
            </div>
            <!-- 提交反馈面板 -->
            <div id="submitPanel" style="flex: 1; overflow-y: auto; min-height: 0;">
                <p style="color: var(--text-muted); font-size: 12px; margin-bottom: 12px;">提交问题后，我们会查看日志并尽快处理</p>
                <div style="margin-bottom: 12px;">
                    <div style="color: var(--accent-gold); font-size: 12px; margin-bottom: 6px;">工单编号: <span id="ticketNumber" style="color: var(--accent-blue);"></span></div>
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 6px;">问题类型</label>
                    <select id="ticketType" style="width: 100%; padding: 10px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 14px;">
                        <option value="error">程序错误/崩溃</option>
                        <option value="balance">额度查询问题</option>
                        <option value="login">登录/切换问题</option>
                        <option value="sync">云端同步问题</option>
                        <option value="feature">功能建议</option>
                        <option value="other">其他问题</option>
                    </select>
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 6px;">问题描述</label>
                    <textarea id="ticketDesc" rows="3" placeholder="请详细描述您遇到的问题..." style="width: 100%; padding: 10px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 14px; resize: none;"></textarea>
                </div>
                <div style="margin-bottom: 12px;">
                    <label style="color: var(--text-secondary); font-size: 12px; display: block; margin-bottom: 6px;">联系方式 (选填)</label>
                    <input type="text" id="ticketContact" placeholder="邮箱或其他联系方式" style="width: 100%; padding: 10px; background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-primary); font-size: 14px;">
                </div>
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px; color: var(--text-muted); font-size: 11px;">
                    <input type="checkbox" id="attachLogs" checked style="width: 14px; height: 14px;">
                    <label for="attachLogs">提交时将自动附带运行日志，用于问题排查</label>
                </div>
            </div>
            <div class="btn-row" id="submitBtnRow" style="flex-shrink: 0; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-color);">
                <button class="btn btn-primary" onclick="submitTicket()">☁ 提交反馈</button>
                <button class="btn btn-secondary" onclick="closeTicketModal()">取消</button>
            </div>
            <!-- 我的工单面板 -->
            <div id="myTicketsPanel" style="display: none; flex: 1; overflow-y: auto; min-height: 0;">
                <div id="ticketList" style="max-height: 100%; overflow-y: auto;">
                    <div style="text-align: center; color: var(--text-muted); padding: 40px;">加载中...</div>
                </div>
            </div>
            <div class="btn-row" id="myTicketsBtnRow" style="display: none; flex-shrink: 0; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-color);">
                <button class="btn btn-secondary" onclick="loadMyTickets()">↻ 刷新</button>
                <button class="btn btn-secondary" onclick="closeTicketModal()">关闭</button>
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
            <div class="loading-message" id="loadingMessage">加载中...</div>
        </div>
    </div>
    <script>
        // 多语言系统
        let currentLang = localStorage.getItem('lang') || 'zh';
        const i18n = {
            en: {
                // 页面标题
                pageTitle: 'Token Manager',
                pageSubtitle: "/ 'tok-en 'man-i-jer / Your key management system",
                // 卡片标题
                importKey: 'Import Key',
                credits: 'Credits',
                currentSession: 'Current Account',
                accountPool: 'Account Pool',
                // 按钮
                clear: 'Clear',
                import: 'Import',
                refresh: 'Refresh',
                cloudSync: 'Cloud Sync',
                queryBalance: 'Query Balance',
                renewAll: 'Renew All',
                ticket: 'Ticket',
                autoSwitch: 'Auto Switch',
                switchBest: 'Switch Best',
                removeExhausted: 'Remove Exhausted',
                switch: 'Switch',
                sync: 'Sync',
                request: 'Request',
                edit: 'Edit',
                del: 'Del',
                active: 'Active',
                close: 'Close',
                save: 'Save',
                cancel: 'Cancel',
                copy: 'Copy',
                confirmDelete: 'Confirm Delete',
                smartRenew: 'Smart Renew',
                forceRenew: 'Force Renew',
                // 表头
                keyId: 'Key ID',
                status: 'Status',
                balance: 'Balance',
                remain: 'Remain',
                usage: 'Usage',
                remark: 'Remark',
                added: 'Added',
                actions: 'Actions',
                // 开关
                refreshGuard: 'Refresh Guard:',
                autoSwitch: 'Auto Switch:',
                on: 'On',
                off: 'Off',
                // 提示信息
                firstImportBonus: 'Click to import 10M quota',
                checkUpdate: 'Check Update',
                shareEarn: 'Share & Earn',
                contact: 'Contact:',
                detecting: 'Detecting...',
                noSession: 'No active session. Run droid auth login first.',
                noAccounts: 'No accounts yet. Import a Key to get started.',
                loading: 'Loading...',
                // Toast消息
                pasteKeyFirst: 'Please paste your Key first',
                loadingKey: 'Loading your SF-Key...',
                syncingCloud: 'Syncing from cloud...',
                queryingBalance: 'Querying all account balances...',
                balanceComplete: 'Balance query complete',
                queryFailed: 'Query failed',
                smartRenewing: 'Smart renewing...',
                forceRenewing: 'Force renewing all accounts...',
                switchingAccount: 'Switching account...',
                deleteConfirm: 'Are you sure you want to delete this account?',
                refreshing: 'Refreshing...',
                switchingBest: 'Switching to best account...',
                noExhausted: 'No exhausted accounts found',
                selectOne: 'Please select at least one account',
                refreshEnabled: 'Refresh guard enabled',
                refreshDisabled: 'Refresh guard disabled',
                connectionRestored: 'Connection restored',
                connectionLost: 'Connection lost, reconnecting...',
                connectionFailed: 'Connection failed, check if client is running',
                restartingClient: 'Restarting client, please wait...',
                retryingAdd: 'Client restored, retrying...',
                timeout: 'Operation timeout, please retry',
                newAccountsSync: 'New accounts detected, syncing from cloud...',
                checkingUpdate: 'Checking for updates...',
                checkFailed: 'Check failed',
                linkCopied: 'Link copied to clipboard',
                linkEmpty: 'Link is empty',
                loadShareFailed: 'Failed to load share info',
                // 模态框
                shareTitle: 'Share & Earn',
                validShares: 'Valid shares:',
                yourShareLink: 'Your share link:',
                rules: 'Rules:',
                rule1: '1. Share link with friends',
                rule2: '2. Friend imports SF-Key = valid share',
                rule3: '3. Every 3 shares = 1 reward key',
                rule4: '4. 10 shares = bonus unlock',
                progress: 'Progress:',
                renewTitle: 'Renew All Tokens',
                renewSmartDesc: 'Smart Renew: Only refresh expired accounts',
                renewForceDesc: 'Force Renew: Refresh all accounts',
                renewWarning: 'Still invalid after renewal?',
                renewReason1: '1. Key quota exhausted',
                renewReason2: '2. Server refresh failed - use Self Refresh',
                editRemark: 'Edit Remark',
                enterRemark: 'Enter remark...',
                selfRefreshTitle: 'Self Refresh Account',
                region: 'Region:',
                steps: 'Steps:',
                step1: '1. Set Chrome as default browser',
                step2: '2. Switch VPN to',
                targetRegion: 'target region',
                step3: '3. Click Cookie Inject below',
                step4: '4. Click Open Login and select your system',
                step5: '5. If not auto-logged in, copy email/password manually',
                step6: '6. After login, click Connect Device in browser',
                step7: '7. Finally click Update Account',
                selfRefreshNote: 'Note: Without self-refresh, functions still work but balance query unavailable.',
                cookieInject: 'Cookie Inject',
                openLogin: 'Open Login',
                copyEmail: 'Copy Email',
                copyPassword: 'Copy Password',
                clearChrome: 'Clear Chrome',
                updateAccount: 'Update Account',
                requestRefresh: 'Request Refresh',
                selectSystem: 'Select System',
                selectSystemDesc: 'Choose your operating system:',
                chooseOS: 'Choose your operating system:',
                exhaustedTitle: 'Remove Exhausted Accounts',
                exhaustedDesc: 'Accounts with usage >= 100%. Select and delete.',
                // 状态
                valid: 'Valid',
                expired: 'Expired',
                pending: 'Pending',
                // 前端后端
                frontend: 'Frontend:',
                backend: 'Backend:'
            },
            zh: {
                // 页面标题
                pageTitle: '密钥管理器',
                pageSubtitle: '/ mi-yao guan-li-qi / 您的密钥管理系统',
                // 卡片标题
                importKey: '导入密钥',
                credits: '致谢',
                currentSession: '当前账号',
                accountPool: '账号池',
                // 按钮
                clear: '清空',
                import: '导入',
                refresh: '刷新',
                cloudSync: '云端同步',
                queryBalance: '查询额度',
                renewAll: '全部续期',
                ticket: '工单',
                autoSwitch: '自动切换',
                switchBest: '切换最优',
                removeExhausted: '删除耗尽',
                switch: '切换',
                sync: '同步',
                request: '申请',
                edit: '备注',
                del: '删除',
                active: '已登录',
                close: '关闭',
                save: '保存',
                cancel: '取消',
                copy: '复制',
                confirmDelete: '确认删除',
                smartRenew: '智能续期',
                forceRenew: '强制续期',
                // 表头
                keyId: '密钥编号',
                status: '状态',
                balance: '额度状态',
                remain: '剩余',
                usage: '使用率',
                remark: '备注',
                added: '添加时间',
                actions: '操作',
                // 开关
                refreshGuard: '刷新保护:',
                autoSwitch: '自动切换:',
                on: '开启',
                off: '关闭',
                // 提示信息
                firstImportBonus: '点击导入1000万额度',
                checkUpdate: '检查更新',
                shareEarn: '分享有礼',
                contact: '联系作者:',
                detecting: '检测中...',
                noSession: '未检测到登录账号（请先运行 droid auth login）',
                noAccounts: '暂无账号，请添加密钥',
                loading: '加载中...',
                // Toast消息
                pasteKeyFirst: '请先粘贴密钥',
                loadingKey: '您的SF-Key正在加载中，请稍后...',
                syncingCloud: '正在从云端同步账号数据...',
                queryingBalance: '正在查询所有账号额度...',
                balanceComplete: '额度查询完成',
                queryFailed: '查询失败',
                smartRenewing: '正在智能续期...',
                forceRenewing: '正在强制续期所有账号...',
                switchingAccount: '正在切换账号...',
                deleteConfirm: '确定要删除这个账号吗？',
                refreshing: '正在刷新...',
                switchingBest: '正在切换到最优账号...',
                noExhausted: '没有已耗尽的账号',
                selectOne: '请至少选择一个账号',
                refreshEnabled: '刷新保护已开启',
                refreshDisabled: '刷新保护已关闭',
                connectionRestored: '服务已恢复连接',
                connectionLost: '服务连接断开，正在尝试重连...',
                connectionFailed: '服务连接失败，请检查客户端是否运行',
                restartingClient: '正在重启客户端，请稍候...',
                retryingAdd: '客户端已恢复，正在重试添加...',
                timeout: '操作超时，请重试',
                newAccountsSync: '检测到新账号，正在从云端同步数据...',
                checkingUpdate: '检查更新中...',
                checkFailed: '检查失败',
                linkCopied: '链接已复制到剪贴板',
                linkEmpty: '链接为空',
                loadShareFailed: '获取分享信息失败',
                // 模态框
                shareTitle: '分享有礼',
                validShares: '有效分享:',
                yourShareLink: '您的专属分享链接:',
                rules: '分享规则:',
                rule1: '1. 分享链接给好友，好友下载并安装客户端',
                rule2: '2. 好友成功导入SF-Key即算有效分享',
                rule3: '3. 每满3个有效分享，获得1个奖励Key',
                rule4: '4. 累计10个有效分享，解锁额外奖励',
                progress: '奖励进度:',
                renewTitle: '全部续期',
                renewSmartDesc: '智能续期：仅刷新已过期的账号',
                renewForceDesc: '强制续期：刷新所有账号（包括有效的）',
                renewWarning: '续期后仍失效？可能原因：',
                renewReason1: '1. Key额度已耗尽',
                renewReason2: '2. 服务器刷新失败 → 请使用「自主刷新」',
                editRemark: '编辑备注',
                enterRemark: '输入备注...',
                selfRefreshTitle: '自主刷新账号',
                region: '地区节点:',
                steps: '刷新步骤：',
                step1: '1. 设置Chrome为默认浏览器',
                step2: '2. 将您的节点切换至',
                targetRegion: '对应地区',
                step3: '3. 点击下方「Cookie注入」',
                step4: '4. 点击「打开登录页」选择系统',
                step5: '5. 如未自动登录，请复制账号密码手动登录',
                step6: '6. 登录成功后，在浏览器中点击「连接设备」',
                step7: '7. 最后点击「更新账号」保存Token',
                selfRefreshNote: '备注：不自主刷新账号功能仍可使用，但无法查询余额。',
                cookieInject: 'Cookie注入',
                openLogin: '打开登录页',
                copyEmail: '复制账号',
                copyPassword: '复制密码',
                clearChrome: '清空Chrome',
                updateAccount: '更新账号',
                requestRefresh: '申请刷新',
                selectSystem: '选择系统',
                selectSystemDesc: '请选择您的操作系统:',
                chooseOS: '请选择您的操作系统：',
                exhaustedTitle: '删除已耗尽账号',
                exhaustedDesc: '以下账号使用率≥100%，勾选后点击删除',
                // 状态
                valid: '有效',
                expired: '已过期',
                pending: '待验证',
                // 前端后端
                frontend: '前端程序员:',
                backend: '后端程序员:'
            }
        };
        
        function t(key) {
            return i18n[currentLang][key] || i18n['en'][key] || key;
        }
        
        function toggleLanguage() {
            currentLang = currentLang === 'en' ? 'zh' : 'en';
            localStorage.setItem('lang', currentLang);
            document.getElementById('langSwitch').textContent = currentLang === 'en' ? '中文' : 'EN';
            applyLanguage();
        }
        
        function applyLanguage() {
            // 页面标题
            document.querySelector('.page-header h2').textContent = t('pageTitle');
            document.querySelector('.page-header .subtitle').textContent = t('pageSubtitle');
            
            // 卡片标题
            const cardTitles = document.querySelectorAll('.card-title');
            if (cardTitles[0]) cardTitles[0].textContent = t('importKey');
            
            // Credits
            document.querySelector('.credits-title').textContent = t('credits');
            
            // 按钮
            document.querySelectorAll('.btn-row')[0].children[0].textContent = '✕ ' + t('clear');
            document.querySelectorAll('.btn-row')[0].children[1].textContent = '↵ ' + t('import');
            
            // 提示
            document.querySelector('.hint-orange').textContent = t('firstImportBonus');
            
            // 信息行
            const infoSpans = document.querySelectorAll('.info-row span');
            if (infoSpans[0]) infoSpans[0].textContent = t('contact') + ' haooicq@gmail.com';
            if (infoSpans[1]) infoSpans[1].textContent = t('checkUpdate');
            if (infoSpans[2]) infoSpans[2].textContent = t('shareEarn');
            
            // 当前会话卡片
            if (cardTitles[1]) cardTitles[1].textContent = t('currentSession');
            
            // 工具栏按钮
            document.getElementById('btnRefresh').textContent = '⟳ ' + t('refresh');
            document.getElementById('btnSwitchBest').textContent = '★ ' + t('switchBest');
            document.getElementById('btnDeleteExhausted').textContent = '✕ ' + t('removeExhausted');
            document.getElementById('autoSwitchLabel').textContent = t('autoSwitch') + ':';
            
            // Self Refresh模态框
            document.getElementById('selfRefreshTitle').textContent = t('selfRefreshTitle');
            document.getElementById('regionLabel').textContent = t('region').replace(':', '');
            document.getElementById('stepsLabel').textContent = t('steps');
            document.getElementById('step1').textContent = t('step1');
            document.getElementById('step2').textContent = t('step2');
            document.getElementById('step3').textContent = t('step3');
            document.getElementById('step4').textContent = t('step4');
            document.getElementById('step5').textContent = t('step5');
            document.getElementById('step6').textContent = t('step6');
            document.getElementById('step7').textContent = t('step7');
            document.getElementById('selfRefreshNote').textContent = t('selfRefreshNote');
            document.getElementById('btnCookieInject').textContent = '◈ ' + t('cookieInject');
            document.getElementById('btnOpenLogin').textContent = '⇗ ' + t('openLogin');
            document.getElementById('btnCopyEmail').textContent = '⊕ ' + t('copyEmail');
            document.getElementById('btnCopyPassword').textContent = '⊕ ' + t('copyPassword');
            document.getElementById('btnClearChrome').textContent = '⊗ ' + t('clearChrome');
            document.getElementById('btnUpdateAccount').textContent = '↻ ' + t('updateAccount');
            document.getElementById('btnRequestRefresh').textContent = '✉ ' + t('requestRefresh');
            document.getElementById('btnCloseSelfRefresh').textContent = '✕ ' + t('close');
            
            // 系统选择模态框
            document.getElementById('selectSystemTitle').textContent = t('selectSystem');
            document.getElementById('selectSystemDesc').textContent = t('selectSystemDesc');
            
            // 刷新列表以应用语言
            loadAccounts();
            loadLoginStatus();
        }
        
        // 主题切换
        let currentTheme = localStorage.getItem('theme') || 'dark';
        
        function toggleTheme() {
            currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
            localStorage.setItem('theme', currentTheme);
            applyTheme();
        }
        
        function applyTheme() {
            const root = document.documentElement;
            if (currentTheme === 'light') {
                // 亮色模式：主色 橙色+黑色，辅助色 绿色+红色
                root.style.setProperty('--bg-primary', '#f8f8f5');
                root.style.setProperty('--bg-secondary', '#ffffff');
                root.style.setProperty('--bg-card', '#ffffff');
                root.style.setProperty('--text-primary', '#1a1a1a');  // 黑色主文字
                root.style.setProperty('--text-secondary', '#2d2d2d'); // 深灰副文字
                root.style.setProperty('--text-muted', '#555555');    // 中灰提示文字
                root.style.setProperty('--border-color', '#d0d0d0');
                root.style.setProperty('--accent-gold', '#d96830');   // 橙色主色
                root.style.setProperty('--accent-orange', '#d96830'); // 橙色主色
                root.style.setProperty('--accent-green', '#1a8754');  // 绿色辅助
                root.style.setProperty('--accent-red', '#d32f2f');    // 红色辅助
                root.style.setProperty('--accent-blue', '#1976d2');   // 蓝色辅助
                document.getElementById('themeSwitch').textContent = '☾';
            } else {
                // 暗色模式：主色 白色+橙色，辅助色 绿色+红色+蓝色，减少灰色
                root.style.setProperty('--bg-primary', '#0d0d0d');
                root.style.setProperty('--bg-secondary', '#151515');
                root.style.setProperty('--bg-card', '#151515');
                root.style.setProperty('--text-primary', '#f5f5f5');   // 白色主文字
                root.style.setProperty('--text-secondary', '#d0d0d0'); // 浅灰副文字(提高对比度)
                root.style.setProperty('--text-muted', '#888888');     // 灰色提示(仅用于次要信息)
                root.style.setProperty('--border-color', '#333333');
                root.style.setProperty('--accent-gold', '#f08040');    // 橙色主色(更亮)
                root.style.setProperty('--accent-orange', '#f08040');  // 橙色主色
                root.style.setProperty('--accent-green', '#4caf50');   // 绿色辅助
                root.style.setProperty('--accent-red', '#f44336');     // 红色辅助
                root.style.setProperty('--accent-blue', '#42a5f5');    // 蓝色辅助
                document.getElementById('themeSwitch').textContent = '☀';
            }
        }
        
        // 页面加载时应用语言和主题
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('langSwitch').textContent = currentLang === 'en' ? '中文' : 'EN';
            applyTheme();
        });

        let loadingTimer = null;
        let progressInterval = null;
        let currentTimeout = 30000;
        function showLoading(message = null, timeout = 30000) {
            message = message || t('loading');
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
                showToast(t('timeout'), 'error');
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
                        showToast(t('connectionRestored'), 'success');
                        loadLoginStatus();
                        loadAccounts();
                        // 连接恢复后，检查并处理待添加的内容
                        setTimeout(() => processPendingAdd(), 500);
                    }
                    return true;
                }
            } catch (e) {
                if (serverOnline) {
                    serverOnline = false;
                    showToast(t('connectionLost'), 'error');
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
        
        let pendingAddContent = null;  // 存储待添加的SF-Key内容
        let isRetryingAdd = false;  // 是否正在重试添加
        
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
                return { success: false, message: t('connectionFailed'), connectionError: true };
            }
        }
        
        // 尝试重启客户端
        async function tryRestartClient() {
            showToast(t('restartingClient'), 'info');
            // 尝试使用 AppleScript 打开终端并运行 factory restart
            try {
                // 创建一个隐藏的 iframe 来触发 URL scheme
                const restartUrl = 'x-apple.systempreferences:';  // 仅用于触发
                // macOS 上尝试打开终端
                window.location.href = 'x-apple-terminal://';
            } catch(e) {}
            
            // 等待并尝试重连
            for (let i = 0; i < 10; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const online = await checkServerStatus();
                if (online) return true;
            }
            return false;
        }
        
        // 当连接恢复时检查并处理待添加的内容
        async function processPendingAdd() {
            if (pendingAddContent && !isRetryingAdd) {
                isRetryingAdd = true;
                showToast(t('retryingAdd'), 'info');
                showLoading(t('loadingKey'), 20000);
                const result = await api('add', { content: pendingAddContent });
                hideLoading();
                if (result.success) {
                    showToast(result.message, 'success');
                    clearInput();
                    pendingAddContent = null;
                    localStorage.removeItem('pendingAddContent');
                    loadAccounts();
                    loadLoginStatus();
                } else if (!result.connectionError) {
                    pendingAddContent = null;
                    localStorage.removeItem('pendingAddContent');
                    if (result.exists) {
                        showToast(result.message, 'info');
                    } else {
                        showToast(result.message, 'error');
                    }
                }
                isRetryingAdd = false;
            }
        }
        
        async function addToken() {
            const content = document.getElementById('tokenInput').value.trim();
            if (!content) { showToast(t('pasteKeyFirst'), 'error'); return; }
            showLoading(t('loadingKey'), 20000);
            const result = await api('add', { content });
            hideLoading();
            if (result.success) {
                showToast(result.message, 'success');
                clearInput();
                loadAccounts();
                loadLoginStatus();
            } else if (result.connectionError) {
                // 连接失败，保存内容并尝试重启客户端
                pendingAddContent = content;
                localStorage.setItem('pendingAddContent', content);
                showToast(t('restartingClient'), 'info');
                
                // 持续尝试重连，最多60秒
                let retryCount = 0;
                const maxRetries = 30;
                const retryInterval = setInterval(async () => {
                    retryCount++;
                    const online = await checkServerStatus();
                    if (online) {
                        clearInterval(retryInterval);
                        // 连接恢复，自动重试添加
                        await processPendingAdd();
                    } else if (retryCount >= maxRetries) {
                        clearInterval(retryInterval);
                        showToast(t('connectionFailed'), 'error');
                    }
                }, 2000);
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
                container.innerHTML = `<div class="empty-state">${t('noAccounts')}</div>`;
                return;
            }
            
            // 检查是否有需要同步的账号（状态为 pending 或 refresh）
            const needSync = result.accounts.some(acc => acc.status === 'pending' || acc.status === 'refresh' || acc.balance_status === 'pending');
            
            // 首次加载且有需要同步的账号，自动触发云端同步
            if (isFirstLoad && needSync) {
                isFirstLoad = false;
                showToast(t('newAccountsSync'), 'info');
                setTimeout(() => syncFromCloud(), 500);
            }
            
            let html = `<div class="table-wrapper"><table><thead><tr><th style="width:40px;">#</th><th>${t('keyId')}</th><th style="width:80px;">${t('status')}</th><th style="width:90px;">${t('balance')}</th><th style="width:70px;">${t('remain')}</th><th style="width:70px;">${t('usage')}</th><th style="width:80px;">${t('remark')}</th><th style="width:100px;">${t('added')}</th><th style="width:200px;">${t('actions')}</th></tr></thead><tbody>`;
            for (const acc of result.accounts) {
                const statusClass = 'status-' + acc.status;
                const statusIcon = acc.is_current ? '🟢' : (acc.status === 'valid' ? '✅' : (acc.status === 'refresh' ? '🔄' : (acc.status === 'pending' ? '⏳' : '❌')));
                const balanceClass = 'balance-' + acc.balance_status;
                const balanceIcon = (acc.status === 'refresh' && acc.balance_text === '-') ? '' : (acc.balance_status === 'good' ? '🟢' : acc.balance_status === 'medium' ? '🟡' : acc.balance_status === 'low' ? '🔴' : acc.balance_status === 'exhausted' ? '⚠️' : acc.balance_status === 'error' ? '❌' : '⏳');
                const keyDisplay = acc.key_id.startsWith('SF-') && acc.key_id.length > 35 ? acc.key_id.substring(0, 35) + '...' : acc.key_id;
                const cachedTip = acc.cached && acc.last_updated ? ` title="缓存数据，更新于: ${acc.last_updated}"` : '';
                const statusTip = acc.status === 'refresh' ? ' title="Token已过期，点击☁️云端同步获取最新数据"' : (acc.status === 'pending' ? ' title="待验证状态，请点击☁️云端同步获取数据"' : '');
                const balanceTip = acc.balance_status === 'error' ? ' title="注意：查询失败并不代表key失效，如果key额度高于20%请在几小时后重新查询，在额度使用完之前，此提示并不影响使用"' : cachedTip;
                // 状态为 refresh 时显示申请刷新按钮（同步按钮已移除，切换时自动同步）
                const refreshRequestBtn = acc.status === 'refresh' ? `<button class="btn btn-secondary action-btn" onclick="requestRefresh('${acc.key_id}')" title="向管理员申请刷新此Key">✉ ${t('request')}</button>` : '';
                const actionBtn = acc.is_current 
                    ? `<span class="btn btn-secondary action-btn" style="cursor:default;border-color:var(--accent-green);color:var(--accent-green);">● ${t('active')}</span>` 
                    : `<button class="btn btn-secondary action-btn" onclick="switchAccount(${acc.index})">◇ ${t('switch')}</button>`;
                // Key编号单元格只显示Key，按钮移到操作列
                const extraActions = refreshRequestBtn;
                html += `<tr><td style="text-align:center;">${acc.index}</td><td>${keyDisplay}</td><td class="${statusClass}"${statusTip}>${acc.is_current ? t('active') : acc.status_text}</td><td class="${balanceClass}"${balanceTip}>${acc.balance_text}</td><td>${acc.remaining}</td><td>${acc.usage_ratio}</td><td>${acc.remark || '-'}</td><td>${acc.added_at}</td><td style="white-space:nowrap;">${extraActions}${actionBtn}<button class="btn btn-secondary action-btn" onclick="editRemark(${acc.index}, '${(acc.remark || '').replace(/'/g, "\\\\'")}')">✎ ${t('edit')}</button><button class="btn btn-secondary action-btn" onclick="deleteAccount(${acc.index})">✕ ${t('del')}</button></td></tr>`;
            }
            html += '</tbody></table></div>';
            container.innerHTML = html;
        }
        async function syncFromCloud() {
            showLoading(t('syncingCloud'), 60000);
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
            showToast(t('queryingBalance'), 'info');
            const result = await api('refresh_balances');
            if (result.success) { showToast(t('balanceComplete'), 'success'); loadAccounts(); }
            else { showToast(result.message || t('queryFailed'), 'error'); }
        }
        function renewAllTokens() {
            document.getElementById('renewModal').classList.add('active');
        }
        function closeRenewModal() {
            document.getElementById('renewModal').classList.remove('active');
        }
        async function doRenewTokens(forceAll) {
            closeRenewModal();
            const msg = forceAll ? t('forceRenewing') : t('smartRenewing');
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
                        statusBadge = '<span class="status-badge badge-expired">Expired</span>';
                    } else {
                        statusBadge = '<span class="status-badge badge-active">Valid</span>';
                    }
                    // 优先显示 sfkey，其次邮箱
                    let userDisplay = info.sf_key_line1 || info.email || (info.sub ? `User: ${info.sub.substring(0, 12)}...` : 'Unknown');
                    if (userDisplay.startsWith('SF-') && userDisplay.length > 35) userDisplay = userDisplay.substring(0, 35) + '...';
                    container.innerHTML = `<div class="status-row"><div class="user-info"><span style="font-size: 11px;">${userDisplay}</span>${statusBadge}</div></div>`;
                } else { container.innerHTML = '<span style="color: var(--text-muted);">No active session. Run droid auth login first.</span>'; }
            } catch (e) { container.innerHTML = '<span style="color: var(--accent-red);">Detection failed</span>'; }
        }
        async function switchAccount(index) {
            showLoading(t('switchingAccount'), 35000);
            const result = await api('switch', { index });
            hideLoading();
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { loadAccounts(); loadLoginStatus(); }
        }
        async function deleteAccount(index) {
            if (!confirm(t('deleteConfirm'))) return;
            const result = await api('delete', { index });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) loadAccounts();
        }
        async function refreshToken(index) {
            showToast(t('refreshing'), 'info');
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
        let currentS5Proxy = '';
        async function requestRefresh(keyId) {
            currentRefreshKeyId = keyId;
            document.getElementById('selfRefreshModal').classList.add('active');
            document.getElementById('refreshKeyIdDisplay').textContent = keyId.substring(0, 35) + '...';
            // 隐藏代理信息（等待加载）
            document.getElementById('s5ProxyInfoBox').style.display = 'none';
            
            // 获取账号的地区和代理信息
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
            
            // 显示S5代理信息
            if (result.success && result.s5_proxy) {
                currentS5Proxy = result.s5_proxy;
                const proxyInfo = parseS5Proxy(result.s5_proxy);
                if (proxyInfo && proxyInfo.ip) {
                    let html = '';
                    html += 'IP地址: <span style="color:var(--accent-orange);">' + proxyInfo.ip + '</span><br>';
                    html += '端口: <span style="color:var(--accent-orange);">' + (proxyInfo.port || '-') + '</span><br>';
                    html += '用户名: <span style="color:var(--accent-orange);">' + (proxyInfo.username || '-') + '</span><br>';
                    html += '密码: <span style="color:var(--accent-orange);">' + (proxyInfo.password || '-') + '</span>';
                    document.getElementById('s5ProxyInfo').innerHTML = html;
                    document.getElementById('s5ProxyInfoBox').style.display = 'block';
                }
            } else {
                currentS5Proxy = '';
            }
        }
        
        // 解析SOCKS5代理字符串
        function parseS5Proxy(s5_proxy) {
            if (!s5_proxy) return null;
            try {
                let proxyStr = s5_proxy;
                if (proxyStr.startsWith('socks5://')) {
                    proxyStr = proxyStr.substring(9);
                }
                const parts = proxyStr.split(':');
                if (parts.length >= 4) {
                    return { ip: parts[0], port: parts[1], username: parts[2], password: parts[3] };
                } else if (parts.length >= 2) {
                    return { ip: parts[0], port: parts[1], username: '', password: '' };
                }
            } catch (e) {}
            return { ip: s5_proxy, port: '', username: '', password: '' };
        }
        
        async function selfRefreshS5Inject() {
            if (!currentS5Proxy) {
                showToast('无代理信息', 'error');
                return;
            }
            showToast('正在配置系统代理...', 'info');
            const result = await api('proxy_inject', { proxy: currentS5Proxy });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        
        async function restoreNetwork() {
            showToast('正在恢复网络设置...', 'info');
            const result = await api('restore_network');
            showToast(result.message, result.success ? 'success' : 'error');
        }
        function closeSelfRefreshModal() {
            document.getElementById('selfRefreshModal').classList.remove('active');
            currentRefreshKeyId = '';
            currentRefreshRegion = '';
        }
        async function selfRefreshClearChrome() {
            showToast('Clearing Chrome Google data...', 'info');
            const result = await api('self_refresh_clear_chrome');
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshCookieInject() {
            if (!currentRefreshKeyId) { showToast('Please select an account first', 'error'); return; }
            showToast('Fetching cookie from cloud...', 'info');
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
            showToast('Opening login page (Mac)...', 'info');
            const result = await api('self_refresh_open_login', { system: 'mac' });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshOpenLoginWindows() {
            closeSystemSelect();
            showToast('Opening login page (Windows)...', 'info');
            const result = await api('self_refresh_open_login', { system: 'windows' });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        async function selfRefreshCopyEmail() {
            if (!currentRefreshKeyId) { showToast('Please select an account first', 'error'); return; }
            const result = await api('self_refresh_get_credentials', { key_id: currentRefreshKeyId });
            if (result.success && result.email) {
                navigator.clipboard.writeText(result.email);
                showToast('Email copied to clipboard', 'success');
            } else {
                showToast(result.message || 'Failed to get email', 'error');
            }
        }
        async function selfRefreshCopyPassword() {
            if (!currentRefreshKeyId) { showToast('Please select an account first', 'error'); return; }
            const result = await api('self_refresh_get_credentials', { key_id: currentRefreshKeyId });
            if (result.success && result.password) {
                navigator.clipboard.writeText(result.password);
                showToast('Password copied to clipboard', 'success');
            } else {
                showToast(result.message || 'Failed to get password', 'error');
            }
        }
        async function selfRefreshUpdateAccount() {
            if (!currentRefreshKeyId) { showToast('Please select an account first', 'error'); return; }
            showToast('Checking and updating account...', 'info');
            const result = await api('self_refresh_update_account', { key_id: currentRefreshKeyId });
            showToast(result.message, result.success ? 'success' : 'error');
            if (result.success) { loadAccounts(); loadLoginStatus(); }
        }
        async function selfRefreshSubmitRequest() {
            if (!currentRefreshKeyId) { showToast('Please select an account first', 'error'); return; }
            showToast('Submitting request...', 'info');
            const result = await api('request_refresh', { key_id: currentRefreshKeyId });
            showToast(result.message, result.success ? 'success' : 'error');
        }
        loadAccounts();
        loadLoginStatus();
        loadCloudConfig();
        
        // 页面加载时检查是否有待添加的内容（从localStorage恢复）
        const savedPendingContent = localStorage.getItem('pendingAddContent');
        if (savedPendingContent) {
            pendingAddContent = savedPendingContent;
            // 延迟1秒后尝试处理待添加的内容
            setTimeout(() => {
                if (serverOnline) {
                    processPendingAdd();
                }
            }, 1000);
        }
        
        let autoRefreshTimer = null;
        async function autoRefreshBalances() { 
            try { 
                await api('auto_refresh'); 
                loadAccounts(); 
            } catch(e) { console.error('Auto refresh error:', e); } 
        }
        function startAutoRefresh() { 
            // 首次延迟10秒后执行，之后每10分钟自动刷新额度和续期
            setTimeout(async () => { 
                await autoRefreshBalances(); 
                await autoRenewTokens();
                autoRefreshTimer = setInterval(async () => {
                    await autoRefreshBalances();
                    await autoRenewTokens();
                }, 600000); // 10分钟
            }, 10000); 
        }
        // 自动续期：静默刷新过期的账号
        async function autoRenewTokens() {
            try {
                const result = await api('renew_all_tokens', { force_all: false });
                if (result.success && result.success_count > 0) {
                    console.log('[自动续期] 已刷新', result.success_count, '个账号');
                    loadAccounts();
                }
            } catch (e) {
                console.log('[自动续期] 执行失败:', e);
            }
        }
        startAutoRefresh();
        
        // 页面关闭时上报离线状态，通知云端接管刷新
        window.addEventListener('beforeunload', async function(e) {
            try {
                await api('report_offline_status');
            } catch (err) {
                console.log('[离线上报] 失败:', err);
            }
        });
        
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
            showToast(t('checkingUpdate'), 'info');
            try {
                const result = await api('check_version');
                if (result.success && result.version) {
                    const v = result.version;
                    const msg = `${currentLang === 'zh' ? '当前版本' : 'Current version'}: ${v.current || '1.0.0'}\\n\\n${currentLang === 'zh' ? '更新日志' : 'Changelog'}:\\n${v.changelog || (currentLang === 'zh' ? '无' : 'None')}`;
                    if (confirm(msg + `\\n\\n${currentLang === 'zh' ? '点击确定下载最新版本' : 'Click OK to download latest version'}`)) {
                        window.open(v.download_url || 'https://github.com/shone2025/shone-factory/releases/latest', '_blank');
                    }
                } else {
                    showToast(result.message || t('checkFailed'), 'error');
                }
            } catch (e) {
                showToast(t('checkFailed') + ': ' + e, 'error');
            }
        }
        
        // 分享有礼功能
        async function openShareModal() {
            document.getElementById('shareModal').classList.add('active');
            loadShareInfo();
        }
        
        function closeShareModal() {
            document.getElementById('shareModal').classList.remove('active');
        }
        
        async function loadShareInfo() {
            const result = await api('get_share_info');
            if (result.success) {
                const count = result.share_count || 0;
                document.getElementById('shareCount').textContent = count;
                document.getElementById('shareLink').value = result.share_link || '';
                
                // 显示星星
                const stars = Math.floor(count / 3);
                let starStr = '';
                for (let i = 0; i < stars; i++) starStr += '⭐';
                if (stars === 0) starStr = '☆☆☆';
                document.getElementById('shareStars').textContent = starStr || '☆☆☆';
                
                // 奖励进度
                const nextReward = 3 - (count % 3);
                let progress = `已获得 ${stars} 个奖励 Key`;
                if (count < 10) {
                    progress += `，再邀请 ${nextReward} 人可获得下一个奖励`;
                } else {
                    progress += ' + 额外奖励已解锁 🎉';
                }
                document.getElementById('rewardProgress').textContent = progress;
            } else {
                showToast(result.message || t('loadShareFailed'), 'error');
            }
        }
        
        async function copyShareLink() {
            const link = document.getElementById('shareLink').value;
            if (link) {
                navigator.clipboard.writeText(link);
                showToast(t('linkCopied'), 'success');
            } else {
                showToast(t('linkEmpty'), 'error');
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
            showLoading(t('switchingBest'), 35000);
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
                list.innerHTML = `<div style="text-align: center; color: var(--accent-green); padding: 20px;">${t('noExhausted')}</div>`;
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
                showToast(t('selectOne'), 'error');
                return;
            }
            if (!confirm(t('deleteConfirm'))) return;
            const result = await api('delete_exhausted', { indices });
            showToast(result.message, result.success ? 'success' : 'error');
            closeExhaustedModal();
            if (result.success) loadAccounts();
        }
        
        // 页面加载时初始化自动切换状态
        loadAutoSwitchStatus();
        
        // v3.2.4: 启动时检查活跃账号Token变化并同步到云端
        async function checkActiveTokenOnStartup() {
            try {
                const result = await api('check_active_startup');
                if (result.synced > 0) {
                    console.log('[启动检查] 已同步', result.synced, '个活跃账号Token到云端');
                }
            } catch (e) {
                console.log('[启动检查] 执行失败:', e);
            }
        }
        checkActiveTokenOnStartup();
        
        // 刷新保护功能
        let refreshProtectEnabled = true;
        let autoRefreshInterval = null;
        
        function toggleRefreshProtect() {
            refreshProtectEnabled = document.getElementById('refreshProtectToggle').checked;
            const statusEl = document.getElementById('refreshProtectStatus');
            
            if (refreshProtectEnabled) {
                statusEl.textContent = t('on');
                statusEl.style.color = 'var(--accent-green)';
                document.getElementById('refreshProtectToggle').nextElementSibling.style.backgroundColor = 'var(--accent-green)';
                startAutoRefresh();
                showToast(t('refreshEnabled'), 'success');
            } else {
                statusEl.textContent = t('off');
                statusEl.style.color = 'var(--accent-red)';
                document.getElementById('refreshProtectToggle').nextElementSibling.style.backgroundColor = 'var(--accent-red)';
                if (autoRefreshTimer) {
                    clearInterval(autoRefreshTimer);
                    autoRefreshTimer = null;
                }
                showToast(t('refreshDisabled'), 'info');
            }
        }
        
        // 工单系统
        let myTickets = [];
        
        function generateTicketNumber() {
            const now = new Date();
            const y = now.getFullYear().toString().slice(-2);
            const m = (now.getMonth() + 1).toString().padStart(2, '0');
            const d = now.getDate().toString().padStart(2, '0');
            const rand = Math.random().toString(36).substring(2, 6).toUpperCase();
            return `TK${y}${m}${d}${rand}`;
        }
        
        function openTicketModal() {
            document.getElementById('ticketNumber').textContent = generateTicketNumber();
            document.getElementById('ticketDesc').value = '';
            document.getElementById('ticketContact').value = '';
            document.getElementById('ticketType').value = 'error';
            showTicketTab('submit');
            document.getElementById('ticketModal').classList.add('active');
        }
        
        function closeTicketModal() {
            document.getElementById('ticketModal').classList.remove('active');
        }
        
        function showTicketTab(tab) {
            if (tab === 'submit') {
                document.getElementById('submitPanel').style.display = 'block';
                document.getElementById('submitBtnRow').style.display = 'flex';
                document.getElementById('myTicketsPanel').style.display = 'none';
                document.getElementById('myTicketsBtnRow').style.display = 'none';
                document.getElementById('tabSubmit').className = 'btn btn-primary';
                document.getElementById('tabMyTickets').className = 'btn btn-secondary';
            } else {
                document.getElementById('submitPanel').style.display = 'none';
                document.getElementById('submitBtnRow').style.display = 'none';
                document.getElementById('myTicketsPanel').style.display = 'block';
                document.getElementById('myTicketsBtnRow').style.display = 'flex';
                document.getElementById('tabSubmit').className = 'btn btn-secondary';
                document.getElementById('tabMyTickets').className = 'btn btn-primary';
                loadMyTickets();
            }
        }
        
        async function submitTicket() {
            const ticketNumber = document.getElementById('ticketNumber').textContent;
            const ticketType = document.getElementById('ticketType').value;
            const ticketDesc = document.getElementById('ticketDesc').value.trim();
            const ticketContact = document.getElementById('ticketContact').value.trim();
            const attachLogs = document.getElementById('attachLogs').checked;
            
            if (!ticketDesc) {
                showToast('请填写问题描述', 'error');
                return;
            }
            
            showLoading('正在提交工单...', 15000);
            
            const result = await api('submit_ticket', {
                ticket_id: ticketNumber,
                type: ticketType,
                description: ticketDesc,
                contact: ticketContact,
                attach_logs: attachLogs
            });
            
            hideLoading();
            
            if (result.success) {
                showToast(`工单 ${ticketNumber} 提交成功！`, 'success');
                closeTicketModal();
            } else {
                showToast(result.message || '提交失败，请稍后重试', 'error');
            }
        }
        
        async function loadMyTickets() {
            const listEl = document.getElementById('ticketList');
            listEl.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 40px;">加载中...</div>';
            
            const result = await api('get_my_tickets');
            
            if (result.success && result.tickets && result.tickets.length > 0) {
                myTickets = result.tickets;
                listEl.innerHTML = myTickets.map(t => {
                    const statusColor = t.status === 'resolved' ? 'var(--accent-green)' : 
                                       t.status === 'processing' ? 'var(--accent-gold)' : 'var(--text-muted)';
                    const statusText = t.status === 'resolved' ? '已解决' : 
                                      t.status === 'processing' ? '处理中' : '待处理';
                    return `<div style="padding: 16px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 12px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                            <span style="color: var(--accent-blue); font-size: 13px;">${t.ticket_id}</span>
                            <span style="color: ${statusColor}; font-size: 12px;">${statusText}</span>
                        </div>
                        <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 6px;">${t.type_text || t.type}</div>
                        <div style="color: var(--text-primary); font-size: 13px; margin-bottom: 8px;">${t.description.substring(0, 100)}${t.description.length > 100 ? '...' : ''}</div>
                        <div style="color: var(--text-muted); font-size: 11px;">${t.created_at}</div>
                        ${t.reply ? `<div style="margin-top: 10px; padding: 10px; background: var(--bg-secondary); border-radius: 6px; color: var(--accent-green); font-size: 12px;">回复: ${t.reply}</div>` : ''}
                    </div>`;
                }).join('');
            } else {
                listEl.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 40px;">暂无工单记录</div>';
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
        try:
            s.send_response(st);s.send_header('Content-Type','application/json; charset=utf-8');s.send_header('Access-Control-Allow-Origin','*');s.end_headers()
            s.wfile.write(json.dumps(d,ensure_ascii=False).encode('utf-8'))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass  # 客户端已断开，静默忽略
    def _0xsh(s,h):
        try:
            s.send_response(200);s.send_header('Content-Type','text/html; charset=utf-8');s.end_headers();s.wfile.write(h.encode('utf-8'))
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass
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
                elif ac=='proxy_inject':r=s._0m._0xS5I(d.get('proxy',''))
                elif ac=='restore_network':r=s._0m._0xRN()
                elif ac=='self_refresh_get_credentials':r=s._0m._0xSRGC(d.get('key_id',''))
                elif ac=='self_refresh_update_account':r=s._0m._0xSRUA(d.get('key_id',''))
                elif ac=='switch_best':r=s._0m._0xsbo()
                elif ac=='get_exhausted':r=s._0m._0xgex()
                elif ac=='delete_exhausted':r=s._0m._0xdex(d.get('indices',[]))
                elif ac=='get_auto_switch':r=s._0m._0xgas()
                elif ac=='set_auto_switch':r=s._0m._0xsas(d.get('enabled',False))
                elif ac=='renew_all_tokens':r=s._0m._0xrat(d.get('force_all',False))
                elif ac=='report_offline_status':r=s._0m._0xROS()
                elif ac=='check_active_startup':r=s._0m._0xCAS()  # v3.2.4: 启动时检查活跃账号Token变化
                elif ac=='ping':r={"success":True,"message":"pong","timestamp":time.time()}
                elif ac=='get_share_info':r=s._0m._0xGSI()
                elif ac=='get_device_id':r={"success":True,"device_id":_generate_device_id()}
                elif ac=='submit_ticket':r=_0xSTK(d)
                elif ac=='get_my_tickets':r=_0xGMT()
                else:r={"success":False,"message":"未知操作"}
                s._0xsj(r)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                pass  # 客户端已断开，静默忽略
            except Exception as e:
                try:
                    s._0xsj({"success":False,"message":str(e)},500)
                except:
                    pass
        else:
            try:
                s.send_response(404);s.end_headers()
            except:
                pass

def _start_heartbeat_thread():
    """启动心跳线程"""
    def heartbeat_worker():
        while True:
            try:
                _send_heartbeat()
            except:
                pass
            time.sleep(300)  # 每5分钟发送一次心跳
    
    thread = threading.Thread(target=heartbeat_worker, daemon=True)
    thread.start()

def _0xM():
    _0xCHK()
    print("="*50)
    print("  ShoneFactory Token Key - Web 版")
    print("="*50)
    print()
    
    # 生成设备ID并注册
    device_id = _generate_device_id()
    print(f"  设备ID: {device_id[:20]}...")
    
    # 注册到云端（异步，不阻塞启动）
    def register_async():
        try:
            result = _register_client()
            if result and result.get('success'):
                print("  ✅ 客户端已注册到云端")
        except:
            pass
    threading.Thread(target=register_async, daemon=True).start()
    
    # 心跳线程已关闭（用于测试）
    # _start_heartbeat_thread()
    
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
