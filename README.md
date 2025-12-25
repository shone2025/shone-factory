# SFK Client v2.3.4

SF-Key 账号池管理客户端

## 功能特性

### 账号管理
- SF-Key 导入与管理
- 账号切换
- 额度查询
- 自动续期

### v2.3.4 更新内容

#### Token 同步优化
- **活跃账号保护**: 正在使用的账号不主动刷新，检测Token变化后同步云端
- **云端接管**: 待使用账号剩余<1小时时由云端接管刷新
- **智能停止**: 使用率>=95%时自动停止续期

#### UI 优化
- 增大字体尺寸，提高可读性
- 优化亮色/暗色模式配色
- 标题显示版本号

## 快速开始

### macOS
```bash
chmod +x mac-start.sh
./mac-start.sh
```
或双击 `Mac factorykey.app`

### Windows
双击 `windows-start.bat`

## 使用说明

1. 启动后浏览器自动打开 `http://localhost:8765`
2. 粘贴 SF-Key 导入账号
3. 点击切换使用不同账号

## 文件说明

| 文件 | 说明 |
|------|------|
| shone_client_web.py | 主程序 |
| sf_codec.py | 编解码模块 |
| token_pool.json | 账号池存储 |
| mac-start.sh | macOS 启动脚本 |
| windows-start.bat | Windows 启动脚本 |

## 系统要求

- Python 3.8+
- 现代浏览器 (Chrome/Firefox/Safari/Edge)

## 许可证

MIT License
