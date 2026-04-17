"""
V2RayN 自动化更新工具
功能：
  1. 从订阅URL获取节点信息
  2. 解析节点并与现有节点合并去重
  3. 连通性测试（支持代理测速）
  4. 更新数据库
  5. 自动选择最快节点
  6. 重启 V2RayN
"""

import os
import sys
import json
import time
import shutil
import sqlite3
import socket
import random
import base64
import urllib.request
import urllib.error
import urllib.parse
import asyncio
import aiohttp
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Tuple
import logging
from logging.handlers import RotatingFileHandler
import psutil
import socks
import subprocess

# 尝试导入 toml
try:
    import toml
except ImportError:
    print("请先安装 toml: pip install toml")
    sys.exit(1)


@dataclass
class NodeInfo:
    """节点信息"""
    address: str = ""
    port: int = 0
    remarks: str = ""
    network: str = "tcp"
    security: str = "auto"
    id: str = ""
    alter_id: int = 0
    flow: str = ""
    stream_security: str = ""
    sni: str = ""
    alpn: str = ""
    path: str = ""
    request_host: str = ""
    header_type: str = "none"
    fingerprint: str = ""
    public_key: str = ""
    short_id: str = ""
    subid: str = ""
    extra: str = ""
    delay: int = -1  # 延迟(ms)
    speed: float = 0.0  # 速度(MB/s)
    config_type: int = 1  # 协议类型: 1=VMess, 3=Shadowsocks, 5=VLESS, 6=Trojan, 11=Anytls


# V2RayN ConfigType 枚举 (根据用户实测对照表)
# ConfigType取值 | 界面显示
# 1 | VMESS
# 3 | Shadowsocks
# 5 | VLESS
# 6 | Trojan
# 11 | Anytls
CONFIG_TYPE_VMESS = 1
CONFIG_TYPE_SHADOWSOCKS = 3
CONFIG_TYPE_VLESS = 5
CONFIG_TYPE_TROJAN = 6
CONFIG_TYPE_HYSTERIA2 = 7
CONFIG_TYPE_ANYTLS = 11


@dataclass
class SpeedTestResult:
    """测速结果"""
    delay: int = -1  # 延迟(ms)
    speed: float = 0.0  # 速度(MB/s)
    success: bool = False


@dataclass
class SubInfo:
    """订阅分组信息"""
    id: str
    remarks: str
    url: str
    enabled: bool


def load_config(config_file: str) -> dict:
    """加载配置文件"""
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"配置文件不存在: {config_file}")
    return toml.load(config_file)


class V2RayNUpdater:
    """V2RayN 自动化更新器"""

    # SOCKS5 代理端口（V2RayN 默认）
    SOCKS5_PORT = 10808

    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.v2rayn_path = self.config["v2rayn_path"]
        self.db_path = os.path.join(self.v2rayn_path, "guiConfigs", "guiNDB.db")
        self.config_path = os.path.join(self.v2rayn_path, "guiConfigs", "guiNConfig.json")
        self.script_dir = os.path.dirname(os.path.abspath(config_path))
        self.log_dir = os.path.join(self.script_dir, "logs")
        self.backup_dir = os.path.join(self.script_dir, "backups")

        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)

        self.logger = self._setup_logger()
        self.speed_test_config = self.config.get("speed_test", {})
        self.target_subs = self.config.get("target_subscriptions", [])

        # 测速配置
        self.speed_mode = self.speed_test_config.get("speed_mode", "tcp")  # proxy/tcp/both/singbox
        self.ping_url = self.speed_test_config.get("ping_url", "https://www.google.com/generate_204")
        self.speed_url = self.speed_test_config.get("speed_url", "https://cachefly.cachefly.net/10mb.test")
        self.timeout = self.speed_test_config.get("timeout", 5)
        self.max_concurrency = self.speed_test_config.get("max_concurrency", 10)
        self.test_bytes = self.speed_test_config.get("test_bytes", 1048576)

        # sing-tools 配置
        self.singtools_path = self.speed_test_config.get("singtools_path", r"C:\GreenSoft\singtools\singtools.exe")
        self.singbox_ping_url = self.speed_test_config.get("singbox_ping_url", "https://www.bt.cn/api/website/test")
        self.singbox_download_url = self.speed_test_config.get("singbox_download_url", "https://www.bt.cn/api/website/test")
        self.singbox_concurrency = self.speed_test_config.get("singbox_concurrency", 4)

    def _setup_logger(self) -> logging.Logger:
        """设置日志"""
        logger = logging.getLogger("V2RayNUpdater")
        logger.setLevel(logging.DEBUG)

        # 避免重复添加 handler
        if logger.handlers:
            return logger

        # 文件日志
        log_file = os.path.join(self.log_dir, f"update_{datetime.now().strftime('%Y%m%d')}.log")
        fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # 控制台日志
        if self.config.get("log", {}).get("print_to_console", True):
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        return logger

    def _close_v2rayn(self):
        """关闭 V2RayN 进程"""
        self.logger.info("正在关闭 V2RayN...")
        killed = False
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info['name'].lower()
                if 'v2rayn' in name or (name.endswith('.exe') and 'v2ray' in name):
                    self.logger.info(f"  终止进程: {proc.info['name']} (PID: {proc.pid})")
                    proc.kill()
                    killed = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if killed:
            time.sleep(1)
        self.logger.info("V2RayN 已关闭")

    def _start_v2rayn(self):
        """启动 V2RayN"""
        if not self.config.get("auto_restart", True):
            self.logger.info("自动重启已禁用，跳过启动")
            return

        exe_path = os.path.join(self.v2rayn_path, "v2rayN.exe")
        if os.path.exists(exe_path):
            self.logger.info(f"启动 V2RayN: {exe_path}")
            os.startfile(exe_path)
        else:
            self.logger.warning(f"V2RayN 可执行文件不存在: {exe_path}")

    def _backup_db(self):
        """备份数据库"""
        if os.path.exists(self.db_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"guiNDB_{timestamp}.db")
            shutil.copy2(self.db_path, backup_path)
            self.logger.info(f"数据库已备份: {backup_path}")

    def _backup_config(self):
        """备份配置文件"""
        if os.path.exists(self.config_path):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(self.backup_dir, f"guiNConfig_{timestamp}.json")
            try:
                shutil.copy2(self.config_path, backup_path)
                self.logger.info(f"配置文件已备份: {backup_path}")
            except Exception as e:
                self.logger.warning(f"配置文件备份失败: {e}")

    def _write_config_safe(self, config: dict):
        """安全写入配置文件（先写临时文件，再重命名）"""
        import tempfile
        temp_path = self.config_path + '.tmp'
        try:
            # 先备份原配置
            self._backup_config()
            
            # 写入临时文件
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            
            # 验证临时文件内容
            with open(temp_path, 'r', encoding='utf-8') as f:
                json.load(f)  # 验证 JSON 有效性
            
            # 重命名替换原文件（原子操作）
            os.replace(temp_path, self.config_path)
            self.logger.debug(f"配置文件已安全写入")
        except Exception as e:
            # 清理临时文件
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise Exception(f"配置文件写入失败: {e}")

    def get_connection(self) -> sqlite3.Connection:
        """获取数据库连接"""
        return sqlite3.connect(self.db_path)

    def get_subscriptions(self) -> List[SubInfo]:
        """从数据库获取订阅分组列表"""
        self.logger.info("读取订阅分组...")
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT Id, Remarks, Url, Enabled FROM SubItem")
        subs = []
        for row in cursor.fetchall():
            subid, remarks, url, enabled = row
            if not url:  # 跳过没有URL的分组（手动添加的）
                continue
            if self.target_subs and remarks not in self.target_subs:
                self.logger.debug(f"  跳过非目标分组: {remarks}")
                continue
            subs.append(SubInfo(id=subid, remarks=remarks, url=url, enabled=bool(enabled)))

        conn.close()
        self.logger.info(f"找到 {len(subs)} 个订阅分组: {[s.remarks for s in subs]}")
        return subs

    def fetch_subscription(self, url: str) -> str:
        """获取订阅内容"""
        self.logger.info(f"获取订阅: {url[:60]}...")
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'V2RayN/5'
            })
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read()
                # 尝试 Base64 解码
                try:
                    return base64.b64decode(content).decode('utf-8')
                except:
                    return content.decode('utf-8')
        except Exception as e:
            self.logger.error(f"  获取订阅失败: {e}")
            return ""

    def parse_nodes(self, content: str, subid: str) -> List[NodeInfo]:
        """解析节点列表"""
        nodes = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue

            try:
                if line.startswith('vmess://'):
                    node = self._parse_vmess(line[8:], subid)
                elif line.startswith('trojan://'):
                    node = self._parse_trojan(line[9:], subid)
                elif line.startswith('ss://'):
                    node = self._parse_ss(line[5:], subid)
                elif line.startswith('vless://'):
                    node = self._parse_vless(line[8:], subid)
                elif line.startswith('anytls://'):
                    node = self._parse_anytls(line[9:], subid)
                else:
                    continue

                if node and node.address and node.port:
                    nodes.append(node)
            except Exception as e:
                self.logger.debug(f"  解析节点失败: {line[:30]}... - {e}")

        return nodes

    def _parse_vmess(self, data: str, subid: str) -> Optional[NodeInfo]:
        """解析 VMess 节点"""
        try:
            try:
                json_str = base64.b64decode(data + '==').decode('utf-8')
            except:
                json_str = data

            config = json.loads(json_str)
            node = NodeInfo(
                address=config.get('add', ''),
                port=int(config.get('port', 0)),
                remarks=config.get('ps', ''),
                network=config.get('net', 'tcp'),
                security=config.get('scy', 'auto'),
                id=config.get('id', ''),
                alter_id=int(config.get('aid', 0)),
                stream_security='tls' if config.get('tls') else '',
                sni=config.get('sni', ''),
                path=config.get('path', ''),
                request_host=config.get('host', ''),
                header_type=config.get('type', 'none'),
                fingerprint=config.get('fp', ''),
                subid=subid,
                config_type=CONFIG_TYPE_VMESS  # 1 = VMess
            )
            return node
        except:
            return None

    def _parse_trojan(self, data: str, subid: str) -> Optional[NodeInfo]:
        """解析 Trojan 节点"""
        try:
            if '@' in data:
                try:
                    decoded = base64.b64decode(data + '==').decode('utf-8')
                    password, rest = decoded.split('@', 1)
                except:
                    password, rest = data.split('@', 1)

                if '#' in rest:
                    rest, remark = rest.rsplit('#', 1)
                else:
                    remark = ''

                parts = rest.rsplit(':', 1)
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

                node = NodeInfo(
                    address=host,
                    port=port,
                    remarks=urllib.parse.unquote(remark),
                    id=password,
                    network='tcp',
                    stream_security='tls',
                    subid=subid,
                    config_type=CONFIG_TYPE_TROJAN  # 6 = Trojan
                )
                return node
        except:
            return None

    def _parse_ss(self, data: str, subid: str) -> Optional[NodeInfo]:
        """解析 Shadowsocks 节点"""
        try:
            try:
                decoded = base64.b64decode(data + '==').decode('utf-8')
            except:
                decoded = data

            if '@' in decoded:
                left, right = decoded.rsplit('@', 1)
                parts = right.rsplit(':', 1)
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

                try:
                    method_encoded = base64.b64decode(left + '==').decode('utf-8')
                    if ':' in method_encoded:
                        method, password = method_encoded.split(':', 1)
                    else:
                        method, password = left, ''
                except:
                    method = 'auto'
                    password = left

                node = NodeInfo(
                    address=host,
                    port=port,
                    remarks='',
                    security=method,
                    id=password,
                    subid=subid,
                    config_type=CONFIG_TYPE_SHADOWSOCKS  # 3 = Shadowsocks
                )
                return node
        except:
            return None

    def _parse_vless(self, data: str, subid: str) -> Optional[NodeInfo]:
        """解析 VLESS 节点"""
        try:
            if '@' in data:
                uuid_part, rest = data.split('@', 1)
                if '#' in rest:
                    rest, remark = rest.rsplit('#', 1)
                else:
                    remark = ''

                parts = rest.split('?')
                host_port = parts[0]
                host = host_port.rsplit(':', 1)[0]
                port = int(host_port.rsplit(':', 1)[1]) if ':' in host_port else 443

                params = {}
                if len(parts) > 1:
                    for param in parts[1].split('&'):
                        if '=' in param:
                            k, v = param.split('=', 1)
                            params[k] = v

                # VLESS Reality 使用 pbk 作为 PublicKey，sid 作为 ShortId
                public_key = params.get('pbk', '') or params.get('pb', '')
                short_id = params.get('sid', '')
                fingerprint = params.get('fp', '')
                # encryption 参数保存到 security 字段（V2RayN 期望值是 "none"）
                encryption = params.get('encryption', 'none')
                # stream_security 来自 security 参数（TLS/REALITY 等）
                stream_security = params.get('security', '')

                node = NodeInfo(
                    address=host,
                    port=port,
                    remarks=urllib.parse.unquote(remark),
                    id=uuid_part,
                    security=encryption,  # 重要：encryption=none 必须保存到 Security 字段
                    network=params.get('type', 'tcp'),
                    flow=params.get('flow', ''),
                    sni=params.get('sni', ''),
                    path=params.get('path', ''),
                    header_type=params.get('headerType', 'none'),
                    stream_security=stream_security,  # TLS/REALITY 等
                    public_key=public_key,  # VLESS Reality PublicKey
                    short_id=short_id,       # VLESS Reality ShortId
                    fingerprint=fingerprint, # VLESS Reality Fingerprint
                    subid=subid,
                    config_type=CONFIG_TYPE_VLESS  # 5 = VLESS
                )
                return node
        except:
            return None

    def _parse_anytls(self, data: str, subid: str) -> Optional[NodeInfo]:
        """解析 AnyTLS 节点"""
        try:
            if '@' in data:
                uuid_part, rest = data.split('@', 1)
                if '#' in rest:
                    rest, remark = rest.rsplit('#', 1)
                else:
                    remark = ''

                parts = rest.split('?')
                host_port = parts[0]
                host = host_port.rsplit(':', 1)[0]
                port = int(host_port.rsplit(':', 1)[1]) if ':' in host_port else 443

                params = {}
                if len(parts) > 1:
                    for param in parts[1].split('&'):
                        if '=' in param:
                            k, v = param.split('=', 1)
                            params[k] = v

                node = NodeInfo(
                    address=host,
                    port=port,
                    remarks=urllib.parse.unquote(remark),
                    id=uuid_part,
                    security=params.get('security', 'tls'),
                    network=params.get('type', 'tcp'),
                    sni=params.get('sni', ''),
                    path=params.get('path', ''),
                    header_type=params.get('headerType', 'none'),
                    stream_security='tls',
                    subid=subid,
                    config_type=CONFIG_TYPE_ANYTLS  # 11 = AnyTLS
                )
                return node
        except:
            return None

    def get_node_key(self, node: NodeInfo) -> str:
        """生成节点唯一标识（使用 address:port:network:path:id 作为 key）"""
        return f"{node.address}:{node.port}:{node.network}:{node.path}:{node.id}"

    def get_existing_nodes(self, conn: sqlite3.Connection, subid: str) -> dict:
        """获取订阅分组中现有的节点"""
        cursor = conn.cursor()
        cursor.execute('''
            SELECT IndexId, Address, Port, Network, Path, Remarks, Id, Security,
                   AlterId, HeaderType, RequestHost, StreamSecurity, Sni, Fingerprint,
                   Flow, Extra
            FROM ProfileItem
            WHERE Subid = ?
        ''', (subid,))

        existing = {}
        for row in cursor.fetchall():
            (index_id, address, port, network, path, remarks, uid, security,
             alter_id, header_type, request_host, stream_security, sni,
             fingerprint, flow, extra) = row

            key = f"{address}:{port}:{network}:{path or ''}:{uid or ''}"
            existing[key] = {
                'index_id': index_id,
                'address': address,
                'port': port,
                'remarks': remarks,
                'delay': -1
            }

        return existing

    def merge_nodes(self, existing: dict, new_nodes: List[NodeInfo]) -> List[Tuple]:
        """合并节点，返回需要插入或更新的节点"""
        result = []
        seen_keys = set()  # 用于去除 new_nodes 中的重复

        for node in new_nodes:
            key = self.get_node_key(node)
            if key in seen_keys:
                continue  # 跳过同批次中的重复节点
            seen_keys.add(key)
            
            if key in existing:
                result.append((existing[key]['index_id'], node, False))
            else:
                result.append((None, node, True))

        return result

    def _tcp_delay_test(self, address: str, port: int) -> int:
        """TCP 连接延迟测试"""
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((address, port))
            sock.close()
            return int((time.time() - start) * 1000)
        except:
            return -1

    def _proxy_delay_test(self, url: str) -> int:
        """通过 SOCKS5 代理测试延迟"""
        try:
            start = time.time()
            proxy_handler = urllib.request.ProxyHandler({
                'socks5': f'127.0.0.1:{self.SOCKS5_PORT}'
            })
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(url, headers={
                'User-Agent': 'V2RayN-Updater/1.0'
            })
            opener.open(req, timeout=self.timeout)
            return int((time.time() - start) * 1000)
        except:
            return -1

    def _get_exit_ip(self, proxy_type: str = None, proxy_addr: str = None, retries: int = 2) -> str:
        """获取出口IP，用于验证代理是否生效
        Args:
            proxy_type: 代理类型 (socks5)
            proxy_addr: 代理地址
            retries: 重试次数，获取失败时自动重试
        Returns:
            出口IP字符串，失败返回None
        """
        for attempt in range(retries):
            try:
                url = "https://api.ip.sb/ip"
                if proxy_type and proxy_addr:
                    proxy_handler = urllib.request.ProxyHandler({
                        proxy_type: proxy_addr
                    })
                    opener = urllib.request.build_opener(proxy_handler)
                else:
                    opener = urllib.request.build_opener()

                req = urllib.request.Request(url, headers={
                    'User-Agent': 'V2RayN-Updater/1.0'
                })
                with opener.open(req, timeout=5) as response:
                    return response.read().decode('utf-8').strip()
            except Exception as e:
                if attempt < retries - 1:
                    time.sleep(0.5)  # 重试前等待500ms
                    continue
                else:
                    return None  # 多次失败后返回None
        return None

    def _proxy_speed_test(self, url: str, test_bytes: int) -> Tuple[int, float]:
        """通过 SOCKS5 代理测试下载速度，返回 (延迟ms, 速度MB/s)"""
        try:
            start = time.time()

            proxy_handler = urllib.request.ProxyHandler({
                'socks5': f'127.0.0.1:{self.SOCKS5_PORT}'
            })
            opener = urllib.request.build_opener(proxy_handler)

            # 设置 Range header 来限制下载量
            req = urllib.request.Request(url, headers={
                'User-Agent': 'V2RayN-Updater/1.0',
                'Range': f'bytes=0-{test_bytes - 1}'
            })

            with opener.open(req, timeout=self.timeout) as response:
                data = response.read(test_bytes)
                elapsed = time.time() - start

            # 计算速度 (MB/s)
            bytes_received = len(data)
            speed_mb = (bytes_received / (1024 * 1024)) / elapsed if elapsed > 0 else 0
            delay_ms = int(elapsed * 1000)

            return delay_ms, speed_mb
        except Exception as e:
            return -1, 0.0

    async def speed_test_node_async(self, node: NodeInfo, semaphore: asyncio.Semaphore) -> SpeedTestResult:
        """异步测试单个节点（带详细日志）"""
        async with semaphore:
            result = SpeedTestResult()
            node_label = f"[{node.remarks}] {node.address}:{node.port}"

            if self.speed_mode == "tcp":
                # 仅 TCP 延迟测试
                result.delay = await asyncio.to_thread(self._tcp_delay_test, node.address, node.port)
                result.success = result.delay > 0
                if result.success:
                    self.logger.info(f"  → {node_label} TCP延迟={result.delay}ms ✓")
                else:
                    self.logger.warning(f"  → {node_label} TCP连接超时 ✗")
                return result

            elif self.speed_mode in ("proxy", "both"):
                # 先用 TCP 快速筛选
                tcp_delay = await asyncio.to_thread(self._tcp_delay_test, node.address, node.port)
                if tcp_delay < 0:
                    result.delay = -1
                    result.success = False
                    self.logger.warning(f"  → {node_label} TCP连接超时 ✗")
                    return result

                if self.speed_mode == "tcp":
                    result.delay = tcp_delay
                    result.success = True
                    self.logger.info(f"  → {node_label} TCP延迟={result.delay}ms ✓")
                    return result

                # proxy 或 both 模式：尝试代理测速
                try:
                    # 切换到目标节点
                    temp_config_path = os.path.join(self.v2rayn_path, "guiConfigs", "guiNConfig.json")
                    if os.path.exists(temp_config_path):
                        with open(temp_config_path, 'r', encoding='utf-8') as f:
                            config = json.load(f)

                        conn = self.get_connection()
                        cursor = conn.cursor()
                        cursor.execute('SELECT IndexId FROM ProfileItem WHERE Address = ? AND Port = ?',
                                     (node.address, node.port))
                        row = cursor.fetchone()
                        conn.close()

                        if row:
                            original_index = config.get('indexId')
                            target_index = row[0]
                            
                            # 如果目标是同一节点，直接测速
                            if original_index == target_index:
                                self.logger.info(f"  → {node_label} (当前已是目标节点)")
                            else:
                                self.logger.info(f"  → {node_label}")
                                self.logger.info(f"    切换节点: IndexId {original_index} → {target_index}")

                            # 获取切换前基准出口IP
                            baseline_ip = await asyncio.to_thread(
                                self._get_exit_ip, 'socks5', f'127.0.0.1:{self.SOCKS5_PORT}'
                            )
                            if baseline_ip:
                                self.logger.info(f"    切换前出口IP: {baseline_ip}")

                            # 切换到目标节点
                            if original_index != target_index:
                                config['indexId'] = target_index
                                self._write_config_safe(config)
                                # 等待节点切换生效（增加到3秒）
                                await asyncio.sleep(3.0)

                            # 获取切换后出口IP（多次获取确保稳定）
                            after_ip = await asyncio.to_thread(
                                self._get_exit_ip, 'socks5', f'127.0.0.1:{self.SOCKS5_PORT}', retries=3
                            )
                            if after_ip:
                                if after_ip != baseline_ip:
                                    self.logger.info(f"    切换后出口IP: {after_ip} (已变更) ✓")
                                else:
                                    self.logger.warning(f"    切换后出口IP: {after_ip} (与切换前相同) ⚠")
                            else:
                                self.logger.warning(f"    无法获取出口IP，代理可能未生效 ⚠")

                            # 代理测速
                            delay, speed = await asyncio.to_thread(
                                self._proxy_speed_test, self.speed_url, self.test_bytes
                            )

                            if delay > 0:
                                result.delay = delay
                                result.speed = speed
                                result.success = True
                                speed_str = f" {speed:.3f}MB/s" if speed > 0 else ""
                                self.logger.info(f"    代理测速成功: 延迟={delay}ms, 速度={speed_str} ✓")
                            else:
                                # 代理测速失败，使用 TCP 延迟
                                result.delay = tcp_delay
                                result.success = True
                                self.logger.warning(f"    代理测速失败(代理无法连接{self.speed_url[:50]}...)，回退到TCP延迟: {tcp_delay}ms ⚠")

                            # 恢复原节点（仅当切换了不同节点时）
                            if original_index != target_index:
                                config['indexId'] = original_index
                                self._write_config_safe(config)

                            return result
                        else:
                            self.logger.warning(f"    节点未在数据库中找到，跳过代理测速 ⚠")
                            result.delay = tcp_delay
                            result.success = True
                            return result
                except Exception as e:
                    self.logger.warning(f"    代理测速异常: {e} ⚠")

                # 回退到 TCP
                result.delay = tcp_delay
                result.success = True
                return result

            return result

    def speed_test_nodes(self, nodes: List[NodeInfo], index_map: dict = None) -> List[Tuple[int, float]]:
        """测速所有节点，返回 [(delay, speed), ...]"""
        if not nodes:
            return []

        # singbox 模式：使用 singtools 测速（不切换 V2RayN 节点）
        if self.speed_mode == "singbox":
            self.logger.info("  使用 singbox 模式测速...")
            return self.speed_test_with_singtools(nodes)

        # proxy 模式需要串行测速（避免配置文件写入冲突）
        if self.speed_mode in ("proxy", "both"):
            concurrency = 1
        else:
            concurrency = self.max_concurrency
        
        self.logger.info(f"  开始测速 (并发: {concurrency})...")
        semaphore = asyncio.Semaphore(concurrency)

        async def test_all():
            tasks = [self.speed_test_node_async(node, semaphore) for node in nodes]
            return await asyncio.gather(*tasks, return_exceptions=True)

        results = asyncio.run(test_all())

        output = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.error(f"  节点 {i+1} 测速异常: {result}")
                output.append((-1, 0.0))
            else:
                output.append((result.delay, result.speed))

        return output

    def generate_snowflake_id(self) -> str:
        """生成雪花ID"""
        timestamp = int(time.time() * 1000)
        random_bits = random.randint(0, 4194303)
        return str((timestamp << 22) | random_bits)

    def save_nodes_to_db(self, conn: sqlite3.Connection, nodes_to_save: List[Tuple], delays: List[Tuple[int, float]]):
        """保存节点到数据库"""
        cursor = conn.cursor()
        sort_value = 5000

        for i, (index_id, node, is_new) in enumerate(nodes_to_save):
            delay, speed = delays[i] if i < len(delays) else (-1, 0.0)

            if is_new:
                index_id = self.generate_snowflake_id()
                cursor.execute('''
                    INSERT INTO ProfileItem (
                        IndexId, ConfigType, ConfigVersion, Address, Port, Id, AlterId,
                        Security, Network, Remarks, HeaderType, RequestHost, Path,
                        StreamSecurity, AllowInsecure, Subid, IsSub, Flow, Sni, Alpn,
                        CoreType, PreSocksPort, Fingerprint, DisplayLog, PublicKey,
                        ShortId, SpiderX, Extra, Ports, Mldsa65Verify, MuxEnabled,
                        Cert, CertSha, EchConfigList, EchForceQuery
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    index_id, node.config_type, 2, node.address, node.port, node.id, node.alter_id,
                    node.security, node.network, node.remarks, node.header_type,
                    node.request_host, node.path, node.stream_security, '', node.subid,
                    1 if node.subid else 0, node.flow, node.sni, node.alpn,
                    0, 0, node.fingerprint, 1, node.public_key, node.short_id,
                    '', '', node.extra, '', '', '', '', '', ''
                ))
                self.logger.debug(f"  新增节点: [{node.config_type}] {node.remarks} ({node.address}:{node.port})")
            else:
                # 更新现有节点的配置信息（包括 PublicKey、Flow 等关键字段）
                cursor.execute('''
                    UPDATE ProfileItem SET
                        ConfigType = ?, Remarks = ?, Id = ?, Security = ?,
                        Network = ?, HeaderType = ?, RequestHost = ?, Path = ?,
                        StreamSecurity = ?, Flow = ?, Sni = ?, Alpn = ?,
                        Fingerprint = ?, PublicKey = ?, ShortId = ?, Extra = ?
                    WHERE IndexId = ?
                ''', (
                    node.config_type, node.remarks, node.id, node.security,
                    node.network, node.header_type, node.request_host, node.path,
                    node.stream_security, node.flow, node.sni, node.alpn,
                    node.fingerprint, node.public_key, node.short_id, node.extra,
                    index_id
                ))
                self.logger.debug(f"  更新节点: [{node.config_type}] {node.remarks} ({node.address}:{node.port})")

            # 更新测速数据到 ProfileExItem
            cursor.execute('''
                INSERT OR REPLACE INTO ProfileExItem (IndexId, Delay, Speed, Sort)
                VALUES (?, ?, ?, ?)
            ''', (index_id, delay if delay > 0 else -1, speed, sort_value - i))

        conn.commit()
        new_count = sum(1 for _, _, is_new in nodes_to_save if is_new)
        self.logger.info(f"已保存 {new_count} 个新节点到数据库")

    def update_config(self, fastest_index_id: str = None):
        """更新 guiNConfig.json"""
        if not os.path.exists(self.config_path):
            self.logger.warning(f"配置文件不存在: {self.config_path}")
            return

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except json.JSONDecodeError as e:
            self.logger.error(f"配置文件格式错误: {e}")
            return

        if fastest_index_id:
            config['indexId'] = fastest_index_id
            try:
                self._write_config_safe(config)
                self.logger.info(f"已更新配置，当前节点 IndexId: {fastest_index_id}")
            except Exception as e:
                self.logger.error(f"更新配置失败: {e}")

    def get_fastest_node(self, conn: sqlite3.Connection, subid: str) -> Tuple:
        """获取最快的节点（只选择 Delay > 0 的节点）"""
        cursor = conn.cursor()
        cursor.execute('''
            SELECT p.IndexId, p.Remarks, e.Delay, e.Speed
            FROM ProfileItem p
            INNER JOIN ProfileExItem e ON p.IndexId = e.IndexId
            WHERE p.Subid = ? AND e.Delay > 0
            ORDER BY e.Delay ASC
            LIMIT 1
        ''', (subid,))

        result = cursor.fetchone()
        if result:
            return result[0], result[1], result[2], result[3]
        return None, None, None, None

    def run(self):
        """执行更新流程"""
        self.logger.info("=" * 50)
        self.logger.info("V2RayN 自动化更新开始")
        mode_names = {"tcp": "TCP延迟", "proxy": "代理测速", "both": "TCP+代理"}
        self.logger.info(f"测速模式: {mode_names.get(self.speed_mode, self.speed_mode)}")
        if self.speed_mode in ("proxy", "both"):
            self.logger.info(f"测速URL: {self.speed_url}")
        self.logger.info("=" * 50)

        try:
            # 1. 关闭 V2RayN
            self._close_v2rayn()
            self._backup_db()

            # 2. 重新启动 V2RayN（用于测速）
            self._start_v2rayn()
            self.logger.info("等待 V2RayN 启动...")
            time.sleep(3)

            # 3. 获取订阅列表
            subs = self.get_subscriptions()
            if not subs:
                self.logger.warning("没有找到订阅分组，退出")
                return

            total_new = 0
            total_existing = 0
            fastest_node = None
            fastest_delay = float('inf')
            fastest_speed = 0.0
            fastest_remarks = ""

            for sub in subs:
                self.logger.info(f"\n{'='*40}")
                self.logger.info(f"处理订阅分组: {sub.remarks}")
                self.logger.info(f"{'='*40}")

                # 4. 获取订阅内容
                content = self.fetch_subscription(sub.url)
                if not content:
                    self.logger.warning(f"  订阅 {sub.remarks} 获取失败，跳过")
                    continue

                # 5. 解析节点
                new_nodes = self.parse_nodes(content, sub.id)
                self.logger.info(f"  从订阅获取 {len(new_nodes)} 个节点")

                if not new_nodes:
                    self.logger.warning(f"  订阅 {sub.remarks} 解析出0个节点，跳过")
                    continue

                # 6. 获取现有节点
                conn = self.get_connection()
                existing = self.get_existing_nodes(conn, sub.id)
                self.logger.info(f"  现有 {len(existing)} 个节点")

                # 7. 合并去重
                merged = self.merge_nodes(existing, new_nodes)
                new_count = sum(1 for _, _, is_new in merged if is_new)
                existing_count = len(merged) - new_count
                self.logger.info(f"  合并后: 新增 {new_count}, 保留 {existing_count}")

                total_new += new_count
                total_existing += existing_count

                # 8. 测速
                nodes_list = [n for _, n, _ in merged]
                results = self.speed_test_nodes(nodes_list)

                # 显示测速结果汇总
                success_count = sum(1 for d, s in results if d > 0)
                failed_count = len(results) - success_count
                self.logger.info(f"  测速汇总: {success_count}/{len(results)} 可用, {failed_count} 失败")

                # 显示前5个节点测速结果
                node_results = list(zip(nodes_list, results))
                node_results.sort(key=lambda x: x[1][0] if x[1][0] > 0 else 999999)
                self.logger.info("  Top 5 延迟节点:")
                for j, (n, (d, s)) in enumerate(node_results[:5]):
                    speed_str = f" {s:.3f}MB/s" if s > 0 else ""
                    if d > 0:
                        self.logger.info(f"    {j+1}. [{n.remarks}] {d}ms{speed_str}")
                    else:
                        self.logger.warning(f"    {j+1}. [{n.remarks}] 超时 ✗")

                # 9. 保存到数据库
                self.save_nodes_to_db(conn, merged, results)

                # 10. 找到最快的节点
                fast_id, fast_remarks, fast_delay, fast_speed = self.get_fastest_node(conn, sub.id)
                if fast_id and fast_delay and fast_delay < fastest_delay:
                    fastest_node = fast_id
                    fastest_delay = fast_delay
                    fastest_speed = fast_speed
                    fastest_remarks = fast_remarks

                conn.close()

            # 11. 更新配置
            if fastest_node:
                self.update_config(fastest_node)

            # 12. 重新启动 V2RayN 使配置生效
            self._close_v2rayn()
            time.sleep(1)
            self._start_v2rayn()

            # 13. 记录日志
            self.logger.info("\n" + "=" * 50)
            self.logger.info("更新完成！")
            self.logger.info(f"新增节点: {total_new}")
            self.logger.info(f"保留节点: {total_existing}")
            if fastest_node and fastest_delay < float('inf'):
                speed_str = f" {fastest_speed:.1f}MB/s" if fastest_speed > 0 else ""
                self.logger.info(f"最快节点: [{fastest_remarks}] 延迟={fastest_delay}ms{speed_str}")
            self.logger.info("=" * 50)

        except Exception as e:
            self.logger.error(f"更新失败: {e}", exc_info=True)

    def node_to_link(self, node: NodeInfo) -> Optional[str]:
        """将节点转换为链接格式"""
        try:
            if node.id and len(node.id) >= 32:  # VMess/VLESS UUID
                # VMess 格式
                vmess = {
                    "v": "2",
                    "ps": node.remarks,
                    "add": node.address,
                    "port": node.port,
                    "id": node.id,
                    "aid": node.alter_id or 0,
                    "scy": node.security or "auto",
                    "net": node.network or "tcp",
                    "type": node.header_type or "none",
                    "host": node.request_host or "",
                    "path": node.path or "",
                    "tls": node.stream_security or ""
                }
                vmess_json = json.dumps(vmess, separators=(',', ':'))
                vmess_b64 = base64.b64encode(vmess_json.encode()).decode()
                return f"vmess://{vmess_b64}"
            elif node.security:  # Shadowsocks
                # SS 格式: ss://base64(method:password)@host:port#remark
                user_pass = f"{node.security}:{node.id}"
                user_pass_b64 = base64.b64encode(user_pass.encode()).decode()
                remark = base64.b64encode(node.remarks.encode()).decode()
                return f"ss://{user_pass_b64}@{node.address}:{node.port}#{remark}"
            else:
                self.logger.debug(f"  无法转换为链接: {node.remarks}")
                return None
        except Exception as e:
            self.logger.debug(f"  转换链接失败: {node.remarks}, {e}")
            return None

    def speed_test_with_singtools(self, nodes: List[NodeInfo]) -> List[Tuple[int, float]]:
        """使用 singtools 进行代理测速（不切换 V2RayN 节点）"""
        if not os.path.exists(self.singtools_path):
            self.logger.error(f"singtools 不存在: {self.singtools_path}")
            self.logger.warning("回退到 TCP 测速模式")
            return [(self._tcp_delay_test(node.address, node.port), 0.0) for node in nodes]

        self.logger.info("使用 singtools 进行代理测速...")

        # 1. 生成节点链接
        links = []
        valid_indices = []
        for i, node in enumerate(nodes):
            link = self.node_to_link(node)
            if link:
                links.append(link)
                valid_indices.append(i)
            else:
                links.append(f"# skip: {node.remarks}")
                valid_indices.append(i)

        # 2. 写入链接文件
        links_path = os.path.join(self.script_dir, "singbox_links.txt")
        meta_path = os.path.join(self.script_dir, "singbox_meta.json")
        converted_path = os.path.join(self.script_dir, "singbox_converted.json")
        output_path = os.path.join(self.script_dir, "singbox_output.json")
        config_path = os.path.join(self.script_dir, "singbox_config.json")

        try:
            with open(links_path, 'w', encoding='utf-8') as f:
                for link in links:
                    f.write(link + '\n')

            # 3. 转换为 sing-box 格式
            self.logger.info("  转换节点格式...")
            result = subprocess.run([
                self.singtools_path, "convert",
                "-i", links_path,
                "-o", converted_path
            ], capture_output=True, text=True, encoding='utf-8')

            if result.returncode != 0:
                self.logger.warning(f"  转换失败: {result.stderr}")
                return [(self._tcp_delay_test(node.address, node.port), 0.0) for node in nodes]

            # 4. 创建测试配置
            test_config = {
                "GroupName": "V2RayN-Updater",
                "SpeedTestMode": "all",
                "PingURL": self.singbox_ping_url,
                "DownloadURL": self.singbox_download_url,
                "Filter": "all",
                "PingMethod": "http",
                "SortMethod": "speed",
                "Concurrency": self.singbox_concurrency,
                "Timeout": self.timeout,
                "BufferSize": 32768,
                "RetryAttempts": 2,
                "RetryDelay": 100,
                "Detect": False,
                "RemoveDup": False,
                "EnableMetrics": True,
                "RemoteIP": True,
                "LogLevel": "warn",
                "LogFile": "speedtest.log",
                "GeoIPDBPath": "GeoLite2-Country.mmdb",
                "DownloadTimeout": 15,
                "DownloadRetries": 2,
                "DownloadBufferSize": 32768
            }

            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(test_config, f, indent=2)

            # 5. 执行测速
            self.logger.info("  开始 singtools 测速...")
            result = subprocess.run([
                self.singtools_path, "test",
                "-i", converted_path,
                "-c", config_path,
                "-o", output_path,
                "-m", meta_path,
                "-e", "warn"
            ], capture_output=True, text=True, encoding='utf-8', timeout=300)

            # 6. 解析测速结果
            results = [(self._tcp_delay_test(node.address, node.port), 0.0) for node in nodes]

            if os.path.exists(meta_path):
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)

                    # 建立 tag -> result 映射
                    tag_results = {}
                    for item in meta:
                        tag = item.get('tag', '')
                        ping = item.get('ping', 0)
                        speed = item.get('speed', 0)
                        tag_results[tag] = (ping, speed)

                    # 更新结果
                    for i, node in enumerate(nodes):
                        tag = node.remarks
                        if tag in tag_results:
                            ping, speed = tag_results[tag]
                            if ping and ping > 0:
                                results[i] = (int(ping), float(speed))
                                self.logger.info(f"    [{node.remarks}] 延迟={ping}ms 速度={speed}MB/s ✓")
                            else:
                                self.logger.warning(f"    [{node.remarks}] 测速失败 ✗")
                        else:
                            self.logger.debug(f"    [{node.remarks}] 未在结果中找到")

                except json.JSONDecodeError as e:
                    self.logger.warning(f"  解析测速结果失败: {e}")

            return results

        except subprocess.TimeoutExpired:
            self.logger.warning("  singtools 测速超时，回退到 TCP 测速")
            return [(self._tcp_delay_test(node.address, node.port), 0.0) for node in nodes]
        except Exception as e:
            self.logger.warning(f"  singtools 测速异常: {e}")
            return [(self._tcp_delay_test(node.address, node.port), 0.0) for node in nodes]
        finally:
            # 清理临时文件
            for path in [links_path, meta_path, converted_path, output_path, config_path]:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except:
                        pass


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "v2rayn_updater.toml")

    if not os.path.exists(config_path):
        print(f"配置文件不存在: {config_path}")
        sys.exit(1)

    updater = V2RayNUpdater(config_path)
    updater.run()


if __name__ == "__main__":
    main()
