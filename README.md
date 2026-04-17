# V2RayN 自动化更新工具

自动从订阅URL获取节点、测速、去重、更新数据库、重启V2RayN。

## 功能特性

- ✅ 从 SubItem 表读取订阅URL
- ✅ 支持 VMess / Trojan / Shadowsocks / VLESS 协议
- ✅ 增量更新（合并现有节点 + 新节点，自动去重）
- ✅ 并发 TCP 延迟测速
- ✅ 自动选择最快节点并更新配置
- ✅ 备份数据库（可回滚）
- ✅ 完整日志记录
- ✅ 自动关闭/重启 V2RayN

## 目录结构

```
v2rayn_updater/
├── v2rayn_updater.toml   # 配置文件
├── v2rayn_updater.py     # 主程序
├── requirements.txt      # Python 依赖
├── README.md             # 说明文档
├── logs/                 # 日志目录
└── backups/              # 数据库备份目录
```

## 安装依赖

```powershell
pip install -r requirements.txt
```

## 配置

编辑 `v2rayn_updater.toml`:

```toml
# V2RayN 安装目录
v2rayn_path = "D:\\AppBundles\\V2Ray"

# 订阅分组配置（留空则更新所有订阅分组）
target_subscriptions = []

# 测速配置
speed_test = {
    timeout_ms = 5000        # 超时时间(毫秒)
    test_url = "https://www.google.com"  # 测速URL（当前版本使用TCP直连）
    max_concurrency = 10     # 最大并发数
}

# 日志配置
log = {
    retention_days = 30      # 日志保留天数
    print_to_console = true  # 打印到控制台
}

# 自动重启
auto_restart = true
```

## 使用方法

```powershell
python v2rayn_updater.py
```

## 流程说明

1. **读取订阅** - 从 `SubItem` 表获取订阅分组信息
2. **获取节点** - 下载并 Base64 解码订阅内容
3. **解析节点** - 解析 VMess/Trojan/SS/VLESS 协议
4. **合并去重** - 与现有节点合并，按 `address:port:network:path` 去重
5. **测速** - TCP 连接测速，记录延迟
6. **写入数据库** - 新节点 INSERT，现有节点更新 Delay
7. **更新配置** - 将最快节点的 IndexId 写入 `guiNConfig.json`
8. **重启** - 关闭 → 启动 V2RayN

## 日志查看

日志保存在 `logs/update_YYYYMMDD.log`，每次运行追加记录。

## 数据表说明

| 表名 | 说明 |
|------|------|
| `SubItem` | 订阅分组（Id, Remarks, Url） |
| `ProfileItem` | 代理节点（IndexId, Address, Port, ...） |
| `ProfileExItem` | 测速数据（IndexId, Delay, Sort） |

## 附录：ConfigType 对照表

V2RayN 数据库 `ProfileItem.ConfigType` 字段与协议类型的对应关系（实测）：

| ConfigType 值 | 界面显示 |
|:---:|:---:|
| 1 | VMESS |
| 3 | Shadowsocks |
| 5 | VLESS |
| 6 | Trojan |
| 7 | Hysteria2 |
| 11 | Anytls |
