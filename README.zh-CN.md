# MCP-Bridge

[English](README.md) | **中文**

> 一个本地 MCP Server，把分布在不同机器、不同网络的三个 AI 客户端接入**同一套工具集**——让它们共享文件、交换消息、互相调用，形成一个协作网络。

`Python 3.12` · `FastMCP` · `164 passed + 3 skipped`

---

## 这是什么

三个 AI 客户端各自为政：

- **VPS Claude** —— Linux 云服务器上的 Claude Code
- **Windows Claude Code** —— Windows 本地的 Claude Code
- **Antigravity** —— Windows 本地的 Antigravity IDE

它们看不到彼此的工作、传不了任务、共享不了上下文。

**MCP-Bridge** 是一个本地 MCP Server（称为 *bridge*），把三方接进同一套工具集。三个 AI 不再各干各的，而是能共享工作成果、互相传递任务——形成一个真正的协作网络。

---

## 架构

```
   VPS (Linux 云服务器)
   ┌──────────────────┐
   │   VPS Claude     │──── HTTPS ────┐
   └──────────────────┘               │
                                       ▼
                          Cloudflare 全球网络
                          bridge.example.com
                          (tunnel)
                                       │
   Windows 本地主机                     ▼
   ┌────────────────────────────────────────────┐
   │  cloudflared ──→ localhost:18800            │
   │                       │                     │
   │              ┌────────▼─────────┐           │
   │              │  Bridge          │           │
   │              │  (FastMCP)       │           │
   │              └────────△─────────┘           │
   │                       │                     │
   │  Windows Claude ───────┤ (localhost 直连)    │
   │                       │                     │
   │  Antigravity ──mcp-proxy┘ (stdio→HTTP 适配)  │
   └────────────────────────────────────────────┘
```

| 决策 | 选择 | 理由 |
|---|---|---|
| Bridge 部署 | 本地 | 工具大多操作本地资源，必须在本地执行 |
| 传输 | HTTP Streamable | 多客户端共享同一 server 实例，状态可共享 |
| 远程接入 | Cloudflare Tunnel | 远程客户端无法直连本地，经隧道接入 |
| 鉴权 | Bearer token | 简单可靠，适合受信任客户端集合 |
| Antigravity 接入 | `sparfenyuk/mcp-proxy` 适配器 | Antigravity 的 MCP 客户端只支持 stdio，由 mcp-proxy 桥接到 HTTP |

---

## 三层跨 AI 协作

| 层 | 机制 | 状态 |
|---|---|---|
| **文件共享** | 三方读写同一共享目录 | ✓ |
| **异步消息** | 结构化 inbox/archive 消息总线，带 reply_to 对话线索 | ✓ |
| **程序化调用** | 一个 AI 通过 bridge 程序化拉起另一个 AI 的 CLI、同步拿回干净结果 | ✓ |

---

## 工具集（10 个）

| # | 工具 | 功能 |
|---|---|---|
| 1 | `echo` | 连通性测试 |
| 2 | `system_status` | CPU/内存/磁盘（刻意排除进程列表、网络接口 IP/MAC）|
| 3 | `read_file` | 读文件，1MB 上限 + UTF-8 检测（拒二进制）|
| 4 | `write_file` | 写文件，5MB 上限 + 3 模式 + TOCTOU 防御 + 父目录自动创建 |
| 5 | `list_dir` | 列目录，5000 条上限 + symlink 仅展示不跟随 |
| 6 | `invoke_ag_cli` | 程序化调用 Antigravity CLI（`--version` / `ask`）|
| 7 | `send_message` | 发结构化消息到接收方 inbox（原子写）|
| 8 | `list_inbox` | 列收件箱消息预览 |
| 9 | `read_message` | 读消息全文 |
| 10 | `mark_read` | 消息从 inbox 归档到 archive |

---

## 安全模型

多数 MCP demo 没有安全模型——要么完全开放文件系统，要么靠客户端自律。本项目是**生产级安全设计**，完整规范见 [`SECURITY.md`](SECURITY.md)。

**路径安全（文件工具）**
- `_validate_path` 七步校验，所有文件工具的单一入口，零绕过
- 路径白名单 + 黑名单（16 条 glob，大小写不敏感）
- 自写回溯算法实现 glob `**` **真递归**——Python `pathlib.match()` 把 `**` 当单段不递归，曾是一个 CRITICAL 绕过漏洞（攻击者把文件放 `.ssh/sub/key` 即可绕过），由 critic 复审发现并修复
- symlink resolve 后用真实路径**重新跑**白名单校验；`write_file` 写入后 `resolve()` 重检的 TOCTOU 深度防御

**命令执行安全（CLI 工具）**
- 命令白名单 + 参数白名单（外部 API 与内部 argv 解耦）
- subprocess 硬约束：list args / `shell=False` / stdin 受控 / 按子命令 timeout
- 进程组隔离 + 进程树清理（timeout 时杀整棵进程树，杜绝孤儿进程）

**审计日志**
- JSON Lines，按日轮转，每次调用必审计（含被拒绝的攻击尝试）
- 反泄漏策略：不记文件内容、不记 prompt 原文、不暴露绝对路径

---

## 项目是怎么建的

这个项目本身就是一次多 AI 协作的成果——而它要解决的，恰恰就是多 AI 协作。

**核心开发**走双模型工作流：一个"全局者"写 spec、设计架构、做 critic 复审、决定 commit；一个"工作者"严格按 spec 实现代码与测试，两者通过结构化文档协议交接。这套机制经得起检验——critic 二审累计抓出 **1 CRITICAL + 3 HIGH** 及多个 MEDIUM/LOW；中途真翻过一次车（凭空设计了一个不存在的 CLI 子命令），靠机制复盘并复原。

**Windows 端的集成测试、跨平台验证、以及对 Antigravity CLI 行为的研究**，由本地的 Windows Claude 和 Antigravity 各自分担——它们正是 bridge 所连接的三方中的两方。换句话说：一个多 AI 协作的工具，本身就是多 AI 协作建起来的。

> 双模型工作流的完整方法论 → **[dual-model-workflow](https://github.com/Haven16262/dual-model-workflow)**

---

## 运行

```bash
git clone https://github.com/Haven16262/MCP-Bridge.git
cd MCP-Bridge

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # 填入 BRIDGE_API_KEY（openssl rand -hex 32）

python bridge.py
```

> **配置提醒：** `bridge/validators.py` 的 Windows 白名单路径含占位符 `YourUsername`，
> 需改成你自己的用户名（或改成你的实际工作目录）。白名单决定文件工具能访问哪些目录。

---

## 测试

```bash
python -m pytest tests/            # 164 passed + 3 skipped
```

> 测试需要 `.env` 已配置(`bridge` 在 import 时校验 `BRIDGE_API_KEY`)。只想跑测试可临时设环境变量:`BRIDGE_API_KEY=test python -m pytest tests/`

- 单元测试覆盖路径校验、symlink、命令白名单、transcript 提取、消息总线
- 涉及外部进程/平台的工具另有集成测试（按平台自动 skip）
- 测试套件在 Linux 和 Windows 双平台无失败

---

## 项目状态

核心三层协作（文件共享 / 异步消息 / 程序化调用）已全部打通并验证。

**已知限制：**
- `invoke_ag_cli("ask")` 拉起的是全新无上下文 AI 实例，非"对话进行中的那个 AI"
- 消息总线为轮询模型，无实时推送
- 身份为自报家门（三方共享同一 Bearer token），不防对抗场景
- 归档消息无自动 TTL 清理

---

## 文档

- [`SECURITY.md`](SECURITY.md) —— 安全规范：白名单/黑名单、路径校验流程、各工具 spec、审计策略

---

*MCP-Bridge 是一个个人工程项目。*
