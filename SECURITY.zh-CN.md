# MCP-Bridge — 安全模型

[English](SECURITY.md) | **中文**

> 此文档定义 bridge 暴露的工具必须遵守的安全边界。Phase 2 第一批工具(文件操作 + 系统状态查询)的设计与实现必须以此为依据。

**适用范围:** Phase 2 第一批工具(`read_file` / `write_file` / `list_dir` / `system_status`)。新工具上线前必须先扩展本文档。

---

## 1. 信任模型

- 当前唯一闸门: 单个 Bearer token (StaticTokenVerifier)
- 三个客户端 (VPS Claude / Windows Claude / Antigravity) **共享同一把 token**
- Token 拥有者 = bridge 全部能力的拥有者
- 没有客户端身份区分,bridge 看不到调用方是哪个 AI

**直接后果:** Token 泄漏 = bridge 完全沦陷。所有安全机制只能减小损害面,不能阻止合法 token 持有者滥用。

---

## 2. 威胁模型 (按发生概率排序)

1. **Token 经 git commit 泄漏** — `.env` 不慎进暂存区,push 到 (即使私有的) repo
2. **Token 经截图/分享泄漏** — 用户分享 `.mcp.json` 或终端截图时露出 token
3. **路径穿越攻击** — 调用方传入 `../../etc/passwd` 之类绕开白名单
4. **符号链接逃逸** — 白名单内一个看似无害的 symlink 实际指向外面
5. **AI 间 prompt injection** — A AI 在文件里嵌指令,B AI 读到后被诱导执行非预期操作
6. **意外覆盖关键文件** — 合法范围内,工具被错误参数调用导致数据丢失

---

## 3. 路径白名单

### VPS (Linux)
```
/root/workspace/MCP/
```

### Windows
```
C:\Users\YourUsername\Antigravity\workspace\MCP\     (Antigravity 私有工作区)
C:\Users\YourUsername\Claude code\workspace\MCP\     (Claude Code 私有工作区)
C:\Users\YourUsername\MCP-shared\                       (三端共享工作区,可跨 IDE 协作)
```

**规则:** 任何文件操作的目标路径,**规范化解析后**必须以上述某一条为前缀,否则拒绝。读和写采用同一份白名单 (无读写分级)。

**共享根使用约定(`MCP-shared/`):**
- 任何客户端写入这里的文件,其他客户端 list/read 均可见
- 私有根写入仍只对该客户端可见(物理隔离)
- 跨客户端协作文件(如多方编辑的草稿、跨 AI 唤醒的中转 prompt)**必须**放在 `MCP-shared/`,不要放私有根
- 共享根**仍受黑名单约束**(任何 `.env*` / `.ssh/**` / `*secret*` 等敏感模式同样拒绝),不要把它当成"放松一档"的根
- 共享根不存在时 bridge 启动会自动创建(只创建目录本身,不创建子目录)
- **启动期失败处理(2026-05-21 增):** 若 mkdir 失败(权限/同名文件占位/父目录不存在)或路径已存在但不是目录,bridge **从运行时白名单中摘掉该根**并记 `shared_root_disabled` 警告。这样后续请求直接返回 `outside_whitelist`(语义一致),而不是 `not_found`(语义混淆)。bridge 仍能服务两个私有根

**§6.5 例外:** `invoke_ag_cli` 的 `ask` 子命令会读取 ag 自身的日志 / transcript 文件(路径在本白名单之外)。这是一个**范围受限的专用例外**,只在 `ag_cli.py` 内部生效 —— 通用文件工具(`read_file` / `list_dir` 等)不受影响,仍只认本白名单。详见 §6.5「transcript 读取的路径安全」。

---

## 4. 路径黑名单 (无条件拒绝,即使在白名单子目录内)

匹配以下任意 glob 模式的路径,直接拒绝:

```
**/.ssh/**
**/.env
**/.env.*
**/.git/config
**/credentials*
**/*secret*
**/.aws/**
**/.gnupg/**
**/id_rsa*
**/id_ed25519*
**/id_ecdsa*
**/.npmrc
**/.pypirc
**/cookies.txt
**/*token*
**/*.key
**/*.pem
```

匹配方式: 大小写不敏感 (Windows 是 case-insensitive 文件系统,需对齐)。

**例外机制:** 暂不设。如果未来确有合法需求 (例如部署脚本需读 .env 模板),通过新增专用工具实现,而不是在文件工具上开例外。

---

## 5. 路径规范化与校验流程

每次接到 path 参数,在调用任何 OS 文件 API 之前,**强制按以下顺序执行**:

1. **类型校验:** 参数必须是字符串,不能为空/None
2. **绝对化:** 相对路径直接拒绝 (强制要求绝对路径,避免 cwd 依赖带来的歧义)
3. **规范化:** 解析 `..`、`.`、连续分隔符、混合分隔符 (Windows 上 `/` 和 `\` 都视为分隔符)
4. **真实化 (`realpath` / `Path.resolve()`):** 跟随 symlink 解析到真实位置
5. **白名单前缀检查:** 真实路径必须以白名单某项为前缀 (前缀比较前两边都加尾随分隔符,防止 `/root/workspace/MCP-evil` 这种邻居路径被误纳入)
6. **黑名单模式检查:** 真实路径任一片段不得匹配黑名单
7. 任一步失败 → 立即拒绝,返回 `{"error": "path_denied", "reason": "<具体原因>"}`,**不暴露真实绝对路径或 cwd** 给客户端
8. 拒绝事件必须落 audit log

参考实现 (Python,**仅作示意,非规范**):

```python
def _validate_path(p: str, op: str) -> Path:
    if not isinstance(p, str) or not p.strip():
        raise BridgeError("path_denied", "empty_or_non_string")
    path = Path(p)
    if not path.is_absolute():
        raise BridgeError("path_denied", "relative_path_forbidden")
    resolved = path.resolve(strict=False)  # 即使文件不存在也继续(用于 write_file 创建新文件)
    if not any(_is_within(resolved, root) for root in WHITELIST_ROOTS):
        raise BridgeError("path_denied", "outside_whitelist")
    if any(_matches_glob(resolved, pat) for pat in BLACKLIST_PATTERNS):
        raise BridgeError("path_denied", "matches_blacklist")
    return resolved

def _is_within(path: Path, root: Path) -> bool:
    # 加尾随分隔符防止前缀邻居误判
    return str(path).lower().startswith(str(root).lower().rstrip(os.sep) + os.sep) \
           or str(path).lower() == str(root).lower().rstrip(os.sep)
```

---

## 6. 工具规范

### 6.1 `read_file(path: str) -> dict`

**行为:** 读取文件全部内容为 UTF-8 文本。

**参数:**
- `path` — 绝对路径

**返回:**
- 成功: `{"content": str, "size": int, "encoding": "utf-8"}`
- 失败: `{"error": "<code>", "reason": "<short>"}`

**约束:**
- 文件 size 上限 1 MB,超过拒绝
- 二进制文件 (无法解码为 UTF-8) 拒绝,返回 `error: "binary_file"`
- 走 §5 完整路径校验

**审计:** 记录 path (解析后)、size、success/error code。**不记录文件内容**。

### 6.2 `write_file(path: str, content: str, mode: str = "overwrite") -> dict`

**行为:** 写入 UTF-8 文本到文件。

**参数:**
- `path` — 绝对路径
- `content` — 字符串
- `mode` — `"overwrite"` (默认) | `"append"` | `"create_only"` (文件已存在则失败)

**返回:**
- 成功: `{"bytes_written": int, "path": str}`
- 失败: `{"error": "<code>", "reason": "<short>"}`

**约束:**
- content size 上限 5 MB,超过拒绝
- 自动创建父目录,**但父目录也必须在白名单内**
- 走 §5 完整路径校验
- 二进制内容不支持本工具 (单独的 `write_binary` 工具,如果将来需要,走独立 spec)

**审计:** 记录 path、bytes_written、mode、success/error code。**不记录写入内容。**

### 6.3 `list_dir(path: str) -> dict`

**行为:** 列举目录条目 (非递归)。

**参数:**
- `path` — 绝对路径

**返回:**
- 成功: `{"entries": [{"name": str, "type": "file"|"dir"|"symlink", "size": int, "mtime": int}]}`
- 失败: `{"error": "<code>", "reason": "<short>"}`

**约束:**
- 走 §5 完整路径校验
- symlink 条目: type 字段标 `"symlink"`,**列出但不跟随** (即使目标在白名单内也不展开)
- 隐藏文件 (Linux `.开头` / Windows hidden 属性): 默认显示
- 条目数上限 5000,超过截断并设 `truncated: true` 标志

**审计:** 记录 path、entry_count、是否 truncated。**不记录每条具体 entry 名。**

### 6.4 `system_status() -> dict`

**行为:** 读取 bridge 所在机器的系统状态快照,只读。

**参数:** 无

**返回:**
```json
{
  "hostname": str,
  "platform": str,
  "uptime_seconds": int,
  "cpu_count": int,
  "cpu_percent": float,
  "memory": {"total_mb": int, "used_mb": int, "available_mb": int},
  "disk": [{"mount": str, "total_gb": float, "used_gb": float, "free_gb": float}],
  "process_count": int,
  "bridge_time_utc": str
}
```

**约束:**
- 无 path 参数,跳过 §5
- 不包含具体进程列表 (避免泄漏运行中的敏感程序名)
- 不包含网络接口 IP/MAC

**审计:** 仅记录时间戳。

### 6.5 `invoke_ag_cli(subcommand: str, args: list[str] = []) -> dict`

**性质:** **命令执行类工具**,与 §6.1-6.4 文件工具的安全模型完全不同 — 文件工具靠**路径白名单**,命令工具靠**命令白名单 + 参数白名单**。

**行为:** 在 bridge 进程内 fork 子进程调用 antigravity CLI(`ag`)。`--version` 返回子进程 stdout;`ask` 因 ag 不向管道写输出(见下),改为子进程退出后从 ag 自己的 transcript 文件提取回答。

**参数:**
- `subcommand: str` — 必填,二级命令名(`--version` / `ask`)
- `args: list[str]` — 可选,该子命令的位置参数。**禁止用字符串拼接传整条命令**,必须分开传

**命令白名单 schema:**
```python
PROMPT_SENTINEL = "<PROMPT>"   # 模块常量;argv_template 中此 token 在 build 时替换为 args[0]

ALLOWED_SUBCOMMANDS = {
    "--version": {
        "argv_template": ["--version"],
        "args_schema": {"type": "exact", "args": []},
        "timeout_s": 10,
        "stdout_limit_bytes": 10 * 1024,
    },
    "ask": {
        # 内部 argv: ag --print "<prompt>" --print-timeout 10m --dangerously-skip-permissions --sandbox
        "argv_template": ["--print", PROMPT_SENTINEL, "--print-timeout", "10m",
                          "--dangerously-skip-permissions", "--sandbox"],
        "args_schema": {"type": "single_prompt", "min_bytes": 1, "max_bytes": 16384},
        "timeout_s": 660,                    # Python 侧 hard timeout(比 ag --print-timeout 多 1 min)
        "answer_limit_bytes": 1024 * 1024,   # 1 MB,提取回答的上限
    },
}
```

**stdin 统一 DEVNULL:** 两个子命令都不需要 stdin —— prompt 走 argv。subprocess stdin 一律接 `DEVNULL`。(Phase 2.2.3 的 `stdin_mode` / pipe 模式已废弃:`--print` 模式下 prompt 作为 argv 元素传入即可,`shell=False` + list args 已杜绝注入,无需走 stdin。)

**关键设计:外部 API 与内部 argv 解耦**
- **客户端调用形式:** `invoke_ag_cli("ask", ["What is Rust?"])`
- **bridge 内部 argv 构造:** 遍历该子命令的 `argv_template`,凡等于 `PROMPT_SENTINEL` 的 token 替换为 `args[0]`,其余原样保留,最前面加 `_AG_BINARY`。`PROMPT_SENTINEL` 只与**模板 token** 比较,与用户 prompt 内容无关 —— 即使用户 prompt 恰好是字符串 `<PROMPT>` 也只会被当作普通 argv 元素
- prompt 作为**独立 list 元素**进入 argv —— `shell=False` 下 list args 无 shell 注入面,安全
- `--version` 模板无 `PROMPT_SENTINEL`,args 已被 `args_schema=exact` 约束为空

**为什么 `ask` 用 `--print` + argv + transcript 提取(Phase 2.2.6 重做):**
- ag `--print` 模式跑单次非交互 prompt。Phase 2.2.6 多轮 Windows 实测确认:ag v1.0.0 **不向 subprocess stdout / stderr 管道写任何内容**(检测到管道重定向 → 输出渲染到 Windows 控制台设备 CONOUT$),无法从管道读回答
- 但 ag 把每次调用的完整结构化记录写到 transcript 文件,bridge 在子进程退出后读该文件提取回答(见下「transcript 回答提取」)
- `--dangerously-skip-permissions`:不加则 ag 碰到工具审批会阻塞到超时;对非交互调用**必加**
- `--sandbox`:ag 在沙箱(终端受限)中运行,收敛 `--dangerously-skip-permissions` 放开的爆炸半径。Phase 2.2.6 实测:`--sandbox` 不影响进程退出与 transcript 落盘,沙箱内工具调用(如目录列举)仍正常。沙箱边界由 ag 自身定义,bridge 依赖之但不控制其精确范围

**args_schema 类型(可扩展):**
- `exact` — args 必须严格等于 `args_schema["args"]`(`--version` 用)
- `single_prompt` — args 必须是 `[prompt: str]`,且 `min_bytes ≤ len(prompt.encode("utf-8")) ≤ max_bytes`

**子命令规格:**
- **`--version`** — 元命令,argv `[--version]`,timeout 10s,stdout ≤ 10KB,直接返回 stdout
- **`ask "<prompt>"`** — 向 ag 发起问询
  - 内部 argv 见上
  - prompt UTF-8 编码字节数 ∈ [1, 16384](~16KB,覆盖代码片段 + 长指令)
  - Python 侧 hard timeout 660s(`ask` 在沙箱内一般 6-15s 完成;660s 是失控防线,比 ag 自身 `--print-timeout 10m` 多留 1 min 让 ag 正常收尾、写完 transcript)
  - 回答从 transcript 提取,上限 1 MB
  - prompt 内容**不**做字符过滤(自然语言 + 代码,list args + `shell=False` 已防注入)
  - **ag 的工作目录固定为 `C:\Users\YourUsername\Antigravity`**(ag 自身行为),`ask` 不控制它。`ask` 的契约是"问 ag 一个问题、ag 用它自身上下文回答",不是"让 ag 操作调用方指定的目录"(后者需 `--add-dir`,不在本期范围)

任何其他 subcommand → `command_not_allowed`;args 不符该子命令 args_schema → `args_not_allowed`。

**二进制查找:**
- bridge **启动时**一次性调 `shutil.which("ag")` 拿绝对路径,缓存到模块常量 `_AG_BINARY`
- 找到 → 记 `ag_cli_ensured` 事件,details `{"path": <绝对路径>}`
- 找不到 → 记 `ag_cli_not_found` 警告,`_AG_BINARY = None`,bridge 继续启动
- 调用时若 `_AG_BINARY is None` → 直接返回 `{"error": "ag_cli_unavailable", "reason": "ag binary not found on PATH"}`

**ag 内部目录定位(启动时一次性解析):**
- ag 把日志和会话记录写在用户主目录下的固定位置。bridge 启动时解析并缓存为模块常量:
  - `_AG_LOG_DIR   = Path.home() / ".gemini" / "antigravity-cli" / "log"`
  - `_AG_BRAIN_DIR = Path.home() / ".gemini" / "antigravity-cli" / "brain"`
- 两者均为**固定常量**,**不接受任何客户端输入**
- 纯路径构造,无 I/O,任何平台都可计算。ag 未安装的平台上目录不存在,但 `_AG_BINARY is None` 时 `ask` 已提前返回 `ag_cli_unavailable`,不会走到目录读取

**subprocess 调用约束:**

```python
# 1. 构造 argv —— 占位符替换,永不字符串拼接
argv = [_AG_BINARY]
for tok in spec["argv_template"]:
    argv.append(args[0] if tok == PROMPT_SENTINEL else tok)

# 2. 平台感知的进程组隔离(timeout 时杀整树用)
if _IS_WINDOWS:
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
    preexec_fn = None
else:
    creation_flags = 0
    preexec_fn = os.setsid    # POSIX 新会话组

# 3. Popen —— stdin 一律 DEVNULL
proc = subprocess.Popen(
    argv,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,        # ask 下为空,仍捕获供审计/诊断
    stderr=subprocess.PIPE,
    text=True,
    shell=False,                   # 永远 False
    creationflags=creation_flags,  # Windows
    preexec_fn=preexec_fn,         # POSIX
    # 不设 cwd(继承 bridge 进程当前目录)
)
try:
    stdout, stderr = proc.communicate(timeout=spec["timeout_s"])
except subprocess.TimeoutExpired:
    _kill_process_tree(proc.pid)          # 详见下节
    proc.communicate()                    # 排干残留
    raise  # 上层 catch 转 timeout error
```

**核心约束:**
- **必须 list 形式调用,严禁 `shell=True`**(防 shell injection)
- **stdin 一律 `DEVNULL`**,**严禁**继承父进程 stdin
- **timeout 取自子命令的 `timeout_s`**(`--version` 10s / `ask` 660s)
- **timeout 触发必须杀整个进程树**,详见下节
- `--version` 的 stdout 截断阈值取 `stdout_limit_bytes`(10KB),超过加尾标 `\n[truncated at N bytes]`
- 不设 cwd

**`ask` 串行化(Phase 2.2.6):**
- `ask` 调用必须**串行** —— bridge 用一把模块级锁包住「快照 `_AG_LOG_DIR` → spawn → 等待退出 → 再快照 → 提取」整段
- **原因:** ag 每次调用在 `_AG_LOG_DIR` 新建一个 `cli-<timestamp>.log`。bridge 靠"spawn 前后该目录的新增文件"定位本次调用的 log(再从中取 conversation UUID)。并发调用会产生多个新文件、无法归属;串行化保证每次恰好一个新文件
- `ask` 一次 6-15s,串行对当前协作场景完全可接受
- `--version` 不涉及 transcript,**不**受此锁约束

**进程树清理(Phase 2.2.3 引入,解决 Phase 2.2.2 bridge 崩溃 bug):**

**问题:** Phase 2.2.2 用 `subprocess.run(timeout=...)`,timeout 时 Windows 下 `ag.cmd`(batch wrapper)被 kill 但派生的 `ag.exe`(孙进程)变孤儿,持有 stdout pipe → bridge 后续 pipe 操作崩溃。

**解法:** subprocess 放入独立进程组,timeout 时杀整个组:

```python
def _kill_process_tree(pid: int) -> None:
    """Kill a process and all descendants. Platform-specific."""
    if _IS_WINDOWS:
        # /T = tree (杀所有后代), /F = force
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(pid)],
                capture_output=True, timeout=5, check=False,
            )
        except (subprocess.TimeoutExpired, OSError):
            pass  # best effort
    else:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            time.sleep(0.5)
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass  # process already gone
```

放在 `bridge/process_tree.py`,被 `ag_cli.py` import。进程组 + 树杀确保 `ag.cmd → ag.exe` 父子链每层都被清理,孤儿不存在,pipe 状态干净。

**transcript 回答提取(Phase 2.2.6,`ask` 专用):**

ag 子进程退出后,bridge 从 ag 自己的文件提取回答。**全程在 `ask` 串行锁内**,步骤:

1. **定位本次 log:** 对比 spawn 前 / 退出后 `_AG_LOG_DIR` 下 `cli-*.log` 文件名集合,取新增的那一个。串行化保证恰好一个;新增 0 个或 >1 个 → `ag_output_unavailable`(reason `log_not_found`)
2. **提取 conversation UUID:** 读该 log 文件,正则匹配 `conversation=<uuid>`。UUID 必须匹配 `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`(小写十六进制 + 连字符),否则 → `ag_output_unavailable`(reason `uuid_not_found`)
3. **构造 transcript 路径:** `_AG_BRAIN_DIR / <uuid> / ".system_generated" / "logs" / "transcript.jsonl"`
4. **读取并解析:** transcript.jsonl 为 JSONL。逐行 `json.loads`,收集 `source == "MODEL"` 且 `type == "PLANNER_RESPONSE"` 的行
5. **提取回答:** 取**最后一个 `content` 非空**的 `PLANNER_RESPONSE` 行的 `content`
   - 简单问答:transcript 只有 1 个 `PLANNER_RESPONSE`,即回答
   - 工具调用:transcript 多行(空 `PLANNER_RESPONSE` → 工具结果行如 `LIST_DIRECTORY` → 最终 `PLANNER_RESPONSE`),取最后一个非空 `PLANNER_RESPONSE`;中间步骤不返回
   - transcript 不存在 → `ag_output_unavailable`(reason `transcript_not_found`);无法解析 → reason `transcript_parse_error`;无任何非空 `PLANNER_RESPONSE` → reason `no_planner_response`
6. 回答超过 `answer_limit_bytes`(1 MB)→ 截断,加尾标 `\n[truncated at N bytes]`

**transcript 读取的路径安全(白名单外读取的范围受限例外):**

bridge 读 `cli-*.log` 和 `transcript.jsonl` 时,这两个路径在 §3 白名单**之外**。这是一个**有意的、范围受限的专用例外** —— 不走 §5 的 `_validate_path`,而由 `ag_cli.py` 内部一个专用读取器处理。其安全性由以下约束保证(任一条不满足即拒绝并记审计):

- **基目录是固定常量:** `_AG_LOG_DIR` / `_AG_BRAIN_DIR` 由 `Path.home()` 启动时解析,**不接受任何客户端输入**
- **唯一可变量是 UUID,且经严格正则校验**后才拼入路径 —— UUID 形如 `^[0-9a-f]{8}-...$`,不含 `/`、`\`、`.`,无法构造路径穿越
- **文件名固定或受限模式:** transcript 文件名恒为 `transcript.jsonl`;log 文件匹配 `cli-*.log` 且匹配结果必须是 `_AG_LOG_DIR` 的**直接子项**(不含路径分隔符)
- **拼好路径后 `resolve()` 重检:** 解析后的真实路径必须仍在 `_AG_LOG_DIR` / `_AG_BRAIN_DIR` 之内,逃出即拒绝(纵深防御,对齐 §7 symlink 重检思路)
- **size 上限:** 单个文件读取上限 5 MB,超限拒绝(防超大文件撑爆内存)
- **只读不写:** 该读取器只读 ag 的文件,从不写
- **通用文件工具不受影响:** `read_file` / `list_dir` 等仍只认 §3 白名单,**碰不到** ag 内部目录。本例外仅 `ag_cli.py` 的 `ask` 路径可用

**返回结构:**

`--version` 成功:
```json
{"exit_code": 0, "stdout": "antigravity 1.0.0\n", "stderr": "", "duration_ms": 143, "command": "ag --version"}
```

`ask` 成功:
```json
{"exit_code": 0, "answer": "2 + 2 = 4。", "conversation_id": "568b060d-a3c5-4b2a-8af1-fb75ed53c342", "duration_ms": 8700, "command": "ag ask"}
```

- `answer` —— 从 transcript 提取的纯文本回答
- `conversation_id` —— ag 本次会话 UUID。**为将来多轮续接(`--conversation <id>`)预留** —— 本期不实现多轮,但调用方可保存它
- **`command` 字段策略:** 只返回 `f"ag {subcommand}"`,**永不拼接 args / prompt 内容**(防止 prompt 通过返回值二次暴露)

失败(8 种错误码):
- `ag_cli_unavailable` — `_AG_BINARY` is None
- `command_not_allowed` — subcommand 不在白名单
- `args_not_allowed` — args 不符该子命令模板
- `timeout` — 超过 `timeout_s` 被树杀
- `execution_error` — subprocess 抛 OSError 等
- `invalid_subcommand` — subcommand 非 str 或为空
- `invalid_args` — args 非 list[str]
- `ag_output_unavailable` —(`ask` 专用)进程正常退出但无法提取回答。`reason` 用归一化模板区分子情况:`log_not_found` / `uuid_not_found` / `transcript_not_found` / `transcript_parse_error` / `no_planner_response`

错误返回结构:
```json
{"error": "ag_output_unavailable", "reason": "transcript_not_found"}
```

**审计(关键):**
- `args_summary` 基础字段:`{"subcommand": str, "args_count": int}` — **永远不记录 args 原文**
- `ask` 附加 `"prompt_bytes": int`(UTF-8 字节数,**只记尺寸不记内容**)。args 校验通过后**立即计算并贯穿所有路径**(success / timeout / execution_error / ag_output_unavailable)
- `--version` 成功 details:`{"exit_code": int, "stdout_size": int, "stderr_size": int, "duration_ms": int}` — **不记录 stdout / stderr 原文**
- `ask` 成功 details:`{"exit_code": int, "answer_bytes": int, "conversation_id": str, "duration_ms": int}` — **只记回答尺寸,不记回答正文**;`conversation_id` 是 ag 内部 UUID,非敏感,记入便于事后追溯
- 失败 details:`{"error": str, "reason": str}` — reason 必须是**固定字串或归一化模板**,不暴露二进制绝对路径 / args 原文 / prompt 内容 / 回答内容
- 调用前必须 audit(包括 disallowed 命令 / 参数的拒绝)
- timeout 触发树杀时额外记 `tree_killed` 事件,details `{"pid": int, "killed": true}`

---

**与文件工具的对比:**
| 维度 | 文件工具(§6.1-6.4) | 命令工具(§6.5) |
|---|---|---|
| 边界检查 | 路径白名单 + 路径黑名单 | 命令白名单 + 参数白名单 |
| 执行环境 | bridge 进程内 IO | fork 子进程 |
| 主要风险 | 路径穿越 / symlink 逃逸 | shell injection / 长跑卡死 |
| 关键防御 | _validate_path 7 步 + realpath 重检 | list args + shell=False + stdin DEVNULL + timeout |

> `ask` 的 transcript 提取额外读取 ag 内部目录(白名单外),其范围受限例外见上「transcript 读取的路径安全」。

---

### 6.6 跨 AI 文件总线 (Phase 2.2.4)

**性质:** **协作通信类工具**,基于现有文件系统(§6.1-6.3 复用),三方 AI 通过共享根 `MCP-shared/_bus/` 异步交换结构化消息。**不依赖任何外部 CLI**(规避 Phase 2.2.3 ag CLI 限制),今天就能工作。

**两阶段工作流(私有 draft → 共享 inbox):**

```
[阶段 1 — 私有起草]
VPS Claude:        /root/workspace/MCP/_bus/outbox/<id>.draft.json    (我看得见,别人物理够不到)
Windows Claude:    C:/.../Claude code/.../MCP/_bus/outbox/<id>.draft.json
Antigravity:       C:/.../Antigravity/.../MCP/_bus/outbox/<id>.draft.json

[阶段 2 — 公开投递]
send_message() 工具原子写入:
→ C:/Users/YourUsername/MCP-shared/_bus/inbox/<recipient>/<id>.json
```

**目录结构:**

```
C:/Users/YourUsername/MCP-shared/_bus/
├── inbox/
│   ├── vps-claude/        ← 给我的信件,我轮询此目录
│   ├── windows-claude/    ← 给 VS 的信件,VS 轮询
│   └── antigravity/       ← 给 ag 的信件,ag 轮询
└── archive/               ← mark_read 后移动至此(保留可追溯)
    ├── vps-claude/
    ├── windows-claude/
    └── antigravity/
```

**消息 JSON schema:**

```json
{
  "id": "msg-<uuid12>",
  "from": "vps-claude" | "windows-claude" | "antigravity",
  "to": "vps-claude" | "windows-claude" | "antigravity",
  "ts": "2026-05-22T08:30:00.123Z",
  "subject": "用一句话介绍 Rust",
  "body": "<正文,UTF-8 文本,≤ 64KB>",
  "reply_to": "msg-abc123def456 (可选,引用上一条消息形成对话线索)"
}
```

**字段约束:**
- `id`: 系统生成,格式 `msg-<12 字符 hex>`,客户端不可指定
- `from` / `to`: 必填,必须在 `{"vps-claude", "windows-claude", "antigravity"}` 内
- `ts`: 系统生成 UTC ISO 8601 ms 精度
- `subject`: 可选,≤ 200 chars(UTF-8 字符,非字节)
- `body`: 必填,UTF-8 字节数 ≤ 65536(64KB)
- `reply_to`: 可选,如指定必须是 `msg-<12hex>` 格式(不验证目标消息是否存在)

**身份模型(已知限制):**
- `from` 字段**自报家门**(self-attested),bridge 不做密码学验证
- 三方共享同一 Bearer token,bridge 协议层无法区分来源
- 信任模型:三个 AI 客户端都是你授权的,**协作场景**够用,不防对抗
- 审计日志记录每次 send/read,事后可追责
- **未来增强(backlog):** 给每个 AI 发独立 Bearer token,bridge 按 token → identity 强制映射

**新 MCP 工具(4 个):**

#### `send_message(to: str, body: str, from_: str, subject: str = "", reply_to: str = "") -> dict`

发送一条消息到指定接收者的 inbox。

**行为:**
1. 校验 `from_` 和 `to` 在身份 allowlist 内
2. 校验 body / subject / reply_to 长度和格式
3. 生成 `id = "msg-" + uuid4().hex[:12]`
4. 生成 `ts` = UTC now ISO ms
5. 构造完整 JSON
6. 原子写入: 先写 `MCP-shared/_bus/inbox/<to>/<id>.json.tmp`,再 `os.rename` 到 `<id>.json`
7. audit_log 记录 send 事件(args_summary 含 from/to/subject 长度 + body 字节数,不含 body 内容)
8. 返回 `{"id": str, "ts": str, "path": str}`

**错误码:**
- `invalid_recipient` — `to` 不在 allowlist
- `invalid_sender` — `from_` 不在 allowlist
- `body_too_large` — body UTF-8 字节 > 65536
- `subject_too_long` — subject > 200 chars
- `invalid_reply_to` — reply_to 不符合 `msg-<12hex>` 格式
- `io_error` — 文件写入失败

#### `list_inbox(box: str, limit: int = 50, unread_only: bool = True) -> dict`

列出指定收件箱内消息(预览,不含 body 内容)。

**行为:**
1. 校验 `box` 在 allowlist 内
2. 走 `_validate_path` 校验 `MCP-shared/_bus/inbox/<box>/`
3. `list_dir` 该目录,按 `ts` 降序(最新在前)
4. 每条返回 `{id, from, to, ts, subject}`(**不含 body**,客户端再调 `read_message` 取全文)
5. 截断到 `limit`,超过设 `truncated=true`
6. `unread_only=true` 时只看 `inbox/<box>/`,`false` 时也扫 `archive/<box>/`
7. audit_log 记录 list 事件
8. 返回 `{"messages": [...], "total": int, "truncated": bool}`

#### `read_message(message_id: str, box: str) -> dict`

读取单条消息全文(含 body)。

**行为:**
1. 校验 `box` 在 allowlist,`message_id` 符合 `msg-<12hex>` 格式
2. 先查 `MCP-shared/_bus/inbox/<box>/<id>.json`,不存在再查 `archive/<box>/<id>.json`
3. 走 `_validate_path` + `read_file` 等价逻辑
4. 解析 JSON,返回完整消息对象(含 body)
5. audit_log 记录 read 事件
6. 返回 `{"message": {...}, "location": "inbox" | "archive"}`

**错误码:**
- `invalid_box` / `invalid_message_id`
- `message_not_found`

#### `mark_read(message_id: str, box: str) -> dict`

把消息从 inbox 移到 archive,标记已处理。

**行为:**
1. 校验同上
2. `os.rename` 把 `inbox/<box>/<id>.json` 移到 `archive/<box>/<id>.json`(原子操作)
3. archive 目录不存在时自动 mkdir(父目录受白名单约束)
4. audit_log 记录 mark_read 事件
5. 返回 `{"archived_to": str}`

**错误码:**
- `message_not_found` — inbox 里没这条
- `already_archived` — archive 里已存在
- `io_error`

**路径校验:**
- bus 目录在 `MCP-shared/` 内,自动落在白名单
- 黑名单不会拦截(消息名是 `msg-<hex>.json`,不命中任何敏感模式)
- 所有 bus 操作仍走 `_validate_path` 7 步流程,**复用现有安全机制**,不另起一套

**轮询模型(MVP):**
- 客户端定期调 `list_inbox(box=self)` 检查新消息
- bridge **不推送**(单方向 HTTP,无 SSE/WebSocket 通道)
- 客户端节奏自控:活跃对话 5-10s 一次,空闲 60s+ 一次
- **未来增强 backlog:** SSE/long-poll 端点支持实时推送(独立大 phase)

**消息生命周期:**
- 创建:`send_message` 原子写入 inbox
- 读取:`read_message` 多次安全
- 归档:`mark_read` 移到 archive(保留可追溯)
- 删除:**MVP 不支持**,如需清理用 `write_file` 覆盖或全局者手动清(用 OS 工具)
- TTL:**MVP 不支持**,archive 无限增长(future:加 retention policy)

**审计(继承 §8 规范):**
- 每次 send/read/list/mark_read 都记审计
- args_summary 含 from/to/id/box,**不含 body/subject 原文**(body_bytes 数值可记)
- 失败 reason 必须是固定字串或归一化模板

**与 ag-cli 工具的对比:**
| 维度 | ag-cli (§6.5) | 文件总线 (§6.6) |
|---|---|---|
| 实时性 | 实时(subprocess 同步) | 异步(轮询) |
| 外部依赖 | 强依赖 ag binary | 零外部依赖,只用文件系统 |
| 输出可靠 | 受 ag 限制(v1.0.0 不通) | 完全可控 |
| 三方协作 | 单向(调用方→ag) | **真正多向**(三方都能发收) |
| 复杂消息 | 单 prompt → 单 response | 可结构化(reply_to 线索 / subject 分类) |
| 状态持久化 | 无 | 有(archive) |

---

## 7. 符号链接策略 (对应 Q5 选项 b)

- **`list_dir`:** symlink 仅作为条目展示 (type=symlink),**不跟随、不展开目标**
- **`read_file` / `write_file`:** 在 §5 第 4 步 `realpath` 解析时跟随 symlink,**然后用解析后的真实路径重新跑白名单 + 黑名单检查**。如果解析后的真实路径逃出白名单,拒绝并记录 (这是攻击信号)
- 不允许跨越 symlink 的部分穿越 (例如 `/root/workspace/MCP/link → /etc/`,然后 read `/root/workspace/MCP/link/passwd` —— `realpath` 解析后路径是 `/etc/passwd`,白名单检查必然失败)

---

## 8. 审计日志

**位置:** `<bridge 项目根>/logs/bridge.log` (Windows 端 bridge.py 同级 logs 目录)。**必须加入 .gitignore。**

**格式:** JSON Lines,每行一条事件:

```json
{"ts": "2026-05-20T17:00:00.123Z", "tool": "read_file", "args_summary": {"path": "/root/workspace/MCP/proj-x/notes.md"}, "result": "ok", "details": {"size": 1234}}
{"ts": "2026-05-20T17:00:05.456Z", "tool": "write_file", "args_summary": {"path": "/root/workspace/MCP/proj-x/out.txt", "mode": "overwrite"}, "result": "error", "details": {"error": "path_denied", "reason": "matches_blacklist"}}
```

**记录规则:**
- 每次工具调用 (成功或失败) 都必须记录
- **不记录文件内容**,也不记录可能含敏感信息的 args (例: 未来 Gmail 工具的 query 字符串)
- 路径记录解析后的真实路径 (帮助事后审计)
- 客户端身份: 当前无法区分 (单 token),字段先留空 `"client": null`

**轮转:** 按日轮转 (使用 Python `logging.handlers.TimedRotatingFileHandler`),保留 30 天历史,过期自动删除。

**用途:** 事后审计、异常调用模式检测、token 泄漏后的影响评估。

---

## 9. Token 策略

**当前:**
- 单一 Bearer token,生成时 32 字节随机十六进制
- 静态,无过期时间
- 存放: Windows 端 `.env` (bridge 启动读),客户端 `.mcp.json` 或 `mcp_config.json`
- **绝不入 git** (`.env` 已在 `.gitignore` 中)

**轮转流程 (手动):**
1. 生成新 token (`openssl rand -hex 32`)
2. 改 Windows `.env`,重启 bridge
3. 同步更新三个客户端配置 (VPS Claude `.mcp.json` / Windows Claude `.mcp.json` / Antigravity `mcp_config.json`)
4. 验证: 各端调 echo 通过
5. 旧 token 彻底废弃

**升级计划 (留给未来):**
- 多 token,不同 token 对应不同工具子集 (例: 一个只读 token 只能调 `read_file` / `list_dir` / `system_status`)
- 客户端身份标识 (header 中带 client_id),日志可区分调用源
- 触发条件: 当 bridge 拥有命令执行类工具时必须升级,在此之前可暂缓

---

## 10. 显式延后 (此版本不处理)

- 多 token / 客户端身份区分 (§9 末)
- 速率限制 (per-tool / per-client)
- ~~命令执行类工具~~ — Phase 2.2.0 已加 `invoke_ag_cli`(§6.5);`--version` 与 `ask` 子命令已实现(`ask` 见 Phase 2.2.6),`code` / `search` 等扩展仍留后续
- Gmail / OAuth 工具 (独立 spec)
- `context.md` 跨空间同步模型 (workflow 设计而非安全设计,但会影响"哪个工具该被频繁调用",到时一起讨论)

---

## 11. 实施验收清单

实现 Phase 2 第一批工具时,每个工具上线前必须自检:

- [ ] 走 §5 完整路径校验,**无任何绕过分支**
- [ ] 路径校验失败时不暴露真实 cwd / 绝对路径给客户端
- [ ] 文件 size 上限已实施
- [ ] 二进制文件检测已实施 (read_file)
- [ ] symlink 按 §7 处理
- [ ] 审计日志按 §8 格式落盘
- [ ] 单测覆盖: 白名单内正常路径、白名单外路径、`../` 穿越、symlink 逃逸、黑名单文件、空路径、超大文件
- [ ] `logs/` 已加入 `.gitignore`

