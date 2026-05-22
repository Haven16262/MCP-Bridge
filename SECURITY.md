# MCP-Bridge — Security Model

**English** | [中文](SECURITY.zh-CN.md)

> This document defines the security boundaries every tool the bridge exposes must obey. The design and implementation of the Phase 2 first-batch tools (file operations + system status) must follow it.

**Scope:** the Phase 2 first-batch tools (`read_file` / `write_file` / `list_dir` / `system_status`). Any new tool must extend this document before it ships.

---

## 1. Trust model

- The only gate today: a single Bearer token (StaticTokenVerifier)
- The three clients (VPS Claude / Windows Claude / Antigravity) **share one token**
- Whoever holds the token holds every capability of the bridge
- There is no per-client identity — the bridge cannot tell which AI is calling

**Direct consequence:** a leaked token means the bridge is fully compromised. Every security mechanism here can only shrink the blast radius — none of them can stop a legitimate token holder from abusing it.

---

## 2. Threat model (ordered by likelihood)

1. **Token leaked via a git commit** — `.env` slips into the staging area and gets pushed to a (even private) repo
2. **Token leaked via a screenshot / sharing** — the token shows up when the user shares `.mcp.json` or a terminal screenshot
3. **Path traversal** — a caller passes something like `../../etc/passwd` to escape the whitelist
4. **Symlink escape** — a seemingly harmless symlink inside the whitelist actually points outside it
5. **Cross-AI prompt injection** — AI A embeds instructions in a file; AI B reads them and is lured into unintended actions
6. **Accidental overwrite of critical files** — within the legitimate scope, a tool is called with wrong arguments and loses data

---

## 3. Path whitelist

### VPS (Linux)
```
/root/workspace/MCP/
```

### Windows
```
C:\Users\YourUsername\Antigravity\workspace\MCP\     (Antigravity private workspace)
C:\Users\YourUsername\Claude code\workspace\MCP\     (Claude Code private workspace)
C:\Users\YourUsername\MCP-shared\                       (three-way shared workspace, cross-IDE collaboration)
```

**Rule:** the target path of any file operation, **after normalization and resolution**, must be prefixed by one of the entries above, otherwise it is rejected. Reads and writes use the same whitelist (no read/write tiering).

**Shared-root conventions (`MCP-shared/`):**
- A file any client writes here is visible to every other client via list/read
- Writes to a private root remain visible only to that client (physical isolation)
- Cross-client collaboration files (multi-party drafts, relay prompts for cross-AI wake-up) **must** go in `MCP-shared/`, not in a private root
- The shared root **is still subject to the blacklist** (any sensitive pattern such as `.env*` / `.ssh/**` / `*secret*` is still rejected) — do not treat it as a "relaxed" root
- If the shared root does not exist, the bridge creates it at startup (the directory itself only, not subdirectories)
- **Startup-failure handling (added 2026-05-21):** if mkdir fails (permissions / a same-named file in the way / missing parent) or the path exists but is not a directory, the bridge **drops that root from the runtime whitelist** and logs a `shared_root_disabled` warning. Subsequent requests then return `outside_whitelist` (semantically consistent) instead of `not_found` (semantically confusing). The bridge can still serve the two private roots.

**§6.5 exception:** the `ask` subcommand of `invoke_ag_cli` reads ag's own log / transcript files (paths outside this whitelist). This is a **deliberate, scope-limited exception** that takes effect only inside `ag_cli.py` — the general file tools (`read_file` / `list_dir`, etc.) are unaffected and still honor only this whitelist. See §6.5 "Path safety of transcript reading".

---

## 4. Path blacklist (unconditionally rejected, even inside a whitelisted subdirectory)

A path matching any of the following glob patterns is rejected outright:

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

Matching is case-insensitive (Windows is a case-insensitive filesystem; the behavior must align).

**Exception mechanism:** none for now. If a legitimate need ever arises (e.g. a deployment script needs to read a `.env` template), implement it via a new dedicated tool rather than opening an exception on the file tools.

---

## 5. Path normalization and validation flow

Every time a `path` argument is received, **before calling any OS file API**, the following steps are enforced in order:

1. **Type check:** the argument must be a string, non-empty / not None
2. **Absolutize:** relative paths are rejected outright (absolute paths are required, to avoid ambiguity from cwd dependence)
3. **Normalize:** resolve `..`, `.`, consecutive separators, mixed separators (on Windows both `/` and `\` are treated as separators)
4. **Realize (`realpath` / `Path.resolve()`):** follow symlinks down to the real location
5. **Whitelist prefix check:** the real path must be prefixed by one of the whitelist entries (a trailing separator is added to both sides before the prefix comparison, to prevent a neighbor path like `/root/workspace/MCP-evil` from being wrongly accepted)
6. **Blacklist pattern check:** no segment of the real path may match the blacklist
7. On any step failing → reject immediately, return `{"error": "path_denied", "reason": "<specific reason>"}`, **without exposing the real absolute path or cwd** to the client
8. The rejection event must be written to the audit log

Reference implementation (Python, **illustrative only, not normative**):

```python
def _validate_path(p: str, op: str) -> Path:
    if not isinstance(p, str) or not p.strip():
        raise BridgeError("path_denied", "empty_or_non_string")
    path = Path(p)
    if not path.is_absolute():
        raise BridgeError("path_denied", "relative_path_forbidden")
    resolved = path.resolve(strict=False)  # continue even if the file doesn't exist (for write_file creating new files)
    if not any(_is_within(resolved, root) for root in WHITELIST_ROOTS):
        raise BridgeError("path_denied", "outside_whitelist")
    if any(_matches_glob(resolved, pat) for pat in BLACKLIST_PATTERNS):
        raise BridgeError("path_denied", "matches_blacklist")
    return resolved

def _is_within(path: Path, root: Path) -> bool:
    # trailing separator prevents prefix-neighbor false matches
    return str(path).lower().startswith(str(root).lower().rstrip(os.sep) + os.sep) \
           or str(path).lower() == str(root).lower().rstrip(os.sep)
```

---

## 6. Tool specifications

### 6.1 `read_file(path: str) -> dict`

**Behavior:** read the entire file content as UTF-8 text.

**Parameters:**
- `path` — absolute path

**Returns:**
- Success: `{"content": str, "size": int, "encoding": "utf-8"}`
- Failure: `{"error": "<code>", "reason": "<short>"}`

**Constraints:**
- File size cap of 1 MB; larger is rejected
- A binary file (cannot be decoded as UTF-8) is rejected, returning `error: "binary_file"`
- Goes through the full §5 path validation

**Audit:** record the path (resolved), size, and success/error code. **File content is not recorded.**

### 6.2 `write_file(path: str, content: str, mode: str = "overwrite") -> dict`

**Behavior:** write UTF-8 text to a file.

**Parameters:**
- `path` — absolute path
- `content` — string
- `mode` — `"overwrite"` (default) | `"append"` | `"create_only"` (fails if the file already exists)

**Returns:**
- Success: `{"bytes_written": int, "path": str}`
- Failure: `{"error": "<code>", "reason": "<short>"}`

**Constraints:**
- Content size cap of 5 MB; larger is rejected
- Parent directories are created automatically, **but the parent must also be inside the whitelist**
- Goes through the full §5 path validation
- Binary content is not supported by this tool (a separate `write_binary` tool, if ever needed, gets its own spec)

**Audit:** record the path, bytes_written, mode, and success/error code. **Written content is not recorded.**

### 6.3 `list_dir(path: str) -> dict`

**Behavior:** list directory entries (non-recursive).

**Parameters:**
- `path` — absolute path

**Returns:**
- Success: `{"entries": [{"name": str, "type": "file"|"dir"|"symlink", "size": int, "mtime": int}]}`
- Failure: `{"error": "<code>", "reason": "<short>"}`

**Constraints:**
- Goes through the full §5 path validation
- Symlink entries: the `type` field is marked `"symlink"`, and the symlink is **listed but not followed** (not expanded even if the target is inside the whitelist)
- Hidden files (Linux `.`-prefixed / Windows hidden attribute): shown by default
- Entry-count cap of 5000; beyond that the list is truncated and a `truncated: true` flag is set

**Audit:** record the path, entry_count, and whether it was truncated. **Individual entry names are not recorded.**

### 6.4 `system_status() -> dict`

**Behavior:** read a read-only snapshot of the system state of the machine the bridge runs on.

**Parameters:** none

**Returns:**
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

**Constraints:**
- No `path` argument, so §5 is skipped
- Does not include the actual process list (to avoid leaking the names of sensitive running programs)
- Does not include network interface IPs/MACs

**Audit:** only a timestamp is recorded.

### 6.5 `invoke_ag_cli(subcommand: str, args: list[str] = []) -> dict`

**Nature:** a **command-execution tool**, with a security model completely different from the §6.1-6.4 file tools — file tools rely on a **path whitelist**, command tools rely on a **command whitelist + argument whitelist**.

**Behavior:** fork a child process inside the bridge process to invoke the antigravity CLI (`ag`). `--version` returns the child's stdout; `ask` — because ag does not write output to the pipe (see below) — instead extracts the answer from ag's own transcript file after the child exits.

**Parameters:**
- `subcommand: str` — required, the subcommand name (`--version` / `ask`)
- `args: list[str]` — optional, the positional arguments for that subcommand. **String-concatenating a whole command is forbidden**; arguments must be passed separately

**Command whitelist schema:**
```python
PROMPT_SENTINEL = "<PROMPT>"   # module constant; this token in argv_template is replaced with args[0] at build time

ALLOWED_SUBCOMMANDS = {
    "--version": {
        "argv_template": ["--version"],
        "args_schema": {"type": "exact", "args": []},
        "timeout_s": 10,
        "stdout_limit_bytes": 10 * 1024,
    },
    "ask": {
        # internal argv: ag --print "<prompt>" --print-timeout 10m --dangerously-skip-permissions --sandbox
        "argv_template": ["--print", PROMPT_SENTINEL, "--print-timeout", "10m",
                          "--dangerously-skip-permissions", "--sandbox"],
        "args_schema": {"type": "single_prompt", "min_bytes": 1, "max_bytes": 16384},
        "timeout_s": 660,                    # Python-side hard timeout (1 min longer than ag's --print-timeout)
        "answer_limit_bytes": 1024 * 1024,   # 1 MB, cap on the extracted answer
    },
}
```

**stdin is uniformly DEVNULL:** neither subcommand needs stdin — the prompt goes through argv. The subprocess stdin is always wired to `DEVNULL`. (Phase 2.2.3's `stdin_mode` / pipe mode is retired: in `--print` mode the prompt is passed as an argv element, and `shell=False` + list args already eliminate injection, so stdin is unnecessary.)

**Key design: the external API is decoupled from the internal argv**
- **Client call form:** `invoke_ag_cli("ask", ["What is Rust?"])`
- **Internal argv construction in the bridge:** iterate the subcommand's `argv_template`; any token equal to `PROMPT_SENTINEL` is replaced with `args[0]`, the rest are kept verbatim, and `_AG_BINARY` is prepended. `PROMPT_SENTINEL` is compared only against **template tokens**, never against the user's prompt content — even if the user's prompt happens to be the string `<PROMPT>`, it is just treated as an ordinary argv element
- The prompt enters argv as a **standalone list element** — under `shell=False`, list args have no shell-injection surface; safe
- `--version`'s template has no `PROMPT_SENTINEL`, and its args are already constrained to empty by `args_schema=exact`

**Why `ask` uses `--print` + argv + transcript extraction (reworked in Phase 2.2.6):**
- ag's `--print` mode runs a single non-interactive prompt. Phase 2.2.6's repeated Windows testing confirmed: ag v1.0.0 **writes nothing to the subprocess stdout / stderr pipes** (it detects the pipe redirection → renders output to the Windows console device CONOUT$), so the answer cannot be read from the pipe
- But ag writes a full structured record of every call to a transcript file; the bridge reads that file after the child exits and extracts the answer (see "Transcript answer extraction" below)
- `--dangerously-skip-permissions`: without it, ag blocks on tool-approval prompts until timeout; for a non-interactive call it is **mandatory**
- `--sandbox`: ag runs in a sandbox (terminal-restricted), which contains the blast radius opened up by `--dangerously-skip-permissions`. Phase 2.2.6 testing showed `--sandbox` does not affect process exit or transcript flushing, and in-sandbox tool calls (e.g. directory listing) still work. The sandbox boundary is defined by ag itself; the bridge relies on it but does not control its exact scope

**args_schema types (extensible):**
- `exact` — args must strictly equal `args_schema["args"]` (used by `--version`)
- `single_prompt` — args must be `[prompt: str]`, with `min_bytes ≤ len(prompt.encode("utf-8")) ≤ max_bytes`

**Subcommand specs:**
- **`--version`** — a meta command, argv `[--version]`, timeout 10s, stdout ≤ 10KB, returns stdout directly
- **`ask "<prompt>"`** — pose a query to ag
  - internal argv as above
  - the prompt's UTF-8 byte length ∈ [1, 16384] (~16KB, covering code snippets + long instructions)
  - Python-side hard timeout of 660s (`ask` in the sandbox typically finishes in 6-15s; 660s is the runaway backstop, 1 min more than ag's own `--print-timeout 10m` to let ag wind down and finish writing the transcript)
  - the answer is extracted from the transcript, capped at 1 MB
  - the prompt content is **not** character-filtered (natural language + code; list args + `shell=False` already prevent injection)
  - **ag's working directory is fixed at `C:\Users\YourUsername\Antigravity`** (ag's own behavior); `ask` does not control it. The contract of `ask` is "pose a question to ag, and ag answers from its own context", not "make ag operate on a directory the caller specifies" (the latter would need `--add-dir`, out of scope for now)

Any other subcommand → `command_not_allowed`; args not matching the subcommand's args_schema → `args_not_allowed`.

**Binary lookup:**
- At **startup** the bridge calls `shutil.which("ag")` once to get the absolute path, cached in the module constant `_AG_BINARY`
- Found → log an `ag_cli_ensured` event, details `{"path": <absolute path>}`
- Not found → log an `ag_cli_not_found` warning, `_AG_BINARY = None`, the bridge continues to start
- On a call, if `_AG_BINARY is None` → return `{"error": "ag_cli_unavailable", "reason": "ag binary not found on PATH"}` directly

**Locating ag's internal directories (resolved once at startup):**
- ag writes its logs and session records to fixed locations under the user home directory. At startup the bridge resolves and caches them as module constants:
  - `_AG_LOG_DIR   = Path.home() / ".gemini" / "antigravity-cli" / "log"`
  - `_AG_BRAIN_DIR = Path.home() / ".gemini" / "antigravity-cli" / "brain"`
- Both are **fixed constants** and **accept no client input**
- They are pure path construction with no I/O, computable on any platform. On a platform where ag is not installed the directories do not exist, but when `_AG_BINARY is None` `ask` returns `ag_cli_unavailable` early and never reaches the directory read

**Subprocess invocation constraints:**

```python
# 1. build argv — placeholder substitution, never string concatenation
argv = [_AG_BINARY]
for tok in spec["argv_template"]:
    argv.append(args[0] if tok == PROMPT_SENTINEL else tok)

# 2. platform-aware process-group isolation (for killing the whole tree on timeout)
if _IS_WINDOWS:
    creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP
    preexec_fn = None
else:
    creation_flags = 0
    preexec_fn = os.setsid    # POSIX new session group

# 3. Popen — stdin always DEVNULL
proc = subprocess.Popen(
    argv,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE,        # empty for ask, still captured for audit/diagnostics
    stderr=subprocess.PIPE,
    text=True,
    shell=False,                   # always False
    creationflags=creation_flags,  # Windows
    preexec_fn=preexec_fn,         # POSIX
    # no cwd set (inherits the bridge process's cwd)
)
try:
    stdout, stderr = proc.communicate(timeout=spec["timeout_s"])
except subprocess.TimeoutExpired:
    _kill_process_tree(proc.pid)          # see the section below
    proc.communicate()                    # drain residual output
    raise  # caught upstream, converted to a timeout error
```

**Core constraints:**
- **Must be invoked in list form; `shell=True` is strictly forbidden** (prevents shell injection)
- **stdin is always `DEVNULL`**; inheriting the parent process's stdin is **strictly forbidden**
- **The timeout comes from the subcommand's `timeout_s`** (`--version` 10s / `ask` 660s)
- **A timeout must kill the entire process tree** — see the section below
- `--version`'s stdout truncation threshold is `stdout_limit_bytes` (10KB); beyond that a `\n[truncated at N bytes]` marker is appended
- No cwd is set

**`ask` serialization (Phase 2.2.6):**
- `ask` calls must be **serialized** — the bridge wraps the whole "snapshot `_AG_LOG_DIR` → spawn → wait for exit → snapshot again → extract" sequence in a module-level lock
- **Reason:** every ag call creates a new `cli-<timestamp>.log` in `_AG_LOG_DIR`. The bridge locates this call's log by the "new file in that directory before vs. after the spawn" (and reads the conversation UUID from it). Concurrent calls would produce multiple new files with no way to attribute them; serialization guarantees exactly one new file per call
- One `ask` takes 6-15s; serialization is entirely acceptable for the current collaboration scenario
- `--version` does not involve a transcript and is **not** subject to this lock

**Process-tree cleanup (introduced in Phase 2.2.3, fixing the Phase 2.2.2 bridge crash bug):**

**The problem:** Phase 2.2.2 used `subprocess.run(timeout=...)`. On a timeout, on Windows, the `ag.cmd` (a batch wrapper) was killed but the derived `ag.exe` (a grandchild) was orphaned, kept holding the stdout pipe → the bridge's subsequent pipe operations crashed.

**The fix:** put the subprocess in its own process group, and on a timeout kill the whole group:

```python
def _kill_process_tree(pid: int) -> None:
    """Kill a process and all descendants. Platform-specific."""
    if _IS_WINDOWS:
        # /T = tree (kill all descendants), /F = force
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

Lives in `bridge/process_tree.py`, imported by `ag_cli.py`. The process group + tree kill ensures every layer of the `ag.cmd → ag.exe` parent-child chain is cleaned up, no orphans remain, and the pipe state stays clean.

**Transcript answer extraction (Phase 2.2.6, `ask`-specific):**

After the ag child exits, the bridge extracts the answer from ag's own files. **The whole sequence runs inside the `ask` serialization lock.** Steps:

1. **Locate this call's log:** compare the set of `cli-*.log` filenames in `_AG_LOG_DIR` before the spawn vs. after the exit, and take the one new file. Serialization guarantees exactly one; 0 new or >1 new → `ag_output_unavailable` (reason `log_not_found`)
2. **Extract the conversation UUID:** read that log file, regex-match `conversation=<uuid>`. The UUID must match `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$` (lowercase hex + hyphens), otherwise → `ag_output_unavailable` (reason `uuid_not_found`)
3. **Construct the transcript path:** `_AG_BRAIN_DIR / <uuid> / ".system_generated" / "logs" / "transcript.jsonl"`
4. **Read and parse:** transcript.jsonl is JSONL. Parse line by line with `json.loads`, collecting lines where `source == "MODEL"` and `type == "PLANNER_RESPONSE"`
5. **Extract the answer:** take the `content` of the **last `PLANNER_RESPONSE` line whose `content` is non-empty**
   - Simple Q&A: the transcript has only one `PLANNER_RESPONSE`, which is the answer
   - Tool calls: the transcript has multiple lines (an empty `PLANNER_RESPONSE` → a tool-result line such as `LIST_DIRECTORY` → a final `PLANNER_RESPONSE`); take the last non-empty `PLANNER_RESPONSE`; intermediate steps are not returned
   - transcript missing → `ag_output_unavailable` (reason `transcript_not_found`); unparseable → reason `transcript_parse_error`; no non-empty `PLANNER_RESPONSE` at all → reason `no_planner_response`
6. If the answer exceeds `answer_limit_bytes` (1 MB) → truncate and append a `\n[truncated at N bytes]` marker

**Path safety of transcript reading (the scope-limited exception to whitelist-bounded reads):**

When the bridge reads `cli-*.log` and `transcript.jsonl`, those paths are **outside** the §3 whitelist. This is a **deliberate, scope-limited exception** — it does not go through §5's `_validate_path`, but is handled by a dedicated reader inside `ag_cli.py`. Its safety is guaranteed by the following constraints (failing any one of them → reject and audit):

- **The base directories are fixed constants:** `_AG_LOG_DIR` / `_AG_BRAIN_DIR` are resolved from `Path.home()` at startup and **accept no client input**
- **The only variable is the UUID, and it is strictly regex-validated** before being joined into a path — a UUID of the form `^[0-9a-f]{8}-...$` contains no `/`, `\`, or `.`, so no path traversal can be constructed
- **Filenames are fixed or pattern-restricted:** the transcript filename is always `transcript.jsonl`; the log file matches `cli-*.log` and the match result must be a **direct child** of `_AG_LOG_DIR` (no path separators)
- **`resolve()` recheck after joining the path:** the resolved real path must still be inside `_AG_LOG_DIR` / `_AG_BRAIN_DIR`; escaping → reject (defense in depth, aligned with the §7 symlink recheck approach)
- **Size cap:** a single file read is capped at 5 MB; over the cap → reject (prevents an oversized file from blowing up memory)
- **Read-only:** this reader only reads ag's files, never writes
- **The general file tools are unaffected:** `read_file` / `list_dir`, etc. still honor only the §3 whitelist and **cannot touch** ag's internal directories. This exception is available only to the `ask` path of `ag_cli.py`

**Return structures:**

`--version` success:
```json
{"exit_code": 0, "stdout": "antigravity 1.0.0\n", "stderr": "", "duration_ms": 143, "command": "ag --version"}
```

`ask` success:
```json
{"exit_code": 0, "answer": "2 + 2 = 4.", "conversation_id": "568b060d-a3c5-4b2a-8af1-fb75ed53c342", "duration_ms": 8700, "command": "ag ask"}
```

- `answer` — the plain-text answer extracted from the transcript
- `conversation_id` — ag's conversation UUID for this call. **Reserved for future multi-turn continuation (`--conversation <id>`)** — multi-turn is not implemented this round, but the caller can save it
- **`command` field policy:** only `f"ag {subcommand}"` is returned, **never concatenating args / prompt content** (prevents the prompt from being re-exposed through the return value)

Failures (8 error codes):
- `ag_cli_unavailable` — `_AG_BINARY` is None
- `command_not_allowed` — the subcommand is not in the whitelist
- `args_not_allowed` — args do not match the subcommand's template
- `timeout` — exceeded `timeout_s` and was tree-killed
- `execution_error` — the subprocess raised OSError, etc.
- `invalid_subcommand` — the subcommand is not a str or is empty
- `invalid_args` — args is not a list[str]
- `ag_output_unavailable` — (`ask`-specific) the process exited normally but the answer could not be extracted. `reason` uses a normalized template to distinguish the sub-cases: `log_not_found` / `uuid_not_found` / `transcript_not_found` / `transcript_parse_error` / `no_planner_response`

Error return structure:
```json
{"error": "ag_output_unavailable", "reason": "transcript_not_found"}
```

**Auditing (critical):**
- `args_summary` base fields: `{"subcommand": str, "args_count": int}` — **the raw args are never recorded**
- `ask` adds `"prompt_bytes": int` (UTF-8 byte count, **size only, never content**). It is **computed immediately after args validation passes and carried through every path** (success / timeout / execution_error / ag_output_unavailable)
- `--version` success details: `{"exit_code": int, "stdout_size": int, "stderr_size": int, "duration_ms": int}` — **the raw stdout / stderr is not recorded**
- `ask` success details: `{"exit_code": int, "answer_bytes": int, "conversation_id": str, "duration_ms": int}` — **only the answer size is recorded, never the answer text**; `conversation_id` is an internal ag UUID, non-sensitive, recorded for later traceability
- Failure details: `{"error": str, "reason": str}` — the reason must be a **fixed string or a normalized template**, never exposing the binary's absolute path / raw args / prompt content / answer content
- An audit must be written before every call (including rejections of disallowed commands / arguments)
- When a timeout triggers a tree kill, an extra `tree_killed` event is logged, details `{"pid": int, "killed": true}`

---

**Comparison with the file tools:**
| Dimension | File tools (§6.1-6.4) | Command tool (§6.5) |
|---|---|---|
| Boundary check | path whitelist + path blacklist | command whitelist + argument whitelist |
| Execution environment | I/O inside the bridge process | forked child process |
| Main risk | path traversal / symlink escape | shell injection / hanging long-runners |
| Key defense | `_validate_path` 7 steps + realpath recheck | list args + shell=False + stdin DEVNULL + timeout |

> `ask`'s transcript extraction additionally reads ag's internal directories (outside the whitelist); its scope-limited exception is described above under "Path safety of transcript reading".

---

### 6.6 Cross-AI file bus (Phase 2.2.4)

**Nature:** a **collaboration-communication tool**, built on the existing filesystem (reusing §6.1-6.3). The three AIs exchange structured messages asynchronously through the shared root `MCP-shared/_bus/`. It **depends on no external CLI** (sidestepping the Phase 2.2.3 ag CLI limitation) and works today.

**Two-stage workflow (private draft → shared inbox):**

```
[Stage 1 — private drafting]
VPS Claude:        /root/workspace/MCP/_bus/outbox/<id>.draft.json    (visible to me, physically unreachable by others)
Windows Claude:    C:/.../Claude code/.../MCP/_bus/outbox/<id>.draft.json
Antigravity:       C:/.../Antigravity/.../MCP/_bus/outbox/<id>.draft.json

[Stage 2 — public delivery]
the send_message() tool writes atomically:
→ C:/Users/YourUsername/MCP-shared/_bus/inbox/<recipient>/<id>.json
```

**Directory structure:**

```
C:/Users/YourUsername/MCP-shared/_bus/
├── inbox/
│   ├── vps-claude/        ← mail for me; I poll this directory
│   ├── windows-claude/    ← mail for VS; VS polls
│   └── antigravity/       ← mail for ag; ag polls
└── archive/               ← messages moved here after mark_read (kept for traceability)
    ├── vps-claude/
    ├── windows-claude/
    └── antigravity/
```

**Message JSON schema:**

```json
{
  "id": "msg-<uuid12>",
  "from": "vps-claude" | "windows-claude" | "antigravity",
  "to": "vps-claude" | "windows-claude" | "antigravity",
  "ts": "2026-05-22T08:30:00.123Z",
  "subject": "Describe Rust in one sentence",
  "body": "<body, UTF-8 text, ≤ 64KB>",
  "reply_to": "msg-abc123def456 (optional, references a prior message to form a thread)"
}
```

**Field constraints:**
- `id`: system-generated, format `msg-<12-char hex>`, not client-specifiable
- `from` / `to`: required, must be within `{"vps-claude", "windows-claude", "antigravity"}`
- `ts`: system-generated UTC ISO 8601 with ms precision
- `subject`: optional, ≤ 200 chars (UTF-8 characters, not bytes)
- `body`: required, UTF-8 byte count ≤ 65536 (64KB)
- `reply_to`: optional; if given, must be of the form `msg-<12hex>` (the target message's existence is not validated)

**Identity model (a known limitation):**
- The `from` field is **self-attested**; the bridge performs no cryptographic verification
- The three clients share one Bearer token, so the bridge's protocol layer cannot distinguish the source
- Trust model: all three AI clients are ones you authorized — enough for a **collaboration scenario**, not a defense against an adversary
- The audit log records every send/read, so actions can be traced after the fact
- **Future enhancement (backlog):** issue each AI its own Bearer token, with the bridge enforcing a token → identity mapping

**New MCP tools (4):**

#### `send_message(to: str, body: str, from_: str, subject: str = "", reply_to: str = "") -> dict`

Send a message to the specified recipient's inbox.

**Behavior:**
1. Validate that `from_` and `to` are in the identity allowlist
2. Validate the length and format of body / subject / reply_to
3. Generate `id = "msg-" + uuid4().hex[:12]`
4. Generate `ts` = UTC now ISO ms
5. Construct the full JSON
6. Atomic write: write `MCP-shared/_bus/inbox/<to>/<id>.json.tmp` first, then `os.rename` to `<id>.json`
7. audit_log records the send event (args_summary includes from/to/subject length + body byte count, not the body content)
8. Return `{"id": str, "ts": str, "path": str}`

**Error codes:**
- `invalid_recipient` — `to` not in the allowlist
- `invalid_sender` — `from_` not in the allowlist
- `body_too_large` — body UTF-8 bytes > 65536
- `subject_too_long` — subject > 200 chars
- `invalid_reply_to` — reply_to does not match the `msg-<12hex>` format
- `io_error` — the file write failed

#### `list_inbox(box: str, limit: int = 50, unread_only: bool = True) -> dict`

List the messages in the specified inbox (previews, without body content).

**Behavior:**
1. Validate that `box` is in the allowlist
2. Run `_validate_path` on `MCP-shared/_bus/inbox/<box>/`
3. `list_dir` that directory, sorted by `ts` descending (newest first)
4. Each entry returns `{id, from, to, ts, subject}` (**no body**; the client then calls `read_message` for the full text)
5. Truncate to `limit`; beyond it set `truncated=true`
6. With `unread_only=true` only `inbox/<box>/` is scanned; with `false` `archive/<box>/` is scanned too
7. audit_log records the list event
8. Return `{"messages": [...], "total": int, "truncated": bool}`

#### `read_message(message_id: str, box: str) -> dict`

Read the full text of a single message (including body).

**Behavior:**
1. Validate that `box` is in the allowlist and `message_id` matches the `msg-<12hex>` format
2. Look first in `MCP-shared/_bus/inbox/<box>/<id>.json`, then in `archive/<box>/<id>.json` if absent
3. Run logic equivalent to `_validate_path` + `read_file`
4. Parse the JSON and return the full message object (including body)
5. audit_log records the read event
6. Return `{"message": {...}, "location": "inbox" | "archive"}`

**Error codes:**
- `invalid_box` / `invalid_message_id`
- `message_not_found`

#### `mark_read(message_id: str, box: str) -> dict`

Move a message from inbox to archive, marking it handled.

**Behavior:**
1. Validation as above
2. `os.rename` moves `inbox/<box>/<id>.json` to `archive/<box>/<id>.json` (an atomic operation)
3. If the archive directory does not exist, mkdir it automatically (the parent is whitelist-constrained)
4. audit_log records the mark_read event
5. Return `{"archived_to": str}`

**Error codes:**
- `message_not_found` — not in the inbox
- `already_archived` — already exists in archive
- `io_error`

**Path validation:**
- The bus directories live inside `MCP-shared/`, so they fall within the whitelist automatically
- The blacklist will not block them (message names are `msg-<hex>.json`, matching no sensitive pattern)
- Every bus operation still goes through the 7-step `_validate_path` flow — **reusing the existing security mechanism**, not creating a separate one

**Polling model (MVP):**
- The client periodically calls `list_inbox(box=self)` to check for new messages
- The bridge **does not push** (one-directional HTTP, no SSE/WebSocket channel)
- The client controls its own cadence: an active conversation every 5-10s, idle every 60s+
- **Future enhancement backlog:** an SSE/long-poll endpoint for real-time push (a separate large phase)

**Message lifecycle:**
- Creation: `send_message` atomically writes to inbox
- Reading: `read_message` is safe to call repeatedly
- Archiving: `mark_read` moves to archive (kept for traceability)
- Deletion: **not supported in the MVP**; to clean up, overwrite with `write_file` or have the overseer clear manually (with OS tools)
- TTL: **not supported in the MVP**; archive grows unbounded (future: a retention policy)

**Auditing (inherits the §8 spec):**
- Every send/read/list/mark_read is audited
- args_summary includes from/to/id/box, **not the raw body/subject** (the body_bytes number may be recorded)
- The failure reason must be a fixed string or a normalized template

**Comparison with the ag-cli tool:**
| Dimension | ag-cli (§6.5) | File bus (§6.6) |
|---|---|---|
| Latency | real-time (synchronous subprocess) | asynchronous (polling) |
| External dependency | hard dependency on the ag binary | zero external dependency, filesystem only |
| Output reliability | constrained by ag (v1.0.0 doesn't work) | fully controllable |
| Three-way collaboration | one-directional (caller → ag) | **truly multi-directional** (all three can send and receive) |
| Complex messages | single prompt → single response | structurable (reply_to threading / subject categorization) |
| State persistence | none | yes (archive) |

---

## 7. Symlink policy (corresponds to Q5 option b)

- **`list_dir`:** a symlink is shown only as an entry (type=symlink), **not followed, target not expanded**
- **`read_file` / `write_file`:** at §5 step 4, `realpath` resolution follows the symlink, **and then the whitelist + blacklist checks are re-run on the resolved real path**. If the resolved real path escapes the whitelist, reject and log it (this is an attack signal)
- Partial traversal across a symlink is not allowed (e.g. `/root/workspace/MCP/link → /etc/`, then reading `/root/workspace/MCP/link/passwd` — after `realpath` resolution the path is `/etc/passwd`, and the whitelist check necessarily fails)

---

## 8. Audit log

**Location:** `<bridge project root>/logs/bridge.log` (a `logs` directory next to bridge.py on the Windows side). **Must be added to .gitignore.**

**Format:** JSON Lines, one event per line:

```json
{"ts": "2026-05-20T17:00:00.123Z", "tool": "read_file", "args_summary": {"path": "/root/workspace/MCP/proj-x/notes.md"}, "result": "ok", "details": {"size": 1234}}
{"ts": "2026-05-20T17:00:05.456Z", "tool": "write_file", "args_summary": {"path": "/root/workspace/MCP/proj-x/out.txt", "mode": "overwrite"}, "result": "error", "details": {"error": "path_denied", "reason": "matches_blacklist"}}
```

**Recording rules:**
- Every tool call (success or failure) must be recorded
- **File content is not recorded**, nor are args that may contain sensitive information (e.g. the query string of a future Gmail tool)
- Paths are recorded as the resolved real path (helps after-the-fact auditing)
- Client identity: currently indistinguishable (single token); the field is left empty for now, `"client": null`

**Rotation:** rotated daily (using Python's `logging.handlers.TimedRotatingFileHandler`), 30 days of history retained, expired files deleted automatically.

**Purpose:** after-the-fact auditing, anomalous-call-pattern detection, impact assessment after a token leak.

---

## 9. Token policy

**Current:**
- A single Bearer token, generated as 32 random hex bytes
- Static, with no expiry
- Stored in: `.env` on the Windows side (read by the bridge at startup), and the clients' `.mcp.json` or `mcp_config.json`
- **Never goes into git** (`.env` is already in `.gitignore`)

**Rotation procedure (manual):**
1. Generate a new token (`openssl rand -hex 32`)
2. Change the Windows `.env`, restart the bridge
3. Update all three client configs in sync (VPS Claude `.mcp.json` / Windows Claude `.mcp.json` / Antigravity `mcp_config.json`)
4. Verify: each client's echo call passes
5. Fully retire the old token

**Upgrade plan (for the future):**
- Multiple tokens, with different tokens mapping to different tool subsets (e.g. a read-only token that can only call `read_file` / `list_dir` / `system_status`)
- A client identity marker (a client_id in the header), so the log can distinguish the call source
- Trigger condition: a mandatory upgrade once the bridge has command-execution tools; before that it can be deferred

---

## 10. Explicitly deferred (not handled in this version)

- Multiple tokens / per-client identity (end of §9)
- Rate limiting (per-tool / per-client)
- ~~Command-execution tools~~ — Phase 2.2.0 added `invoke_ag_cli` (§6.5); the `--version` and `ask` subcommands are implemented (`ask` see Phase 2.2.6), while extensions like `code` / `search` remain for later
- Gmail / OAuth tools (a separate spec)
- The cross-space sync model for `context.md` (a workflow design rather than a security design, but it affects "which tool should be called frequently"; to be discussed together when the time comes)

---

## 11. Implementation acceptance checklist

When implementing the Phase 2 first-batch tools, before each tool ships it must self-check:

- [ ] Goes through the full §5 path validation, **with no bypass branch whatsoever**
- [ ] On a path-validation failure, does not expose the real cwd / absolute path to the client
- [ ] The file size cap is implemented
- [ ] Binary-file detection is implemented (read_file)
- [ ] Symlinks are handled per §7
- [ ] The audit log is written in the §8 format
- [ ] Unit tests cover: a normal in-whitelist path, an out-of-whitelist path, `../` traversal, symlink escape, a blacklisted file, an empty path, an oversized file
- [ ] `logs/` is added to `.gitignore`
