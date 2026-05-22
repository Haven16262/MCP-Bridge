# MCP-Bridge

**English** | [中文](README.zh-CN.md)

> A local MCP server that wires three AI clients — spread across different machines and networks — into **one shared toolset**, letting them share files, exchange messages, and invoke one another. A real collaboration network.

`Python 3.12` · `FastMCP` · `164 passed + 3 skipped`

---

## What it is

Three AI clients, each on its own island:

- **VPS Claude** —— Claude Code on a Linux cloud server
- **Windows Claude Code** —— Claude Code on a local Windows machine
- **Antigravity** —— the Antigravity IDE on the same Windows machine

They can't see each other's work, can't hand off tasks, can't share context.

**MCP-Bridge** is a local MCP server (the *bridge*) that connects all three to one shared toolset. The three AIs stop working in isolation — they share results and pass tasks to one another, forming a real collaboration network.

---

## Architecture

```
   VPS (Linux cloud server)
   ┌──────────────────┐
   │   VPS Claude     │──── HTTPS ────┐
   └──────────────────┘               │
                                       ▼
                          Cloudflare global network
                          bridge.example.com
                          (tunnel)
                                       │
   Windows local host                  ▼
   ┌────────────────────────────────────────────┐
   │  cloudflared ──→ localhost:18800            │
   │                       │                     │
   │              ┌────────▼─────────┐           │
   │              │  Bridge          │           │
   │              │  (FastMCP)       │           │
   │              └────────△─────────┘           │
   │                       │                     │
   │  Windows Claude ───────┤ (direct localhost)  │
   │                       │                     │
   │  Antigravity ──mcp-proxy┘ (stdio→HTTP)       │
   └────────────────────────────────────────────┘
```

| Decision | Choice | Why |
|---|---|---|
| Bridge deployment | Local | Most tools operate on local resources, so they must run locally |
| Transport | HTTP Streamable | Multiple clients share one server instance with shared state |
| Remote access | Cloudflare Tunnel | Remote clients can't reach the local host directly; they connect through a tunnel |
| Auth | Bearer token | Simple and reliable; fits a set of trusted clients |
| Antigravity integration | `sparfenyuk/mcp-proxy` adapter | Antigravity's MCP client only supports stdio; mcp-proxy bridges it to HTTP |

---

## Three layers of cross-AI collaboration

| Layer | Mechanism | Status |
|---|---|---|
| **File sharing** | All three read and write a shared directory | ✓ |
| **Async messaging** | A structured inbox/archive message bus with `reply_to` threading | ✓ |
| **Programmatic invocation** | One AI programmatically launches another AI's CLI through the bridge and gets a clean result back synchronously | ✓ |

---

## Toolset (10 tools)

| # | Tool | Function |
|---|---|---|
| 1 | `echo` | Connectivity test |
| 2 | `system_status` | CPU / memory / disk (deliberately excludes the process list and network interface IPs/MACs) |
| 3 | `read_file` | Read a file — 1MB cap + UTF-8 detection (rejects binary) |
| 4 | `write_file` | Write a file — 5MB cap + 3 modes + TOCTOU defense + auto parent-dir creation |
| 5 | `list_dir` | List a directory — 5000-entry cap + symlinks shown but not followed |
| 6 | `invoke_ag_cli` | Programmatically invoke the Antigravity CLI (`--version` / `ask`) |
| 7 | `send_message` | Send a structured message to a recipient's inbox (atomic write) |
| 8 | `list_inbox` | List inbox message previews |
| 9 | `read_message` | Read a full message |
| 10 | `mark_read` | Archive a message from inbox to archive |

---

## Security model

Most MCP demos have no security model — they either expose the whole filesystem or rely on client goodwill. This project is a **production-grade security design**; the full spec is in [`SECURITY.md`](SECURITY.md).

**Path security (file tools)**
- `_validate_path` — a 7-step check, the single entry point for every file tool, with zero bypass
- Path whitelist + blacklist (16 globs, case-insensitive)
- A hand-written backtracking algorithm gives glob `**` **true recursion** — Python's `pathlib.match()` treats `**` as a single, non-recursive segment, which was a CRITICAL bypass (an attacker could evade the blacklist by placing a file at `.ssh/sub/key`); found and fixed in critic review
- After a symlink is resolved, the whitelist check is **re-run** on the real path; `write_file` re-resolves after writing as a TOCTOU defense

**Command-execution security (CLI tools)**
- Command whitelist + argument whitelist (the external API is decoupled from the internal argv)
- Subprocess hard constraints: list args / `shell=False` / controlled stdin / per-subcommand timeout
- Process-group isolation + process-tree cleanup (on timeout, the entire process tree is killed — no orphans)

**Audit log**
- JSON Lines, rotated daily; every call is audited (including rejected attack attempts)
- Anti-leak policy: no file contents, no raw prompts, no absolute paths

---

## How it was built

This project is itself a product of multi-AI collaboration — and multi-AI collaboration is exactly the problem it solves.

**Core development** ran on a dual-model workflow:VPS side： an "overseer" wrote specs, designed the architecture, ran critic reviews, and decided when to commit; a "worker" implemented code and tests strictly to spec. The two handed off through a structured document protocol. The mechanism holds up under scrutiny — critic reviews caught **1 CRITICAL + 3 HIGH** plus several MEDIUM/LOW issues; the project once went off the rails (a CLI subcommand was designed that didn't actually exist) and recovered through the process.

**Windows-side integration testing, cross-platform verification, and research into the Antigravity CLI's behavior** were handled by the local Windows Claude and Antigravity themselves — two of the three clients the bridge connects. In other words: a multi-AI collaboration tool, built by multi-AI collaboration.

> The full methodology of the dual-model workflow → **[dual-model-workflow](https://github.com/Haven16262/dual-model-workflow)**

---

## Running it

```bash
git clone https://github.com/Haven16262/MCP-Bridge.git
cd MCP-Bridge

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # set BRIDGE_API_KEY (openssl rand -hex 32)

python bridge.py
```

> **Configuration note:** the Windows whitelist paths in `bridge/validators.py` contain the placeholder `YourUsername` — change it to your own username (or to your actual working directories). The whitelist decides which directories the file tools may access.

---

## Testing

```bash
python -m pytest tests/            # 164 passed + 3 skipped
```

> Tests require `.env` to be configured (`bridge` checks `BRIDGE_API_KEY` at import time). To just run the tests, set the variable inline: `BRIDGE_API_KEY=test python -m pytest tests/`

- Unit tests cover path validation, symlinks, the command whitelist, transcript extraction, and the message bus
- Tools that touch external processes or platforms have separate integration tests (auto-skipped per platform)
- The test suite passes with no failures on both Linux and Windows

---

## Project status

All three collaboration layers (file sharing / async messaging / programmatic invocation) are implemented and verified.

**Known limitations:**
- `invoke_ag_cli("ask")` spawns a fresh, context-free AI instance — not "the AI you are currently talking to"
- The message bus is poll-based; there is no real-time push
- Identity is self-declared (all three clients share one Bearer token); it does not defend against an adversarial setting
- Archived messages have no automatic TTL cleanup

---

## Documentation

- [`SECURITY.md`](SECURITY.md) —— the security spec: whitelist/blacklist, the path-validation flow, per-tool specs, the audit policy

## License

[MIT](LICENSE) © 2026 Haven16262

---

*MCP-Bridge is a personal engineering project.*
