# QQ NT 本地导出工作流

把自己有权读取的 QQ NT 本地聊天记录解密为 SQLite，按会话和日期导出 Markdown，并通过本地 MCP 提供给 Coding Agent。仓库仅包含通用代码、配置模板和人工构造的测试数据；密钥、聊天数据库、联系人、导出结果都留在使用者自己的电脑上。

支持链路：本地配置 → 已知密钥录入或显式 macOS 密钥扫描 → SQLCipher 解密 → 列会话 → 按时间导出 → MCP/Agent 分析。核心 CLI 仅需 Python 标准库；MCP 是可选依赖。当前数据库结构来自 macOS QQ NT，未承诺兼容每一个 QQ 版本。

## 先试用（不需要 QQ 或密钥）

克隆这个私有仓库后进入目录，使用 Python 3.11 或更新版本：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[mcp]'
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/qq-export --help
```

测试只在系统临时目录构造虚拟群、虚拟联系人和消息，不读取你的 QQ、系统钥匙串或聊天历史。安装 SQLCipher 后，测试还会实际执行“合成 SQLite → SQLCipher 加密 → QQ 格式前置头 → 解密 → 导出”，不只是 mock。没有 SQLCipher 时仅跳过该集成测试；CI 必须安装 SQLCipher 4 并运行完整测试。

## 1. 准备依赖和配置

macOS 安装 SQLCipher：

```bash
brew install sqlcipher
mkdir -p ~/.config/qq-export-workflow
cp config.example.toml ~/.config/qq-export-workflow/config.toml
```

用编辑器打开配置。找到本机账号的 `nt_db` 目录并填入 `source_dir`：

```bash
find "$HOME/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ" -type d -name nt_db
```

可能存在多个账号目录；按你要导出的账号选择，不要把整棵 QQ 目录上传给 Agent。配置里的 `nt_qq_REPLACE_ME` 是占位符，必须替换。`sqlcipher` 默认从 PATH 查找，也可以填你的 SQLCipher 可执行文件绝对路径。Apple Silicon Homebrew 通常为 `/opt/homebrew/bin/sqlcipher`，但以本机实际路径为准。

默认私有工作目录为 `~/.local/share/qq-export-workflow`，默认密钥为该目录下的 `database.key`。保持它们在源码仓库之外，且与 `source_dir` 分离。工具拒绝将状态目录设为用户主目录或源数据库目录；已有状态目录需要权限 `0700`，新目录和密钥分别自动使用 `0700`、`0600`。可以通过 `--config /absolute/path/config.toml` 或环境变量 `QQ_EXPORT_CONFIG` 指定配置。

```bash
.venv/bin/qq-export doctor
```

`doctor` 仅输出 SQLCipher、源数据库和密钥是否存在，不显示私人路径或内容。

## 2. 获取或录入密钥

如果已有此账号当前数据库的合法密钥，使用隐藏输入，不把它放进命令行、聊天窗口或 git：

```bash
.venv/bin/qq-export set-key
```

首次没有密钥时，可显式使用本机 macOS QQ 进程扫描器。打开并登录 QQ，进入任意聊天让数据库被加载，然后执行：

```bash
.venv/bin/qq-export scan-key --allow-process-memory
```

扫描器只尝试 QQ 进程中 16 或 32 位可打印候选密钥，并用数据库第一页的 SQLCipher HMAC 验证，不打印候选值或命中密钥。命中结果保存为 `key_file` 和相邻 `.params.json`，后续解密会读取经过验证的参数。

macOS 可能禁止访问进程内存；普通登录/导出不代表已获得调试权限。工具不会自动提权、修改 QQ 签名、修改 SIP 或安全设置。若当前机器已具有合适的调试权限而只缺 root 权限，可以自行明确运行：

```bash
sudo "$PWD/.venv/bin/python" -m qq_export_workflow --config "$HOME/.config/qq-export-workflow/config.toml" scan-key --allow-process-memory
```

`sudo` 运行时，配置中的 `~` 按发起用户的主目录展开，不会误指向 root 的主目录；扫描新建的密钥、参数文件和目录会交回发起用户。`sudo` 本身不保证突破系统的进程保护。本仓库不要求关闭 SIP；仍被拒绝时，使用已有合法密钥，或在已经获准调试的环境中取得密钥。扫描器只支持上述候选格式与 SHA 系列参数，QQ 版本变化可能使该方法失效。已有密钥文件绝不覆盖；需要重取时在配置中选择新的 `key_file`，确认可用后自行处理旧文件。

首次配置遇到权限问题，可阅读可选高级说明 [macOS 文件访问、进程权限与 SIP 恢复流程](docs/macos-permissions.md)。其中包括用户自行决定的 Recovery 临时调整及立即恢复保护步骤；它不是默认安装动作，Agent 和安装程序不会执行系统修改。

## 3. 稳定解密快照

**完全退出 QQ 后**执行：

```bash
.venv/bin/qq-export refresh
```

与旧工作流的直接热复制不同，此版本要求稳定源库：拒绝非空 WAL，并在复制期间检查源文件是否变化及是否出现 WAL，避免漏掉未 checkpoint 的消息。不要手动删除 WAL 文件；从 QQ 正常退出，让应用自己完成 checkpoint。扫描密钥需要 QQ 运行；解密快照需要 QQ 退出，这两步的前提不同。

源文件始终只读。每个数据库先去除可配置头部（默认 1024 字节），使用 SQLCipher 4 参数解密，验证 SQLite 完整性和主库表结构，全部成功才更新当前快照。失败返回非零退出码、保留旧快照，不把旧文件误报为新鲜数据。群/联系人库缺失时按数字 ID 工作；存在但解密失败则整次刷新失败。

快照在 `state_dir/generations/` 下，每次成功刷新保留一代；它们包含完整聊天，注意本地磁盘与备份。工具不会自行删除旧代，确认无用后可由你清理旧目录，但不要删除 `CURRENT` 指向的当前代。

## 4. 查找会话和导出

```bash
.venv/bin/qq-export list --keyword '示例群'
.venv/bin/qq-export export 101 --kind group --from 2026-01-01 --to 2026-01-31
.venv/bin/qq-export export 101 --kind group --limit 200
.venv/bin/qq-export export 101 --kind group --from 2026-01-01 --to 2026-01-31 --output ~/.local/share/qq-export-workflow/exports/january.md
```

`101` 为合成示例 ID，实际使用 `list` 返回的 ID。`group` 是群聊，`private` 是私聊；同一个数字可能同时对应两类会话，因此建议总是明确指定 `--kind`。支持名称精确/模糊查找，但匹配到多个会话时会报错，不擅自取第一个。

日期使用配置 `timezone`（默认 `Asia/Shanghai`）。`--to 2026-01-31` 包含当天全部消息；精确到时分秒的结束时间包含该时间点；ISO 日期时间可带时区。`--limit N` 取筛选范围内最新 N 条，按时间正序输出，0 表示全部。

默认输出到终端，不自动写文件。指定 `--output` 才创建权限为 `0600` 的文件，已有文件不会覆盖。终端和 MCP 返回的数据是真实聊天，需要按你的隐私要求处理。

文本、发送者、群名片、备注优先于昵称、时间分组得到保留；多行文本保留换行。图片、文件、语音、视频、表情、引用、系统消息、红包、应用、贴纸、合并聊天记录和通话有标签或已有文字。**不会自动导出媒体原文件、还原语音或完整引用内容**。未知消息类型和损坏 protobuf 会保留明确占位，避免静默丢消息。

## 5. 配置 MCP 和 Agent

先用 CLI 成功刷新并列出会话，再生成适合本机的 JSON 片段：

```bash
.venv/bin/qq-export mcp-config
```

把生成的 `mcpServers.qq` 项合并到支持 stdio MCP 的客户端配置；该输出包含本机路径，只留在本机。不要覆盖客户端其他 MCP 配置。使用 Codex 的 TOML 配置时采用等价配置（路径替换为实际绝对路径）：

```toml
[mcp_servers.qq]
command = "/absolute/path/to/repository/.venv/bin/python"
args = ["-m", "qq_export_workflow.mcp_server"]

[mcp_servers.qq.env]
QQ_EXPORT_CONFIG = "/absolute/path/to/local/config.toml"
```

启动入口是 `.venv/bin/qq-export-mcp` 或 `.venv/bin/python -m qq_export_workflow.mcp_server`。工具为 `qq_list_chats`、`qq_export_conversation`、`qq_refresh`；无需 `sudo`，不会通过 MCP 获取密钥。`qq_export_conversation` 只在内存返回 Markdown，不落导出文件；超出 120,000 字符会明确标记截断，请缩小日期范围或用 CLI 完整导出。

可选 Agent Skill 在 `skills/qq-export/SKILL.md`。将整个 `qq-export` 目录复制到客户端的 skills 目录即可；若已有同名 skill，先检查内容，不覆盖现有工作流。仓库内的 `AGENTS.md` 可直接指导 Coding Agent。

可复制给 Agent 的提示：

> 请阅读本仓库 README.md 和 AGENTS.md，为我创建独立虚拟环境与仓库外本地配置，运行合成测试和 doctor，接好 qq MCP。已有密钥只让我在本机隐藏输入；不要读取密钥内容或上传数据库。先列出我指定的会话，确认唯一 ID/类型，再导出我指定日期范围。若需要进程扫描或改变系统设置，停止并说明具体需求，不自动操作。

MCP 服务本身没有网络上传逻辑，但将聊天作为工具结果返回给云端 Agent 时，内容会随客户端请求进入该服务。只想本地处理时使用 CLI 或本地模型；私有 GitHub 仓库不能替代这一边界。

## 故障排查和验证范围

- `doctor` 的 `sqlcipher_available=false`：检查 PATH 或配置可执行文件绝对路径，建议 SQLCipher 4。
- 首次刷新失败：确认主库路径、当前密钥、头部长度、页面大小和 KDF/HMAC 参数；参数模板并非所有版本的保证。
- 升级或重新登录后失败：QQ 可能换密钥；不要将旧快照当成刷新成功。选择新 `key_file` 重取再验证。
- 刷新失败且有 WAL：完全退出 QQ 后再试，不手动删除数据库旁文件。
- 会话导出失败：先 `list`，明确 ID 与 kind，检查日期先后关系和 limit 非负。
- 名称缺失：可选联系人表版本不同或对应库未提供，数字 ID 仍可用。
- macOS 进程扫描：合成测试验证 HMAC，但不会连接真实 QQ 进程；具体机器的进程访问权限和客户端版本需自行验证。

来源和历史设计经验见 [PROVENANCE.md](PROVENANCE.md)，隐私边界见 [SECURITY.md](SECURITY.md)。
