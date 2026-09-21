import argparse
import getpass
import json
from pathlib import Path
import shutil
import sys

from .errors import SafeError
from .config import load, write_private
from .decrypt import refresh
from .messages import export, list_chats


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local QQ NT export workflow")
    parser.add_argument("--config", help="Configuration TOML path (or QQ_EXPORT_CONFIG)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Check configuration and SQLCipher availability")
    commands.add_parser("set-key", help="Read a key using a hidden local prompt")
    keyscan = commands.add_parser("scan-key", help="Explicit macOS process-memory key recovery")
    keyscan.add_argument("--allow-process-memory", action="store_true")
    commands.add_parser("refresh", help="Decrypt a stable source snapshot (quit QQ first)")
    listing = commands.add_parser("list", help="List conversations as JSON")
    listing.add_argument("--keyword", default="")
    exporting = commands.add_parser("export", help="Render a conversation to stdout or an explicit file")
    exporting.add_argument("chat")
    exporting.add_argument("--kind", choices=("group", "private"))
    exporting.add_argument("--from", dest="start", default="")
    exporting.add_argument("--to", dest="end", default="")
    exporting.add_argument("--limit", type=int, default=0)
    exporting.add_argument("--output", type=Path)
    exporting.add_argument("--refresh", action="store_true")
    commands.add_parser("mcp-config", help="Print a local MCP client configuration fragment")
    args = parser.parse_args(argv)
    try:
        config = load(args.config)
        if args.command == "doctor":
            checks = {"sqlcipher_available": bool(shutil.which(config["sqlcipher"])),
                      "source_available": (config["source_dir"] / "nt_msg.db").is_file(),
                      "key_available": config["key_file"].is_file()}
            print(json.dumps(checks, indent=2))
            return 0 if all(checks.values()) else 1
        elif args.command == "set-key":
            if not sys.stdin.isatty():
                raise SafeError("set-key requires an interactive terminal")
            secret = getpass.getpass("Database passphrase (hidden): ")
            if not secret or any(ord(c) < 32 for c in secret):
                raise SafeError("Key must be a nonempty single-line passphrase")
            write_private(config["key_file"], secret)
            print("Key saved privately.")
        elif args.command == "scan-key":
            from .keyscan import scan
            print(scan(config, args.allow_process_memory))
        elif args.command == "refresh":
            print(refresh(config))
        elif args.command == "list":
            print(json.dumps(list_chats(config, args.keyword), ensure_ascii=False, indent=2))
        elif args.command == "export":
            if args.refresh:
                refresh(config)
            text = export(config, args.chat, args.start, args.end, args.limit, args.kind)
            if args.output:
                write_private(args.output.expanduser().resolve(), text)
                print("Export written to the requested file.")
            else:
                print(text, end="")
        elif args.command == "mcp-config":
            import os
            path = Path(args.config or os.environ.get("QQ_EXPORT_CONFIG", "~/.config/qq-export-workflow/config.toml")).expanduser().resolve()
            print(json.dumps({"mcpServers": {"qq": {"command": sys.executable,
                "args": ["-m", "qq_export_workflow.mcp_server"],
                "env": {"QQ_EXPORT_CONFIG": str(path)}}}}, indent=2))
    except SafeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        # Tool errors can include SQL/key fragments or personal paths; do not echo them.
        print("Operation failed. Check configuration, permissions, key, QQ shutdown/WAL state, conversation ambiguity and date range. Existing exports/snapshots were preserved.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
