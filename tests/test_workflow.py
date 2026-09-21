import contextlib
import asyncio
from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo

from qq_export_workflow.cli import main
from qq_export_workflow.config import load, write_private, user_path
from qq_export_workflow.decrypt import current, literal, refresh
from qq_export_workflow.keyscan import scan, verify
from qq_export_workflow.messages import export, list_chats, render


def vint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return vint(number << 3) + vint(value)
    return vint((number << 3) | 2) + vint(len(value)) + value


def message(text="synthetic hello", kind=1):
    return field(40800, field(45002, kind) + field(45101 if kind == 1 else 80900, text.encode()))


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "state"
        generation = "a" * 32
        self.dbdir = self.state / "generations" / generation
        self.dbdir.mkdir(parents=True)
        self.state.chmod(0o700)
        self.dbdir.parent.chmod(0o700)
        (self.state / "CURRENT").write_text(generation)
        self.config = dict(source_dir=self.root / "encrypted", state_dir=self.state,
                           key_file=self.root / "database.key", sqlcipher=shutil.which("sqlcipher") or "/opt/homebrew/bin/sqlcipher",
                           header_bytes=1024, page_size=4096, kdf_iter=4000,
                           hmac_algorithm="SHA1", kdf_algorithm="SHA512", timezone="Asia/Shanghai")
        self.config["source_dir"].mkdir()
        self.config["key_file"].write_text("synthetic-passphrase")
        self.moment = int(datetime(2026, 1, 2, 23, 59, 59, tzinfo=ZoneInfo("Asia/Shanghai")).timestamp())
        with sqlite3.connect(self.dbdir / "nt_msg.db") as database:
            for table in ("group_msg_table", "c2c_msg_table"):
                database.execute(f'CREATE TABLE {table} ("40030" INTEGER,"40050" INTEGER,"40033" INTEGER,"40093" TEXT,"40800" BLOB)')
            for timestamp, body in ((self.moment - 10, message()), (self.moment, message("boundary")), (self.moment + 1, message("next day"))):
                database.execute('INSERT INTO group_msg_table VALUES(101, ?, 201, NULL, ?)', (timestamp, body))
            database.execute('INSERT INTO c2c_msg_table VALUES(101, ?, 201, ?, ?)', (self.moment, "Synthetic card", message("private hello")))
        with sqlite3.connect(self.dbdir / "group_info.db") as database:
            database.execute('CREATE TABLE group_list ("60001" INTEGER,"60007" TEXT)')
            database.execute('INSERT INTO group_list VALUES(101, "Example study group")')
        with sqlite3.connect(self.dbdir / "profile_info.db") as database:
            database.execute('CREATE TABLE profile_info_v6 ("1002" INTEGER,"20002" TEXT)')
            database.execute('CREATE TABLE buddy_list ("1002" INTEGER,"1001" TEXT)')
            database.execute('INSERT INTO profile_info_v6 VALUES(201, "Nickname")')
            database.execute('INSERT INTO buddy_list VALUES(201, "Example friend")')

    def test_names_dates_sender_and_limits(self):
        self.assertEqual(len(list_chats(self.config)), 2)
        text = export(self.config, "101", "2026-01-02", "2026-01-02", kind="group")
        self.assertIn("2 messages", text)
        self.assertIn("Example friend", text)
        self.assertIn("boundary", text)
        self.assertNotIn("next day", text)
        limited = export(self.config, "101", limit=1, kind="group")
        self.assertIn("next day", limited)
        self.assertNotIn("boundary", limited)
        self.assertIn("Synthetic card", export(self.config, "101", kind="private"))

    def test_ambiguous_id_and_invalid_range_fail(self):
        with self.assertRaises(ValueError):
            export(self.config, "101")
        with self.assertRaises(ValueError):
            export(self.config, "101", start="2026-02-01", end="2026-01-01", kind="group")
        with self.assertRaises(ValueError):
            export(self.config, "101", limit=-1, kind="group")

    def test_all_original_media_types_and_malformed_protobuf(self):
        expected = {2: "图片", 3: "文件", 4: "语音", 5: "视频", 6: "表情", 7: "引用", 8: "系统", 9: "红包", 10: "应用", 16: "聊天记录", 21: "通话"}
        for kind, label in expected.items():
            self.assertIn(label, render(message("", kind)))
        self.assertEqual(render(message("sticker", 11)), "sticker")
        self.assertIn("类型99", render(message("", 99)))
        self.assertIn("无法解析", render(b"\x80"))
        self.assertEqual(render(message("one\ntwo")), "one\ntwo")
        self.assertEqual(render(message("first") + message("second")), "first second")

    def test_no_implicit_export_and_no_overwrite(self):
        before = set(self.root.rglob("*"))
        export(self.config, "101", kind="group")
        self.assertEqual(before, set(self.root.rglob("*")))
        output = self.root / "result.md"
        write_private(output, "synthetic")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_private(output, "replacement")

    def test_scan_requires_explicit_opt_in(self):
        with self.assertRaises(ValueError):
            scan(self.config)

    def encrypt_fixtures(self):
        executable = self.config["sqlcipher"]
        if not shutil.which(executable):
            self.skipTest("SQLCipher not installed; integration test requires SQLCipher 4")
        for name in ("nt_msg", "group_info", "profile_info"):
            encrypted = self.root / (name + ".cipher")
            sql = (f"ATTACH DATABASE {literal(encrypted)} AS encrypted KEY 'synthetic-passphrase';"
                   "PRAGMA encrypted.cipher_page_size=4096; PRAGMA encrypted.kdf_iter=4000;"
                   "PRAGMA encrypted.cipher_hmac_algorithm=HMAC_SHA1;"
                   "PRAGMA encrypted.cipher_kdf_algorithm=PBKDF2_HMAC_SHA512;"
                   "SELECT sqlcipher_export('encrypted'); DETACH DATABASE encrypted;")
            result = subprocess.run([executable, "-bail", str(self.dbdir / (name + ".db"))], input=sql, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, "Synthetic encryption failed")
            (self.config["source_dir"] / (name + ".db")).write_bytes(b"\0" * 1024 + encrypted.read_bytes())

    def test_sqlcipher_roundtrip_key_validation_and_failed_refresh_preserves_snapshot(self):
        self.encrypt_fixtures()
        encrypted = self.config["source_dir"] / "nt_msg.db"
        page = encrypted.read_bytes()[1024:5120]
        self.assertEqual(verify(b"synthetic-passphrase", page), {"kdf_iter": 4000, "hmac_algorithm": "SHA1"})
        self.assertIsNone(verify(b"wrong-passphrase", page))
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.config["source_dir"].glob("*.db")}
        refresh(self.config)
        self.assertIn("boundary", export(self.config, "101", kind="group"))
        self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.config["source_dir"].glob("*.db")})
        previous = current(self.config)
        self.config["key_file"].write_text("wrong-passphrase")
        with self.assertRaises(ValueError):
            refresh(self.config)
        self.assertEqual(current(self.config), previous)
        self.assertIn("boundary", export(self.config, "101", kind="group"))
        self.assertEqual(list(self.state.glob("refresh-*")), [])

    def test_nonempty_wal_rejected(self):
        (self.config["source_dir"] / "nt_msg.db").write_bytes(b"synthetic")
        (self.config["source_dir"] / "nt_msg.db-wal").write_bytes(b"uncheckpointed")
        with self.assertRaisesRegex(ValueError, "WAL"):
            refresh(self.config)

    def test_cli_failure_hides_private_exception(self):
        captured = io.StringIO()
        with patch("qq_export_workflow.cli.load", side_effect=ValueError("synthetic-secret")), contextlib.redirect_stderr(captured):
            self.assertEqual(main(["doctor"]), 1)
        self.assertNotIn("synthetic-secret", captured.getvalue())

    def config_file(self):
        path = self.root / "config.toml"
        path.write_text("\n".join(f"{key} = {json.dumps(str(value)) if isinstance(value, Path) else json.dumps(value)}" for key, value in self.config.items()))
        return path

    def test_config_rejects_source_state_overlap(self):
        path = self.config_file()
        self.assertEqual(load(path)["timezone"], "Asia/Shanghai")
        self.config["state_dir"] = self.config["source_dir"] / "private"
        with self.assertRaises(ValueError):
            load(self.config_file())

    @unittest.skipUnless(os.name == "posix", "sudo expansion is a POSIX feature")
    def test_sudo_paths_use_invoking_users_home(self):
        from types import SimpleNamespace
        with patch("os.geteuid", return_value=0), patch.dict(os.environ, {"SUDO_UID": "12345"}), patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.root))):
            self.assertEqual(user_path("~/state/database.key"), self.root.resolve() / "state/database.key")

    def test_wal_appearing_during_copy_rejected(self):
        self.encrypt_fixtures()
        original = shutil.copyfileobj
        def copy_then_wal(reader, writer):
            original(reader, writer)
            (self.config["source_dir"] / "nt_msg.db-wal").write_bytes(b"synthetic WAL")
        before = current(self.config)
        with patch("qq_export_workflow.decrypt.shutil.copyfileobj", side_effect=copy_then_wal):
            with self.assertRaisesRegex(ValueError, "WAL"):
                refresh(self.config)
        self.assertEqual(current(self.config), before)

    def test_cli_doctor_and_full_export(self):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            self.assertEqual(main(["--config", str(self.config_file()), "doctor"]), 1)
        self.assertFalse(json.loads(capture.getvalue())["source_available"])
        output = self.root / "cli-result.md"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--config", str(self.config_file()), "export", "101", "--kind", "group", "--output", str(output)]), 0)
        self.assertIn("boundary", output.read_text())

    def test_mcp_stdio_roundtrip(self):
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            import fastmcp
        except ImportError:
            self.skipTest("Install .[mcp] to exercise actual stdio MCP transport")
        config_path = self.config_file()
        async def run():
            parameters = StdioServerParameters(command=sys.executable, args=["-m", "qq_export_workflow.mcp_server"],
                                               env={**os.environ, "QQ_EXPORT_CONFIG": str(config_path)}, cwd=str(Path(__file__).resolve().parents[1]))
            with open(os.devnull, "w") as stderr:
                async with stdio_client(parameters, errlog=stderr) as (reader, writer):
                    async with ClientSession(reader, writer) as session:
                        await session.initialize()
                        discovered = await session.list_tools()
                        self.assertEqual({tool.name for tool in discovered.tools}, {"qq_list_chats", "qq_export_conversation", "qq_refresh"})
                        listed = await session.call_tool("qq_list_chats", {"keyword": "Example"})
                        self.assertFalse(listed.isError)
                        self.assertIn("Example study group", str(listed))
                        result = await session.call_tool("qq_export_conversation", {"chat": "101", "kind": "group", "start": "2026-01-02", "end": "2026-01-02"})
                        self.assertFalse(result.isError)
                        self.assertIn("boundary", str(result))
                        self.assertNotIn("next day", str(result))
                        self.assertFalse(list(self.root.rglob("*.md")))
        asyncio.run(asyncio.wait_for(run(), timeout=30))


if __name__ == "__main__":
    unittest.main()
