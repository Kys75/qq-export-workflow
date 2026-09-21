from .errors import SafeError
import os
from pathlib import Path
import tomllib
from zoneinfo import ZoneInfo

NAMES = ("nt_msg", "group_info", "profile_info")


def user_home():
    if hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SUDO_UID", "").isdigit():
        import pwd
        return Path(pwd.getpwuid(int(os.environ["SUDO_UID"])).pw_dir)
    return Path.home()


def user_path(value):
    value = str(value)
    if value == "~" or value.startswith("~/"):
        return (user_home() / value[2:]).resolve() if value != "~" else user_home().resolve()
    return Path(value).expanduser().resolve()


def load(path=None):
    path = user_path(path or os.environ.get("QQ_EXPORT_CONFIG", "~/.config/qq-export-workflow/config.toml"))
    with path.open("rb") as stream:
        config = tomllib.load(stream)
    for key in ("source_dir", "state_dir", "key_file"):
        config[key] = user_path(config[key])
    source, state, key = (config[name] for name in ("source_dir", "state_dir", "key_file"))
    if source == state or source in state.parents or state in source.parents or source == key or source in key.parents:
        raise SafeError("Private state and key paths must be separate from the source database tree")
    if state in (Path.home(), user_home()) or len(state.parts) < 3:
        raise SafeError("state_dir must be a dedicated application directory")
    for key, default in (("header_bytes", 1024), ("page_size", 4096), ("kdf_iter", 4000)):
        config[key] = int(config.get(key, default))
    if config["header_bytes"] < 0 or config["kdf_iter"] < 1 or config["page_size"] not in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
        raise SafeError("Invalid SQLCipher numeric parameters")
    for key, default in (("hmac_algorithm", "SHA1"), ("kdf_algorithm", "SHA512")):
        config[key] = config.get(key, default).upper()
        if config[key] not in ("SHA1", "SHA256", "SHA512"):
            raise SafeError("Unsupported SQLCipher hash algorithm")
    config["sqlcipher"] = config.get("sqlcipher", "sqlcipher")
    config["timezone"] = config.get("timezone", "Asia/Shanghai")
    ZoneInfo(config["timezone"])
    return config


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_mode & 0o077:
        raise SafeError("Private state directory must have mode 0700; select a dedicated directory")
    return path


def write_private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as stream:
        stream.write(data)
