from .errors import SafeError
"""Explicit macOS QQ process scan. Never invoked by refresh or MCP."""
import ctypes
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys

from .config import write_private


def verify(candidate, page, iterations=(4000, 4096), kdf="sha512"):
    salt = page[:16]
    for count in iterations:
        encryption = hashlib.pbkdf2_hmac(kdf, candidate, salt, count, dklen=32)
        authentication = hashlib.pbkdf2_hmac(kdf, encryption, bytes(b ^ 0x3a for b in salt), 2, dklen=32)
        for algorithm, length in (("sha1", 20), ("sha256", 32), ("sha512", 64)):
            usable = len(page) - ((16 + length + 15) // 16 * 16)
            expected = hmac.new(authentication, page[16:usable + 16] + struct.pack("<I", 1), algorithm).digest()
            if hmac.compare_digest(expected, page[usable + 16:usable + 16 + length]):
                return dict(kdf_iter=count, hmac_algorithm=algorithm.upper())
    return None


class Region(ctypes.Structure):
    _fields_ = [("protection", ctypes.c_int), ("max_protection", ctypes.c_int),
                ("inheritance", ctypes.c_uint), ("shared", ctypes.c_int),
                ("reserved", ctypes.c_int), ("offset", ctypes.c_ulonglong),
                ("behavior", ctypes.c_int), ("user_wired_count", ctypes.c_ushort)]


def scan(config, authorized=False):
    if not authorized:
        raise SafeError("Explicit --allow-process-memory is required for key scanning")
    if sys.platform != "darwin":
        raise SafeError("Process scanning is available only on macOS")
    if config["key_file"].exists() or os.path.exists(str(config["key_file"]) + ".params.json"):
        raise SafeError("Key or parameter file exists; choose a new key_file path before rescanning")
    pids = subprocess.run(["pgrep", "-x", "QQ"], capture_output=True, text=True, check=False).stdout.split()
    if len(pids) != 1:
        raise SafeError("Expected one running QQ process; open and log in to QQ")
    with (config["source_dir"] / "nt_msg.db").open("rb") as stream:
        stream.seek(config["header_bytes"])
        page = stream.read(config["page_size"])
    if len(page) != config["page_size"]:
        raise SafeError("Database does not contain a full first page")
    library = ctypes.CDLL(None)
    library.task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
    library.mach_vm_region.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64), ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    library.mach_vm_read_overwrite.argtypes = [ctypes.c_uint, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64)]
    task = ctypes.c_uint()
    own_task = ctypes.c_uint.in_dll(library, "mach_task_self_").value
    if library.task_for_pid(own_task, int(pids[0]), ctypes.byref(task)):
        raise SafeError("macOS denied process access. No security settings were changed. See README alternatives.")
    pattern = re.compile(rb"(?<![\x21-\x7e])([\x21-\x7e]{16}|[\x21-\x7e]{32})(?![\x21-\x7e])")
    seen = set()
    address = ctypes.c_uint64()
    try:
        while True:
            size, info = ctypes.c_uint64(), Region()
            count, object_name = ctypes.c_uint(ctypes.sizeof(info) // 4), ctypes.c_uint()
            status = library.mach_vm_region(task, ctypes.byref(address), ctypes.byref(size), 9, ctypes.cast(ctypes.byref(info), ctypes.POINTER(ctypes.c_int)), ctypes.byref(count), ctypes.byref(object_name))
            if status:
                break
            if object_name.value:
                library.mach_port_deallocate(own_task, object_name)
            base = address.value
            if info.protection & 1 and info.protection & 2 and size.value < 600 * 1024 * 1024:
                position = 0
                while position < size.value:
                    length = min(16 * 1024 * 1024, size.value - position)
                    buffer, received = ctypes.create_string_buffer(length), ctypes.c_uint64()
                    if not library.mach_vm_read_overwrite(task, base + position, length, ctypes.addressof(buffer), ctypes.byref(received)):
                        data = buffer.raw[:received.value]
                        for match in pattern.finditer(data):
                            candidate = match.group(1)
                            fingerprint = hashlib.sha256(candidate).digest()
                            if fingerprint in seen:
                                continue
                            seen.add(fingerprint)
                            params = verify(candidate, page, tuple(dict.fromkeys((config["kdf_iter"], 4000, 4096))), config["kdf_algorithm"].lower())
                            if params:
                                created_parents = []
                                parent = config["key_file"].parent
                                while not parent.exists():
                                    created_parents.append(parent)
                                    parent = parent.parent
                                write_private(config["key_file"], candidate.decode("ascii"))
                                sidecar = config["key_file"].with_name(config["key_file"].name + ".params.json")
                                write_private(sidecar, json.dumps(params))
                                if os.environ.get("SUDO_UID") and os.environ.get("SUDO_GID"):
                                    for path in [config["key_file"], sidecar, *created_parents]:
                                        os.chown(path, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
                                return "Validated key saved privately; key material is never printed."
                    position += length - 33 if length == 16 * 1024 * 1024 else length
            address.value = base + size.value
    finally:
        library.mach_port_deallocate(own_task, task)
    raise SafeError("No validated key found; QQ version, key format or parameters may differ")
