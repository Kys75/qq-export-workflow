from .errors import SafeError
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .decrypt import current

TABLES = {"group": "group_msg_table", "private": "c2c_msg_table"}
LABELS = {2: "图片", 3: "文件", 4: "语音", 5: "视频", 6: "表情", 7: "引用", 8: "系统",
          9: "红包", 10: "应用", 11: "贴纸", 16: "聊天记录", 21: "通话"}


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise SafeError("Truncated protobuf")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise SafeError("Oversized protobuf varint")


def fields(data):
    result = {}
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not number:
            raise SafeError("Invalid protobuf field")
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                length, offset = varint(data, offset)
            else:
                length = 8 if wire == 1 else 4
            if offset + length > len(data):
                raise SafeError("Truncated protobuf field")
            value, offset = data[offset:offset + length], offset + length
        else:
            raise SafeError("Unsupported protobuf wire type")
        result.setdefault(number, []).append(value)
    return result


def render(body):
    if not body:
        return ""
    try:
        result = []
        for encoded in fields(body).get(40800, []):
            element = fields(encoded)
            kind = element.get(45002, [None])[0]
            value = element.get(45101 if kind == 1 else 80900, [b""])[0]
            if kind in (1, 11) and isinstance(value, bytes) and value:
                result.append(value.decode("utf-8", "replace"))
            else:
                result.append("[" + LABELS.get(kind, f"类型{kind}") + "]")
        return " ".join(result) or "[无可识别消息元素]"
    except (ValueError, TypeError, IndexError):
        return "[无法解析消息体]"


def connect(path):
    return sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)


def names(directory):
    groups, contacts = {}, {}
    for filename, target, queries in (
        ("group_info.db", groups, [('SELECT group_list."60001", group_list."60007" FROM group_list',)]),
        ("profile_info.db", contacts, [('SELECT profile_info_v6."1002", profile_info_v6."20002" FROM profile_info_v6',),
                                      ('SELECT buddy_list."1002", buddy_list."1001" FROM buddy_list',)]),
    ):
        path = directory / filename
        if not path.exists():
            continue
        with connect(path) as database:
            for (query,) in queries:
                try:
                    for identity, name in database.execute(query):
                        if identity and name:
                            target[int(identity)] = str(name)
                except sqlite3.OperationalError:
                    # Optional name tables vary across QQ releases; IDs still work.
                    continue
    return groups, contacts


def list_chats(config, keyword="", directory=None):
    directory = directory or current(config)
    groups, contacts = names(directory)
    result = []
    with connect(directory / "nt_msg.db") as database:
        for kind, table in TABLES.items():
            mapping = groups if kind == "group" else contacts
            for identity, timestamp in database.execute(f'SELECT "40030", MAX("40050") FROM {table} GROUP BY "40030"'):
                if identity is None:
                    continue
                name = mapping.get(int(identity), str(identity))
                if keyword.casefold() not in name.casefold() and keyword not in str(identity):
                    continue
                result.append(dict(kind=kind, id=int(identity), name=name, latest=timestamp))
    return sorted(result, key=lambda row: row["latest"] or 0, reverse=True)


def resolve(config, chat, kind=None, directory=None):
    if kind is not None and kind not in TABLES:
        raise SafeError("kind must be group or private")
    candidates = [item for item in list_chats(config, directory=directory) if not kind or item["kind"] == kind]
    exact = [item for item in candidates if str(item["id"]) == str(chat) or item["name"] == chat]
    matches = exact or [item for item in candidates if str(chat).casefold() in item["name"].casefold()]
    if len(matches) != 1:
        raise SafeError("Conversation is missing or ambiguous; list chats and pass exact ID plus kind")
    return matches[0]


def boundary(value, zone, end=False):
    if not value:
        return None
    date_only = len(value.strip()) == 10
    try:
        parsed = datetime.fromisoformat(value.replace("/", "-"))
    except ValueError as error:
        raise SafeError("Use YYYY-MM-DD or ISO date/time") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    if end and date_only:
        parsed += timedelta(days=1)
        return parsed.timestamp(), True
    return parsed.timestamp(), False


def export(config, chat, start="", end="", limit=0, kind=None):
    if limit < 0:
        raise SafeError("limit must be zero (all) or positive")
    directory = current(config)
    conversation = resolve(config, chat, kind, directory)
    _, contacts = names(directory)
    zone = ZoneInfo(config["timezone"])
    lower, upper = boundary(start, zone), boundary(end, zone, True)
    if lower and upper and lower[0] > upper[0]:
        raise SafeError("start must precede end")
    conditions, arguments = ['"40030"=?'], [conversation["id"]]
    if lower:
        conditions.append('"40050">=?')
        arguments.append(lower[0])
    if upper:
        conditions.append('"40050"' + ("<?" if upper[1] else "<=?"))
        arguments.append(upper[0])
    table = TABLES[conversation["kind"]]
    query = f'SELECT rowid, "40050", "40033", "40093", "40800" FROM {table} WHERE ' + " AND ".join(conditions)
    query += ' ORDER BY "40050" DESC, rowid DESC' if limit else ' ORDER BY "40050" ASC, rowid ASC'
    if limit:
        query += " LIMIT ?"
        arguments.append(limit)
    with connect(directory / "nt_msg.db") as database:
        rows = database.execute(query, arguments).fetchall()
    if limit:
        rows.reverse()
    output = [f"# {conversation['name']}", "", f"> {conversation['kind']} id={conversation['id']}; {len(rows)} messages; timezone={config['timezone']}", ""]
    day = None
    for _, timestamp, sender, nickname, body in rows:
        moment = datetime.fromtimestamp(timestamp, zone) if timestamp is not None else None
        date = moment.strftime("%Y-%m-%d") if moment else "Unknown date"
        if date != day:
            output.extend(["", f"## {date}", ""])
            day = date
        name = nickname or contacts.get(int(sender or 0), str(sender or "Unknown"))
        clock = moment.strftime("%H:%M:%S") if moment else "Unknown time"
        content = render(body).replace("\n", "\n  ")
        output.append(f"- **{clock}** {name}: {content}")
    return "\n".join(output) + "\n"
