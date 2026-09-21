from fastmcp import FastMCP

from .errors import SafeError
from .config import load
from .decrypt import refresh as refresh_databases
from .messages import export, list_chats

mcp = FastMCP("qq")


@mcp.tool
def qq_list_chats(keyword: str = "") -> list[dict]:
    """List local QQ groups/private chats. Results contain private names and IDs."""
    try:
        return list_chats(load(), keyword)
    except SafeError as error:
        raise ValueError(str(error)) from None
    except Exception:
        raise ValueError("Cannot list QQ chats; verify configuration and refresh locally") from None


@mcp.tool
def qq_export_conversation(chat: str, start: str = "", end: str = "", limit: int = 0,
                           kind: str | None = None, refresh: bool = False) -> str:
    """Return local Markdown in memory. Dates use configured timezone. Media are placeholders.

    Specify kind and exact ID after listing. The returned chat text goes to the MCP client.
    This does not create an export file. Narrow time/limit if the response is truncated.
    """
    try:
        config = load()
        if refresh:
            refresh_databases(config)
        text = export(config, chat, start, end, limit, kind)
        return text if len(text) <= 120000 else text[:120000] + "\n[Truncated: narrow the date range or limit; CLI can export the full result.]\n"
    except SafeError as error:
        raise ValueError(str(error)) from None
    except Exception:
        raise ValueError("Cannot export QQ chats; verify exact conversation ID/kind, dates and local snapshot") from None


@mcp.tool
def qq_refresh() -> str:
    """Decrypt and validate local snapshots; fully quit QQ first. Does not recover keys."""
    try:
        return refresh_databases(load())
    except SafeError as error:
        raise ValueError(str(error)) from None
    except Exception:
        raise ValueError("Refresh failed; quit QQ, check key and run local doctor. Previous snapshot preserved.") from None


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
