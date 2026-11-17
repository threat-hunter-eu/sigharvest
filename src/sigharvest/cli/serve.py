"""`sigharvest serve`: the local web UI (`sigharvest web` is a hidden alias, the name suriharvest used)."""

from __future__ import annotations

import os

import typer

from sigharvest.cli.common import console, fail, user_errors
from sigharvest.config import find_workspace

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def extra_hosts(allow_host: list[str]) -> list[str]:
    return [h.strip() for h in [*allow_host, *os.environ.get("SIGHARVEST_ALLOWED_HOSTS", "").split(",")] if h.strip()]


def read_token(token_env: str | None, host: str) -> str | None:
    """The access token from the variable named by --token-env; refuses a non-loopback address without one."""
    from sigharvest.web.security import MIN_TOKEN_LENGTH

    token = None
    if token_env:
        token = os.environ.get(token_env)
        if not token or len(token) < MIN_TOKEN_LENGTH:
            fail(f"environment variable {token_env} must hold a token of at least {MIN_TOKEN_LENGTH} characters", code=2)
    if host not in LOOPBACK and token is None:
        fail(
            f"binding to {host} (beyond this machine) needs authentication: put a token of {MIN_TOKEN_LENGTH}+ characters in an "
            "environment variable and pass --token-env VAR (see docs/web.md)",
            code=2,
        )
    return token


def port_unavailable(host: str, port: int) -> str | None:
    """Why `serve` could not listen on host:port (in use, no such address), or None. Checked before the start banner
    so a busy port is one `error:` line with exit code 2, not a banner followed by a uvicorn error and exit code 3."""
    import socket

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        return str(e.strerror or e)
    family, _, _, _, addr = infos[0]
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if os.name != "nt":  # as uvicorn does; on Windows SO_REUSEADDR would let the bind steal a port in use
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(addr)
        except OSError as e:
            return str(e.strerror or e)
    return None


def serve(
    host: str = typer.Option("127.0.0.1", help="Address to bind. Any address but loopback needs --token-env."),
    port: int = typer.Option(8799, min=1, max=65535, help="Port to listen on."),
    token_env: str | None = typer.Option(
        None,
        "--token-env",
        metavar="VAR",
        help="Name of an environment variable holding the access token (16+ characters). Clients send it as the HTTP Basic "
        "password (any user name) or as a Bearer token. Required with any --host but loopback.",
    ),
    allow_host: list[str] = typer.Option(
        [],
        "--allow-host",
        metavar="HOST",
        help="Extra host name the UI answers to (repeatable), e.g. the LAN address or name with --host 0.0.0.0, or a reverse "
        "proxy's name. Requests with any other Host header are refused (DNS rebinding). Also: SIGHARVEST_ALLOWED_HOSTS=a,b.",
    ),
) -> None:
    """Search, browse and export rules, ATT&CK coverage and collections in a browser."""
    import uvicorn

    from sigharvest.service import open_db
    from sigharvest.web.app import create_app

    token = read_token(token_env, host)
    ws = find_workspace()
    with user_errors():
        extra = extra_hosts(allow_host)
        if host not in LOOPBACK and not extra:
            console.print("[yellow]Requests must use this Host name; add the names clients use with --allow-host.[/]")
        sessions = open_db(ws, migrate=True)
        busy = port_unavailable(host, port)
        if busy:
            fail(f"cannot listen on {host} port {port}: {busy} (is another server running? choose another with --port)", code=2)
        shown = f"[{host}]" if ":" in host else host
        console.print(f"sigharvest UI on http://{shown}:{port}/ (workspace {ws.root}); Ctrl+C stops it")
        app = create_app(ws, sessions, allowed_hosts=[host, *extra], token=token)
        uvicorn.run(app, host=host, port=port, log_level="warning", proxy_headers=False, access_log=False)
