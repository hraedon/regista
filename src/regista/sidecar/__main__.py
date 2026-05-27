from __future__ import annotations

import os
import sys

import structlog


def _configure_structlog_stderr():
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    )


def main():
    _configure_structlog_stderr()

    dsn = os.environ.get("REGISTA_DSN")
    project = os.environ.get("REGISTA_PROJECT")
    hmac_key_path = os.environ.get("REGISTA_HMAC_KEY_PATH")
    tokens_path = os.environ.get("REGISTA_TOKENS_PATH")
    bind = os.environ.get("REGISTA_BIND", "127.0.0.1:8080")
    try:
        pool_min = int(os.environ.get("REGISTA_POOL_MIN", "1"))
    except ValueError:
        print("REGISTA_POOL_MIN must be an integer", file=sys.stderr)
        sys.exit(2)
    try:
        pool_max = int(os.environ.get("REGISTA_POOL_MAX", "10"))
    except ValueError:
        print("REGISTA_POOL_MAX must be an integer", file=sys.stderr)
        sys.exit(2)

    missing = []
    if not dsn:
        missing.append("REGISTA_DSN")
    if not project:
        missing.append("REGISTA_PROJECT")
    if not hmac_key_path:
        missing.append("REGISTA_HMAC_KEY_PATH")
    if not tokens_path:
        missing.append("REGISTA_TOKENS_PATH")
    if missing:
        print(f"Missing required env vars: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)

    if ":" not in bind:
        print(f"REGISTA_BIND must be in host:port format, got {bind!r}", file=sys.stderr)
        sys.exit(2)
    host, port_str = bind.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        print(f"REGISTA_BIND port must be an integer, got {port_str!r}", file=sys.stderr)
        sys.exit(2)

    from regista import Regista

    sub = Regista(
        dsn, project, hmac_key_path,
        pool_min=pool_min, pool_max=pool_max,
    )

    from .app import create_app
    from .auth import TokenRegistry

    tokens = TokenRegistry.from_file(tokens_path)
    disable_docs = os.environ.get("REGISTA_DISABLE_DOCS", "").lower() in ("1", "true", "yes")
    docs_url = None if disable_docs else "/docs"
    openapi_url = None if disable_docs else "/openapi.json"
    app = create_app(sub, tokens, docs_url=docs_url, openapi_url=openapi_url)

    import uvicorn

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
