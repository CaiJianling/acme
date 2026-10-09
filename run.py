"""Entry point: uvicorn + background scheduler.

Run with a single worker. Multiple workers would each start their own scheduler
and issue duplicate ACME requests.
"""

from __future__ import annotations

import argparse
import logging
import sys

from app.config import load
from app.web import create_app

# Windows consoles default to GBK, which mangles the Chinese log lines.
for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

settings = load()
app = create_app(settings)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSL 证书管理平台。默认值来自环境变量或 .env（ACME_HOST / ACME_PORT）。",
        epilog="例：python run.py --port 9000 --host 0.0.0.0",
    )
    parser.add_argument("--host", default=settings.host, help=f"监听地址，默认 {settings.host}")
    parser.add_argument("--port", type=int, default=settings.port, help=f"监听端口，默认 {settings.port}")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port 必须是 1-65535 之间的整数")
    return args


def main(argv: list[str] | None = None) -> None:
    import uvicorn

    args = parse_args(argv)
    logging.getLogger("app").info("监听 http://%s:%d（数据目录 %s）", args.host, args.port, settings.data_dir)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        workers=1,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
