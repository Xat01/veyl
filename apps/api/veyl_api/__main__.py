"""``python -m veyl_api`` — run the API with uvicorn.

A module entry point rather than a shell script so the server starts the same
way on every platform, and so ``veyl-api`` from ``pyproject.toml``'s
``[project.scripts]`` works without a wrapper.

    python -m veyl_api                # 127.0.0.1:8000
    python -m veyl_api --port 9000
    python -m veyl_api --reload       # development only
"""

from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veyl-api", description="Run the Veyl API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Restart on file changes. Development only; never use it in a deployment.",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
    )
    args = parser.parse_args(argv)

    # Bound to loopback by default. A security tool's API should not be reachable
    # from the network until an operator says so explicitly, and ``--host 0.0.0.0``
    # is that statement.
    if args.reload and args.host not in ("127.0.0.1", "localhost"):
        print(
            "refusing to combine --reload with a non-loopback bind address: the "
            "reloader watches the filesystem and is a development-only affordance",
            file=sys.stderr,
        )
        return 2

    try:
        import uvicorn
    except ImportError:
        print(
            "uvicorn is not installed. Install the API's runtime dependencies with "
            '`pip install -e ".[dev]"`, or `pip install "uvicorn[standard]"`.',
            file=sys.stderr,
        )
        return 1

    from veyl_api.config import settings

    if settings.env == "production" and args.reload:
        print("refusing to run with --reload in a production environment", file=sys.stderr)
        return 2

    os.environ.setdefault("VEYL_ENV", settings.env)
    uvicorn.run(
        "veyl_api.api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
