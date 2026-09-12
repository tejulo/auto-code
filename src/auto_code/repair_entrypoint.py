from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import sys


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="auto-code-repair")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--run", required=True)
    prepare.add_argument("--failure", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--workspace", required=True)
    apply.add_argument("--request", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    prepare: Callable[[str, str], object] | None = None,
    apply: Callable[[str, str], object] | None = None,
) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
        if args.command == "prepare" and prepare is not None:
            prepare(args.run, args.failure)
            return 0
        if args.command == "apply" and apply is not None:
            apply(args.workspace, args.request)
            return 0
    except (ValueError, PermissionError):
        pass
    print("auto-code-repair: operation unavailable", file=sys.stderr)
    return 2


def entrypoint() -> None:
    raise SystemExit(main())
