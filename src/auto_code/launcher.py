"""Installed privileged launcher entrypoint.

The ticket-facing CLI never imports this module. Launcher configuration and
credentials are supplied through inherited descriptors rather than arguments.
"""

from __future__ import annotations

from launcher_finalization import FinalizationLauncher, FinalizationLauncherError

import sys


def main() -> int:
    print("auto-code-launcher: protected runtime unavailable", file=sys.stderr)
    return 2


def entrypoint() -> None:
    raise SystemExit(main())


__all__ = ["FinalizationLauncher", "FinalizationLauncherError", "entrypoint", "main"]
