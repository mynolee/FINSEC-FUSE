"""Install the explicit public provider and use the fixed-output CLI boundary."""
from __future__ import annotations

import sys

from . import export as public_export
from . import export_provider


def configure_public_exporter():
    public_export.configure_export_provider(export_provider, cli=export_provider.main)
    return export_provider


def main(argv=None):
    try:
        configure_public_exporter()
    except BaseException:
        try:
            sys.stderr.write("Exporter configuration unavailable.\n")
        except BaseException:
            pass
        return 1
    return public_export.run_export_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
