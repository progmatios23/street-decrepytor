# language: Python 3, file: cli/main.py
# Entry: flat commands in commands.py, groups in cmd_groups.py
from __future__ import annotations

from street_decrepytor.cli.commands import main
from street_decrepytor.cli.cmd_groups import register_groups

if "static" not in main.commands:
    register_groups(main)

if __name__ == "__main__":
    main()
