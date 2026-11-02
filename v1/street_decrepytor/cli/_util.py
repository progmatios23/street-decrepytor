# language: Python 3, file: cli/_util.py
from __future__ import annotations

import json

import click


def print_json(obj: object) -> None:
    click.echo(json.dumps(obj, indent=2, default=str))


class AgentGroup(click.Group):
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        super().format_help(ctx, formatter)
        formatter.write_paragraph()
        formatter.write_text("Quick start (agents & operators):")
        formatter.write_text(
            "  street-decrepytor unpack sample.exe\n"
            "  street-decrepytor dump --spawn sample.exe --wait 12 --vad --fix-pe --iat\n"
            "  street-decrepytor recrack Potassium.dll"
        )
