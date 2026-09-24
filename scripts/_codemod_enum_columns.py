"""One-shot codemod: convert enum-annotated String columns to EnumType.

Idempotent and safe to re-run. Only touches annotations of the form
``Mapped[SomeEnum] = mapped_column(String(nn), ...)`` where the annotation name
is a known Veyl enum. Anything else is left untouched.

    python scripts/_codemod_enum_columns.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = ROOT / "apps" / "api" / "veyl_api" / "models.py"
ENUMS = ROOT / "apps" / "api" / "veyl_api" / "enums.py"


def _enum_names() -> set[str]:
    """Every class defined in enums.py that subclasses an Enum."""
    source = ENUMS.read_text(encoding="utf-8")
    names: set[str] = set()
    for match in re.finditer(r"^class\s+(\w+)\s*\(([^)]*)\):", source, re.MULTILINE):
        class_name, bases = match.group(1), match.group(2)
        if "StrEnum" in bases or "Enum" in bases or "IntEnum" in bases:
            names.add(class_name)
    return names


# Single-line:  name: Mapped[EnumName] = mapped_column(String(32), rest)
SINGLE = re.compile(
    r"^(?P<indent>\s*)(?P<name>\w+):\s*Mapped\[(?P<enum>\w+)\]\s*=\s*"
    r"mapped_column\(\s*String\((?P<len>\d+)\)\s*,\s*(?P<rest>.*?)\)\s*$"
)

# Multi-line opening:      name: Mapped[EnumName] = mapped_column(
#                              String(32), rest...
MULTI_OPEN = re.compile(
    r"^(?P<indent>\s*)(?P<name>\w+):\s*Mapped\[(?P<enum>\w+)\]\s*=\s*"
    r"mapped_column\(\s*$"
)
MULTI_BODY = re.compile(r"^\s*String\((?P<len>\d+)\)\s*,\s*(?P<rest>.*)$")


def main() -> int:
    names = _enum_names()
    if not names:
        print("no enums discovered — aborting", file=sys.stderr)
        return 1

    lines = MODELS.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    converted = 0
    index = 0

    while index < len(lines):
        line = lines[index]

        single = SINGLE.match(line)
        if single and single.group("enum") in names:
            enum_name = single.group("enum")
            length = single.group("len")
            rest = single.group("rest").strip()
            # Keep the trailing comment if there is one, but note the type.
            tail = f", {rest}" if rest else ""
            out.append(
                f'{single.group("indent")}{single.group("name")}: '
                f'Mapped[{enum_name}] = mapped_column('
                f'EnumType("veyl_api.enums:{enum_name}", length={length}){tail})'
            )
            converted += 1
            index += 1
            continue

        multi = MULTI_OPEN.match(line)
        if multi and multi.group("enum") in names:
            enum_name = multi.group("enum")
            # Look ahead for the String(nn), ... body line.
            if index + 1 < len(lines):
                body = MULTI_BODY.match(lines[index + 1])
                if body:
                    length = body.group("len")
                    rest = body.group("rest").strip()
                    out.append(
                        f'{multi.group("indent")}{multi.group("name")}: '
                        f'Mapped[{enum_name}] = mapped_column('
                    )
                    tail = f", {rest}" if rest else ""
                    out.append(
                        f'{multi.group("indent")}    '
                        f'EnumType("veyl_api.enums:{enum_name}", length={length}){tail}'
                    )
                    converted += 1
                    index += 2
                    continue

        out.append(line)
        index += 1

    MODELS.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"converted {converted} enum column(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
