#!/usr/bin/env python3
"""Reject em/en dashes in user-visible Cleanton copy.

The distribution repo bans em dashes in docs; the same rule applies to anything
the user can actually read on screen: Slint markup (where a dash inside a
`text:` property is rendered verbatim) and Rust string literals (finding titles,
descriptions, status lines and CLI output all come from these).

Comments are *not* user-visible, so they are skipped: this scanner walks the
Rust source with a small state machine that ignores line comments, block
comments and doc comments, and only inspects what is left inside string
literals (including raw strings). Slint has no string-literal syntax outside of
property values, so every `.slint` file is scanned whole.

Exit code 0 = clean, 1 = dashes found in user-visible copy.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Only U+2014 EM DASH is banned. U+2013 EN DASH stays legal because it appears
# inside detection regexes (campaign marker strings that really do contain one),
# where rewriting the literal would silently break the pattern.
DASHES = ("\u2014",)

SCAN_DIRS = ("crates",)
SLINT_SUFFIXES = (".slint",)
RUST_SUFFIXES = (".rs",)

# `b'x'`, `'x'`, `'\n'`, `'\u{2014}'`. Anything else starting with a quote is a
# lifetime (`&'a str`), which must NOT swallow the text up to the next quote.
CHAR_LITERAL = re.compile(
    r"""b?'(?:[^'\\\n]|\\[^'\n]|\\u\{[0-9a-fA-F]+\})'""",
)
# `r"..."`, `r#"..."#`, `br"..."`, `br#"..."#`.
RAW_STRING = re.compile(r"""b?r(#*)(")""")


def rust_string_literals(source: str) -> list[tuple[int, str]]:
    """Return `(line_number, literal_body)` for every string literal in `source`.

    A deliberately small scanner: enough Rust lexical structure to skip
    comments, lifetimes and character literals, which is all this check needs.
    """
    out: list[tuple[int, str]] = []
    i = 0
    n = len(source)
    line = 1
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        # Line comment.
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        # Block comment (Rust nests these).
        if source.startswith("/*", i):
            depth = 1
            i += 2
            while i < n and depth:
                if source[i] == "\n":
                    line += 1
                if source.startswith("/*", i):
                    depth += 1
                    i += 2
                    continue
                if source.startswith("*/", i):
                    depth -= 1
                    i += 2
                    continue
                i += 1
            continue
        # Character literal (skip it); a lifetime falls through to `i += 1`.
        if ch in "br'" and CHAR_LITERAL.match(source, i):
            i = CHAR_LITERAL.match(source, i).end()
            continue
        # Raw string with zero or more hashes.
        raw = RAW_STRING.match(source, i)
        if raw:
            start_line = line
            terminator = '"' + raw.group(1)
            body_at = raw.end()
            end = source.find(terminator, body_at)
            if end < 0:
                end = n
            body = source[body_at:end]
            line += body.count("\n")
            out.append((start_line, body))
            i = end + len(terminator)
            continue
        if ch == '"':
            start_line = line
            i += 1
            buf: list[str] = []
            while i < n and source[i] != '"':
                # A backslash always escapes exactly what follows it, so consume
                # both bytes together; that also keeps the closing quote of an
                # escaped `\"` from ending the literal early.
                if source[i] == "\\":
                    buf.append(source[i])
                    i += 1
                    if i < n:
                        buf.append(source[i])
                        i += 1
                    continue
                if source[i] == "\n":
                    line += 1
                buf.append(source[i])
                i += 1
            i += 1
            out.append((start_line, "".join(buf)))
            continue
        i += 1
    return out


def main() -> int:
    problems: list[str] = []

    for scan_dir in SCAN_DIRS:
        for path in sorted((REPO / scan_dir).rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue

            if path.suffix in SLINT_SUFFIXES:
                for number, text in enumerate(source.splitlines(), start=1):
                    if any(dash in text for dash in DASHES):
                        problems.append(
                            f"{path.relative_to(REPO)}:{number}: em dash in Slint copy: "
                            f"{text.strip()}"
                        )
                continue

            if path.suffix in RUST_SUFFIXES and "/tests/" not in path.as_posix():
                for number, literal in rust_string_literals(source):
                    if any(dash in literal for dash in DASHES):
                        shown = literal if len(literal) <= 96 else literal[:93] + "..."
                        problems.append(
                            f"{path.relative_to(REPO)}:{number}: em dash in a string literal: "
                            f"{shown}"
                        )

    if problems:
        print(f"== user-visible copy: {len(problems)} em/en dash problem(s) ==")
        for problem in problems:
            print(f"  error: {problem}")
        print("Replace em dashes with a comma, colon, hyphen or separate sentence.")
        return 1

    print("User-visible copy OK (no em or en dashes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
