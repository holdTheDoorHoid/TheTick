#!/usr/bin/env python3
"""Fail the build if any HTTP route is reachable without an authentication check.

The /txid endpoint - the one that transmits a credential to the door
controller - shipped without a check while every other sensitive handler had
one. It was a single missing line in a file where the checks are written by
hand, one per handler, so nothing flagged it.

This walks the route table and the handler bodies and insists that every
registered route either calls basicAuthFailed() or is on an explicit list of
routes that are deliberately open. Adding a route without a check fails CI;
deliberately opening one requires editing the allowlist, which is a visible
decision rather than an omission.
"""

import re
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "src" / "tick_http.cpp"

# Routes intentionally served without a password. Everything else must check.
DELIBERATELY_OPEN = {
    # Vendored CSS/JS only. Serving these openly is what lets the login
    # prompt render at all.
    "/static",
}

AUTH_CALL = "basicAuthFailed()"


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return text


def extract_block(text: str, start: int) -> str:
    """Return the balanced brace/paren block beginning at or after `start`."""
    depth = 0
    began = False
    out = []
    for i in range(start, len(text)):
        c = text[i]
        if c in "({":
            depth += 1
            began = True
        elif c in ")}":
            depth -= 1
        out.append(c)
        if began and depth == 0:
            break
    return "".join(out)


def main() -> int:
    raw = SOURCE.read_text()
    text = strip_comments(raw)

    # Named handler functions, so a route registered by name can be checked.
    handlers = {}
    for m in re.finditer(r"\b(?:static\s+)?(?:void|bool)\s+(\w+)\s*\(\s*\)\s*\{", text):
        handlers[m.group(1)] = extract_block(text, m.end() - 1)

    failures = []
    checked = 0

    # Extract from the opening paren of server.on so the whole registration -
    # every lambda argument included - is inside the balanced block.
    for m in re.finditer(r'server\.on\s*(\()', text):
        registration = extract_block(text, m.start(1))
        route_match = re.search(r'"([^"]+)"', registration)
        if not route_match:
            continue
        route = route_match.group(1)
        checked += 1

        if route in DELIBERATELY_OPEN:
            continue

        body = registration
        # A route registered by handler name carries its check in that function.
        for name, fn_body in handlers.items():
            if re.search(r"\b%s\b" % re.escape(name), registration):
                body += fn_body

        if AUTH_CALL not in body:
            failures.append(route)

    for m in re.finditer(r'server\.serveStatic\s*\(\s*"([^"]+)"', text):
        route = m.group(1)
        checked += 1
        if route not in DELIBERATELY_OPEN:
            failures.append(
                "%s (serveStatic bypasses the auth check entirely)" % route
            )

    # onNotFound is the catch-all filesystem path and must check.
    nf = re.search(r"server\.onNotFound\s*\(", text)
    if nf:
        checked += 1
        if AUTH_CALL not in extract_block(text, nf.end() - 1):
            failures.append("onNotFound")

    if failures:
        print("HTTP routes reachable without authentication:", file=sys.stderr)
        for f in failures:
            print("  %s" % f, file=sys.stderr)
        print(
            "\nAdd `if (basicAuthFailed()) return;` to the handler, or add the "
            "route to DELIBERATELY_OPEN in %s if it is meant to be public."
            % Path(__file__).name,
            file=sys.stderr,
        )
        return 1

    print("HTTP auth audit: %d routes checked, all authenticated." % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
