"""
Command-line interface for email_sanitizer.

Usage:
    python -m email_sanitizer path/to/email.txt
    cat email.txt | python -m email_sanitizer
    email-sanitize path/to/email.txt        (after pip install)
"""

import sys
import argparse

from .sanitizer import sanitize_email


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="email-sanitize",
        description="Sanitize raw email content before passing it to an LLM.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a file containing raw email content (HTML or plain text). "
        "If omitted, reads from stdin.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the sanitized output (no flags/summary to stderr).",
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()

    result = sanitize_email(raw)

    if not args.quiet:
        print("=" * 60, file=sys.stderr)
        print(f"Hidden content stripped: {result['was_modified']}", file=sys.stderr)
        if result["flags"]:
            print(f"⚠️  Suspicious phrases detected ({len(result['flags'])}):", file=sys.stderr)
            for phrase in result["flags"]:
                print(f"   - {phrase!r}", file=sys.stderr)
        else:
            print("No suspicious instruction-like phrases detected.", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(file=sys.stderr)

    print(result["safe_prompt"])


if __name__ == "__main__":
    main()
