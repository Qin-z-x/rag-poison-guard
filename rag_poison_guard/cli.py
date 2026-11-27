"""Command line interface for rag-poison-guard."""

from __future__ import annotations

import argparse
import json
import sys

from .core import DEFAULT_EXTENSIONS, SEVERITY_RANK, VERSION, scan_corpus

TOOL = "rag-poison-guard"


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _print_report(report: dict) -> None:
    summary = report["summary"]
    print("%s %s  scan  %d document(s)" % (TOOL, VERSION, summary["documents"]))
    for index, document in enumerate(report["documents"], start=1):
        print(
            "doc %d/%d  %-52s risk=%-3d verdict=%s  findings=%d"
            % (index, summary["documents"], document["path"], document["risk_score"], document["verdict"], document["summary"]["total"])
        )
        for finding in document["findings"]:
            print(
                "  %-6s %-22s line %-4d col %-4d %s"
                % (finding["severity"].upper(), finding["code"], finding["line"], finding["column"], finding["message"])
            )
    print(
        "summary: %d document(s), %d finding(s): %d high, %d medium, %d low; poisoned=%d suspicious=%d clean=%d"
        % (
            summary["documents"],
            summary["findings"],
            summary["counts"]["high"],
            summary["counts"]["medium"],
            summary["counts"]["low"],
            summary["poisoned_docs"],
            summary["suspicious_docs"],
            summary["clean_docs"],
        )
    )


def _gate(report: dict, fail_on: str) -> int:
    if not fail_on:
        return 0
    threshold = SEVERITY_RANK[fail_on]
    count = sum(
        1
        for document in report["documents"]
        for finding in document["findings"]
        if SEVERITY_RANK[finding["severity"]] >= threshold
    )
    if count:
        print("FAIL: %d finding(s) at or above severity %r" % (count, fail_on), file=sys.stderr)
        return 1
    print("PASS: no finding at or above severity %r" % fail_on)
    return 0


def _extensions_from(value: str):
    if not value:
        return DEFAULT_EXTENSIONS
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _cmd_scan(args) -> int:
    report = scan_corpus(args.paths, extensions=_extensions_from(args.ext), extra_canaries=args.canary)
    report["paths"] = args.paths
    if args.json:
        _print_json(report)
    else:
        _print_report(report)
    return _gate(report, args.fail_on)


def _cmd_report(args) -> int:
    report = scan_corpus(args.paths, extensions=_extensions_from(args.ext), extra_canaries=args.canary)
    report["paths"] = args.paths
    _print_json(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="Scan RAG documents/corpus for injection and hidden-content risks (stdlib-only).",
    )
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, handler, help_text in (
        ("scan", _cmd_scan, "scan files or directories and print a risk report"),
        ("report", _cmd_report, "emit the full JSON report"),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("paths", nargs="+", help="files or directories to scan")
        sub.add_argument("--json", action="store_true", help="emit JSON")
        sub.add_argument("--fail-on", choices=["low", "medium", "high"], help="exit 1 when a finding at or above this severity exists")
        sub.add_argument("--ext", help="comma-separated extensions to include when scanning directories (default: %s)" % ",".join(DEFAULT_EXTENSIONS))
        sub.add_argument("--canary", action="append", default=[], help="extra canary marker to detect (repeatable)")
        sub.set_defaults(func=handler)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print("error: path not found: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
