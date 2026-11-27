"""CLI behaviour tests for rag-poison-guard."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import unittest

from rag_poison_guard.cli import main

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = str(ROOT / "examples" / "corpus")
CLEAN = str(ROOT / "examples" / "corpus" / "clean_doc.md")
CANARY = str(ROOT / "examples" / "corpus" / "poisoned_canary.md")


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_corpus_json(self):
        code, out, _ = run(["scan", CORPUS, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["documents"], 6)
        self.assertGreaterEqual(payload["summary"]["poisoned_docs"], 4)

    def test_gate_blocks_corpus(self):
        code, _, err = run(["scan", CORPUS, "--fail-on", "high"])
        self.assertEqual(code, 1)
        self.assertIn("FAIL", err)

    def test_clean_document_passes(self):
        code, _, _ = run(["scan", CLEAN, "--fail-on", "low"])
        self.assertEqual(code, 0)

    def test_custom_canary_gate(self):
        code, out, _ = run(["scan", CANARY, "--canary", "SECRET-12345", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        codes = {finding["code"] for document in payload["documents"] for finding in document["findings"]}
        self.assertIn("RAG-CANARY", codes)
        code, _, _ = run(["scan", CANARY, "--canary", "SECRET-12345", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_report_json(self):
        code, out, _ = run(["report", CORPUS])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["tool"], "rag-poison-guard")

    def test_missing_path_exits_2(self):
        code, _, err = run(["scan", str(ROOT / "nope")])
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_extension_filter(self):
        code, out, _ = run(["scan", CORPUS, "--ext", ".nothing", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["documents"], 0)
