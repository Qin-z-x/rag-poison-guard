## rag-poison-guard v0.1.0

Scan RAG/document corpora for content that tries to steer the model rather than
inform the user. Stdlib-only Python.

### Included

- `python -m rag_poison_guard scan|report <paths...>` — files or directories,
  recursive, with extension filtering; `--json`, `--fail-on`, repeatable
  `--canary`.
- Rules: hidden HTML/CSS (`display:none`, `visibility:hidden`, zero font,
  off-screen absolute positioning, `hidden` attribute), HTML comments with
  instruction content, zero-width/bidi/Tags-block payload characters,
  multilingual "ignore previous instructions" variants (EN/ZH/JA/ES),
  chat special tokens (`<|im_start|>`, `[INST]`, ...), canary markers,
  mixed-script homoglyph words and unusual dominant-language shifts.
- Per-document risk score (0-100), verdict (`clean`/`suspicious`/`poisoned`),
  finding counts and evidence snippets; corpus-level summary.
- 39 unit tests, GitHub Actions CI on Python 3.10/3.12, real captured evidence
  over a six-document synthetic corpus.

### Honest notes

- This is a heuristic content scanner. It does not disclose a new vulnerability,
  does not claim a new CVE and cannot prove a corpus is clean: a security policy
  document that *quotes* an injection phrase will be flagged (documented).
- Hidden-content and language rules are approximations; renderers differ.
- The synthetic corpus contains no real attack payloads; canaries are fake.
