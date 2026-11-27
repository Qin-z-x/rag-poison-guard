# Threat model: RAG corpus poisoning

## Honesty statement

This project is a **heuristic content scanner** for retrieval corpora. It does
not disclose a new vulnerability, does not claim a new CVE, and cannot prove that
a corpus is clean. Its job is to prioritise review and to gate ingestion on the
strongest signals. The synthetic corpus in `examples/` contains harmless markers,
not real attacks; canaries are fake.

## 1. The threat

A RAG pipeline retrieves documents and inserts their text into the model context.
If an attacker can place text in any indexed source (web pages, PDFs, issue
comments, shared drives, vendor feeds), they can place *instructions* there. The
model sees retrieved text as data, but nothing in the pipeline enforces that: a
document that says "ignore previous instructions" competes with the system prompt.

Attack surface:

* hidden content that a human reviewer never sees but extraction feeds to the model
  (CSS-hidden divs, HTML comments, off-screen text, white-on-white text);
* invisible characters that encode or hide instructions;
* role/template tokens that forge conversation structure;
* multilingual phrasing that evades an English-only keyword list;
* canary markers that reveal data contamination or a leak.

## 2. Rules and severity rationale

| Rule | Severity | Why |
| --- | --- | --- |
| `RAG-TAG-PAYLOAD` | high | Tags-block text is invisible ASCII; essentially never legitimate |
| `RAG-ZW-RUN` (bidi) | high | bidi controls reorder text and are a known trick |
| `RAG-ZW-RUN` (zero-width) | medium / high | invisible payload channel; long runs are high |
| `RAG-INSTRUCTION` | high | the core "steer the model" signal, in four languages |
| `RAG-SPECIAL-TOKEN` | high | forged roles/template delimiters |
| `RAG-CANARY` | high | evaluation marker in production corpus = contamination signal |
| `RAG-HTML-COMMENT` | high / medium | hidden content; high when instruction-like |
| `RAG-HIDDEN-CSS` | medium | hiding surface; needs an instruction to be weaponised |
| `RAG-CROSS-LINGUAL` | medium | instruction in a script the document does not use |
| `RAG-MIXED-SCRIPT` | medium | homoglyph impersonation of trusted words |
| `RAG-LANG-SHIFT` | low | weak language-mixing signal, informational |

Risk score: `high` 40, `medium` 15, `low` 5, cap 100. Parsing: this is not a
probability, it is a triage heuristic.

## 3. False positives, explicitly

* Security policies, AI-safety research, red-team reports and documentation that
  *quote* injection phrases are flagged as `RAG-INSTRUCTION`. This is accepted:
  such documents should be reviewed and possibly allow-listed by path.
* A multilingual document that legitimately mixes scripts gets
  `RAG-LANG-SHIFT` / `RAG-CROSS-LINGUAL` (low/medium).
* A document about Unicode or prompt injection may contain zero-width or
  canary examples and be flagged.
* Code blocks are masked for markup rules, but NOT for instruction/ZW rules: a
  model still reads code-fence content.

## 4. What this does not claim

* Not a sanitizer and not a model-level guard: it reports risk, it does not
  neutralise the document.
* Not a full renderer: hiding techniques beyond the modelled CSS list (JS
  hiding, overlays, image text, PDF-only content) are out of scope.
* Not real language identification: Unicode script heuristics only.
* No new CVE, no disclosure process.

## 5. Limitations, explicitly

* Line/column are approximate for multi-line patterns.
* Custom encodings and rare scripts may evade the invisible-character rules.
* Canary patterns are examples; extend `--canary` for your own markers.
* Large corpora: the scanner is O(text) but reads whole files into memory; stream
  or chunk for very large documents.
* A `clean` verdict means "none of the modelled signals fired", not "safe".

## 6. Recommended pipeline

1. Extract text with the same extractor the RAG pipeline uses (not the rendered view).
2. Normalise Unicode; strip zero-width/bidi/Tags characters.
3. Remove HTML comments and hidden containers.
4. Scan with this tool; quarantine and review `poisoned` documents, allow-list
   reviewed false positives.
5. Keep retrieved text clearly delimited as data in the prompt, and keep system
   instructions in a separate, higher-priority channel.
6. Track canaries and alert when they appear outside the evaluation set.

## 7. Prior art

* Greshake et al., "Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection" (arXiv:2302.12173).
* Public 2024 reporting on invisible-Unicode prompt injection / ASCII smuggling.
* Unicode confusables guidance.
* Canary-based data-contamination detection in LLM evaluation sets.
