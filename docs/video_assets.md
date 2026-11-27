# Video assets: rag-poison-guard

Every command and output below was captured from the real CLI over the synthetic corpus in examples/corpus/.

## Beat sheet (outputs are captured from real runs)

| time | beat | command | captured output (first line) |
| --- | --- | --- | --- |
| 0:00-0:30 | Hook: a clean-looking corpus hides injected instructions | `python -m rag_poison_guard scan examples/corpus` | rag-poison-guard 0.1.0  scan  6 document(s) |
| 0:30-1:05 | Gate ingestion on high-risk documents | `python -m rag_poison_guard scan examples/corpus --fail-on high` | rag-poison-guard 0.1.0  scan  6 document(s) |
| 1:05-1:40 | Canary markers and custom canaries | `python -m rag_poison_guard scan examples/corpus/poisoned_canary.md --canary SECRET-12345` | rag-poison-guard 0.1.0  scan  1 document(s) |
| 1:40-2:10 | A clean document stays clean | `python -m rag_poison_guard scan examples/corpus/clean_doc.md --fail-on low` | rag-poison-guard 0.1.0  scan  1 document(s) |
| 2:10-2:35 | Tests and honest limits | python -m unittest discover -s tests -t . | Ran 39 tests in ... OK |

## Real command transcripts for the recording

### 0:00-0:30 -- Hook: a clean-looking corpus hides injected instructions

Point at the per-document risk scores and the poisoned verdicts; open the hidden HTML doc to show the content a renderer would hide.

```console
$ python -m rag_poison_guard scan examples/corpus
rag-poison-guard 0.1.0  scan  6 document(s)
doc 1/6  examples/corpus/clean_doc.md                         risk=0   verdict=clean  findings=0
doc 2/6  examples/corpus/mixed_language.md                    risk=100 verdict=poisoned  findings=4
  MEDIUM RAG-CROSS-LINGUAL      line 5    col 1    instruction appears in a script that is not the document's dominant script (CJK vs LATIN)
  HIGH   RAG-INSTRUCTION        line 5    col 1    instruction-injection phrasing (zh-ignore): '忽略之前的所有指令'
  LOW    RAG-LANG-SHIFT         line 5    col 1    line is mostly CJK while the document is mostly LATIN
  HIGH   RAG-INSTRUCTION        line 6    col 1    instruction-injection phrasing (es-ignore): 'Ignora las instrucciones anteriores'
doc 3/6  examples/corpus/poisoned_canary.md                   risk=40  verdict=poisoned  findings=1
  HIGH   RAG-CANARY             line 3    col 63   canary marker in the corpus: 'RAG-CANARY-7C1A9B'
doc 4/6  examples/corpus/poisoned_hidden_html.md              risk=100 verdict=poisoned  findings=5
  MEDIUM RAG-HIDDEN-CSS         line 5    col 1    markup hides content from a human renderer but not from text extraction
  HIGH   RAG-INSTRUCTION        line 5    col 27   instruction-injection phrasing (en-ignore): 'IGNORE ALL PREVIOUS INSTRUCTIONS'
  HIGH   RAG-HTML-COMMENT       line 9    col 1    HTML comment contains an instruction-like payload (en-ignore)
  HIGH   RAG-INSTRUCTION        line 9    col 13   instruction-injection phrasing (en-ignore): 'OVERRIDE: f
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 0]
```

### 0:30-1:05 -- Gate ingestion on high-risk documents

`--fail-on high` exits 1, so a RAG ingestion job can refuse the corpus.

```console
$ python -m rag_poison_guard scan examples/corpus --fail-on high
rag-poison-guard 0.1.0  scan  6 document(s)
doc 1/6  examples/corpus/clean_doc.md                         risk=0   verdict=clean  findings=0
doc 2/6  examples/corpus/mixed_language.md                    risk=100 verdict=poisoned  findings=4
  MEDIUM RAG-CROSS-LINGUAL      line 5    col 1    instruction appears in a script that is not the document's dominant script (CJK vs LATIN)
  HIGH   RAG-INSTRUCTION        line 5    col 1    instruction-injection phrasing (zh-ignore): '忽略之前的所有指令'
  LOW    RAG-LANG-SHIFT         line 5    col 1    line is mostly CJK while the document is mostly LATIN
  HIGH   RAG-INSTRUCTION        line 6    col 1    instruction-injection phrasing (es-ignore): 'Ignora las instrucciones anteriores'
doc 3/6  examples/corpus/poisoned_canary.md                   risk=40  verdict=poisoned  findings=1
  HIGH   RAG-CANARY             line 3    col 63   canary marker in the corpus: 'RAG-CANARY-7C1A9B'
doc 4/6  examples/corpus/poisoned_hidden_html.md              risk=100 verdict=poisoned  findings=5
  MEDIUM RAG-HIDDEN-CSS         line 5    col 1    markup hides content from a human renderer but not from text extraction
  HIGH   RAG-INSTRUCTION        line 5    col 27   instruction-injection phrasing (en-ignore): 'IGNORE ALL PREVIOUS INSTRUCTIONS'
  HIGH   RAG-HTML-COMMENT       line 9    col 1    HTML comment contains an instruction-like payload (en-ignore)
  HIGH   RAG-INSTRUCTION        line 9    col 13   instruction-injection phrasing (en-ignore): 'OVERRIDE: f
... (truncated; full output in docs/EVIDENCE.md)
[exit code: 1]
```

### 1:05-1:40 -- Canary markers and custom canaries

Canary tokens are how a team proves a document leaked into training or a prompt.

```console
$ python -m rag_poison_guard scan examples/corpus/poisoned_canary.md --canary SECRET-12345
rag-poison-guard 0.1.0  scan  1 document(s)
doc 1/1  examples/corpus/poisoned_canary.md                   risk=80  verdict=poisoned  findings=2
  HIGH   RAG-CANARY             line 3    col 63   canary marker in the corpus: 'RAG-CANARY-7C1A9B'
  HIGH   RAG-CANARY             line 4    col 36   configured canary marker found: 'SECRET-12345'
summary: 1 document(s), 2 finding(s): 2 high, 0 medium, 0 low; poisoned=1 suspicious=0 clean=0
[exit code: 0]
```

### 1:40-2:10 -- A clean document stays clean

No findings at `--fail-on low`; the code block containing HTML is documentation and is explained in THREAT_MODEL.

```console
$ python -m rag_poison_guard scan examples/corpus/clean_doc.md --fail-on low
rag-poison-guard 0.1.0  scan  1 document(s)
doc 1/1  examples/corpus/clean_doc.md                         risk=0   verdict=clean  findings=0
summary: 1 document(s), 0 finding(s): 0 high, 0 medium, 0 low; poisoned=0 suspicious=0 clean=1
PASS: no finding at or above severity 'low'
[exit code: 0]
```

### 2:10-2:35 -- Tests and honest limits

```console
$ python -m unittest discover -s tests -t .
Ran 39 tests
OK
```

## Ready files for the edit

- `docs/screenshots/terminal_canary.txt`
- `docs/screenshots/terminal_clean.txt`
- `docs/screenshots/terminal_gate.txt`
- `docs/screenshots/terminal_scan.txt`
- `docs/screenshots/terminal_tests.txt`
- `docs/EVIDENCE.md`
- `examples/corpus/poisoned_hidden_html.md`

## OBS/screen-recording notes

- Record a 1920x1080 terminal at 120x32 characters; the commands above fit without wrapping.
- Run every command from the repository root so the relative paths match.
- The JSON runs are for the evidence log only and are not needed on camera.

## Caveats to state on camera

The corpus is synthetic. Heuristics can miss renderer-specific hiding tricks and can flag documents that deliberately quote attack phrases (e.g. security policies). Tune and review before quarantining.
