# rag-poison-guard

[![CI](https://github.com/Qin-z-x/rag-poison-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Qin-z-x/rag-poison-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![stdlib-only core](https://img.shields.io/badge/core-stdlib%20only-brightgreen.svg)](scripts/check_core_deps.py)

**Scan a RAG corpus for poisoning risks before you index it.** Retrieved
documents that try to *steer* the model rather than inform the user are a
well-known indirect-prompt-injection problem: hidden CSS text, HTML comments,
zero-width/bidi payloads, multilingual "ignore previous instructions" phrasing,
forged chat special tokens and canary markers. This tool gives each document a
risk score, a verdict and evidence snippets, and can gate ingestion in CI.

```console
$ python -m rag_poison_guard scan examples/corpus
rag-poison-guard 0.1.0  scan  6 document(s)
doc 1/6  examples/corpus/clean_doc.md                         risk=0   verdict=clean  findings=0
doc 2/6  examples/corpus/mixed_language.md                    risk=100 verdict=poisoned  findings=4
  MEDIUM RAG-CROSS-LINGUAL      line 5  col 1  instruction appears in a script that is not the document's dominant script (CJK vs LATIN)
  HIGH   RAG-INSTRUCTION        line 5  col 1  instruction-injection phrasing (zh-ignore): '忽略之前的所有指令'
  LOW    RAG-LANG-SHIFT         line 5  col 1  line is mostly CJK while the document is mostly LATIN
  HIGH   RAG-INSTRUCTION        line 6  col 1  instruction-injection phrasing (es-ignore): 'Ignora las instrucciones anteriores'
doc 3/6  examples/corpus/poisoned_canary.md                   risk=40  verdict=poisoned  findings=1
  HIGH   RAG-CANARY             line 3  col 63  canary marker in the corpus: 'RAG-CANARY-7C1A9B'
...
summary: 6 document(s), 16 finding(s): 13 high, 2 medium, 1 low; poisoned=5 suspicious=0 clean=1
```

## Why this matters (public prior art)

| Risk | Where it comes from | Reference class |
| --- | --- | --- |
| Hidden instructions in retrieved text | web pages, PDFs, HTML docs, issue comments | indirect prompt injection (Greshake et al., 2023) |
| Invisible payload characters | zero-width runs, bidi controls, Unicode Tags block | invisible-Unicode / ASCII-smuggling reporting (2024) |
| Forged chat roles | `<\|im_start\|>`, `[INST]`, `### System` copied from templates | prompt-template injection |
| Canary leaks | evaluation-set markers showing up in training/prompt corpora | data-contamination and leak detection |
| Homoglyph impersonation | Cyrillic/Greek letters inside Latin words | Unicode confusables |

This project is a **content scanner**, not a clean-room guarantee; see the
honest scope below.

## Install

```bash
git clone https://github.com/Qin-z-x/rag-poison-guard.git
cd rag-poison-guard
python -m pip install -e .       # optional: installs the rag-poison-guard CLI
```

No runtime dependencies. Python 3.10+.

## CLI

```text
python -m rag_poison_guard scan   <path...> [--ext .md,.txt] [--canary STR]... [--json] [--fail-on {low,medium,high}]
python -m rag_poison_guard report <path...> [--json]
```

Paths may be files or directories (recursive). Exit codes: `0` success / gate
not reached, `1` `--fail-on` threshold reached, `2` usage error or missing path.

Example integrations:

```bash
# gate a RAG ingestion job: refuse the corpus if any high-risk document exists
python -m rag_poison_guard scan corpus/ --fail-on high

# review per-document risk in a machine-readable form
python -m rag_poison_guard scan corpus/ --json > corpus-risk.json

# detect a custom marker in addition to the default canary patterns
python -m rag_poison_guard scan corpus/ --canary RAG-CANARY-7C1A9B --canary SECRET-12345
```

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| `RAG-HIDDEN-CSS` | medium | `display:none`, `visibility:hidden`, zero font size, off-screen absolute positioning, `hidden` attribute |
| `RAG-HTML-COMMENT` | high / medium | comment containing an instruction phrase / large hidden comment |
| `RAG-ZW-RUN` | high / medium | zero-width and variation-selector runs; bidi controls |
| `RAG-TAG-PAYLOAD` | high | Unicode Tags block characters (invisible ASCII channel) |
| `RAG-INSTRUCTION` | high | ignore/disregard/forget/override phrasing in EN, ZH, JA, ES; "you are now", "reveal the system prompt", "do not tell the user" |
| `RAG-CROSS-LINGUAL` | medium | instruction phrasing in a script that is not the document's dominant script |
| `RAG-SPECIAL-TOKEN` | high | `<\|im_start\|>`, `<\|endoftext\|>`, `<<SYS>>`, `[INST]`, `### System` and similar |
| `RAG-CANARY` | high | default canary patterns and user-supplied `--canary` markers |
| `RAG-MIXED-SCRIPT` | medium | Latin/Cyrillic/Greek homoglyph words |
| `RAG-LANG-SHIFT` | low | a line mostly in a different script than the document |

Risk score: `high` = 40, `medium` = 15, `low` = 5, capped at 100. Verdict:
`clean` (no findings), `poisoned` (any high finding or score >= 40),
`suspicious` otherwise.

**Code blocks are masked for markup rules** so documentation examples like
`<div style="display:none">` do not trigger `RAG-HIDDEN-CSS` (tested). Invisible
characters and instruction phrases are still scanned everywhere, because a model
reads the raw text.

## Tests and CI

```bash
python scripts/check_core_deps.py            # stdlib-only core check
python -m unittest discover -s tests -t .    # 39 tests
python scripts/capture_evidence.py           # regenerate docs/EVIDENCE.md + captures
```

CI (`.github/workflows/ci.yml`) runs on GitHub Actions for Python 3.10 and 3.12:
stdlib-only check, unit tests, a corpus JSON smoke test, the clean-document gate,
the custom-canary gate and both expected outcomes of the `--fail-on high` gate.

## Honest scope and limits

* **Heuristic, not proof.** The scanner prioritises review; it cannot prove a
  corpus is clean. Renderer-specific hiding tricks, JS-driven hiding, image text
  and PDF-only content are out of scope.
* Documents that *quote* injection phrases (security policies, AI-safety papers,
  red-team reports) are flagged. This is a documented false positive, not
  special-cased away.
* Language-shift detection uses Unicode scripts, not real language ID, and can
  fire on legitimately multilingual documents (low severity).
* Invisible-character rules are an independent implementation of a public
  approach; they do not decode every encoding scheme.
* Quarantine is a policy decision: review the evidence snippet before blocking.
* This does not disclose a new vulnerability and does not claim a new CVE.
* Canaries in the examples are synthetic.

## Suggested GitHub topics

`security`, `llm`, `rag`, `prompt-injection`, `data-poisoning`, `zero-width`,
`python`, `cli`, `ai-safety`, `sanitizer`

## 中文简介

**rag-poison-guard** 用于在入库/检索前扫描 RAG 文档语料的投毒与隐藏内容风险，包括：
CSS 隐藏文本（`display:none`、`visibility:hidden`、零字号、绝对定位移出屏幕、`hidden` 属性）、
HTML 注释中的指令、零宽/双向控制符与 Unicode Tags 隐藏信道、多语言“忽略之前指令”变体
（英/中/日/西）、伪造的对话特殊 token（`<|im_start|>`、`[INST]`、`### System` 等）、
canary 标记、混合文字同形字以及文档主导语言异常偏移。每个文档输出风险分（0–100）、
结论（clean / suspicious / poisoned）与证据片段，并支持 `--json`、`--canary`（可重复）
和 `--fail-on` 门禁。核心库**仅使用 Python 标准库**。

代码块中的 HTML 示例不会触发隐藏内容规则（已测试），但隐形字符与指令短语在所有文本中
都会被扫描——因为模型读取的是原始文本。本项目是启发式内容扫描器，不能证明语料干净；
引用攻击话术的安全政策文档会被标记，这是已记录在文档中的误报。示例语料全部为合成数据，
不声称发现新漏洞或新 CVE。

## 视频演示

B站：https://www.bilibili.com/video/BV1BE1pztE4o（67 秒）

视频使用本仓库自带的合成/无害样例与真实命令输出；本项目是启发式检测工具，边界见上文说明。

## License

MIT -- see [LICENSE](LICENSE). Prior art acknowledged: indirect prompt injection
(Greshake et al.), invisible-Unicode/ASCII-smuggling reporting, Unicode
confusables, and canary-based data-contamination detection.
