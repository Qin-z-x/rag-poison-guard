"""rag_poison_guard core: scan RAG documents for poisoning and hidden-content risk.

The scanner deliberately combines independent signals instead of one regex:

* markup hiding (CSS, HTML comments, hidden attribute) -- text a human renderer
  will not show but a text extractor will feed to the model;
* invisible character payloads (zero-width, bidi controls, Tags block);
* instruction-injection phrasing in English, Chinese, Japanese and Spanish;
* chat special tokens and canary markers;
* mixed-script homoglyph words and unusual dominant-language shifts.

Each document gets a risk score and a verdict; nothing here proves a document is
clean, it prioritises review.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES, start=1)}
RISK_WEIGHTS = {"low": 5, "medium": 15, "high": 40}
DEFAULT_EXTENSIONS = (".md", ".markdown", ".txt", ".rst", ".html", ".htm", ".json", ".csv", ".xml", ".yaml", ".yml")

ZERO_WIDTH_CHARS = frozenset(
    "\u180e\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\u034f\ufe0e\ufe0f\ufeff"
)
BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
TAG_BLOCK = range(0xE0000, 0xE0080)
VS_SUPPLEMENT = range(0xE0100, 0xE01F0)

HIDDEN_CSS_RE = re.compile(
    r"(?is)<[a-z][^>]*?(?:"
    r"style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[.\d]*)?(?:\s*;|\s*[\"']))"
    r"|style\s*=\s*[\"'][^\"']*font-size\s*:\s*0(?:px|em|%)?"
    r"|style\s*=\s*[\"'][^\"']*position\s*:\s*absolute[^\"']*(?:left|top|right|bottom)\s*:\s*-\d{3,}"
    r"|hidden(?:\s|=|>)"
    r")"
)
HTML_COMMENT_RE = re.compile(r"(?s)<!--(.*?)-->")
SPECIAL_TOKEN_RE = re.compile(
    r"(?i)(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<\|endofprompt\|>|<<SYS>>|\[/?INST\]|###\s*(?:instruction|system|assistant)\b|<\|system\|>)"
)
TAG_PAYLOAD_RE = re.compile("[\U000E0000-\U000E007F]")
CANARY_DEFAULT_RE = re.compile(
    r"(?i)\b(?:rag[-_ ]?canary|leak[-_ ]?canary)[-_ ][a-z0-9]{4,}\b"
    r"|\bcanary[-_ ]?[a-z0-9]{6,}\b"
    r"|\bcanary\s+token\b|\bdo not expose\b"
)
MIXED_WORD_RE = re.compile(r"[^\W\d_]{4,}", re.UNICODE)

INSTRUCTION_PATTERNS = [
    (
        "en-ignore",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}?"
            r"\b(?:previous|prior|above|earlier|system|all)\b[^.\n]{0,24}?"
            r"\b(?:instructions?|prompts?|rules|guidance|context|directions?)\b"
        ),
    ),
    (
        "en-role",
        re.compile(
            r"(?i)(?:\byou are now\b|\bnew instructions?\s*:|\bfrom now on you\b|\bact as (?:an?|the) (?:admin|developer|system)\b"
            r"|\breveal (?:your|the) (?:system )?prompt\b|\bdo not (?:tell|inform|reveal)\b[^.\n]{0,30}\b(?:user|human)\b)"
        ),
    ),
    (
        "en-ignore-user",
        re.compile(r"(?i)\bignore (?:the )?(?:user|human)(?:'s)? (?:question|request|message)\b"),
    ),
    (
        "zh-ignore",
        re.compile(r"(?:忽略|无视|忘掉|跳过)(?:之前|以上|前面|先前|所有|上面)(?:的)?(?:所有|全部)?(?:指令|提示|规则|内容|要求)"),
    ),
    ("zh-new", re.compile(r"(?:新的?|以下的?)(?:指令|提示)[:：]")),
    ("zh-dont-tell", re.compile(r"不要告诉(?:用户|他|她|任何人)|不要向用户透露")),
    ("ja-ignore", re.compile(r"(?:以前|これまで|上記|前)の(?:指示|命令|ルール)(?:を)?(?:無視|忘れ)")),
    ("es-ignore", re.compile(r"(?i)\bignora(?:r)? (?:las )?instrucciones (?:anteriores|previas|del sistema)\b")),
]

SCRIPT_NAMES = {
    "LATIN": "LATIN",
    "CYRILLIC": "CYRILLIC",
    "GREEK": "GREEK",
    "CJK": "CJK",
    "HIRAGANA": "JAPANESE",
    "KATAKANA": "JAPANESE",
    "HANGUL": "HANGUL",
    "ARABIC": "ARABIC",
    "HEBREW": "HEBREW",
    "DEVANAGARI": "DEVANAGARI",
    "THAI": "THAI",
}
HOMOGLYPH_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK"})

FIXES = {
    "RAG-HIDDEN-CSS": "Strip style/hidden markup before indexing; ingest rendered text, not raw HTML with hidden containers.",
    "RAG-HTML-COMMENT": "Remove HTML comments during extraction; never feed comment content into the retrieval context.",
    "RAG-ZW-RUN": "Normalise Unicode (strip zero-width/bidi/variation selectors) before chunking and indexing.",
    "RAG-TAG-PAYLOAD": "Strip the Unicode Tags block and flag the document; Tags-block text is an invisible ASCII channel.",
    "RAG-INSTRUCTION": "Treat retrieved text as data, keep system instructions separate, and quarantine/flag the document for review.",
    "RAG-CROSS-LINGUAL": "Review instructions that appear in a different language than the document body; escalate to the same review queue as RAG-INSTRUCTION.",
    "RAG-SPECIAL-TOKEN": "Strip chat/template special tokens from ingested text so documents cannot forge roles.",
    "RAG-CANARY": "A canary marker means this document is tracked; do not index it in production and investigate how it appeared.",
    "RAG-MIXED-SCRIPT": "Normalise confusables and flag mixed-script words; homoglyph text can impersonate trusted terms.",
    "RAG-LANG-SHIFT": "Low-severity signal: a paragraph in a different script than the document. Review if the document should be monolingual.",
}
__all__ = ["Finding", "scan_document", "scan_corpus", "scan_text", "summarize", "VERSION", "DEFAULT_EXTENSIONS", "FIXES"]


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    line: int = 1
    column: int = 1
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "fix": FIXES.get(self.code, ""),
            "data": self.data,
        }


def _line_starts(text: str) -> list:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _line_col(starts, offset: int) -> tuple:
    index = bisect_right(starts, offset) - 1
    return index + 1, offset - starts[index] + 1


def _mask_code(text: str) -> str:
    """Blank fenced and inline code so markup rules do not fire on documentation examples."""
    out = []
    in_fence = False
    fence = ""
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if not in_fence and len(stripped) >= 3 and stripped[:3] in ("```", "~~~"):
            in_fence = True
            fence = stripped[:3]
            out.append(re.sub(r"[^\n]", " ", line))
            continue
        if in_fence:
            out.append(re.sub(r"[^\n]", " ", line))
            if stripped.startswith(fence):
                in_fence = False
            continue
        out.append(re.sub(r"`[^`\n]+`", lambda match: " " * len(match.group(0)), line))
    return "".join(out)


def _script_of(char: str) -> str:
    name = unicodedata.name(char, "")
    if not name:
        return "OTHER"
    for key, value in SCRIPT_NAMES.items():
        if name.startswith(key):
            return value
    return "OTHER"


def _script_counts(text: str) -> dict:
    counts = {}
    for char in text:
        if not char.isalpha():
            continue
        script = _script_of(char)
        if script == "OTHER":
            continue
        counts[script] = counts.get(script, 0) + 1
    return counts


def _dominant_script(counts: dict) -> str:
    if not counts:
        return "OTHER"
    return max(counts.items(), key=lambda item: item[1])[0]


def scan_text(text: str, extra_canaries=None, name: str = "") -> list:
    """Return findings for one document's text."""
    extra_canaries = extra_canaries or []
    masked = _mask_code(text)
    starts = _line_starts(text)
    findings = []

    def add(code, severity, message, offset, data=None):
        line, column = _line_col(starts, offset)
        findings.append(Finding(code, severity, message, line, column, data or {}))

    for match in HIDDEN_CSS_RE.finditer(masked):
        snippet = re.sub(r"\s+", " ", match.group(0))[:160]
        add("RAG-HIDDEN-CSS", "medium", "markup hides content from a human renderer but not from text extraction", match.start(), {"snippet": snippet})
    for match in HTML_COMMENT_RE.finditer(masked):
        body = match.group(1) or ""
        instruction = _find_instruction(body)
        if instruction:
            add("RAG-HTML-COMMENT", "high", "HTML comment contains an instruction-like payload (%s)" % instruction, match.start(), {"snippet": body.strip()[:160]})
        elif len(body.strip()) >= 160:
            add("RAG-HTML-COMMENT", "medium", "large HTML comment (hidden content surface)", match.start(), {"length": len(body), "snippet": body.strip()[:120]})

    zero_count = 0
    tag_count = 0
    bidi_count = 0
    for index, char in enumerate(text):
        code_point = ord(char)
        if char in ZERO_WIDTH_CHARS:
            zero_count += 1
        elif char in BIDI_CHARS:
            bidi_count += 1
        elif code_point in TAG_BLOCK:
            tag_count += 1
        elif code_point in VS_SUPPLEMENT:
            zero_count += 1
    if tag_count:
        add("RAG-TAG-PAYLOAD", "high", "%d Unicode Tags-block characters (invisible ASCII channel)" % tag_count, _first_offset(text, lambda ch: ord(ch) in TAG_BLOCK), {"count": tag_count})
    if bidi_count:
        add("RAG-ZW-RUN", "high", "%d bidi control characters (text reordering)" % bidi_count, _first_offset(text, lambda ch: ch in BIDI_CHARS), {"count": bidi_count, "kind": "bidi"})
    if zero_count:
        severity = "high" if zero_count >= 32 else "medium"
        add("RAG-ZW-RUN", severity, "%d zero-width/variation-selector characters" % zero_count, _first_offset(text, lambda ch: ch in ZERO_WIDTH_CHARS or ord(ch) in VS_SUPPLEMENT), {"count": zero_count, "kind": "zero-width"})

    document_scripts = _script_counts(text)
    dominant = _dominant_script(document_scripts)
    for label, pattern in INSTRUCTION_PATTERNS:
        for match in pattern.finditer(text):
            add("RAG-INSTRUCTION", "high", "instruction-injection phrasing (%s): %r" % (label, _short(match.group(0))), match.start(), {"variant": label})
            line_text = _line_text(text, starts, match.start())
            line_scripts = _script_counts(line_text)
            line_dominant = _dominant_script(line_scripts)
            if dominant != "OTHER" and line_dominant != dominant and sum(line_scripts.values()) >= 8:
                add(
                    "RAG-CROSS-LINGUAL",
                    "medium",
                    "instruction appears in a script that is not the document's dominant script (%s vs %s)" % (line_dominant, dominant),
                    match.start(),
                    {"variant": label},
                )
    for match in SPECIAL_TOKEN_RE.finditer(text):
        add("RAG-SPECIAL-TOKEN", "high", "chat/template special token in ingested text: %r" % match.group(0)[:40], match.start())

    for match in CANARY_DEFAULT_RE.finditer(text):
        add("RAG-CANARY", "high", "canary marker in the corpus: %r" % _short(match.group(0)), match.start(), {"canary": match.group(0)})
    lowered = text.lower()
    for canary in extra_canaries:
        if not canary:
            continue
        position = lowered.find(canary.lower())
        while position != -1:
            add("RAG-CANARY", "high", "configured canary marker found: %r" % canary, position, {"canary": canary})
            position = lowered.find(canary.lower(), position + len(canary))

    for match in MIXED_WORD_RE.finditer(text):
        word = match.group(0)
        scripts = {_script_of(char) for char in word if char.isalpha()}
        scripts &= HOMOGLYPH_SCRIPTS
        if len(scripts) >= 2:
            add("RAG-MIXED-SCRIPT", "medium", "mixed-script homoglyph word %r" % word[:40], match.start(), {"word": word, "scripts": sorted(scripts)})

    for line_index, line in enumerate(text.splitlines()):
        counts = _script_counts(line)
        total = sum(counts.values())
        if total < 12:
            continue
        line_dominant = _dominant_script(counts)
        if dominant != "OTHER" and line_dominant != dominant:
            minor = total - counts.get(dominant, 0)
            if minor >= 8:
                offset = starts[line_index] if line_index < len(starts) else 0
                add("RAG-LANG-SHIFT", "low", "line is mostly %s while the document is mostly %s" % (line_dominant, dominant), offset, {"line": line_index + 1, "line_script": line_dominant, "document_script": dominant})

    findings.sort(key=lambda finding: (finding.line, finding.column, finding.code))
    return findings


def _first_offset(text: str, predicate) -> int:
    for index, char in enumerate(text):
        if predicate(char):
            return index
    return 0


def _short(value: str, limit: int = 120) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def _line_text(text: str, starts, offset: int) -> str:
    index = bisect_right(starts, offset) - 1
    start = starts[index]
    end = text.find("\n", start)
    if end == -1:
        end = len(text)
    return text[start:end]


def _find_instruction(text: str) -> str:
    for label, pattern in INSTRUCTION_PATTERNS:
        if pattern.search(text):
            return label
    return ""


def summarize(findings) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {"total": len(findings), "counts": counts, "max_severity": max_severity}


def risk_score(findings) -> int:
    score = sum(RISK_WEIGHTS[finding.severity] for finding in findings)
    return min(score, 100)


def verdict_for(findings) -> str:
    if not findings:
        return "clean"
    if any(finding.severity == "high" for finding in findings) or risk_score(findings) >= 40:
        return "poisoned"
    return "suspicious"


def scan_document(path, text: str = None, extra_canaries=None) -> dict:
    """Scan one document and return its per-document report."""
    document_path = Path(path)
    if text is None:
        text = document_path.read_text(encoding="utf-8", errors="replace")
    findings = scan_text(text, extra_canaries=extra_canaries, name=str(path))
    summary = summarize(findings)
    return {
        "path": document_path.as_posix(),
        "name": document_path.name,
        "bytes": len(text.encode("utf-8")),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "lines": len(text.splitlines()),
        "findings": [finding.to_dict() for finding in findings],
        "summary": summary,
        "risk_score": risk_score(findings),
        "verdict": verdict_for(findings),
    }


def iter_documents(paths, extensions=DEFAULT_EXTENSIONS) -> list:
    """Resolve files and directories into a deterministic, sorted document list."""
    extensions = tuple(ext.lower() for ext in extensions)
    documents = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and child.suffix.lower() in extensions:
                    documents.append(child)
        elif path.is_file():
            documents.append(path)
        else:
            raise FileNotFoundError(str(path))
    unique = []
    seen = set()
    for document in documents:
        key = document.resolve().as_posix()
        if key not in seen:
            seen.add(key)
            unique.append(document)
    return unique


def scan_corpus(paths, extensions=DEFAULT_EXTENSIONS, extra_canaries=None) -> dict:
    """Scan a list of files/directories and return a corpus report."""
    documents = iter_documents(paths, extensions)
    reports = [scan_document(document, extra_canaries=extra_canaries) for document in documents]
    counts = {severity: 0 for severity in SEVERITIES}
    poisoned = 0
    total_findings = 0
    for report in reports:
        total_findings += report["summary"]["total"]
        for severity in SEVERITIES:
            counts[severity] += report["summary"]["counts"][severity]
        if report["verdict"] == "poisoned":
            poisoned += 1
    max_severity = "none"
    for severity in SEVERITIES:
        if counts[severity]:
            max_severity = severity
    return {
        "tool": "rag-poison-guard",
        "version": VERSION,
        "summary": {
            "documents": len(reports),
            "findings": total_findings,
            "counts": counts,
            "max_severity": max_severity,
            "poisoned_docs": poisoned,
            "suspicious_docs": sum(1 for report in reports if report["verdict"] == "suspicious"),
            "clean_docs": sum(1 for report in reports if report["verdict"] == "clean"),
        },
        "documents": reports,
        "clean": total_findings == 0,
    }
