"""Rendering for daily check results: a plain-text console view and a markdown file."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List


class Status(str, Enum):
    OK = "OK"
    ATTENTION = "ATTENTION"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


STATUS_ICON = {
    Status.OK: "✅",
    Status.ATTENTION: "⚠️",
    Status.SKIPPED: "⏭️",
    Status.ERROR: "❌",
}


@dataclass
class Section:
    title: str
    status: Status
    summary: str
    row_headers: List[str] = field(default_factory=list)
    rows: List[List[str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def render_console(sections: List[Section]) -> str:
    lines = [f"Daily Checks — {datetime.now().strftime('%Y-%m-%d %H:%M')}", "=" * 60]
    for s in sections:
        lines.append("")
        lines.append(f"{STATUS_ICON[s.status]} {s.title} — {s.summary}")
        if s.row_headers and s.rows:
            widths = [len(h) for h in s.row_headers]
            str_rows = [[str(c) for c in row] for row in s.rows]
            for row in str_rows:
                for i, cell in enumerate(row):
                    widths[i] = max(widths[i], len(cell))
            header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(s.row_headers))
            lines.append("  " + header_line)
            lines.append("  " + "-" * len(header_line))
            for row in str_rows:
                lines.append("  " + "  ".join(c.ljust(widths[i]) for i, c in enumerate(row)))
        for n in s.notes:
            lines.append(f"  note: {n}")
    return "\n".join(lines)


def render_markdown(sections: List[Section]) -> str:
    lines = [f"# Daily Checks — {datetime.now().strftime('%Y-%m-%d %H:%M')}", ""]
    for s in sections:
        lines.append(f"## {STATUS_ICON[s.status]} {s.title}")
        lines.append(s.summary)
        lines.append("")
        if s.row_headers and s.rows:
            lines.append("| " + " | ".join(s.row_headers) + " |")
            lines.append("|" + "|".join(["---"] * len(s.row_headers)) + "|")
            for row in s.rows:
                lines.append("| " + " | ".join(str(c) for c in row) + " |")
            lines.append("")
        for n in s.notes:
            lines.append(f"> {n}")
        lines.append("")
    return "\n".join(lines)


def write_report(sections: List[Section], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"daily-checks-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    path.write_text(render_markdown(sections), encoding="utf-8")
    return path
