"""Standup prep prompts.

Nothing here is pulled from a system — the team's standup is verbal, so
this is just the three categories you track, included as a memory-jogger
rather than automated data. If that ever moves somewhere queryable (e.g.
Zoom AI Companion meeting summaries), this is where a real integration
would replace the static prompts.
"""
try:
    from .report import Section, Status
except ImportError:
    from report import Section, Status


def prep_section() -> Section:
    return Section(
        title="Standup Prep",
        status=Status.OK,
        summary="Prompts only — nothing pulled automatically.",
        notes=[
            "Interesting things the team is working on (share for learning/collaboration)?",
            "Blockers — what's stopping progress?",
            "Help needed — asks or side projects that aren't blockers?",
        ],
    )
