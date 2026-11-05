"""Print a mermaid stateDiagram-v2 of the pipeline from pipeline.TRANSITIONS / STATES / TERMINAL.

    uv run python docs/scripts/state_diagram.py

Paste the output into docs/pipeline.md. One edge per TRANSITIONS entry (the `fail` transition from `*`
becomes a note); the label is `trigger / conditions`, `else` for the unguarded fallback of a trigger,
plus the `after` callback in parentheses. Edge labels are ASCII only.
"""

from detection_engineering_agent.pipeline import NEXT, STATES, TERMINAL, TRANSITIONS


def label(t: dict, guarded_before: bool) -> str:
    cond = t.get("conditions") or ("else" if guarded_before else "")
    text = t["trigger"] + (f" / {cond}" if cond else "")
    return text + (f" ({t['after']})" if t.get("after") else "")


def main() -> None:
    lines = ["stateDiagram-v2", "    direction LR", "    [*] --> start"]
    seen_guard: dict[str, bool] = {}
    for t in TRANSITIONS:
        if t["source"] == "*":
            continue
        lines.append(f"    {t['source']} --> {t['dest']} : {label(t, seen_guard.get(t['trigger'], False))}")
        seen_guard[t["trigger"]] = seen_guard.get(t["trigger"], False) or bool(t.get("conditions"))
    for s in STATES:
        if s in TERMINAL and s != "error":
            lines.append(f"    {s} --> [*]")
    fail = next(t for t in TRANSITIONS if t["source"] == "*")
    lines += [
        f"    note right of {next(iter(NEXT))}",
        f"        {fail["trigger"]}: from any state to {fail["dest"]} on an exception or the cost cap",
        f"        ({fail['before']} keeps prior_state; dea run --resume re-enters it)",
        "    end note",
    ]
    print("\n".join(lines))


if __name__ == "__main__":
    main()
