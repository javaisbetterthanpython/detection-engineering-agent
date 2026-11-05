import re
from collections import Counter
from difflib import get_close_matches

from pydantic import BaseModel

from .models import Inventory

BUILTINS = {"index", "sourcetype", "source", "host", "earliest", "latest", "_time", "_raw", "count", "firstTime", "lastTime"}
KEYWORDS = {"AND", "OR", "NOT", "IN", "as", "by"}
OPTION_WORDS = {"field", "value", "input", "output", "outputnew", "max_match", "offset_field", "mode", "limit", "span",
                "delim", "usenull", "allnum", "otherfield", "local", "keepempty", "consecutive", "path", "prefix", "timeformat",
                "maxspan", "maxpause", "window"}
_SKIP = BUILTINS | KEYWORDS | OPTION_WORDS
_BY = re.compile(r"\bby\s+([\w.,=\s]+?)(?=\||$)", re.I)
_VALUE = r'(?:"[^"]*"|[^\s)\]]+)'
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "mon": 2592000}
_BANNED = r"\|\s*(head|delete|collect|outputlookup|sendemail|script|run|map|dump|rest|dbxquery)\b"
_FUNC = r"\b(?:lower|upper|len|trim|ltrim|rtrim|match|like|isnull|isnotnull|coalesce|replace|substr|split|mvcount|tonumber|tostring|cidrmatch|urldecode)\(\s*([A-Za-z_][\w.]*)\b(?!\s*\()"
_NOT_GROUP = r"NOT\s*\((?:[^()]|\([^()]*\))*\)"  # `NOT (a=1 OR b=2)`, one level of nesting
_QUOTED = r'"(?:\\.|[^"\\])*"'


def _unquote(s: str) -> str:
    """Blank double-quoted strings (backslash escapes honoured) so regexes never see a literal value as SPL."""
    return re.sub(_QUOTED, '""', s)


class Lint(BaseModel):
    errors: list[str] = []
    warnings: list[str] = []


def normalise(s: str) -> str:
    s = re.sub(r"\s+", " ", s.strip())
    s = re.sub(r"^search\s+", "", s, flags=re.I)
    return re.sub(r"\s*\|\s*`\w+_filter`$", "", s)


def runnable(s: str) -> str:
    s = normalise(s)
    return s if s.startswith("|") else f"search {s}"


def with_filter(s: str, stem: str) -> str:
    return f"{normalise(s)} | `{stem}_filter`"


def window_seconds(w: str) -> int:
    m = re.fullmatch(r"-(\d+)([smhdw])(@\w+)?", w)
    if not m:
        raise ValueError(f"invalid window {w!r}")
    return int(m[1]) * _UNITS[m[2]]


def _split(s: str) -> list[str]:
    """Split on top-level `|`: outside double-quoted strings (backslash escapes honoured) and outside `[subsearch]` brackets."""
    s, segs, quoted, depth, start, i = normalise(s), [], False, 0, 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and quoted:
            i += 1
        elif c == '"':
            quoted = not quoted
        elif c == "[" and not quoted:
            depth += 1
        elif c == "]" and not quoted and depth:
            depth -= 1
        elif c == "|" and not quoted and not depth:
            segs.append(s[start:i].strip())
            start = i + 1
        i += 1
    return segs + [s[start:].strip()]


def _names(csv: str) -> list[str]:
    return [f for f in re.split(r"[,\s]+", csv.strip().rstrip("]")) if f]


def _by_names(s: str) -> list[str]:
    return [f for by in _BY.findall(s) for f in _names(by) if f != "_time" and not f.startswith("span=")]


def referenced_fields(s: str) -> set[str]:
    s = _unquote(s)
    found = re.findall(r"(\w[\w.]*)\s*(?:!=|<=|>=|=|<|>)", s) + re.findall(r"(\w[\w.]*)\s+IN\s*\(", s)
    found += _by_names(s)
    found += re.findall(r"\b(?:count|dc|values|min|max|sum|avg|earliest|latest|first|last|list)\(([\w.]+)\)", s)
    found += re.findall(_FUNC, s)  # first argument of eval/where functions: `where match(F, ...)`, `eval x=lower(F)`
    found += re.findall(r"\brex\s+field\s*=\s*([\w.]+)", s)
    for seg in _split(s):  # columns of `| table` / `| fields [-+]`, fields of `| fillnull [value=v]`
        if m := re.match(r"(?:table|fields)\s+(.*)", seg, re.I):
            found += [f for f in _names(re.sub(r"^[-+]\s*", "", m[1])) if "*" not in f]
        elif m := re.match(r"fillnull\b(.*)", seg, re.I):
            found += _names(re.sub(rf"\bvalue\s*=\s*{_VALUE}", "", m[1], flags=re.I))
    return {f for f in found if f not in _SKIP}


def derived_fields(s: str) -> set[str]:
    q = _unquote(s)  # a quoted value such as `CommandLine="* as admin*"` must not derive `admin`; only the rex capture lives in quotes
    found = [f for seg in _split(q) for body in re.findall(r"\beval\s+(.*)", seg)
             for f in re.findall(r"(?:^|,)\s*([\w.]+)\s*=(?!=)", body)]
    found += re.findall(r"\bas\s+([\w.]+)", q, re.I)
    found += re.findall(r"\(\?<(\w+)>", s) + re.findall(r"output(?:new)?=([\w.]+)", q, re.I)
    found += [f for out in re.findall(r"\bOUTPUT(?:NEW)?\s+([\w.\s,]+?)(?=\||$)", q) for f in _names(out)]
    return set(found)


def group_fields(s: str) -> list[str]:
    segs = _split(s)
    for seg in reversed(segs):
        if re.match(r"t?stats\b", seg, re.I):
            return _by_names(seg)
    for seg in reversed(segs):
        if re.match(r"table\b", seg, re.I):
            return _names(seg[5:])
    return []


def _values(s: str, key: str) -> set[str]:
    vals = re.findall(rf"\b{key}\s*=\s*({_VALUE})", s, re.I)
    vals += [v for grp in re.findall(rf"\b{key}\s+IN\s*\(([^)]*)\)", s, re.I) for v in _names(grp)]
    return {v.strip('"') for v in vals if v.strip('"')}


def indexes_in(s: str) -> set[str]:
    return _values(s, "index")


def sourcetypes_in(s: str) -> set[str]:
    return _values(s, "sourcetype")


def exclusions(s: str) -> list[str]:
    found = re.findall(rf"NOT\s+[\w.]+\s*=\s*{_VALUE}|NOT\s+[\w.]+\s+(?i:IN)\s*\([^)]*\)|[\w.]+\s*!=\s*{_VALUE}", s)
    wheres = [seg for seg in _split(s) if re.match(r"where\b.*\bNOT\b", seg, re.I)]  # `| where NOT (...)` verbatim
    found += [g for seg in _split(s) if seg not in wheres for g in re.findall(_NOT_GROUP, seg)]  # `NOT (...)` outside `where`
    return found + wheres


def _mask(s: str) -> str:
    """Same-length copy with quoted strings and parenthesised groups blanked, so only the segment's own clauses remain."""
    out, quoted, depth, i = [], False, 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\" and quoted:
            out.append("  ")
            i += 2
            continue
        if c == '"':
            quoted = not quoted
        elif c == "(" and not quoted:
            depth += 1
        elif c == ")" and not quoted and depth:
            depth -= 1
        out.append(" " if quoted or depth or c in '"()' else c)
        i += 1
    return "".join(out)


def _by_list(seg: str) -> list[str]:
    return [f for by in _BY.findall(_mask(seg)) for f in _names(by)]


def _add_by(seg: str, item: str) -> str:
    m = re.search(r"\bby\s+", _mask(seg), re.I)  # the grouping clause, never a `by` inside `eval(... "by ...")`
    return f"{seg[:m.start()]}by {item} {seg[m.end():]}" if m else f"{seg} by {item}"


def bucketed(s: str, span: str = "20m") -> str:
    segs = _split(s)
    i = next((i for i, seg in enumerate(segs) if i and re.match(r"stats\b", seg, re.I)), None)
    if len(segs) > 1 and segs[0] == "" and re.match(r"tstats\b", segs[1], re.I):
        if "_time" in _by_list(segs[1]):
            return s
        segs[1] = _add_by(segs[1], f"_time span={span}")
    elif i:
        if "_time" in _by_list(segs[i]):  # already schedule-shaped (`| bin _time span=20m | stats ... by _time ...`)
            return s
        segs[i] = _add_by(segs[i], "_time")
        segs.insert(i, f"bin _time span={span}")
    else:
        return s
    return " | ".join(segs).lstrip()


def lint(spl: str, inventory: Inventory, stem: str, sources: list[str]) -> Lint:
    n = normalise(spl)
    nq = _unquote(n)  # rules 1, 2 and 5 read SPL syntax, so a quoted `latest=`, `|run` alternation or backtick is not it
    out = Lint()
    if re.search(r"(?:earliest|latest)=|_index_(?:earliest|latest)", nq, re.I):
        out.errors.append("time modifiers (earliest/latest/_index_*) are not allowed; the schedule sets the window")
    for cmd in re.findall(_BANNED, nq, re.I):
        out.errors.append(f"banned command '| {cmd}'")
    idx, sts = indexes_in(n), sourcetypes_in(n)
    if not idx and not n.startswith("`"):
        out.errors.append("no index= / index IN term (or a leading macro)")
    if "*" in idx:
        out.errors.append("index=* is not allowed")
    out.errors += [f"unknown index '{ix}'" for ix in sorted(idx - {"*"} - inventory.index_names())]
    out.errors += [f"unknown sourcetype '{st}'" for st in sorted(sts - inventory.sourcetype_names())]
    macros = set(inventory.macros) | {f"{stem}_filter"}
    out.errors += [f"unknown macro '`{m}`'" for m in re.findall(r"`(\w+)(?:\([^)]*\))?`", nq) if m not in macros]
    known = set().union(*(inventory.fields_for(st) for st in (sts or sources)))
    soft = bool(re.search(r"\|\s*tstats\b|datamodel=", n))
    for f in sorted(referenced_fields(n) - derived_fields(n) - known):
        if soft:  # data-model fields are not in the inventory by design
            out.warnings.append(f"unverified field '{f}'")
        else:
            hint = get_close_matches(f, known, n=1, cutoff=0.8)
            out.errors.append(f"unknown field '{f}' " + (f"(did you mean '{hint[0]}'?)" if hint else "(not in available_fields)"))
    base = re.sub(r'"[^"]*"', '""', _split(n)[0])
    if re.search(r"(?:^|\s)\*\S", base) or re.search(r'_raw="\*', n):
        out.errors.append("bare leading-wildcard term scans every event; anchor it to a field")
    if not group_fields(n):
        out.errors.append("no group fields: end with | stats count ... by <fields> or | table <fields>")
    if len(n) > 4000:
        out.warnings.append("search longer than 4000 chars")
    slow = re.findall(r"\|\s*(transaction|streamstats)\b", n)
    slow += ["eval with earliest()/latest()"] * bool(re.search(r"\|\s*eval\b[^|]*\b(?:earliest|latest)\(", n))
    slow += [f"span={v}{u}" for v, u in re.findall(r"span=(\d+)(mon|[smhdw])\b", n) if int(v) * _UNITS[u] > 1200]
    out.warnings += [f"schedule: {c} cannot complete inside the 20-minute dispatch window" for c in slow]
    return out


def _distinct(rows: list[dict], field: str) -> int:
    return len({str(r.get(field)) for r in rows})


def top_values(rows: list[dict], fields: list[str], n: int = 5) -> dict[str, list[tuple[str, int]]]:
    out = {}
    for f in fields:
        if rows and _distinct(rows, f) <= 0.8 * len(rows):
            c = Counter()
            for r in rows:
                c[str(r.get(f, ""))] += int(r.get("count", 1))
            out[f] = c.most_common(n)
    return out


def high_cardinality(rows: list[dict], fields: list[str], min_rows: int = 10) -> list[tuple[str, int, int]]:
    if len(rows) < min_rows:  # a handful of rows is always "distinct"; the line would tell the tuner to drop its only group field
        return []
    return [(f, d, len(rows)) for f in fields if (d := _distinct(rows, f)) > 0.8 * len(rows)]


def project(rows: list[dict], fields: list[str], n: int = 5) -> list[dict]:
    return [{k: r[k] for k in fields if k in r} for r in rows[:n]]


def rewrite_index(s: str, index: str, host: str | None = None) -> str:
    scope = f'index={index} host="{host}"' if host else f"index={index}"
    first = iter([scope])
    out, n = re.subn(rf"\bindex\s*=\s*{_VALUE}|\bindex\s+IN\s*\([^)]*\)", lambda _: next(first, f"index={index}"), s, flags=re.I)
    if not n:  # no index term (leading macro, lint rule 3): scope the search explicitly or recall would read the macro's production index
        out = re.sub(r"^(search\s+|\|\s*tstats\b.*?\bwhere\s+)", lambda m: f"{m[1]}{scope} ", s, count=1, flags=re.I)
    return out
