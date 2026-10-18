"""A subset-of-SPL evaluator that runs the app's saved searches in Python.

Scope
-----
The goal is to execute the *exact* search strings in savedsearches.conf over
synthetic events so detection logic can be unit tested without a Splunk
instance. The subset implemented is what the 25 detections and the lookup /
macro / eventtype plumbing need:

``search`` (implicit first segment and the command)
    ``field=value`` with ``*`` wildcards, ``!=`` ``<`` ``>`` ``<=`` ``>=``,
    ``field IN (a, b)``, ``AND`` ``OR`` ``NOT`` with parentheses, bare terms
    matched against ``_raw``, ``eventtype=name`` expansion, `` `macro` ``
    expansion (with arguments).
``where``, ``eval``            see :mod:`harness.expr` for the expression subset.
``stats``, ``eventstats``, ``streamstats``
    count, count(field), count(eval(expr)), dc, sum, avg, min, max, stdev,
    stdevp, var, median, range, values, list, earliest, latest, first, last;
    ``as`` aliases; ``by`` fields. streamstats supports ``current=``,
    ``window=`` and ``time_window=``.
``bin``/``bucket`` (``span=``), ``sort`` (limit, +/- fields), ``rare``/``top``
(``limit=``, ``by``), ``lookup`` (``AS``, ``OUTPUT``/``OUTPUTNEW``),
``rex`` (named groups), ``regex``, ``rename``, ``table``, ``fields``, ``head``,
``dedup``, ``fillnull``, ``mvexpand``, ``inputlookup``.

Not implemented (raises :class:`SPLError`): subsearches, ``timechart``,
``tstats``, ``transaction``, ``join``, ``append`` and anything else not
listed above. Time range modifiers (``dispatch.earliest_time``) are not
applied: the harness evaluates the whole dataset.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .conf import SplunkConf
from .expr import (Compiled, compile_expr, compare, get_field, is_null, to_number, to_text, truthy)
from .lookups import LookupTable, load_lookups

Event = dict[str, Any]


class SPLError(ValueError):
    """Raised when a search uses syntax outside the supported subset."""


# --------------------------------------------------------------------------
# Environment: macros, eventtypes, lookups
# --------------------------------------------------------------------------
@dataclass
class Macro:
    name: str
    args: list[str]
    definition: str


@dataclass
class SPLEnvironment:
    """Knowledge objects a search can reference."""

    macros: dict[str, Macro] = field(default_factory=dict)
    eventtypes: dict[str, str] = field(default_factory=dict)
    lookups: dict[str, LookupTable] = field(default_factory=dict)

    @classmethod
    def from_app(cls, app_dir: Path | str) -> "SPLEnvironment":
        """Load macros.conf, eventtypes.conf and lookups from a Splunk app."""
        app = Path(app_dir)
        env = cls()
        macros_path = app / "default" / "macros.conf"
        if macros_path.exists():
            for stanza, settings in SplunkConf.load(macros_path).items():
                match = re.match(r"^(\w+)(?:\((\d+)\))?$", stanza)
                if not match or "definition" not in settings:
                    continue
                args = [a.strip() for a in settings.get("args", "").split(",") if a.strip()]
                env.macros[stanza] = Macro(match.group(1), args, settings["definition"])
        eventtypes_path = app / "default" / "eventtypes.conf"
        if eventtypes_path.exists():
            for stanza, settings in SplunkConf.load(eventtypes_path).items():
                if "search" in settings:
                    env.eventtypes[stanza] = settings["search"]
        transforms_path = app / "default" / "transforms.conf"
        if transforms_path.exists():
            env.lookups = load_lookups(SplunkConf.load(transforms_path), app / "lookups")
        return env


_MACRO_RE = re.compile(r"`(\w+)(?:\(((?:[^`()]|\([^`()]*\))*)\))?`")


def _split_top_level(text: str, sep: str = ",") -> list[str]:
    """Split on ``sep`` outside quotes and parentheses."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    buf: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in {'"', "'"}:
            quote = ch
            buf.append(ch)
        elif ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def expand_macros(spl: str, macros: dict[str, Macro]) -> str:
    """Replace `` `name` `` and `` `name(args)` `` with their definitions."""
    for _ in range(25):
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            raw_args = match.group(2)
            args = [a.strip() for a in _split_top_level(raw_args)] if raw_args is not None else []
            key = f"{name}({len(args)})" if args else name
            macro = macros.get(key)
            if macro is None:
                raise SPLError(f"Unknown macro `{key}`")
            definition = macro.definition
            for formal, actual in zip(macro.args, args):
                definition = definition.replace(f"${formal}$", actual)
            return definition

        new = _MACRO_RE.sub(repl, spl)
        if new == spl:
            return spl
        spl = new
    raise SPLError("Macro expansion did not converge (recursive macro?)")


_EVENTTYPE_RE = re.compile(r'\beventtype\s*=\s*("([^"]+)"|(\S+))')


def expand_eventtypes(spl: str, eventtypes: dict[str, str]) -> str:
    """Replace ``eventtype=name`` with the eventtype's search in parentheses."""
    def repl(match: re.Match[str]) -> str:
        name = match.group(2) or match.group(3)
        if name not in eventtypes:
            raise SPLError(f"Unknown eventtype {name}")
        return f"({eventtypes[name]})"

    return _EVENTTYPE_RE.sub(repl, spl)


def split_pipeline(spl: str) -> list[str]:
    """Split a search on top-level ``|`` characters (quote aware)."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(spl):
        ch = spl[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(spl):
                buf.append(spl[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == '"':
            quote = ch
            buf.append(ch)
        elif ch == "[":
            raise SPLError("Subsearches are not supported by the harness")
        elif ch == "|":
            segments.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf).strip())
    return segments


# --------------------------------------------------------------------------
# Search filter language
# --------------------------------------------------------------------------
@dataclass
class _Term:
    field: str | None
    op: str | None
    value: str
    quoted: bool


def _tokenize_search(text: str) -> list[Any]:
    tokens: list[Any] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue
        buf: list[str] = []
        fld: str | None = None
        op: str | None = None
        quoted = False
        while i < n and not text[i].isspace() and text[i] not in "()":
            c = text[i]
            if c == '"':
                quoted = True
                i += 1
                while i < n and text[i] != '"':
                    if text[i] == "\\" and i + 1 < n and text[i + 1] in {'"', "\\"}:
                        buf.append(text[i + 1])
                        i += 2
                        continue
                    buf.append(text[i])
                    i += 1
                i += 1
                continue
            if op is None and not quoted and c in "=<>!":
                if c == "!" and text[i + 1:i + 2] == "=":
                    fld, op, buf, i = "".join(buf), "!=", [], i + 2
                    continue
                if c in "<>" and text[i + 1:i + 2] == "=":
                    fld, op, buf, i = "".join(buf), c + "=", [], i + 2
                    continue
                if c in "=<>":
                    fld, op, buf, i = "".join(buf), c, [], i + 1
                    continue
            buf.append(c)
            i += 1
        tokens.append(_Term(fld, op, "".join(buf), quoted))
    return tokens


def _wildcard_regex(pattern: str) -> re.Pattern[str]:
    return re.compile("^" + ".*".join(re.escape(p) for p in pattern.split("*")) + "$", re.IGNORECASE | re.DOTALL)


Predicate = Callable[[Event], bool]


def _field_term(fld: str, op: str, value: str) -> Predicate:
    if op == "=":
        if value == "*":
            return lambda ev: not is_null(get_field(ev, fld))
        regex = _wildcard_regex(value)
        number = to_number(value) if "*" not in value else None

        def eq(ev: Event) -> bool:
            actual = get_field(ev, fld)
            if is_null(actual):
                return False
            items = actual if isinstance(actual, list) else [actual]
            for item in items:
                if regex.match(to_text(item)):
                    return True
                if number is not None and to_number(item) == number:
                    return True
            return False

        return eq
    if op == "!=":
        positive = _field_term(fld, "=", value)
        return lambda ev: (not is_null(get_field(ev, fld))) and not positive(ev)
    return lambda ev: compare(get_field(ev, fld), value, op)


def _raw_term(value: str) -> Predicate:
    if value == "*":
        return lambda ev: True
    if "*" in value:
        regex = re.compile(".*".join(re.escape(p) for p in value.split("*")), re.IGNORECASE)
        return lambda ev: regex.search(_haystack(ev)) is not None
    needle = value.lower()
    return lambda ev: needle in _haystack(ev).lower()


def _haystack(ev: Event) -> str:
    raw = ev.get("_raw")
    if raw is not None:
        return str(raw)
    return " ".join(to_text(v) for k, v in ev.items() if not k.startswith("_"))


class _SearchParser:
    """Splunk precedence: NOT binds tightest, then OR, then (implicit) AND."""

    def __init__(self, text: str) -> None:
        self.tokens = _tokenize_search(text)
        self.pos = 0

    def peek(self) -> Any:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def parse(self) -> Predicate:
        if not self.tokens:
            return lambda ev: True
        pred = self.parse_and()
        if self.peek() is not None:
            raise SPLError(f"Unbalanced parentheses in search: {self.tokens}")
        return pred

    def _is_kw(self, tok: Any, word: str) -> bool:
        return isinstance(tok, _Term) and tok.op is None and not tok.quoted and tok.value == word

    def parse_and(self) -> Predicate:
        preds = [self.parse_or()]
        while True:
            tok = self.peek()
            if tok is None or tok == ")":
                break
            if self._is_kw(tok, "AND"):
                self.pos += 1
            preds.append(self.parse_or())
        if len(preds) == 1:
            return preds[0]
        return lambda ev, ps=tuple(preds): all(p(ev) for p in ps)

    def parse_or(self) -> Predicate:
        left = self.parse_unary()
        while self._is_kw(self.peek(), "OR"):
            self.pos += 1
            right = self.parse_unary()
            left = (lambda a, b: lambda ev: a(ev) or b(ev))(left, right)
        return left

    def parse_unary(self) -> Predicate:
        tok = self.peek()
        if tok is None:
            raise SPLError("Unexpected end of search expression")
        if self._is_kw(tok, "NOT"):
            self.pos += 1
            inner = self.parse_unary()
            return lambda ev: not inner(ev)
        if tok == "(":
            self.pos += 1
            inner = self.parse_and()
            if self.peek() != ")":
                raise SPLError("Missing closing parenthesis in search")
            self.pos += 1
            return inner
        if tok == ")":
            raise SPLError("Unexpected ) in search")
        self.pos += 1
        term: _Term = tok
        # field IN (a, b, c)
        nxt = self.peek()
        if term.op is None and self._is_kw(nxt, "IN") and self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1] == "(":
            self.pos += 2
            values: list[str] = []
            while self.peek() is not None and self.peek() != ")":
                item = self.tokens[self.pos]
                self.pos += 1
                if isinstance(item, _Term):
                    raw = item.value
                    for piece in ([raw] if item.quoted else raw.split(",")):
                        piece = piece.rstrip(",").strip() if item.quoted else piece.strip()
                        if piece:
                            values.append(piece)
            if self.peek() != ")":
                raise SPLError("Missing ) after IN list")
            self.pos += 1
            preds = [_field_term(term.value, "=", v) for v in values]
            return lambda ev, ps=tuple(preds): any(p(ev) for p in ps)
        if term.op is None:
            return _raw_term(term.value)
        if term.value == "" and isinstance(nxt, _Term) and nxt.op is None:
            self.pos += 1
            return _field_term(term.field or "", term.op, nxt.value)
        return _field_term(term.field or "", term.op, term.value)


def compile_search(text: str) -> Predicate:
    """Compile a search-filter expression into a predicate."""
    return _SearchParser(text).parse()


# --------------------------------------------------------------------------
# Aggregations
# --------------------------------------------------------------------------
@dataclass
class AggSpec:
    func: str
    arg: str | None
    alias: str
    eval_fn: Compiled | None = None


def _values_of(rows: list[Event], field_name: str) -> list[Any]:
    out: list[Any] = []
    for row in rows:
        value = get_field(row, field_name)
        if is_null(value):
            continue
        if isinstance(value, list):
            out.extend(v for v in value if not is_null(v))
        else:
            out.append(value)
    return out


def _numeric(values: Iterable[Any]) -> list[float]:
    return [n for n in (to_number(v) for v in values) if n is not None]


def _mv(values: list[Any]) -> Any:
    if not values:
        return None
    return values[0] if len(values) == 1 else values


def aggregate(spec: AggSpec, rows: list[Event]) -> Any:
    """Compute one aggregation over ``rows``."""
    func = spec.func
    if func == "count":
        if spec.eval_fn is not None:
            return sum(1 for r in rows if truthy(spec.eval_fn(r)))
        if spec.arg:
            return sum(1 for r in rows if not is_null(get_field(r, spec.arg)))
        return len(rows)
    if spec.arg is None:
        raise SPLError(f"{func}() requires a field argument")
    values = _values_of(rows, spec.arg)
    if func == "dc" or func == "distinct_count":
        return len({to_text(v) for v in values})
    if func == "values":
        return _mv(sorted({to_text(v) for v in values}))
    if func == "list":
        return _mv([to_text(v) for v in values])
    if func in {"earliest", "latest"}:
        candidates = [(to_number(r.get("_time")) or 0, i, get_field(r, spec.arg)) for i, r in enumerate(rows)
                      if not is_null(get_field(r, spec.arg))]
        if not candidates:
            return None
        chosen = min(candidates) if func == "earliest" else max(candidates)
        return chosen[2]
    if func == "first":
        return values[0] if values else None
    if func == "last":
        return values[-1] if values else None
    numbers = _numeric(values)
    if func in {"min", "max"}:
        if not values:
            return None
        if len(numbers) == len(values):
            return min(numbers) if func == "min" else max(numbers)
        texts = [to_text(v) for v in values]
        return min(texts) if func == "min" else max(texts)
    if not numbers:
        return None
    if func == "sum":
        return sum(numbers)
    if func == "avg" or func == "mean":
        return sum(numbers) / len(numbers)
    if func == "stdev":
        return statistics.stdev(numbers) if len(numbers) > 1 else 0
    if func == "stdevp":
        return statistics.pstdev(numbers)
    if func == "var":
        return statistics.variance(numbers) if len(numbers) > 1 else 0
    if func == "median":
        return statistics.median(numbers)
    if func == "range":
        return max(numbers) - min(numbers)
    raise SPLError(f"Unsupported aggregation function {func}()")


_BY_RE = re.compile(r"\s+by\s+", re.IGNORECASE)


def _split_by(text: str) -> tuple[str, list[str]]:
    """Split ``<aggs> by <fields>`` at a top-level ``by``."""
    depth = 0
    quote: str | None = None
    padded = " " + text
    i = 0
    while i < len(padded):
        ch = padded[i]
        if quote:
            if ch == quote:
                quote = None
        elif ch == '"':
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and padded[i:i + 4].lower() == " by ":
            head = padded[:i]
            tail = padded[i + 4:]
            return head.strip(), [f.strip() for f in re.split(r"[,\s]+", tail.strip()) if f.strip()]
        i += 1
    return text.strip(), []


def _parse_agg_specs(text: str) -> tuple[list[AggSpec], dict[str, str]]:
    """Parse ``count as x, dc(user) as y, current=f`` into specs + options."""
    specs: list[AggSpec] = []
    options: dict[str, str] = {}
    i = 0
    n = len(text)
    while i < n:
        if text[i].isspace() or text[i] == ",":
            i += 1
            continue
        match = re.match(r"[A-Za-z_][\w.]*", text[i:])
        if not match:
            raise SPLError(f"Cannot parse aggregation at: {text[i:]!r}")
        word = match.group(0)
        i += len(word)
        if i < n and text[i] == "=":
            # option like current=f or window=10
            j = i + 1
            while j < n and not text[j].isspace() and text[j] != ",":
                j += 1
            options[word.lower()] = text[i + 1:j].strip('"')
            i = j
            continue
        arg: str | None = None
        if i < n and text[i] == "(":
            depth = 0
            j = i
            quote: str | None = None
            while j < n:
                c = text[j]
                if quote:
                    if c == quote:
                        quote = None
                elif c == '"':
                    quote = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            arg = text[i + 1:j].strip()
            i = j + 1
        alias = f"{word}({arg})" if arg is not None else word
        rest = text[i:]
        as_match = re.match(r"\s+as\s+([\w.]+)", rest, re.IGNORECASE)
        if as_match:
            alias = as_match.group(1)
            i += as_match.end()
        spec = AggSpec(word.lower(), arg, alias)
        if arg is not None and re.match(r"^eval\s*\(", arg, re.IGNORECASE):
            inner = arg[arg.index("(") + 1:-1]
            spec.eval_fn = compile_expr(inner)
            spec.arg = None
        specs.append(spec)
    return specs, options


def _group_key(row: Event, by: list[str]) -> tuple[Any, ...] | None:
    key: list[Any] = []
    for name in by:
        value = get_field(row, name)
        if is_null(value):
            return None
        key.append(to_text(value) if not isinstance(value, (int, float)) else value)
    return tuple(key)


def _group(rows: list[Event], by: list[str]) -> dict[tuple[Any, ...], list[Event]]:
    groups: dict[tuple[Any, ...], list[Event]] = {}
    for row in rows:
        key = _group_key(row, by)
        if key is None:
            continue
        groups.setdefault(key, []).append(row)
    return groups


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
_SPAN_RE = re.compile(r"^(\d+)(s|sec|secs|m|min|mins|h|hr|hrs|d|day|days|w)?$")


def _span_seconds(text: str) -> float:
    match = _SPAN_RE.match(text.strip())
    if not match:
        raise SPLError(f"Unsupported span {text!r}")
    unit = (match.group(2) or "s")[0]
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


def _strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _rex_pattern(text: str) -> str:
    """Extract the quoted regex from a rex/regex argument string."""
    match = re.search(r'"((?:[^"\\]|\\.)*)"', text)
    if not match:
        raise SPLError(f"rex requires a quoted regular expression: {text}")
    pattern = match.group(1).replace('\\"', '"')
    return re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", pattern)


class Pipeline:
    """Execute SPL strings against in-memory events."""

    def __init__(self, env: SPLEnvironment | None = None) -> None:
        self.env = env or SPLEnvironment()

    def expand(self, spl: str) -> str:
        """Expand macros and eventtypes (eventtypes may reference macros)."""
        text = spl.strip()
        for _ in range(10):
            new = expand_eventtypes(expand_macros(text, self.env.macros), self.env.eventtypes)
            if new == text:
                return text
            text = new
        raise SPLError("Macro/eventtype expansion did not converge")

    # entry point -----------------------------------------------------
    def run(self, spl: str, events: list[Event]) -> list[Event]:
        """Run ``spl`` over ``events`` and return the result rows."""
        segments = split_pipeline(self.expand(spl))
        rows: list[Event]
        first = segments[0]
        if first == "":
            rows = list(events)
        elif re.match(r"^\s*inputlookup\b", first, re.IGNORECASE):
            rows = self.cmd_inputlookup(first.split(None, 1)[1] if " " in first.strip() else "", [])
        else:
            if re.match(r"^\s*search\b", first, re.IGNORECASE):
                first = first.strip()[6:]
            rows = [ev for ev in events if compile_search(first)(ev)]
        for segment in segments[1:]:
            if not segment:
                continue
            parts = segment.split(None, 1)
            name = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""
            handler = getattr(self, f"cmd_{name}", None)
            if handler is None:
                raise SPLError(f"Unsupported command '{name}' (harness subset); see harness/spl.py docstring")
            rows = handler(args, rows)
        return rows

    # filters ---------------------------------------------------------
    def cmd_search(self, args: str, rows: list[Event]) -> list[Event]:
        pred = compile_search(args)
        return [r for r in rows if pred(r)]

    def cmd_where(self, args: str, rows: list[Event]) -> list[Event]:
        fn = compile_expr(args)
        return [r for r in rows if truthy(fn(r))]

    def cmd_regex(self, args: str, rows: list[Event]) -> list[Event]:
        match = re.match(r"^\s*([\w.]+)\s*(!?=)\s*", args)
        fld = match.group(1) if match else "_raw"
        negate = bool(match and match.group(2) == "!=")
        regex = re.compile(_rex_pattern(args))
        out = []
        for row in rows:
            value = get_field(row, fld)
            hit = not is_null(value) and regex.search(to_text(value)) is not None
            if hit != negate:
                out.append(row)
        return out

    # per-row transforms ---------------------------------------------
    def cmd_eval(self, args: str, rows: list[Event]) -> list[Event]:
        assignments: list[tuple[str, Compiled]] = []
        for clause in _split_top_level(args):
            if not clause.strip():
                continue
            name, sep, expression = clause.partition("=")
            if not sep:
                raise SPLError(f"eval clause without '=': {clause}")
            assignments.append((_strip_quotes(name.strip().strip("'")), compile_expr(expression.strip())))
        out = []
        for row in rows:
            new = dict(row)
            for name, fn in assignments:
                value = fn(new)
                if is_null(value):
                    new.pop(name, None)
                else:
                    new[name] = value
            out.append(new)
        return out

    def cmd_rex(self, args: str, rows: list[Event]) -> list[Event]:
        if re.search(r"\bmode\s*=\s*sed\b", args):
            raise SPLError("rex mode=sed is not supported")
        field_match = re.search(r"\bfield\s*=\s*([\w.]+)", args)
        fld = field_match.group(1) if field_match else "_raw"
        regex = re.compile(_rex_pattern(args))
        out = []
        for row in rows:
            value = get_field(row, fld)
            new = dict(row)
            if not is_null(value):
                for item in (value if isinstance(value, list) else [value]):
                    found = regex.search(to_text(item))
                    if found:
                        for name, captured in found.groupdict().items():
                            if captured is not None:
                                new[name] = captured
                        break
            out.append(new)
        return out

    def cmd_rename(self, args: str, rows: list[Event]) -> list[Event]:
        pairs: list[tuple[str, str]] = []
        for clause in _split_top_level(args):
            match = re.match(r"^\s*([\w.*]+|\"[^\"]+\")\s+as\s+([\w.*]+|\"[^\"]+\")\s*$", clause, re.IGNORECASE)
            if not match:
                raise SPLError(f"Cannot parse rename clause: {clause}")
            pairs.append((_strip_quotes(match.group(1)), _strip_quotes(match.group(2))))
        out = []
        for row in rows:
            new = dict(row)
            for old, newname in pairs:
                if old in new:
                    new[newname] = new.pop(old)
            out.append(new)
        return out

    def cmd_fillnull(self, args: str, rows: list[Event]) -> list[Event]:
        value_match = re.search(r"\bvalue\s*=\s*(\"[^\"]*\"|\S+)", args)
        fill: Any = _strip_quotes(value_match.group(1)) if value_match else "0"
        if to_number(fill) is not None:
            fill = to_number(fill)
        remaining = re.sub(r"\bvalue\s*=\s*(\"[^\"]*\"|\S+)", "", args)
        fields = [f for f in re.split(r"[,\s]+", remaining.strip()) if f]
        if not fields:
            fields = sorted({k for r in rows for k in r if not k.startswith("_")})
        out = []
        for row in rows:
            new = dict(row)
            for name in fields:
                if is_null(new.get(name)):
                    new[name] = fill
            out.append(new)
        return out

    def cmd_lookup(self, args: str, rows: list[Event]) -> list[Event]:
        tokens = [t for t in re.split(r"[\s,]+", args.strip()) if t]
        tokens = [t for t in tokens if not re.match(r"^(local|update)=", t, re.IGNORECASE)]
        if not tokens:
            raise SPLError("lookup requires a table name")
        name = tokens[0]
        if name.endswith(".csv"):
            name = name[:-4]
        table = self.env.lookups.get(name)
        if table is None:
            raise SPLError(f"Unknown lookup {name}")
        inputs: list[tuple[str, str]] = []
        outputs: list[tuple[str, str]] = []
        mode = "OUTPUT"
        target = inputs
        i = 1
        while i < len(tokens):
            tok = tokens[i]
            if tok.upper() in {"OUTPUT", "OUTPUTNEW"}:
                mode = tok.upper()
                target = outputs
                i += 1
                continue
            lookup_field = tok
            event_field = tok
            if i + 2 < len(tokens) and tokens[i + 1].upper() == "AS":
                event_field = tokens[i + 2]
                i += 3
            else:
                i += 1
            target.append((lookup_field, event_field))
        if not inputs:
            raise SPLError("lookup requires at least one input field")
        if not outputs:
            outputs = [(f, f) for f in table.fieldnames if f not in {lf for lf, _ in inputs}]
        out = []
        for row in rows:
            new = dict(row)
            criteria: dict[str, str] = {}
            for lf, ef in inputs:
                value = get_field(row, ef)
                if is_null(value):
                    criteria = {}
                    break
                criteria[lf] = to_text(value if not isinstance(value, list) else value[0])
            if criteria:
                hit = table.match(criteria)
                if hit:
                    for lf, ef in outputs:
                        if mode == "OUTPUTNEW" and not is_null(new.get(ef)):
                            continue
                        if hit.get(lf, "") != "":
                            new[ef] = hit[lf]
            out.append(new)
        return out

    def cmd_bin(self, args: str, rows: list[Event]) -> list[Event]:
        span_match = re.search(r"\bspan\s*=\s*(\S+)", args)
        if not span_match:
            raise SPLError("bin requires span=")
        span = _span_seconds(span_match.group(1))
        remaining = re.sub(r"\bspan\s*=\s*\S+", "", args)
        as_match = re.search(r"\s+as\s+([\w.]+)", remaining, re.IGNORECASE)
        alias = as_match.group(1) if as_match else None
        remaining = re.sub(r"\s+as\s+[\w.]+", "", remaining, flags=re.IGNORECASE)
        fld = remaining.strip()
        if not fld:
            raise SPLError("bin requires a field")
        out = []
        for row in rows:
            new = dict(row)
            number = to_number(get_field(row, fld))
            if number is not None:
                new[alias or fld] = int(number // span * span)
            out.append(new)
        return out

    cmd_bucket = cmd_bin

    def cmd_mvexpand(self, args: str, rows: list[Event]) -> list[Event]:
        fld = args.strip().split()[0]
        out = []
        for row in rows:
            value = get_field(row, fld)
            if isinstance(value, list):
                for item in value:
                    new = dict(row)
                    new[fld] = item
                    out.append(new)
            else:
                out.append(row)
        return out

    # transforming commands -----------------------------------------
    def cmd_stats(self, args: str, rows: list[Event]) -> list[Event]:
        agg_text, by = _split_by(args)
        specs, _ = _parse_agg_specs(agg_text)
        if not specs:
            raise SPLError("stats requires at least one aggregation")
        if not by:
            if not rows:
                # Splunk returns count=0 for a bare count over no events, otherwise nothing.
                return [{s.alias: 0 for s in specs}] if all(s.func == "count" for s in specs) else []
            return [{s.alias: aggregate(s, rows) for s in specs}]
        out = []
        for key, group in _group(rows, by).items():
            row: Event = dict(zip(by, key))
            for spec in specs:
                value = aggregate(spec, group)
                if not is_null(value):
                    row[spec.alias] = value
            out.append(row)
        return out

    def cmd_eventstats(self, args: str, rows: list[Event]) -> list[Event]:
        agg_text, by = _split_by(args)
        specs, _ = _parse_agg_specs(agg_text)
        if by:
            computed = {key: {s.alias: aggregate(s, group) for s in specs} for key, group in _group(rows, by).items()}
        else:
            whole = {s.alias: aggregate(s, rows) for s in specs}
        out = []
        for row in rows:
            new = dict(row)
            values = computed.get(_group_key(row, by) or ()) if by else whole  # type: ignore[union-attr]
            if values:
                for alias, value in values.items():
                    if not is_null(value):
                        new[alias] = value
            out.append(new)
        return out

    def cmd_streamstats(self, args: str, rows: list[Event]) -> list[Event]:
        agg_text, by = _split_by(args)
        specs, options = _parse_agg_specs(agg_text)
        current = options.get("current", "true").lower() not in {"f", "false", "0"}
        window = int(options.get("window", "0") or 0)
        time_window = _span_seconds(options["time_window"]) if "time_window" in options else None
        history: dict[tuple[Any, ...], list[Event]] = {}
        out = []
        for row in rows:
            new = dict(row)
            key = _group_key(row, by) if by else ()
            if key is None:
                out.append(new)
                continue
            hist = history.setdefault(key, [])
            if time_window is not None:
                now = to_number(row.get("_time"))
                if now is not None:
                    hist[:] = [h for h in hist if (to_number(h.get("_time")) or 0) >= now - time_window]
            scope = hist + [row] if current else list(hist)
            if window:
                scope = scope[-window:]
            for spec in specs:
                value = aggregate(spec, scope)
                if not is_null(value):
                    new[spec.alias] = value
            hist.append(row)
            if window and len(hist) > window:
                del hist[:-window]
            out.append(new)
        return out

    def _rare_top(self, args: str, rows: list[Event], descending: bool) -> list[Event]:
        field_text, by = _split_by(args)
        options: dict[str, str] = {}
        fields: list[str] = []
        for tok in re.split(r"[,\s]+", field_text.strip()):
            if not tok:
                continue
            if "=" in tok:
                k, _, v = tok.partition("=")
                options[k.lower()] = v
            else:
                fields.append(tok)
        if not fields:
            raise SPLError("rare/top requires at least one field")
        limit = int(options.get("limit", "10"))
        countfield = options.get("countfield", "count")
        percentfield = options.get("percentfield", "percent")
        out = []
        for key, group in (_group(rows, by).items() if by else [((), rows)]):
            counts: dict[tuple[Any, ...], int] = {}
            for row in group:
                vkey = _group_key(row, fields)
                if vkey is None:
                    continue
                counts[vkey] = counts.get(vkey, 0) + 1
            total = sum(counts.values())
            ordered = sorted(counts.items(), key=lambda kv: (-kv[1] if descending else kv[1], kv[0]))
            if limit:
                ordered = ordered[:limit]
            for vkey, count in ordered:
                row = dict(zip(by, key))
                row.update(zip(fields, vkey))
                row[countfield] = count
                row[percentfield] = round(count / total * 100, 6) if total else 0
                out.append(row)
        return out

    def cmd_rare(self, args: str, rows: list[Event]) -> list[Event]:
        return self._rare_top(args, rows, descending=False)

    def cmd_top(self, args: str, rows: list[Event]) -> list[Event]:
        return self._rare_top(args, rows, descending=True)

    # ordering / projection -------------------------------------------
    def cmd_sort(self, args: str, rows: list[Event]) -> list[Event]:
        tokens = [t for t in re.split(r"[,\s]+", args.strip()) if t]
        limit = 10000
        if tokens and re.match(r"^\d+$", tokens[0]):
            limit = int(tokens.pop(0))
        if tokens and re.match(r"^limit=\d+$", tokens[0]):
            limit = int(tokens.pop(0).split("=")[1])
        keys: list[tuple[str, bool]] = []
        for tok in tokens:
            desc = tok.startswith("-")
            name = tok.lstrip("+-")
            name = re.sub(r"^(?:ip|num|str|auto)\((.*)\)$", r"\1", name)
            keys.append((name, desc))
        result = list(rows)
        for name, desc in reversed(keys):
            values = [get_field(r, name) for r in result]
            present = [v for v in values if not is_null(v)]
            numeric = bool(present) and all(to_number(v) is not None for v in present)

            def sort_key(row: Event, n: str = name, num: bool = numeric) -> tuple[Any, ...]:
                value = get_field(row, n)
                if is_null(value):
                    return (1, 0)
                if isinstance(value, list):
                    value = value[0]
                return (0, to_number(value) if num else to_text(value))

            result.sort(key=sort_key, reverse=desc)
            if desc:
                # keep null rows last even when descending
                result = [r for r in result if not is_null(get_field(r, name))] + [r for r in result if is_null(get_field(r, name))]
        return result[:limit] if limit else result

    def cmd_head(self, args: str, rows: list[Event]) -> list[Event]:
        match = re.search(r"(\d+)", args)
        return rows[: int(match.group(1)) if match else 10]

    def cmd_dedup(self, args: str, rows: list[Event]) -> list[Event]:
        fields = [f for f in re.split(r"[,\s]+", args.strip()) if f and "=" not in f]
        seen: set[tuple[Any, ...]] = set()
        out = []
        for row in rows:
            key = _group_key(row, fields)
            if key is None or key in seen:
                continue
            seen.add(key)
            out.append(row)
        return out

    def cmd_table(self, args: str, rows: list[Event]) -> list[Event]:
        fields = [f for f in re.split(r"[,\s]+", args.strip()) if f]
        return [{f: r[f] for f in fields if f in r and not is_null(r[f])} for r in rows]

    def cmd_fields(self, args: str, rows: list[Event]) -> list[Event]:
        text = args.strip()
        remove = text.startswith("-")
        text = text.lstrip("+-").strip()
        fields = [f for f in re.split(r"[,\s]+", text) if f]
        if remove:
            return [{k: v for k, v in r.items() if k not in fields} for r in rows]
        return [{k: v for k, v in r.items() if k in fields or k.startswith("_")} for r in rows]

    def cmd_inputlookup(self, args: str, rows: list[Event]) -> list[Event]:
        name = args.strip().split()[0] if args.strip() else ""
        if name.endswith(".csv"):
            name = name[:-4]
        table = self.env.lookups.get(name)
        if table is None:
            raise SPLError(f"Unknown lookup {name}")
        return [dict(r) for r in table.rows]


def run_search(spl: str, events: list[Event], env: SPLEnvironment | None = None) -> list[Event]:
    """One-shot helper: run ``spl`` against ``events``."""
    return Pipeline(env).run(spl, events)
