"""Evaluator for the Splunk ``eval``/``where`` expression language (subset).

Supported
---------
* literals: numbers, ``"strings"``, ``'quoted field names'``
* field references (bare identifiers); missing fields evaluate to ``null``
* arithmetic ``+ - * / %`` and string concatenation ``.``
* comparisons ``= == != < > <= >=``, ``LIKE``, ``IN (...)``
* boolean ``AND OR NOT`` (also ``and or not``)
* functions: len lower upper trim ltrim rtrim match like if case coalesce
  isnull isnotnull isnum isint tonumber tostring round abs floor ceiling
  ceil sqrt exp log pow max min mvcount mvindex mvjoin mvdedup split replace
  substr strftime strptime now relative_time cidrmatch in validate typeof
  nullif true false null random

Semantics follow Splunk where it matters for detections: comparisons with a
null operand are false (so ``where`` drops the row), numeric-looking strings
compare numerically, and arithmetic on null yields null.
"""

from __future__ import annotations

import ipaddress
import math
import random
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable

Value = Any
Env = dict[str, Any]
Compiled = Callable[[Env], Value]


class ExprError(ValueError):
    """Raised for a syntax error in an eval expression."""


_NUM_RE = re.compile(r"^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$")


def to_number(value: Value) -> int | float | None:
    """Return ``value`` as int/float when it is numeric, else ``None``."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if _NUM_RE.match(text):
            number = float(text)
            if number.is_integer() and "." not in text and "e" not in text.lower():
                return int(number)
            return number
    return None


def is_null(value: Value) -> bool:
    """Splunk null: Python ``None`` or an empty multivalue."""
    return value is None or (isinstance(value, list) and len(value) == 0)


def to_text(value: Value) -> str:
    """Render a value the way Splunk would print it in a table."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return f"{value:.6f}".rstrip("0").rstrip(".")
    if isinstance(value, list):
        return "\n".join(to_text(v) for v in value)
    return str(value)


def truthy(value: Value) -> bool:
    """Boolean interpretation used by AND/OR/NOT and ``if``."""
    if is_null(value):
        return False
    if isinstance(value, bool):
        return value
    number = to_number(value)
    if number is not None:
        return number != 0
    if isinstance(value, str):
        return value.lower() not in {"", "false", "f", "0"}
    return bool(value)


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------
_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<num>\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?![A-Za-z_])
      | (?P<str>"(?:[^"\\]|\\.)*")
      | (?P<fld>'(?:[^'\\]|\\.)*')
      | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
      | (?P<op>==|!=|<=|>=|[-+*/%.=<>(),])
    )""",
    re.VERBOSE,
)

_KEYWORDS = {"AND", "OR", "NOT", "LIKE", "IN"}


def _unescape(text: str) -> str:
    out = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in {'"', "'", "\\"}:
                out.append(nxt)
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def tokenize(text: str) -> list[tuple[str, str]]:
    """Split an expression into ``(kind, text)`` tokens."""
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(text):
        if text[pos:].strip() == "":
            break
        match = _TOKEN_RE.match(text, pos)
        if not match or match.end() == pos:
            raise ExprError(f"Unexpected character {text[pos]!r} at offset {pos} in: {text}")
        pos = match.end()
        kind = match.lastgroup or ""
        value = match.group(kind)
        if kind == "ident" and value.upper() in _KEYWORDS and not (
            value.upper() in {"IN", "LIKE"} and text[pos:].lstrip().startswith("(")
            and (not tokens or tokens[-1][0] in {"op", "kw"})
        ):
            tokens.append(("kw", value.upper()))
        elif kind == "str":
            tokens.append(("str", _unescape(value[1:-1])))
        elif kind == "fld":
            tokens.append(("fld", _unescape(value[1:-1])))
        else:
            tokens.append((kind, value))
    return tokens


# --------------------------------------------------------------------------
# Field access and comparison helpers
# --------------------------------------------------------------------------
def get_field(env: Env, name: str) -> Value:
    """Return a field, treating missing / empty as null."""
    value = env.get(name)
    if isinstance(value, str) and value == "":
        return None
    return value


def compare(left: Value, right: Value, op: str) -> bool:
    """Splunk-style comparison: numeric when both sides are numeric."""
    if is_null(left) or is_null(right):
        return False
    if isinstance(left, list):
        results = [compare(item, right, op) for item in left]
        return (not any(compare(item, right, "=") for item in left)) if op == "!=" else any(results)
    if isinstance(right, list):
        results = [compare(left, item, op) for item in right]
        return (not any(compare(left, item, "=") for item in right)) if op == "!=" else any(results)
    ln, rn = to_number(left), to_number(right)
    a: Any
    b: Any
    if ln is not None and rn is not None:
        a, b = ln, rn
    else:
        a, b = to_text(left), to_text(right)
    if op in {"=", "=="}:
        return a == b
    if op == "!=":
        return a != b
    if op == "<":
        return a < b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == ">=":
        return a >= b
    raise ExprError(f"Unknown comparison operator {op}")


def like(subject: Value, pattern: Value) -> bool:
    """SQL LIKE with ``%`` and ``_`` wildcards (case-sensitive like Splunk)."""
    if is_null(subject) or is_null(pattern):
        return False
    regex = "^" + "".join(".*" if c == "%" else "." if c == "_" else re.escape(c) for c in to_text(pattern)) + "$"
    return re.match(regex, to_text(subject), re.DOTALL) is not None


# --------------------------------------------------------------------------
# Functions
# --------------------------------------------------------------------------
def _num_fn(fn: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Value) -> Value:
        numbers = [to_number(a) for a in args]
        if any(n is None for n in numbers):
            return None
        try:
            return fn(*numbers)
        except (ValueError, ZeroDivisionError, OverflowError):
            return None

    return wrapper


def _str(value: Value) -> str | None:
    return None if is_null(value) else to_text(value)


def fn_round(value: Value, digits: Value = 0) -> Value:
    number = to_number(value)
    nd = to_number(digits)
    if number is None or nd is None:
        return None
    result = round(float(number), int(nd))
    return int(result) if int(nd) == 0 else result


def fn_tonumber(value: Value, base: Value = 10) -> Value:
    if is_null(value):
        return None
    base_n = to_number(base) or 10
    text = to_text(value).strip()
    if base_n == 10:
        return to_number(text)
    try:
        if base_n == 16 and text.lower().startswith("0x"):
            text = text[2:]
        return int(text, int(base_n))
    except ValueError:
        return None


def fn_tostring(value: Value, fmt: Value = None) -> Value:
    if is_null(value):
        return None
    if fmt is None:
        return to_text(value)
    number = to_number(value)
    fmt_text = to_text(fmt).lower()
    if number is None:
        return to_text(value)
    if fmt_text == "hex":
        return hex(int(number))
    if fmt_text == "commas":
        return f"{number:,}"
    if fmt_text == "duration":
        total = int(number)
        return f"{total // 3600:02d}:{(total % 3600) // 60:02d}:{total % 60:02d}"
    return to_text(value)


def fn_strftime(epoch: Value, fmt: Value) -> Value:
    number = to_number(epoch)
    if number is None or is_null(fmt):
        return None
    dt = datetime.fromtimestamp(float(number), tz=timezone.utc)
    return dt.strftime(to_text(fmt).replace("%3N", f"{dt.microsecond // 1000:03d}").replace("%6N", f"{dt.microsecond:06d}"))


def fn_strptime(text: Value, fmt: Value) -> Value:
    if is_null(text) or is_null(fmt):
        return None
    try:
        dt = datetime.strptime(to_text(text), to_text(fmt))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


_REL_RE = re.compile(r"^([+-]?\d+)(s|sec|m|min|h|hr|d|day|w|week|mon|y)?(?:@.*)?$")


def fn_relative_time(epoch: Value, spec: Value) -> Value:
    number = to_number(epoch)
    if number is None or is_null(spec):
        return None
    text = to_text(spec).strip()
    if text == "now":
        return number
    match = _REL_RE.match(text)
    if not match:
        return None
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    seconds = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hr": 3600, "d": 86400, "day": 86400,
               "w": 604800, "week": 604800, "mon": 2592000, "y": 31536000}[unit]
    return number + amount * seconds


def fn_mvcount(value: Value) -> Value:
    if is_null(value):
        return None
    return len(value) if isinstance(value, list) else 1


def fn_mvindex(value: Value, start: Value, end: Value = None) -> Value:
    if is_null(value):
        return None
    items = value if isinstance(value, list) else [value]
    s = to_number(start)
    if s is None:
        return None
    s = int(s)
    if end is None:
        try:
            return items[s]
        except IndexError:
            return None
    e = int(to_number(end) or 0)
    sliced = items[s:e + 1] if e >= 0 else items[s:len(items) + e + 1]
    return sliced or None


def fn_mvjoin(value: Value, sep: Value) -> Value:
    if is_null(value):
        return None
    items = value if isinstance(value, list) else [value]
    return to_text(sep).join(to_text(i) for i in items)


def fn_mvdedup(value: Value) -> Value:
    if is_null(value):
        return None
    items = value if isinstance(value, list) else [value]
    seen: list[Value] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen if len(seen) > 1 else seen[0]


def fn_split(value: Value, sep: Value) -> Value:
    if is_null(value):
        return None
    parts = to_text(value).split(to_text(sep))
    return parts if len(parts) > 1 else parts[0]


def fn_replace(value: Value, pattern: Value, replacement: Value) -> Value:
    if is_null(value) or is_null(pattern):
        return None
    repl = to_text(replacement)
    # Splunk uses \1 style back-references which Python's re also accepts.
    try:
        return re.sub(to_text(pattern), repl, to_text(value))
    except re.error as exc:
        raise ExprError(f"Bad regex in replace(): {exc}") from exc


def fn_match(value: Value, pattern: Value) -> bool:
    if is_null(value) or is_null(pattern):
        return False
    try:
        regex = re.compile(to_text(pattern))
    except re.error as exc:
        raise ExprError(f"Bad regex in match(): {exc}") from exc
    items = value if isinstance(value, list) else [value]
    return any(regex.search(to_text(item)) for item in items)


def fn_substr(value: Value, start: Value, length: Value = None) -> Value:
    if is_null(value):
        return None
    text = to_text(value)
    s = int(to_number(start) or 1)
    idx = s - 1 if s > 0 else len(text) + s
    if length is None:
        return text[idx:]
    return text[idx: idx + int(to_number(length) or 0)]


def fn_cidrmatch(cidr: Value, ip: Value) -> bool:
    if is_null(cidr) or is_null(ip):
        return False
    try:
        return ipaddress.ip_address(to_text(ip)) in ipaddress.ip_network(to_text(cidr), strict=False)
    except ValueError:
        return False


def fn_coalesce(*args: Value) -> Value:
    for arg in args:
        if not is_null(arg):
            return arg
    return None


def fn_in(value: Value, *options: Value) -> bool:
    if is_null(value):
        return False
    return any(compare(value, opt, "=") for opt in options)


def fn_case(*args: Value) -> Value:
    for i in range(0, len(args) - 1, 2):
        if truthy(args[i]):
            return args[i + 1]
    return None


def fn_if(cond: Value, a: Value, b: Value) -> Value:
    return a if truthy(cond) else b


def fn_typeof(value: Value) -> str:
    if is_null(value):
        return "Invalid"
    if isinstance(value, bool):
        return "Boolean"
    if to_number(value) is not None:
        return "Number"
    return "String"


def fn_nullif(a: Value, b: Value) -> Value:
    return None if compare(a, b, "=") else a


def fn_validate(*args: Value) -> Value:
    for i in range(0, len(args) - 1, 2):
        if not truthy(args[i]):
            return args[i + 1]
    return None


def fn_max(*args: Value) -> Value:
    values = [a for a in args if not is_null(a)]
    if not values:
        return None
    numbers = [to_number(v) for v in values]
    if all(n is not None for n in numbers):
        return max(numbers)  # type: ignore[type-var]
    return max(to_text(v) for v in values)


def fn_min(*args: Value) -> Value:
    values = [a for a in args if not is_null(a)]
    if not values:
        return None
    numbers = [to_number(v) for v in values]
    if all(n is not None for n in numbers):
        return min(numbers)  # type: ignore[type-var]
    return min(to_text(v) for v in values)


FUNCTIONS: dict[str, Callable[..., Value]] = {
    "len": lambda v: None if is_null(v) else len(to_text(v)),
    "lower": lambda v: None if is_null(v) else to_text(v).lower(),
    "upper": lambda v: None if is_null(v) else to_text(v).upper(),
    "trim": lambda v, chars=None: None if is_null(v) else to_text(v).strip(_str(chars)),
    "ltrim": lambda v, chars=None: None if is_null(v) else to_text(v).lstrip(_str(chars)),
    "rtrim": lambda v, chars=None: None if is_null(v) else to_text(v).rstrip(_str(chars)),
    "match": fn_match,
    "like": like,
    "if": fn_if,
    "case": fn_case,
    "coalesce": fn_coalesce,
    "isnull": lambda v: is_null(v),
    "isnotnull": lambda v: not is_null(v),
    "isnum": lambda v: to_number(v) is not None,
    "isint": lambda v: isinstance(to_number(v), int),
    "isstr": lambda v: not is_null(v) and to_number(v) is None,
    "tonumber": fn_tonumber,
    "tostring": fn_tostring,
    "round": fn_round,
    "abs": _num_fn(abs),
    "floor": _num_fn(lambda x: int(math.floor(x))),
    "ceiling": _num_fn(lambda x: int(math.ceil(x))),
    "ceil": _num_fn(lambda x: int(math.ceil(x))),
    "sqrt": _num_fn(math.sqrt),
    "exp": _num_fn(math.exp),
    "log": _num_fn(lambda x, base=10: math.log(x, base)),
    "ln": _num_fn(math.log),
    "pow": _num_fn(lambda x, y: x ** y),
    "max": fn_max,
    "min": fn_min,
    "mvcount": fn_mvcount,
    "mvindex": fn_mvindex,
    "mvjoin": fn_mvjoin,
    "mvdedup": fn_mvdedup,
    "split": fn_split,
    "replace": fn_replace,
    "substr": fn_substr,
    "strftime": fn_strftime,
    "strptime": fn_strptime,
    "now": lambda: int(time.time()),
    "time": lambda: time.time(),
    "relative_time": fn_relative_time,
    "cidrmatch": fn_cidrmatch,
    "in": fn_in,
    "validate": fn_validate,
    "typeof": fn_typeof,
    "nullif": fn_nullif,
    "true": lambda: True,
    "false": lambda: False,
    "null": lambda: None,
    "random": lambda: random.randint(0, 2**31 - 1),
}


# --------------------------------------------------------------------------
# Parser (recursive descent -> closures)
# --------------------------------------------------------------------------
class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.tokens = tokenize(text)
        self.pos = 0

    # token helpers ---------------------------------------------------
    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        idx = self.pos + offset
        return self.tokens[idx] if idx < len(self.tokens) else None

    def next(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise ExprError(f"Unexpected end of expression: {self.text}")
        self.pos += 1
        return tok

    def accept(self, kind: str, value: str | None = None) -> bool:
        tok = self.peek()
        if tok and tok[0] == kind and (value is None or tok[1] == value):
            self.pos += 1
            return True
        return False

    def expect(self, kind: str, value: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok and tok[0] == kind and (value is None or tok[1] == value):
            self.pos += 1
            return tok
        raise ExprError(f"Expected {value or kind} at token {self.pos} in: {self.text}")

    # grammar ---------------------------------------------------------
    def parse(self) -> Compiled:
        node = self.parse_or()
        if self.peek() is not None:
            raise ExprError(f"Trailing tokens after expression: {self.text}")
        return node

    def parse_or(self) -> Compiled:
        left = self.parse_and()
        while self.accept("kw", "OR"):
            right = self.parse_and()
            left = (lambda a, b: lambda env: truthy(a(env)) or truthy(b(env)))(left, right)
        return left

    def parse_and(self) -> Compiled:
        left = self.parse_not()
        while self.accept("kw", "AND"):
            right = self.parse_not()
            left = (lambda a, b: lambda env: truthy(a(env)) and truthy(b(env)))(left, right)
        return left

    def parse_not(self) -> Compiled:
        if self.accept("kw", "NOT"):
            inner = self.parse_not()
            return lambda env: not truthy(inner(env))
        return self.parse_comparison()

    def parse_comparison(self) -> Compiled:
        left = self.parse_additive()
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in {"=", "==", "!=", "<", ">", "<=", ">="}:
            self.pos += 1
            right = self.parse_additive()
            op = tok[1]
            return (lambda a, b, o: lambda env: compare(a(env), b(env), o))(left, right, op)
        if tok and tok[0] == "kw" and tok[1] == "LIKE":
            self.pos += 1
            right = self.parse_additive()
            return (lambda a, b: lambda env: like(a(env), b(env)))(left, right)
        if tok and tok[0] == "kw" and tok[1] == "IN":
            self.pos += 1
            self.expect("op", "(")
            options: list[Compiled] = []
            if not self.accept("op", ")"):
                options.append(self.parse_or())
                while self.accept("op", ","):
                    options.append(self.parse_or())
                self.expect("op", ")")
            return (lambda a, opts: lambda env: fn_in(a(env), *[o(env) for o in opts]))(left, options)
        return left

    def parse_additive(self) -> Compiled:
        left = self.parse_multiplicative()
        while True:
            tok = self.peek()
            if tok and tok[0] == "op" and tok[1] in {"+", "-", "."}:
                self.pos += 1
                right = self.parse_multiplicative()
                left = (lambda a, b, o: lambda env: _arith(a(env), b(env), o))(left, right, tok[1])
            else:
                return left

    def parse_multiplicative(self) -> Compiled:
        left = self.parse_unary()
        while True:
            tok = self.peek()
            if tok and tok[0] == "op" and tok[1] in {"*", "/", "%"}:
                self.pos += 1
                right = self.parse_unary()
                left = (lambda a, b, o: lambda env: _arith(a(env), b(env), o))(left, right, tok[1])
            else:
                return left

    def parse_unary(self) -> Compiled:
        if self.accept("op", "-"):
            inner = self.parse_unary()
            return lambda env: _arith(0, inner(env), "-")
        if self.accept("op", "+"):
            return self.parse_unary()
        return self.parse_primary()

    def parse_primary(self) -> Compiled:
        tok = self.next()
        kind, value = tok
        if kind == "num":
            number = to_number(value)
            return lambda env, n=number: n
        if kind == "str":
            return lambda env, s=value: s
        if kind == "fld":
            return lambda env, name=value: get_field(env, name)
        if kind == "op" and value == "(":
            inner = self.parse_or()
            self.expect("op", ")")
            return inner
        if kind == "ident":
            nxt = self.peek()
            if nxt and nxt[0] == "op" and nxt[1] == "(":
                self.pos += 1
                args: list[Compiled] = []
                if not self.accept("op", ")"):
                    args.append(self.parse_or())
                    while self.accept("op", ","):
                        args.append(self.parse_or())
                    self.expect("op", ")")
                name = value.lower()
                if name not in FUNCTIONS:
                    raise ExprError(f"Unsupported eval function {value}()")
                func = FUNCTIONS[name]
                return (lambda f, a: lambda env: f(*[x(env) for x in a]))(func, args)
            if value.lower() in {"true", "false", "null"}:
                literal = {"true": True, "false": False, "null": None}[value.lower()]
                return lambda env, lit=literal: lit
            return lambda env, name=value: get_field(env, name)
        raise ExprError(f"Unexpected token {value!r} in: {self.text}")


def _arith(left: Value, right: Value, op: str) -> Value:
    if op == ".":
        if is_null(left) and is_null(right):
            return None
        return to_text(left) + to_text(right)
    if is_null(left) or is_null(right):
        return None
    ln, rn = to_number(left), to_number(right)
    if ln is None or rn is None:
        if op == "+":
            return to_text(left) + to_text(right)
        return None
    try:
        if op == "+":
            return ln + rn
        if op == "-":
            return ln - rn
        if op == "*":
            return ln * rn
        if op == "/":
            return ln / rn
        if op == "%":
            return ln % rn
    except ZeroDivisionError:
        return None
    raise ExprError(f"Unknown operator {op}")


def compile_expr(text: str) -> Compiled:
    """Compile an eval/where expression into a callable ``fn(event) -> value``."""
    return _Parser(text).parse()


def evaluate(text: str, env: Env) -> Value:
    """Convenience: compile and evaluate in one step."""
    return compile_expr(text)(env)
