"""Default-deny policy: a tool call is allowed only if a rule explicitly permits it."""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Mapping

# Exact types only (checked with `type(v) in ...`): bool is NOT an int, and subclasses of
# str/int/float (which could override __eq__/__len__) are rejected.
_TYPES = {"str": (str,), "int": (int,), "number": (int, float), "bool": (bool,)}

# Applied to every "str" argument that does not set its own max_len.
DEFAULT_MAX_STR_LEN = 65_536

# Tool names declared in a policy loaded via from_dict/from_json must be plain ASCII.
# Lookups are exact (no Unicode normalisation), so look-alike names never match a rule.
_TOOL_NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/\-]{0,127}", re.ASCII)


class PolicyError(ValueError):
    """A policy document is missing or malformed. Raised at load time, never at call time."""


@dataclass(frozen=True)
class ArgRule:
    type: str = "str"                 # str | int | number | bool
    required: bool = True
    enum: tuple = ()                  # if non-empty, value must be one of these
    max_len: int | None = None        # for str (defaults to the policy's max_str_len)
    pattern: str | None = None        # for str; must fully match
    min: float | None = None          # for int/number
    max: float | None = None          # for int/number


@dataclass(frozen=True)
class ToolRule:
    args: Mapping[str, ArgRule] = field(default_factory=dict)
    allow_extra_args: bool = False    # unknown arguments are denied by default


_ARG_KEYS = {f.name for f in fields(ArgRule)}
_TOOL_KEYS = {"args", "allow_extra_args", "description"}
_TOP_KEYS = {"tools", "max_str_len", "version", "description"}


class Policy:
    def __init__(self, tools: Mapping[str, ToolRule], max_str_len: int = DEFAULT_MAX_STR_LEN):
        self.tools = dict(tools)
        self.max_str_len = max_str_len

    # ------------------------------------------------------------------ loading
    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        """Build and *strictly validate* a policy. Raises PolicyError on anything malformed."""
        if not isinstance(data, Mapping):
            raise PolicyError("policy must be a mapping")
        extra = set(data) - _TOP_KEYS
        if extra:
            raise PolicyError(f"unknown top-level keys: {sorted(extra)}")
        raw_tools = data.get("tools")
        if not isinstance(raw_tools, Mapping):
            raise PolicyError("'tools' must be a mapping")
        tools = {}
        for name, spec in raw_tools.items():
            if not isinstance(spec, Mapping):
                raise PolicyError(f"tool {name!r}: spec must be a mapping")
            bad = set(spec) - _TOOL_KEYS
            if bad:
                raise PolicyError(f"tool {name!r}: unknown keys {sorted(bad)}")
            raw_args = spec.get("args", {})
            if not isinstance(raw_args, Mapping):
                raise PolicyError(f"tool {name!r}: 'args' must be a mapping")
            args = {}
            for a, r in raw_args.items():
                if not isinstance(r, Mapping):
                    raise PolicyError(f"tool {name!r} arg {a!r}: rule must be a mapping")
                bad = set(r) - _ARG_KEYS
                if bad:
                    raise PolicyError(f"tool {name!r} arg {a!r}: unknown keys {sorted(bad)}")
                r = dict(r)
                if isinstance(r.get("enum"), list):
                    r["enum"] = tuple(r["enum"])
                args[a] = ArgRule(**r)
            tools[name] = ToolRule(args=args, allow_extra_args=spec.get("allow_extra_args", False))
        policy = cls(tools, max_str_len=data.get("max_str_len", DEFAULT_MAX_STR_LEN))
        problems = policy.validate()
        if problems:
            raise PolicyError("; ".join(problems))
        return policy

    @classmethod
    def from_json(cls, path: str | Path) -> "Policy":
        """Load a policy JSON file. Raises PolicyError if missing, unreadable, or malformed.

        Duplicate keys and NaN/Infinity literals are rejected.
        """
        def no_dupes(pairs):
            out = {}
            for k, v in pairs:
                if k in out:
                    raise PolicyError(f"duplicate key {k!r}")
                out[k] = v
            return out

        def no_constants(c):
            raise PolicyError(f"non-standard JSON constant {c} not allowed")

        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {str(path)!r}: {type(exc).__name__}") from None
        try:
            data = json.loads(text, object_pairs_hook=no_dupes, parse_constant=no_constants)
        except ValueError as exc:  # includes JSONDecodeError and PolicyError
            raise PolicyError(f"policy file {str(path)!r} is invalid: {exc}") from None
        return cls.from_dict(data)

    def validate(self) -> list[str]:
        """Return a list of problems (empty if the policy is well-formed)."""
        p: list[str] = []
        if type(self.max_str_len) is not int or self.max_str_len < 0:
            p.append("max_str_len must be a non-negative int")
        for name, rule in self.tools.items():
            if type(name) is not str or not _TOOL_NAME_RE.fullmatch(name):
                p.append(f"tool name {name!r} must be ASCII [A-Za-z0-9_][A-Za-z0-9_.:/-]{{0,127}}")
                continue
            if not isinstance(rule, ToolRule) or type(rule.allow_extra_args) is not bool:
                p.append(f"tool {name!r}: invalid ToolRule")
                continue
            for a, ar in rule.args.items():
                w = f"tool {name!r} arg {a!r}"
                if type(a) is not str or not a.isascii() or not a.isidentifier():
                    p.append(f"{w}: argument name must be an ASCII identifier")
                if not isinstance(ar, ArgRule):
                    p.append(f"{w}: not an ArgRule")
                    continue
                if ar.type not in _TYPES:
                    p.append(f"{w}: type must be one of {sorted(_TYPES)}")
                    continue
                if type(ar.required) is not bool:
                    p.append(f"{w}: required must be bool")
                for k in ("min", "max"):
                    v = getattr(ar, k)
                    if v is not None and (type(v) not in (int, float) or not math.isfinite(v)):
                        p.append(f"{w}: {k} must be a finite number")
                if ar.max_len is not None and (type(ar.max_len) is not int or ar.max_len < 0):
                    p.append(f"{w}: max_len must be a non-negative int")
                if ar.pattern is not None:
                    try:
                        re.compile(ar.pattern)
                    except (re.error, TypeError) as exc:
                        p.append(f"{w}: invalid pattern ({exc})")
                if not isinstance(ar.enum, tuple) or any(type(e) not in _TYPES[ar.type] for e in ar.enum):
                    p.append(f"{w}: enum values must all be of type {ar.type}")
        return p

    # ------------------------------------------------------------------ evaluation
    def check(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str]:
        if type(tool) is not str:
            return False, "tool_not_allowed"
        rule = self.tools.get(tool)
        if rule is None:
            return False, "tool_not_allowed"
        if not isinstance(arguments, Mapping):
            return False, "arguments_not_a_mapping"
        if not rule.allow_extra_args:
            extra = set(arguments) - set(rule.args)
            if extra:
                return False, f"unexpected_args:{','.join(sorted(map(str, extra)))}"
        for name, ar in rule.args.items():
            if name not in arguments:
                if ar.required:
                    return False, f"missing_arg:{name}"
                continue
            ok, why = _check_arg(name, arguments[name], ar, self.max_str_len)
            if not ok:
                return False, why
        return True, "allowed"


def _check_arg(name: str, value: Any, ar: ArgRule, max_str_len: int = DEFAULT_MAX_STR_LEN) -> tuple[bool, str]:
    expected = _TYPES[ar.type]            # KeyError -> caught by Gate -> deny
    if type(value) not in expected:       # exact type: rejects bool-as-int, subclasses, nested objects
        return False, f"bad_type:{name}"
    if type(value) is float and not math.isfinite(value):
        return False, f"not_finite:{name}"  # NaN compares False to every bound, so reject it explicitly
    if type(value) is str:
        limit = ar.max_len if ar.max_len is not None else max_str_len
        if len(value) > limit:            # checked BEFORE enum/regex so huge inputs are cheap to reject
            return False, f"too_long:{name}"
    if ar.enum and value not in ar.enum:
        return False, f"not_in_enum:{name}"
    if type(value) is str:
        if ar.pattern is not None and re.fullmatch(ar.pattern, value) is None:
            return False, f"pattern_mismatch:{name}"
    if type(value) in (int, float):
        if ar.min is not None and value < ar.min:
            return False, f"below_min:{name}"
        if ar.max is not None and value > ar.max:
            return False, f"above_max:{name}"
    return True, "ok"
