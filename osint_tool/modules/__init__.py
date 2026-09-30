"""Module registry.

Every lookup is a plain function registered with ``@module``. It receives
the normalized target string and returns a JSON-serializable dict. Raising
``ModuleError`` (or any exception) marks the module as failed in the UI.
"""

import time
from dataclasses import dataclass, field


class ModuleError(Exception):
    pass


@dataclass
class Module:
    name: str
    title: str
    types: tuple
    description: str
    func: callable = field(repr=False)
    order: int = 50


REGISTRY = {}


def module(name, title, types, description="", order=50):
    def wrap(func):
        REGISTRY[name] = Module(name, title, tuple(types), description, func, order)
        return func

    return wrap


def modules_for(target_type):
    mods = [m for m in REGISTRY.values() if target_type in m.types]
    return sorted(mods, key=lambda m: m.order)


def run_module(name, target):
    mod = REGISTRY.get(name)
    if mod is None:
        raise KeyError(name)
    started = time.monotonic()
    try:
        data = mod.func(target)
        ok, error = True, None
    except ModuleError as exc:
        data, ok, error = None, False, str(exc)
    except Exception as exc:  # network errors, parse errors, etc.
        data, ok, error = None, False, f"{type(exc).__name__}: {exc}"
    return {
        "module": name,
        "title": mod.title,
        "ok": ok,
        "error": error,
        "data": data,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
    }


# Import submodules so they register themselves.
from . import (  # noqa: E402,F401
    dns,
    whois,
    email_security,
    subdomains,
    web,
    tls,
    wayback,
    ipintel,
    username,
    email,
    phone,
    hashid,
    dorks,
)
