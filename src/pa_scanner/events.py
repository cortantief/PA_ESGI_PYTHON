# pa_scanner/events.py  (or whatever module name you choose)
from __future__ import annotations

from typing import Callable, Literal, TypeAlias
from blinker import Signal
from enum import Enum


class VulnType(str, Enum):
    XSS = "XSS"
    SQLI = "SQLI"
    LFI = "LFI"

    def __str__(self) -> str:
        return self.value


# ──────────────────────────────────────────
# 1.  Define the raw signals
# ──────────────────────────────────────────
SCAN_START: Signal = Signal("scan-start")          # kwargs: target
SCAN_END:   Signal = Signal("scan-end")            # kwargs: target
PAGE_FOUND: Signal = Signal("page-found")          # kwargs: url
PARAM_FOUND: Signal = Signal("param-found")        # kwargs: url,param
VULN_FOUND: Signal = Signal("vuln-found")          # kwargs: url,type,payload

# ──────────────────────────────────────────
# 2.  Type aliases for user callbacks
# ──────────────────────────────────────────
ScanStartCB:  TypeAlias = Callable[[str], None]
ScanEndCB:    TypeAlias = Callable[[str], None]
PageFoundCB:  TypeAlias = Callable[[str], None]
ParamFoundCB: TypeAlias = Callable[[str, str], None]
VulnFoundCB:  TypeAlias = Callable[[str, VulnType, str], None]


# ──────────────────────────────────────────
# 3.  Tiny wrappers that hide *sender*
#     Can be used as decorators *or* plain calls.
# ──────────────────────────────────────────


def on_scan_start(cb: ScanStartCB, *, weak: bool = False) -> ScanStartCB:
    SCAN_START.connect(lambda _s, target: cb(target), weak=weak)
    return cb                       # allows use as a decorator


def on_scan_end(cb: ScanEndCB, *, weak: bool = False) -> ScanEndCB:
    SCAN_END.connect(lambda _s, target: cb(target), weak=weak)
    return cb


def on_page_found(cb: PageFoundCB, *, weak: bool = False) -> PageFoundCB:
    PAGE_FOUND.connect(lambda _s, url: cb(url), weak=weak)
    return cb


def on_param_found(cb: ParamFoundCB, *, weak: bool = False) -> ParamFoundCB:
    PARAM_FOUND.connect(lambda _s, url, param: cb(url, param), weak=weak)
    return cb


def on_vuln_found(cb: VulnFoundCB, *, weak: bool = False) -> VulnFoundCB:
    VULN_FOUND.connect(
        lambda _s, url, type, payload: cb(url, type, payload), weak=weak
    )
    return cb

# ──────────────────────────────────────────
# 4.  Helper functions to *emit* events
#     (used only inside SecurityScanner)
# ──────────────────────────────────────────


def scan_start(target: str) -> None:
    SCAN_START.send(target=target)


def scan_end(target: str) -> None:
    SCAN_END.send(target=target)


def page_found(url: str) -> None:
    PAGE_FOUND.send(url=url)


def param_found(url: str, param: str) -> None:
    PARAM_FOUND.send(url=url, param=param)


def vuln_found(url: str, type: VulnType, payload: str) -> None:
    VULN_FOUND.send(url=url, type=type, payload=payload)


__all__ = [          # everything IDEs/docs should expose
    "on_scan_start", "on_scan_end",
    "on_page_found", "on_param_found", "on_vuln_found",
    "VulnType",
]
