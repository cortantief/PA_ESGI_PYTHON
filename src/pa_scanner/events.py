# pa_scanner/events.py  (or whatever module name you choose)
from __future__ import annotations

from typing import Callable, TypeAlias
from blinker import Signal
from .rapport_gen import Vulnerability


SCAN_START: Signal = Signal("scan-start")
SCAN_END:   Signal = Signal("scan-end")
PAGE_FOUND: Signal = Signal("page-found")
PARAM_FOUND: Signal = Signal("param-found")
VULN_FOUND: Signal = Signal("vuln-found")


ScanStartCB:  TypeAlias = Callable[[str], None]
ScanEndCB:    TypeAlias = Callable[[str], None]
PageFoundCB:  TypeAlias = Callable[[str], None]
ParamFoundCB: TypeAlias = Callable[[str, str], None]
VulnFoundCB:  TypeAlias = Callable[[Vulnerability], None]


def on_scan_start(cb: ScanStartCB, *, weak: bool = False) -> ScanStartCB:
    SCAN_START.connect(lambda _s, target: cb(target), weak=weak)
    return cb


def on_scan_end(cb: ScanEndCB, *, weak: bool = False) -> ScanEndCB:
    SCAN_END.connect(lambda _s, target: cb(target), weak=weak)
    return cb


def on_page_found(cb: PageFoundCB, *, weak: bool = False) -> PageFoundCB:
    PAGE_FOUND.connect(lambda _s, url: cb(url), weak=weak)
    return cb


def on_param_found(cb: ParamFoundCB, *, weak: bool = False) -> ParamFoundCB:
    PARAM_FOUND.connect(lambda _s, url, param: cb(url, param), weak=weak)
    return cb


def on_vuln_found(cb: VulnFoundCB,  *, weak: bool = False) -> VulnFoundCB:
    VULN_FOUND.connect(
        lambda _s, vuln: cb(vuln), weak=weak
    )
    return cb


def scan_start(target: str) -> None:
    SCAN_START.send(target=target)


def scan_end(target: str) -> None:
    SCAN_END.send(target=target)


def page_found(url: str) -> None:
    PAGE_FOUND.send(url=url)


def param_found(url: str, param: str) -> None:
    PARAM_FOUND.send(url=url, param=param)


def vuln_found(vuln: Vulnerability) -> None:
    VULN_FOUND.send(vuln=vuln)


__all__ = [
    "on_scan_start", "on_scan_end",
    "on_page_found", "on_param_found", "on_vuln_found",
    "VulnType",
]
