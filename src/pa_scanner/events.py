from blinker import Signal

SCAN_START: Signal = Signal("scan-start")     # payload: {"target": str}
SCAN_END: Signal = Signal("scan-end")       # payload: {"target": str}
PAGE_FOUND: Signal = Signal("page-found")     # payload: {"url": str}
# payload: {"url": str, "param": str}
PARAM_FOUND: Signal = Signal("param-found")
# payload: {"url": str, type": Literal["XSS","SQLI","LFI"],"payload": str}
VULN_FOUND: Signal = Signal("vuln-found")
__all__ = [
    "SCAN_START", "SCAN_END",
    "PAGE_FOUND", "PARAM_FOUND", "VULN_FOUND",
]
