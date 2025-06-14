import threading
import time
from datetime import datetime
from rich.console import Console
from rich.text import Text
from rich.style import Style
from threading import Lock
from collections import deque


class PrettyLogger:
    LEVELS = ["DEBUG", "INFO", "WARNING",
              "ERROR", "CRITICAL", "PAYLOAD", "TRAFFIC"]

    def __init__(self, level="INFO"):
        self.console = Console()
        self.level = level.upper()
        if self.level not in self.LEVELS:
            self.level = "INFO"

        self.styles = {
            "DEBUG": "bright_cyan",
            "INFO": "bright_blue",
            "WARNING": "bright_yellow",
            "ERROR": "bright_red",
            "CRITICAL": "bright_white on red",
            "PAYLOAD": "bright_magenta",
            "TRAFFIC": "bright_green",
            "TIMESTAMP": "bright_green",
        }

        self._buffer = deque()         # Optional: can be used for batch/log history
        self._lock = Lock()            # Protect console output

    def _enqueue_and_flush(self, lvl, msg):
        if self.LEVELS.index(lvl) < self.LEVELS.index(self.level):
            return

        ts = datetime.now().strftime("%H:%M:%S")
        styled_ts = Text(ts, style=self.styles["TIMESTAMP"])
        styled_level = Text(lvl, style=self.styles.get(lvl, ""))

        # Build the full styled message
        line = Text("[") + styled_ts + Text("] [") + \
            styled_level + Text("] ") + Text(msg)

        # Lock to ensure atomic print
        with self._lock:
            self.console.print(line)

    def debug(self, msg): self._enqueue_and_flush("DEBUG", msg)
    def info(self, msg): self._enqueue_and_flush("INFO", msg)
    def warning(self, msg): self._enqueue_and_flush("WARNING", msg)
    def error(self, msg): self._enqueue_and_flush("ERROR", msg)
    def critical(self, msg): self._enqueue_and_flush("CRITICAL", msg)
    def payload(self, msg): self._enqueue_and_flush("PAYLOAD", msg)
    def traffic(self, msg): self._enqueue_and_flush("TRAFFIC", msg)
