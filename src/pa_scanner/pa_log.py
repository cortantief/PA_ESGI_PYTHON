
from datetime import datetime
from rich.console import Console
from rich.text import Text
from threading import Lock
from collections import deque


class PrettyLogger:
    LEVELS = ["DEBUG", "INFO", "WARNING",
              "ERROR", "CRITICAL", "PAYLOAD", "TRAFFIC"]

    def __init__(self, level="INFO", enabled=True):
        self.console = Console()
        self.level = level.upper()
        self.enabled = enabled
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

        self._buffer = deque()
        self._lock = Lock()

    def _enqueue_and_flush(self, lvl, msg):
        if self.LEVELS.index(lvl) < self.LEVELS.index(self.level) or not self.enabled:
            return

        ts = datetime.now().strftime("%H:%M:%S")
        styled_ts = Text(ts, style=self.styles["TIMESTAMP"])
        styled_level = Text(lvl, style=self.styles.get(lvl, ""))

        line = Text("[") + styled_ts + Text("] [") + \
            styled_level + Text("] ") + Text(msg)

        with self._lock:
            self.console.print(line)

    def debug(self, msg): self._enqueue_and_flush("DEBUG", msg)
    def info(self, msg): self._enqueue_and_flush("INFO", msg)
    def warning(self, msg): self._enqueue_and_flush("WARNING", msg)
    def error(self, msg): self._enqueue_and_flush("ERROR", msg)
    def critical(self, msg): self._enqueue_and_flush("CRITICAL", msg)
    def payload(self, msg): self._enqueue_and_flush("PAYLOAD", msg)
    def traffic(self, msg): self._enqueue_and_flush("TRAFFIC", msg)
