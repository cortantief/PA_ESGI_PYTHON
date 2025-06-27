import subprocess
import re
import os
import tempfile
import urllib
import urllib.parse


def sql_checker(url: str):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    # Use a temp HOME to avoid writing .local files
    with tempfile.TemporaryDirectory() as temp_home:
        env = os.environ.copy()
        env["HOME"] = temp_home

        command = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--technique=BEUSTQ",
            "--output-dir=/dev/null"
        ]

        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env
        ) as process:

            vulnerable = False
            payload_info = None

            for line in process.stdout:
                clean_line = ansi_escape.sub('', line).strip()
                # Look for known sqlmap indicators of vulnerability
                if "is vulnerable" in clean_line or "parameter" in clean_line and "appears to be injectable" in clean_line:
                    vulnerable = True

                if clean_line.lower().startswith("payload:"):
                    payload_info = clean_line.lower().split(
                        "payload:", 1)[1].strip()

                if vulnerable and payload_info:
                    process.terminate()
                    return urllib.parse.unquote(payload_info)

        return None
