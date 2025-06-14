import subprocess
import re


def lfi_checker(url: str):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    command = ["lfitester", "-u", url]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    vulnerable = False
    payload = None

    for line in process.stdout:
        clean_line = ansi_escape.sub('', line).strip()
        if "[+]" in clean_line and "found" in clean_line:
            vulnerable = True
            payload = clean_line.split("with")[1].strip()
            if vulnerable and payload:
                process.terminate()
                return payload
    return None
