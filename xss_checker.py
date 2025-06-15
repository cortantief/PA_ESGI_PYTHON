import subprocess
import re
import urllib
import urllib.parse


def xss_checker(url: str):
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    command = ["xsstrike", "-u", url, "--skip"]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    payload = None
    efficiency = None
    confidence = None
    result = None
    for line in process.stdout:
        clean_line = ansi_escape.sub('', line).strip()
        if "[+] Payload:" in clean_line:
            payload = clean_line.split("[+] Payload:")[1].strip()
        elif "[!] Efficiency:" in clean_line:
            efficiency = int(clean_line.split("[!] Efficiency:")[1].strip())
        elif "[!] Confidence:" in clean_line:
            confidence = int(clean_line.split("[!] Confidence:")[1].strip())

        if payload and efficiency is not None and confidence is not None:

            if confidence == 10:
                process.terminate()
                return urllib.parse.unquote(payload)
            elif result is None or (result is not None and result["confidence"] < confidence):
                result = urllib.parse.unquote(payload)
    return result
