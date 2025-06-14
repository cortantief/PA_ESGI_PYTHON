import subprocess
import re


def xss_checker(url: str):
    """
    Runs xsstrike against a URL and stops on first payload found.

    Returns:
        dict: {"Payload": ..., "Efficiency": ..., "Confidence": ...}
        or None if no payload was found.
    """
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')

    command = ["xsstrike", "-u", url]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True
    )

    payload = None
    efficiency = None
    confidence = None

    for line in process.stdout:
        clean_line = ansi_escape.sub('', line).strip()

        if "[+] Payload:" in clean_line:
            payload = clean_line.split("[+] Payload:")[1].strip()
        elif "[!] Efficiency:" in clean_line:
            efficiency = int(clean_line.split("[!] Efficiency:")[1].strip())
        elif "[!] Confidence:" in clean_line:
            confidence = int(clean_line.split("[!] Confidence:")[1].strip())

        if payload and efficiency is not None and confidence is not None:
            process.terminate()  # Stop xsstrike
            return {
                "payload": payload,
                "efficiency": efficiency,
                "confidence": confidence
            }

    return None
