from collections import Counter
import matplotlib.pyplot as plt
import os
import jinja2
import pdfkit
from datetime import datetime, timezone
import tempfile
import json
from pathlib import Path
from typing import TypedDict, List, Literal
from enum import Enum
from dataclasses import dataclass


class VulnerabilityName(str, Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting (XSS)"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    IDOR = "Insecure Direct Object Reference"
    DIRECTORY_TRAVERSAL = "Directory Traversal"
    LFI = "Local File Inclusion"


@dataclass
class Vulnerability:
    name: VulnerabilityName
    endpoint: str

    def export(self) -> dict:
        return {
            "name": self.name.value,
            "endpoint": self.endpoint,
            "description": get_vulnerability_description(self.name)
        }


class VulnerabilityStore:
    def __init__(self, target: str):
        self.vulnerabilities: List[Vulnerability] = []
        self.target = target

    def add_vuln(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)

    def export(self):
        export = []
        for vuln in self.vulnerabilities:
            export.append(vuln.export())
        return export


def get_vulnerability_description(vuln_name: VulnerabilityName) -> str:
    descriptions = {
        VulnerabilityName.SQLI: "Occurs when unsanitized input is embedded in SQL queries. Use parameterized queries or ORM frameworks.",
        VulnerabilityName.XSS: "Allows attackers to inject malicious scripts into web pages. Prevent it using output encoding and CSP headers.",
        VulnerabilityName.CSRF: "Tricks users into performing unintended actions. Use CSRF tokens and SameSite cookie attributes.",
        VulnerabilityName.IDOR: "Exposes internal objects by changing user-controlled identifiers. Enforce proper authorization checks.",
        VulnerabilityName.DIRECTORY_TRAVERSAL: "Allows access to unauthorized files by manipulating path inputs. Validate and sanitize file paths.",
        VulnerabilityName.LFI: "Enables reading of local files on the server. Validate file inclusion inputs and avoid dynamic file loading."
    }

    return descriptions.get(vuln_name, "No description available.")


def generate_chart(vulnerabilities):
    """
    Generates a pie chart image of vulnerability counts by type using matplotlib,
    and returns the file path to the temporary image file.
    """
    counts = Counter(v["name"] for v in vulnerabilities)
    labels = list(counts.keys())
    values = list(counts.values())

    # Optional: assign a consistent color for each type (fallback to gray)
    base_colors = [
        "#0d6efd", "#6f42c1", "#d63384", "#fd7e14",
        "#20c997", "#198754", "#ffc107", "#dc3545"
    ]
    colors = base_colors[:len(labels)]

    # Create temporary image file
    temp_img = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    plt.figure(figsize=(5, 5))
    plt.pie(values, labels=labels, autopct='%1.1f%%', colors=colors)
    plt.title("Vulnerabilities by Type")
    plt.tight_layout()
    plt.savefig(temp_img.name, bbox_inches='tight')
    plt.close()

    return temp_img.name


def render_html(vulnerabilities, outputpath: str):
    chart_path = generate_chart(vulnerabilities)

    # Jinja2 rendering
    template_loader = jinja2.FileSystemLoader(searchpath="templates")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template("layout.html")

    now_utc = datetime.now(timezone.utc)
    html_content = template.render(
        vulnerabilities=vulnerabilities,
        generation_time=now_utc.strftime("%Y-%m-%d %H:%M %Z"),
        target_name="http://test.local",
        chart_image_path=chart_path
    )

    # Create temp HTML file (not using context manager)
    tmp_html_file = tempfile.NamedTemporaryFile(
        suffix=".html", delete=False, mode="w", encoding="utf-8")
    tmp_html_file.write(html_content)
    tmp_html_file.flush()  # ensure it's on disk
    tmp_html_path = tmp_html_file.name
    tmp_html_file.close()  # ensure it's not locked by Python
    try:
        pdfkit.from_file(tmp_html_path, outputpath, options={
            'enable-internal-links': '',
            'enable-local-file-access': '',
            'quiet': ''
        })
    finally:
        os.remove(tmp_html_path)
        os.remove(chart_path)


def output_json(vulnerabilities, outputpath: str):
    with open(outputpath, "w") as output:
        output.write(json.dumps(vulnerabilities, indent=2))


if __name__ == "__main__":
    store = VulnerabilityStore(target="http://test.local")
    vulns = [
        Vulnerability(VulnerabilityName.SQLI, "/login"),
        Vulnerability(VulnerabilityName.SQLI, "/admin/login"),
        Vulnerability(VulnerabilityName.SQLI, "/search"),
        Vulnerability(VulnerabilityName.XSS, "/profile"),
        Vulnerability(VulnerabilityName.XSS, "/comment"),
        Vulnerability(VulnerabilityName.XSS, "/forum/post"),
        Vulnerability(VulnerabilityName.CSRF, "/account/settings"),
        Vulnerability(VulnerabilityName.CSRF, "/user/email/change"),
        Vulnerability(VulnerabilityName.CSRF, "/billing/update"),
        Vulnerability(VulnerabilityName.IDOR, "/user/1234"),
        Vulnerability(VulnerabilityName.IDOR, "/orders/5678"),
        Vulnerability(VulnerabilityName.IDOR, "/invoices/3456"),
        Vulnerability(VulnerabilityName.DIRECTORY_TRAVERSAL,
                      "/download?file=../../etc/passwd"),
        Vulnerability(VulnerabilityName.DIRECTORY_TRAVERSAL,
                      "/view?path=../../../var/log"),
        Vulnerability(VulnerabilityName.DIRECTORY_TRAVERSAL,
                      "/files?name=../../../secret.txt"),
        Vulnerability(VulnerabilityName.LFI, "/include?page=about"),
        Vulnerability(VulnerabilityName.LFI,
                      "/render?template=../../../etc/shadow"),
        Vulnerability(VulnerabilityName.LFI, "/load?module=config"),
        Vulnerability(VulnerabilityName.SQLI, "/reports"),
        Vulnerability(VulnerabilityName.XSS, "/messages"),
        Vulnerability(VulnerabilityName.CSRF, "/payment/submit"),
        Vulnerability(VulnerabilityName.IDOR, "/profile/9999"),
        Vulnerability(VulnerabilityName.LFI, "/config/load"),
        Vulnerability(VulnerabilityName.DIRECTORY_TRAVERSAL,
                      "/archive?file=../../../boot.ini"),
        Vulnerability(VulnerabilityName.SQLI, "/api/query"),
        Vulnerability(VulnerabilityName.XSS, "/support/ticket"),
        Vulnerability(VulnerabilityName.CSRF, "/feedback/submit"),
        Vulnerability(VulnerabilityName.IDOR, "/employee/records"),
        Vulnerability(VulnerabilityName.LFI, "/viewer?log=access.log"),
        Vulnerability(VulnerabilityName.DIRECTORY_TRAVERSAL,
                      "/config/edit?file=../../.env"),
    ]

    for vuln in vulns:
        store.add_vuln(vuln)
    render_html(store.export(), "/tmp/test.pdf")
    output_json(store.export(), "/tmp/test.json")
