import urllib.parse
import argparse
import os
from .security_scanner import SecurityScanner


def url_type(value: str):
    parsed = urllib.parse.urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise argparse.ArgumentTypeError(f"Invalid URL: {value!r}")
    return parsed.geturl()


def writable_and_creatable(path):
    if os.path.exists(path):
        if not os.path.isfile(path):
            raise argparse.ArgumentTypeError(
                f"'{path}' exists but is not a file.")
        if not os.access(path, os.W_OK):
            raise argparse.ArgumentTypeError(
                f"'{path}' exists but is not writable.")
    else:
        parent = os.path.dirname(path) or '.'
        if not os.path.isdir(parent) or not os.access(parent, os.W_OK):
            raise argparse.ArgumentTypeError(
                f"Cannot create '{path}'. Check directory permissions.")
    return path


def main():
    parser = argparse.ArgumentParser(
        prog='PA_ESGI-sharbouli-scorvisier',
        description='Un programme basique qui permet de checker les vulnérabilités dun site WEB'
    )
    parser.add_argument("-u", "--url", required=True,
                        type=url_type, help="Une url à tester")
    parser.add_argument(
        "-l", "--log",
        type=str.upper,
        choices=["INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Niveau de logging (Par défaut: %(default)s)",
    )
    parser.add_argument(
        "-o", "--output",
        type=writable_and_creatable,
        help="Chemin vers un fichier qui peut être écrit ou créé",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=1,
        help="Nombre de threads pour l'analyse"
    )

    args = parser.parse_args()
    scanner = SecurityScanner(
        target=args.url,
        threads_nbr=args.threads,
        log_level=args.log,
        output_file=args.output
    )
    scanner.run()
