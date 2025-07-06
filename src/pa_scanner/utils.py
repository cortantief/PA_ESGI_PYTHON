import string
import random
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


def add_or_update_url_param(url: str, key: str, value) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    # Update or add the parameter
    query[key] = value

    # Build new query string
    new_query = urlencode(query, doseq=True)

    # Construct updated URL
    new_url = urlunparse(parsed._replace(query=new_query))
    return new_url


def strip_url_params(url: str) -> str:
    parsed = urlparse(url)
    stripped = parsed._replace(query="", params="", fragment="")
    return urlunparse(stripped)


def generate_random_value(length=8, digits=False):

    if digits:
        chars = string.digits
    else:
        chars = string.ascii_letters + string.digits

    return ''.join(random.choices(chars, k=length))
