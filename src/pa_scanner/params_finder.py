from . import utils
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .fingerprint import generate_fingerprint, compare_fingerprint


def params_finder(url: str):
    fing = generate_fingerprint(url)
    with open("../wordlists/parameters.txt", "r") as wordlists:
        parsed_url = urlparse(url)

        # Get existing query parameters

        # Add or update a parameter
        words = []
        for word in map(lambda x: x.strip(), wordlists):
            # Note: values must be in list format
            query_params = {}
            query_params[word] = [utils.generate_random_value()]

            # Convert parameters back to query string
            new_query = urlencode(query_params, doseq=True)

            # Rebuild the URL with the updated query string
            new_url = urlunparse(parsed_url._replace(query=new_query))
            new_fing = generate_fingerprint(new_url)
            if not compare_fingerprint(fing, new_fing) and compare_fingerprint(fing, generate_fingerprint(url)):
                words.append(word)
        return words
