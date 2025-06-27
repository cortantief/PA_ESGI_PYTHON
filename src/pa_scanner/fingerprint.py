import requests
import hashlib
import time


def hash_content(content):
    return hashlib.sha256(content.encode('utf-8')).hexdigest()


def generate_fingerprint(url: str):

    # Inject random benign value

    try:
        start_time = time.time()
        response = requests.get(url, timeout=5)
        end_time = time.time()
        return {
            "url": url,
            "status_code": response.status_code,
            "error": None,
            "headers": dict(response.headers),
            "content_hash": hash_content(response.text),
            "content_length": len(response.text),
            "response_time": round(end_time - start_time, 4)
        }
    except requests.RequestException as e:
        return {
            "url": url,
            "error": str(e),
            "status_code": -1,
            "headers": {},
            "content_hash": None,
            "content_length": 0,
            "response_time": None

        }


def compare_fingerprint(a, b):
    s = a["status_code"] == b["status_code"]
    cl = a["content_length"] == b["content_length"]
    err = a["error"] == b["error"]
    return s and cl and err
