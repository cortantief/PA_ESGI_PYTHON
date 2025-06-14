import urllib.parse
import scrapy
import urllib
import re
from scrapy.crawler import CrawlerProcess
import tree
import threading
import argparse
from pydispatch import dispatcher
from scrapy import signals
from queue import Queue
from typing import List
import os
import params_finder
import lfi_checker
import xss_finder
import sql_checker
import utils
import pa_log

LOG_LEVEL = "INFO"


def worker(task_queue: Queue):
    while not task_queue.empty():
        task = task_queue.get()
        url = task["url"]
        if not task:
            return
        node: tree.WebTree = task["node"]
        if not node.params:
            words = params_finder.params_finder(url)
            for param in words:
                node.params[param] = [utils.generate_random_value()]
                if LOG_LEVEL == "INFO":
                    parsed = urllib.parse.urlparse(url)
                    print(f"Param `{param}` found in {parsed.path}")
        for param in node.params.keys():
            clean = utils.add_or_update_url_param(
                utils.strip_url_params(url), param, node.params[param])
            lfi = lfi_checker.lfi_checker(clean)
            xss = xss_finder.xss_checker(clean)
            if xss:
                pa_log.warning(url)
            if lfi:
                pa_log.warning(url)
        task_queue.task_done()  # Mark task as done


def in_domain(url: str, domain: str) -> bool:
    try:
        d = urllib.parse.urlparse(url)
        return d.netloc == domain
    except:
        return False


class Scrapper(scrapy.Spider):
    start_urls = []
    found_url = set()
    schema_regex = re.compile(r"^([a-zA-Z]+://|[a-zA-Z]+:)")
    threads: List[threading.Thread] = []

    def __init__(self, target: str, threads_nbr: int = 1, **kwargs):
        domain = urllib.parse.urlparse(target).netloc
        self.queue = Queue()
        if target[-1] != "/":
            target = target + "/"
        super().__init__(domain, **kwargs)
        self.start_urls = [target]
        self.allowed_domains = [domain.split(":")[0]]
        self.tree = tree.WebTree("/")
        self.target = target
        self.threads_nbr = threads_nbr
        dispatcher.connect(self.spider_closed, signals.spider_closed)

    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(url=url, callback=self.parse)

    def get_url(self, response):
        urls = []
        for url in response.css("a::attr(href)").getall():
            if not self.schema_regex.search(url):
                url = urllib.parse.urljoin(self.target, url)
                parsed_url = urllib.parse.urlparse(url)
                path = parsed_url.path
                params = urllib.parse.parse_qs(parsed_url.query)
                node = None
                if path not in self.found_url and path != "/":
                    self.found_url.add(path)
                    node = self.tree.add(path)
                    node.params = params

                    urls.append({"link": urllib.parse.urljoin(
                        self.target, path), "path": path, "node": node})
                else:
                    node = self.tree.find_by_path(path)
                    if path == "/":
                        node = self.tree
                    for key in params.keys():
                        if key not in node.params:
                            node.params[key] = params[key]
        return urls

    def parse(self, response):
        for url in self.get_url(response):
            node = url["node"]
            if node is not None:
                self.queue.put({"node": node, "url": url["link"]})
            yield scrapy.Request(url["link"], callback=self.parse)

    def spider_closed(self):
        threads = []
        for _ in range(self.threads_nbr):

            thread = threading.Thread(
                target=worker, args=(self.queue,))
            thread.start()
            threads.append(thread)

        for t in thread:
            t.join()
        self.queue.join()


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
        if not os.path.isdir(parent):
            raise argparse.ArgumentTypeError(
                f"Directory '{parent}' does not exist.")
        if not os.access(parent, os.W_OK):
            raise argparse.ArgumentTypeError(
                f"Directory '{parent}' is not writable, so cannot create '{path}'."
            )
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='PA_ESGI-sharbouli-scorvisier',
        description='Un programme basique qui permet de checker les vulnérabilités',
        epilog='')
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
        help="path to a file that either exists and is writable, or can be created"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=1,
        help="path to a file that either exists and is writable, or can be created"
    )
    args = parser.parse_args()
    LOG_LEVEL = args.log
    process = CrawlerProcess(
        settings={"LOG_LEVEL": 'WARNING', 'LOG_ENABLED': False, })
    process.crawl(
        Scrapper, target=args.url, threads_nbr=args.threads)
    process.start()
