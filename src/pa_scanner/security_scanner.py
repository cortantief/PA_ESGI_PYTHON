from . import tree
from . import params_finder
from . import lfi_checker
from . import xss_checker
from . import sql_checker
from . import utils
from . import pa_log
from . import events as ev

from .events import VulnType

import scrapy
import re
from scrapy.crawler import CrawlerProcess
import threading
from pydispatch import dispatcher
from scrapy import signals
from queue import Queue
import urllib


class SecurityScanner:
    def __init__(self, target: str, threads_nbr: int = 1, log_level: str = "INFO"):
        self.target = target if target.endswith("/") else target + "/"
        self.domain = urllib.parse.urlparse(self.target).netloc
        self.threads_nbr = threads_nbr
        self.log_level = log_level
        self.queue = Queue()
        self.tree = tree.WebTree("/")
        self.process = CrawlerProcess(
            settings={'LOG_ENABLED': False}
        )
        self._logger = pa_log.PrettyLogger(level=log_level)

    def run(self):
        ev.scan_start(self.target)
        dispatcher.connect(self._on_spider_closed, signals.spider_closed)
        self.process.crawl(self.Scrapper, scanner=self)
        self.process.start()

    def _on_spider_closed(self):
        threads = []
        for _ in range(self.threads_nbr):
            thread = threading.Thread(target=self._worker)
            thread.start()
            threads.append(thread)
        for t in threads:
            t.join()
        self.queue.join()
        ev.scan_end(self.target)

    def _worker(self):
        while not self.queue.empty():
            task = self.queue.get()
            if not task:
                return

            url = task["url"]
            node: tree.WebTree = task["node"]

            if not node.params:
                words = params_finder.params_finder(url)
                for param in words:
                    node.params[param] = [utils.generate_random_value()]
                    ev.PARAM_FOUND.send(url=url, param=param)
                    parsed = urllib.parse.urlparse(url)
                    self._logger.info(
                        f"Param `{param}` found in {parsed.path}")

            for param in node.params:
                clean = utils.add_or_update_url_param(
                    utils.strip_url_params(url), param, node.params[param]
                )
                if lfi := lfi_checker.lfi_checker(clean):
                    vulnerable = utils.add_or_update_url_param(
                        utils.strip_url_params(url), param, lfi
                    )
                    self._logger.warning(
                        f"{VulnType.LFI} Vulnerability found : {lfi}")
                    ev.vuln_found(url=vulnerable,
                                  type=VulnType.LFI, payload=lfi)
                if xss := xss_checker.xss_checker(clean):
                    vulnerable = utils.add_or_update_url_param(
                        utils.strip_url_params(url), param, xss
                    )
                    self._logger.warning(
                        f"{VulnType.XSS} Vulnerability found : {vulnerable}")
                    ev.vuln_found(
                        url=vulnerable, type=VulnType.XSS, payload=xss)
                if sqli := sql_checker.sql_checker(clean):
                    vulnerable = utils.add_or_update_url_param(
                        utils.strip_url_params(url), param, sqli
                    )
                    self._logger.warning(
                        f"{VulnType.SQLI} Vulnerability found : {vulnerable}")
                    ev.vuln_found(
                        url=vulnerable, type=VulnType.SQLI, payload=sqli)

            self.queue.task_done()

    class Scrapper(scrapy.Spider):
        name = "scrapper"
        schema_regex = re.compile(r"^([a-zA-Z]+://|[a-zA-Z]+:)")

        def __init__(self, scanner: "SecurityScanner", **kwargs):
            super().__init__(**kwargs)
            self.scanner = scanner
            self.start_urls = [scanner.target]
            self.allowed_domains = [scanner.domain.split(":")[0]]
            self.found_url = set()

        def start_requests(self):
            for url in self.start_urls:
                yield scrapy.Request(url=url, callback=self.parse)

        def parse(self, response):
            for url_data in self.extract_urls(response):
                node = url_data["node"]
                if node:
                    self.scanner.queue.put(
                        {"node": node, "url": url_data["link"]})
                yield scrapy.Request(url_data["link"], callback=self.parse)

        def extract_urls(self, response):
            urls = []
            for url in response.css("a::attr(href)").getall():
                if not self.schema_regex.search(url):
                    full_url = urllib.parse.urljoin(self.scanner.target, url)
                    parsed_url = urllib.parse.urlparse(full_url)
                    path = parsed_url.path
                    params = urllib.parse.parse_qs(parsed_url.query)
                    node = None

                    if path not in self.found_url and path != "/":
                        self.found_url.add(path)
                        node = self.scanner.tree.add(path)
                        node.params = params
                        urls.append(
                            {"link": full_url, "path": path, "node": node})
                    else:
                        node = self.scanner.tree.find_by_path(
                            path) or self.scanner.tree
                        for key in params:
                            if key not in node.params:
                                node.params[key] = params[key]
            return urls
