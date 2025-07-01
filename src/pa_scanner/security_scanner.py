from . import tree
from . import params_finder
from . import lfi_checker
from . import xss_checker
from . import sql_checker
from . import utils
from . import pa_log
from . import events as ev
from . import rapport_gen
from .rapport_gen import Vulnerability, VulnerabilityName
import scrapy
import re
from scrapy.crawler import CrawlerProcess
import threading
from pydispatch import dispatcher
from scrapy import signals
from queue import Queue
import urllib
import time


class SecurityScanner:
    def __init__(self, target: str, threads_nbr: int = 1, log_level: str = "INFO", output_file: str | None = None):
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
        self._task_size = 0
        self._started = False
        self.output_file = output_file
        self._vuln_store = rapport_gen.VulnerabilityStore(target)

        @ev.on_vuln_found
        def _log_vuln(vuln: rapport_gen.Vulnerability):
            self._logger.warning(
                f'Vulnerability of type {vuln.name} is found in the endpoint `{vuln.endpoint}` with parameter `{vuln.param}` with that payload : {vuln.payload}')
            self._vuln_store.add_vuln(vuln)

    def get_progress(self) -> float:
        if not self._started or self._task_size == 0:
            return 0.0

        remaining = self.queue.unfinished_tasks      # ← after task_done()
        done = self._task_size - remaining
        return done / self._task_size * 100.0

    def run(self):
        dispatcher.connect(self._on_spider_closed, signals.spider_closed)
        self.process.crawl(self.Scrapper, scanner=self)
        self.process.start()

    def _on_spider_closed(self):
        threads = []
        self._task_size = self.queue.qsize()
        self._started = True
        ev.scan_start(self.target)
        for _ in range(self.threads_nbr):
            thread = threading.Thread(target=self._worker)
            thread.start()
            threads.append(thread)
        for t in threads:
            t.join()
        self.queue.join()
        ev.scan_end(self.target)
        if self.output_file:
            self._logger.info(f"Creating file to path `{self.output_file}`")
            try:
                rapport_gen.render_html(
                    self._vuln_store.export(), self.output_file, self.target)
            except Exception as e:
                self._logger.error(e)

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
                    ev.param_found(url=url, param=param)
                    parsed = urllib.parse.urlparse(url)
                    self._logger.info(
                        f"Param `{param}` found in {parsed.path}")

            url_clean = utils.strip_url_params(url)
            for param in node.params:
                vuln = None
                clean = utils.add_or_update_url_param(
                    url_clean, param, node.params[param]
                )
                if lfi := lfi_checker.lfi_checker(clean):
                    vuln = Vulnerability(
                        VulnerabilityName.LFI, url, param, lfi)
                    ev.vuln_found(vuln)

                if xss := xss_checker.xss_checker(clean):
                    vuln = Vulnerability(
                        VulnerabilityName.XSS, url, param, xss)
                    ev.vuln_found(vuln)

                if sqli := sql_checker.sql_checker(clean):
                    vuln = Vulnerability(
                        VulnerabilityName.SQLI, url, param, sqli)
                    ev.vuln_found(vuln)

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
