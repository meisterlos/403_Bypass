from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import requests

from .strategies import BypassVariant, generate_bypass_variants


@dataclass
class ScanConfig:
    target_url: str
    headers: Dict[str, str]
    proxies: Optional[Dict[str, str]]
    timeout_seconds: float
    max_workers: int
    delay_between_requests_ms: int
    include_non_idempotent: bool
    query_payloads: List[str]
    user_agent: Optional[str]
    cookies: Optional[str]


@dataclass
class ScanResult:
    method: str
    url: str
    status_code: int
    content_length: int
    elapsed_ms: int
    description: str


class Scanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def _prepare_session(self) -> requests.Session:
        session = requests.Session()
        if self.config.user_agent:
            session.headers.update({"User-Agent": self.config.user_agent})
        if self.config.cookies:
            session.headers.update({"Cookie": self.config.cookies})
        if self.config.headers:
            session.headers.update(self.config.headers)
        return session

    def _send_one(self, session: requests.Session, variant: BypassVariant) -> Optional[ScanResult]:
        if self.is_stopped():
            return None
        try:
            start = time.time()
            response = session.request(
                method=variant.method,
                url=variant.url,
                headers=variant.headers,
                timeout=self.config.timeout_seconds,
                allow_redirects=False,
                proxies=self.config.proxies,
                verify=True,
            )
            elapsed_ms = int((time.time() - start) * 1000)
            content_length = int(
                response.headers.get(
                    "Content-Length", len(response.content) if response.content is not None else 0
                )
            )
            result = ScanResult(
                method=variant.method,
                url=variant.url,
                status_code=response.status_code,
                content_length=content_length,
                elapsed_ms=elapsed_ms,
                description=variant.description,
            )
            return result
        except requests.RequestException:
            return None

    def run(self) -> Iterable[ScanResult]:
        variants = generate_bypass_variants(
            self.config.target_url,
            base_headers=self.config.headers,
            include_non_idempotent=self.config.include_non_idempotent,
            extra_query_payloads=self.config.query_payloads,
        )

        session = self._prepare_session()

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = []
            for v in variants:
                if self.is_stopped():
                    break
                futures.append(executor.submit(self._send_one, session, v))
                if self.config.delay_between_requests_ms > 0:
                    time.sleep(self.config.delay_between_requests_ms / 1000.0)

            for fut in as_completed(futures):
                if self.is_stopped():
                    break
                result = fut.result()
                if result is not None:
                    yield result
