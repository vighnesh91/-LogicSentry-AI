#!/usr/bin/env python3
"""LogicSentry AI: single-file business-logic SAST and DAST analyzer."""

from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import binascii
import copy
import difflib
import functools
import importlib
import importlib.metadata
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from pathlib import Path, PurePosixPath
from typing import (
    Any,
    Callable,
    Iterable,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Union,
)
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlsplit,
    urlunsplit,
)

if sys.version_info < (3, 11):
    raise SystemExit("LogicSentry AI requires Python 3.11 or newer.")


# Core dependencies are required for the scanner itself. Heavy AI/browser
# integrations are optional and are loaded lazily only when requested.
_VERSION_RULES = {
    "pydantic": ((2, 0, 0), (3, 0, 0)),
    "aiohttp": ((3, 9, 0), (4, 0, 0)),
    "rich": ((13, 0, 0), None),
}
_CORE_REQUIREMENTS = (
    "pydantic>=2,<3",
    "aiohttp>=3.9,<4",
    "rich>=13",
)
OPTIONAL_AI_REQUIREMENTS = (
    "transformers>=4.40",
    "torch>=2.0",
    "accelerate>=0.26",
)
OPTIONAL_BROWSER_REQUIREMENTS = ("playwright>=1.40",)


AI_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"
AI_MAX_PROMPT_TOKENS = 6_000
AI_FIELD_TOKEN_LIMITS: dict[str, int] = {
    "execution_context": 16,
    "strategy": 96,
    "mutation_or_route": 256,
    "baseline_status": 16,
    "baseline_body": 1_000,
    "attack_status": 16,
    "attack_body": 1_000,
    "file_path": 160,
    "source_language": 32,
    "extracted_code_block": 2_500,
}
AI_TOKEN_TRUNCATION_MARKER = " ...[truncated]"
_AI_PIPELINE_LOCK = threading.Lock()
AI_MASTER_PROMPT = (
    '<system_role>\n'
    'You are LogicSentry AI, a deterministic, serverless '
    'application security triage engine operating entirely '
    'offline inside a local runtime environment. Your '
    'objective is to perform deep contextual analysis on '
    'local source code structures and dynamic differential '
    'HTTP security responses to isolate actual business '
    'logic vulnerabilities and suppress heuristic false '
    'positives. You run completely locally without external '
    'API or internet dependencies.\n'
    '</system_role>\n'
    '\n'
    '<security_definitions>\n'
    '1. ACCESSIBLE VULNERABILITY / RISK FINDING '
    '(is_vulnerable = true): \n'
    '   - [DAST Context]: A parameter mutation, transaction '
    'replay, step skip, or authorization context switch '
    'successfully forced an application to execute or '
    'process unauthorized mutations under a successful HTTP '
    '200/201 context, producing processing side-effects '
    'like negative balances, unauthorized data exposures, '
    'steps skipped out-of-order, or elevated roles.\n'
    '   - [SAST Context]: A code block, route handler, or '
    'business variable implementation completely lacks '
    'authorization checks, data boundary validations, '
    'price/discount sanity checks, or access-control '
    'middleware, making it inherently vulnerable to '
    'exploitation.\n'
    '2. DISCARDABLE FALSE POSITIVE / SECURE ARCHITECTURE '
    '(is_vulnerable = false):\n'
    '   - [DAST Context]: The application caught the input '
    'anomaly safely and rejected the execution thread via '
    'standard validation field failure messages, 400 Bad '
    'Request schemas, 401/403 Permission Denied blocks, '
    'unhandled database traces, or generic landing page '
    'redirects.\n'
    '   - [SAST Context]: The source code explicitly '
    'validates input boundaries, checks user permissions, '
    'uses robust security decorators/guards, or limits '
    'mutations safely using structural constraints.\n'
    '</security_definitions>\n'
    '\n'
    '<formatting_and_production_constraints>\n'
    '- DATA OUTPUT REQUIREMENT: You must answer STRICTLY '
    'with a raw, valid JSON block matching the '
    'target_json_schema provided. \n'
    '- PROHIBITED CONTENT: Do not include markdown code '
    'fences (e.g., do not wrap text in blocks like ```json '
    '... ```), preamble text, introduction filler, '
    'processing notes, or conversational trailing '
    'explanations. \n'
    '- FORMAT INTEGRITY: Your output must begin exactly '
    "with the character '{{' and end exactly with the "
    "character '}}'.\n"
    '- DATA HANDLING: If data fields look truncated or are '
    'missing, evaluate the text provided as-is without '
    'breaking formatting constraints.\n'
    '</formatting_and_production_constraints>\n'
    '\n'
    '<few_shot_reasoning_chains>\n'
    '  <example_1_dast_vulnerable>\n'
    '    <input_type>DAST</input_type>\n'
    '    <input>Strategy: parameter_manipulation | '
    'Mutation: total: 50 -> -500 | Baseline: 200 | Attack: '
    '200</input>\n'
    '    '
    '<output>{{"is_vulnerable":true,"confidence_score":0.99'
    ',"reasoning":"The checkout handler accepted an '
    'inverted price index, completing a transaction with an '
    'unauthorized negative charge parameter under a '
    'successful HTTP 200 context."}}</output>\n'
    '  </example_1_dast_vulnerable>\n'
    '  <example_2_dast_secure>\n'
    '    <input_type>DAST</input_type>\n'
    '    <input>Strategy: privilege_escalation_bola | '
    'Mutation: Header Auth UserA -> UserB | Baseline: 200 | '
    'Attack: 403</input>\n'
    '    '
    '<output>{{"is_vulnerable":false,"confidence_score":0.9'
    '8,"reasoning":"The API correctly applied validation '
    'boundaries when switching identity contexts, throwing '
    'a clean 403 authorization denial without leaking '
    'cross-user records."}}</output>\n'
    '  </example_2_dast_secure>\n'
    '</few_shot_reasoning_chains>\n'
    '\n'
    '<runtime_execution_payload>\n'
    '  Execution_Context: {execution_context}\n'
    '  Strategy/Finding_Type: {strategy}\n'
    '  Mutation_or_Route_Path: {mutation_or_route}\n'
    '  Baseline Status: {baseline_status}\n'
    '  Baseline Body: {baseline_body}\n'
    '  Attack Status: {attack_status}\n'
    '  Attack Body: {attack_body}\n'
    '  File Path: {file_path}\n'
    '  Source Language: {source_language}\n'
    '  Extracted Code Block: {extracted_code_block}\n'
    '</runtime_execution_payload>\n'
    '\n'
    '<target_json_schema>\n'
    '{{"is_vulnerable": true or false, "confidence_score": '
    '0.00 to 1.00, "reasoning": "string"}}\n'
    '</target_json_schema>'
)


def _compact_ai_value(value: object, limit: int = 10_000) -> str:
    """Normalize a prompt field and bound untrusted response/source text."""
    text = "N/A" if value is None else str(value)
    text = " ".join(text.split())
    if not text:
        return "N/A"
    if len(text) > limit:
        return text[:limit] + " ...[truncated]"
    return text


def _compact_ai_response_body(value: object, limit: int = 6_000) -> str:
    """Strip visible HTML noise, then compact and bound an HTTP body."""
    text = "N/A" if value is None else str(value)
    if re.search(r"</?[A-Za-z][^>]*>", text):
        try:
            parser = _VisibleTextParser()
            parser.feed(text)
            parser.close()
            text = " ".join(parser.parts)
        except Exception:
            pass
    return _compact_ai_value(text, limit)


def _bounded_ai_text(value: object, limit: int = 12_000) -> str:
    """Trim and bound source context without flattening its code structure."""
    text = "N/A" if value is None else str(value).strip()
    if not text:
        return "N/A"
    if len(text) > limit:
        return text[:limit] + "\n...[truncated]"
    return text


def _count_ai_tokens(tokenizer: Any | None, text: str) -> int:
    """Count prompt tokens with a conservative tokenizer-free fallback."""
    if tokenizer is not None:
        try:
            return len(tokenizer.encode(text, add_special_tokens=False))
        except Exception:
            pass
    return max(1, len(text.encode("utf-8")))


def _truncate_ai_text(
    text: str,
    max_tokens: int,
    tokenizer: Any | None,
) -> str:
    """Truncate one field to an explicit tokenizer-aware budget."""
    if max_tokens <= 0:
        return ""
    if _count_ai_tokens(tokenizer, text) <= max_tokens:
        return text

    marker = AI_TOKEN_TRUNCATION_MARKER
    marker_tokens = _count_ai_tokens(tokenizer, marker)
    content_tokens = max(0, max_tokens - marker_tokens)
    if tokenizer is not None:
        try:
            token_ids = tokenizer.encode(text, add_special_tokens=False)
            truncated = tokenizer.decode(
                token_ids[:content_tokens],
                skip_special_tokens=True,
                clean_up_tokenization_spaces=False,
            )
            return truncated.rstrip() + marker
        except Exception:
            pass

    # UTF-8 byte slicing is a conservative tokenizer-free upper bound.
    raw_text = text.encode("utf-8")[:content_tokens]
    truncated = raw_text.decode("utf-8", errors="ignore").rstrip()
    return truncated + marker


def _format_ai_prompt(
    prompt_values: Mapping[str, str],
    tokenizer: Any | None,
    *,
    max_prompt_tokens: int = AI_MAX_PROMPT_TOKENS,
    field_token_limits: Mapping[str, int] = AI_FIELD_TOKEN_LIMITS,
) -> str:
    """Format the master prompt under explicit field and total token caps."""
    if max_prompt_tokens < 1:
        raise ValueError("max_prompt_tokens must be positive")
    bounded_values = dict(prompt_values)
    for field_name, field_limit in field_token_limits.items():
        if field_name in bounded_values:
            bounded_values[field_name] = _truncate_ai_text(
                bounded_values[field_name], field_limit, tokenizer
            )

    def render() -> str:
        return AI_MASTER_PROMPT.format(**bounded_values)

    prompt = render()
    prompt_tokens = _count_ai_tokens(tokenizer, prompt)
    # Keep the highest-value structural evidence first, trimming large code
    # blocks and response bodies before compact identifiers and strategy text.
    for field_name in (
        "extracted_code_block",
        "baseline_body",
        "attack_body",
        "mutation_or_route",
        "file_path",
        "strategy",
    ):
        while prompt_tokens > max_prompt_tokens:
            current_tokens = _count_ai_tokens(
                tokenizer, bounded_values.get(field_name, "")
            )
            if current_tokens <= 32:
                break
            excess = prompt_tokens - max_prompt_tokens
            reduction = max(excess, max(32, current_tokens // 4))
            next_limit = max(32, current_tokens - reduction)
            shortened = _truncate_ai_text(
                bounded_values[field_name], next_limit, tokenizer
            )
            if shortened == bounded_values[field_name]:
                shortened = _truncate_ai_text(
                    bounded_values[field_name], current_tokens - 32, tokenizer
                )
            if shortened == bounded_values[field_name]:
                break
            bounded_values[field_name] = shortened
            prompt = render()
            prompt_tokens = _count_ai_tokens(tokenizer, prompt)

    if prompt_tokens > max_prompt_tokens:
        raise ValueError(
            "fixed AI prompt exceeds the configured model token budget"
        )
    return prompt


def _extract_json_object(text: str) -> dict[str, object]:
    """Extract the first balanced JSON object from generated model text."""
    start = text.find("{")
    if start < 0:
        raise ValueError("model output contains no JSON object")
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                parsed = json.loads(text[start : index + 1])
                if not isinstance(parsed, dict):
                    raise ValueError("model JSON root must be an object")
                return parsed
    raise ValueError("model output contains an incomplete JSON object")


_AI_JSON_KEY_ALIASES: dict[str, tuple[str, ...]] = {
    "is_vulnerable": ("vulnerable", "isvulnerable", "vulnerability"),
    "reasoning": ("reason", "explanation", "rationale"),
    "confidence_score": ("confidence", "score"),
}
_AI_VERDICT_FIELD_RE = re.compile(
    r"(?is)(?P<key>['\"]?(?:is[\s_-]*vulnerable|vulnerable)['\"]?)"
    r"\s*[:=]\s*(?P<value>['\"]?(?:true|false)['\"]?)(?![a-z0-9_])"
)
_AI_REASON_KEY_RE = re.compile(
    r"(?is)(?P<key>['\"]?(?:reasoning|reason|explanation|rationale)['\"]?)"
    r"\s*[:=]\s*"
)
_AI_QUOTED_REASON_RE = re.compile(
    r"(?is)(?P<key>['\"]?(?:reasoning|reason|explanation|rationale)['\"]?)"
    r"\s*[:=]\s*(?P<quote>['\"])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)"
)
_AI_REASON_ARRAY_RE = re.compile(
    r"(?is)(?P<key>['\"]?(?:reasoning|reason|explanation|rationale)['\"]?)"
    r"\s*[:=]\s*\[(?P<items>.*?)\]"
)
_AI_QUOTED_TEXT_RE = re.compile(
    r"(?is)(?P<quote>['\"])(?P<value>(?:\\.|(?!(?P=quote)).)*)(?P=quote)"
)


def _normalize_ai_payload_keys(
    payload: Mapping[str, object],
) -> dict[str, object]:
    """Canonicalize schema keys and aliases emitted by compact models."""
    normalized: dict[str, object] = {}
    for raw_key, value in payload.items():
        key = re.sub(
            r"[^a-z0-9]+", "_", str(raw_key).strip().casefold()
        ).strip("_")
        if key:
            normalized[key] = value
    for canonical, aliases in _AI_JSON_KEY_ALIASES.items():
        if canonical not in normalized:
            for alias in aliases:
                if alias in normalized:
                    normalized[canonical] = normalized[alias]
                    break
    return normalized


def _decode_regex_string(value: str, quote: str) -> str:
    """Decode a quoted regex-captured field without evaluating code."""
    try:
        decoded = ast.literal_eval(quote + value + quote)
    except (SyntaxError, ValueError):
        return value
    return decoded if isinstance(decoded, str) else value


def _extract_ai_payload_regex(text: str) -> dict[str, object]:
    """Recover verdict and rationale fields when JSON framing is malformed."""
    verdict_match = _AI_VERDICT_FIELD_RE.search(text)
    if verdict_match is None:
        raise ValueError("regex fallback found no vulnerability verdict")
    verdict_key = verdict_match.group("key").strip("\"'")
    verdict_text = verdict_match.group("value").strip("\"'").casefold()
    payload: dict[str, object] = {
        verdict_key: verdict_text == "true",
    }

    array_match = _AI_REASON_ARRAY_RE.search(text)
    reason_match = _AI_QUOTED_REASON_RE.search(text)
    if array_match is not None:
        reason_key = array_match.group("key").strip("\"'")
        array_items = array_match.group("items")
        reasoning_parts = [
            _decode_regex_string(match.group("value"), match.group("quote"))
            for match in _AI_QUOTED_TEXT_RE.finditer(array_items)
        ]
        reasoning = " ".join(
            part.strip() for part in reasoning_parts if part.strip()
        )
        if not reasoning:
            reasoning = " ".join(array_items.split())
    elif reason_match is not None:
        reason_key = reason_match.group("key").strip("\"'")
        reasoning = _decode_regex_string(
            reason_match.group("value"), reason_match.group("quote")
        )
    else:
        key_match = _AI_REASON_KEY_RE.search(text)
        if key_match is None:
            raise ValueError("regex fallback found no reasoning field")
        reason_key = key_match.group("key").strip("\"'")
        reasoning = text[key_match.end() :].strip()
        if reasoning.startswith("["):
            item_matches = list(_AI_QUOTED_TEXT_RE.finditer(reasoning))
            if item_matches:
                reasoning = " ".join(
                    _decode_regex_string(
                        match.group("value"), match.group("quote")
                    ).strip()
                    for match in item_matches
                )
        elif reasoning[:1] in {"'", '"'}:
            reasoning = reasoning[1:]
        next_field = re.search(
            r"(?is)[,;]\s*['\"]?(?:is[\s_-]*vulnerable|vulnerable|"
            r"confidence(?:[_\s-]*score)?|reasoning|reason|explanation|"
            r"rationale)['\"]?\s*[:=]",
            reasoning,
        )
        if next_field is not None:
            reasoning = reasoning[: next_field.start()]
        reasoning = reasoning.strip().strip(" \t\r\n,;`*_{}[]\"'")
    if not isinstance(reasoning, str) or not reasoning.strip():
        raise ValueError("regex fallback found an empty reasoning field")
    payload[reason_key] = reasoning
    return payload


def _has_valid_ai_payload(payload: Mapping[str, object]) -> bool:
    """Check the minimum safe schema needed to act on model triage."""
    return (
        isinstance(payload.get("is_vulnerable"), bool)
        and isinstance(payload.get("reasoning"), str)
        and bool(str(payload.get("reasoning", "")).strip())
    )


def _extract_ai_payload(text: str) -> dict[str, object]:
    """Parse balanced JSON, recover with regex, and fail open on bad output."""
    try:
        parsed = _extract_json_object(text)
    except Exception:
        parsed = None
    if isinstance(parsed, Mapping):
        normalized = _normalize_ai_payload_keys(parsed)
        if _has_valid_ai_payload(normalized):
            return normalized

    try:
        recovered = _normalize_ai_payload_keys(
            _extract_ai_payload_regex(text)
        )
    except Exception:
        recovered = {}
    if _has_valid_ai_payload(recovered):
        return recovered
    return {
        "is_vulnerable": True,
        "reasoning": (
            "AI output could not be parsed; heuristic finding retained."
        ),
    }


@functools.lru_cache(maxsize=1)
def _load_local_ai_pipeline() -> Any | None:
    """Load an already-cached local model; never download during a scan."""
    try:
        import torch
        from huggingface_hub import snapshot_download
        from transformers import pipeline as hf_pipeline
    except Exception as exc:
        print(
            "[LogicSentry AI] Local AI dependencies are unavailable; heuristic "
            f"findings will be retained ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return None

    def load_from_directory(model_directory: str) -> Any:
        return hf_pipeline(
            "text-generation",
            model=model_directory,
            tokenizer=model_directory,
            torch_dtype=torch.float32,
            device_map="auto",
            model_kwargs={"local_files_only": True},
        )

    try:
        local_directory = snapshot_download(
            repo_id=AI_MODEL_NAME,
            local_files_only=True,
        )
        return load_from_directory(local_directory)
    except Exception as local_error:
        error_text = f"{type(local_error).__name__}: {local_error}".casefold()
        memory_pressure = (
            isinstance(local_error, MemoryError)
            or "outofmemory" in type(local_error).__name__.casefold()
            or "out of memory" in error_text
        )
        if memory_pressure:
            print(
                "[LogicSentry AI] Local AI model could not be loaded because of "
                "memory pressure; heuristic findings will be retained.",
                file=sys.stderr,
            )
            return None

        # Offline-first: never download model weights during a scan.
        print(
            "[LogicSentry AI] Cached AI model not found; local AI triage is "
            "disabled. Heuristic findings will be retained. "
            f"({type(local_error).__name__})",
            file=sys.stderr,
        )
        return None


HAR_CAPTURE_NAVIGATION_TIMEOUT_MS = 90_000
HAR_CAPTURE_PROCESS_TIMEOUT_SECONDS = 150.0
HTTP_CRAWL_MAX_PAGES = 24
HTTP_CRAWL_MAX_DEPTH = 2
HTTP_CRAWL_MAX_LINKS_PER_PAGE = 80
HTTP_CRAWL_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
HTTP_CRAWL_TIMEOUT_SECONDS = 15.0
HTTP_CRAWL_DELAY_SECONDS = 0.15
_HTTP_CRAWL_SKIP_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".svg", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4",
)


class _PageLinkParser(HTMLParser):
    """Collect bounded anchor links for the browserless URL crawler."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.casefold() not in {"a", "area"}:
            return
        href = dict(attrs).get("href")
        if (
            href
            and len(href) <= 4096
            and len(self.links) < HTTP_CRAWL_MAX_LINKS_PER_PAGE
        ):
            self.links.append(href)


def _http_url_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP origin, rejecting unsafe URL components."""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.casefold()
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if (
        scheme not in {"http", "https"}
        or not hostname
        or parts.username is not None
        or parts.password is not None
    ):
        return None
    normalized_port = port
    if normalized_port is None:
        normalized_port = 443 if scheme == "https" else 80
    if not 1 <= normalized_port <= 65535:
        return None
    return scheme, hostname.rstrip(".").casefold(), normalized_port


def _normalize_http_crawl_url(url: str) -> str | None:
    """Drop fragments and canonicalize an HTTP URL for crawl de-duplication."""
    origin = _http_url_origin(url)
    if origin is None:
        return None
    parts = urlsplit(url)
    scheme, hostname, port = origin
    default_port = 443 if scheme == "https" else 80
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port != default_port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


async def _capture_http_crawl_har(
    target_url: str, har_path: Path
) -> int:
    """Capture a bounded, same-origin HTTP crawl as a HAR 1.2 document."""
    start_url = _normalize_http_crawl_url(target_url)
    origin = _http_url_origin(target_url)
    if start_url is None or origin is None:
        raise ValueError("target URL is not a valid absolute HTTP(S) URL")

    queue: list[tuple[str, int]] = [(start_url, 0)]
    queued = {start_url}
    visited: set[str] = set()
    entries: list[dict[str, Any]] = []
    timeout = ClientTimeout(total=HTTP_CRAWL_TIMEOUT_SECONDS)
    connector = TCPConnector(limit=1)
    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        trust_env=True,
        raise_for_status=False,
        headers={
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/json;q=0.9,*/*;q=0.8"
            ),
            "User-Agent": "LogicSentry AI/1.0 authorized security scan",
        },
    ) as session:
        queue_index = 0
        while (
            queue_index < len(queue)
            and len(visited) < HTTP_CRAWL_MAX_PAGES
        ):
            current_url, depth = queue[queue_index]
            queue_index += 1
            if current_url in visited:
                continue
            visited.add(current_url)
            started_at = datetime.now(timezone.utc).isoformat()
            try:
                async with session.get(
                    current_url,
                    allow_redirects=False,
                ) as response:
                    raw_body = await response.content.read(
                        HTTP_CRAWL_MAX_RESPONSE_BYTES + 1
                    )
                    truncated = len(raw_body) > HTTP_CRAWL_MAX_RESPONSE_BYTES
                    if truncated:
                        raw_body = raw_body[:HTTP_CRAWL_MAX_RESPONSE_BYTES]
                        response.close()

                    mime_type = response.headers.get(
                        "Content-Type", "application/octet-stream"
                    )
                    normalized_mime = (
                        mime_type.split(";", 1)[0].strip().casefold()
                    )
                    is_text = (
                        normalized_mime.startswith("text/")
                        or normalized_mime.endswith("+json")
                        or normalized_mime.endswith("+xml")
                        or normalized_mime in {
                            "application/json",
                            "application/xml",
                            "application/javascript",
                            "application/x-javascript",
                        }
                    )
                    body_text: str | None = None
                    if is_text:
                        try:
                            charset = response.charset or "utf-8"
                        except LookupError:
                            charset = "utf-8"
                        body_text = raw_body.decode(charset, errors="replace")
                        if truncated:
                            body_text += "\n...[capture truncated]"
                        content: dict[str, Any] = {
                            "size": len(raw_body),
                            "mimeType": mime_type,
                            "text": body_text,
                        }
                    else:
                        content = {
                            "size": len(raw_body),
                            "mimeType": mime_type,
                            "text": base64.b64encode(raw_body).decode("ascii"),
                            "encoding": "base64",
                        }

                    request_url = str(response.url)
                    request_headers = [
                        {"name": str(name), "value": str(value)}
                        for name, value in (
                            response.request_info.headers.items()
                        )
                    ]
                    response_headers = [
                        {"name": str(name), "value": str(value)}
                        for name, value in response.headers.items()
                        if name.casefold()
                        not in {"content-encoding", "transfer-encoding"}
                    ]
                    query_string = [
                        {"name": name, "value": value}
                        for name, value in parse_qsl(
                            urlsplit(request_url).query,
                            keep_blank_values=True,
                        )
                    ]
                    entries.append(
                        {
                            "startedDateTime": started_at,
                            "time": -1,
                            "request": {
                                "method": response.method,
                                "url": request_url,
                                "httpVersion": "HTTP/1.1",
                                "headers": request_headers,
                                "queryString": query_string,
                                "cookies": [],
                                "headersSize": -1,
                                "bodySize": -1,
                            },
                            "response": {
                                "status": response.status,
                                "statusText": response.reason or "",
                                "httpVersion": "HTTP/1.1",
                                "headers": response_headers,
                                "cookies": [],
                                "content": content,
                                "redirectURL": response.headers.get(
                                    "Location", ""
                                ),
                                "headersSize": -1,
                                "bodySize": len(raw_body),
                            },
                            "cache": {},
                            "timings": {
                                "send": -1,
                                "wait": -1,
                                "receive": -1,
                            },
                        }
                    )

                    location = response.headers.get("Location")
                    if location:
                        redirect_url = _normalize_http_crawl_url(
                            urljoin(request_url, location)
                        )
                        if (
                            redirect_url
                            and _http_url_origin(redirect_url) == origin
                            and redirect_url not in queued
                        ):
                            queue.append((redirect_url, depth))
                            queued.add(redirect_url)

                    if (
                        body_text
                        and normalized_mime
                        in {"text/html", "application/xhtml+xml"}
                        and depth < HTTP_CRAWL_MAX_DEPTH
                    ):
                        link_parser = _PageLinkParser()
                        link_parser.feed(body_text)
                        for href in link_parser.links:
                            discovered = _normalize_http_crawl_url(
                                urljoin(request_url, href)
                            )
                            if (
                                discovered is None
                                or _http_url_origin(discovered) != origin
                                or discovered in queued
                            ):
                                continue
                            discovered_path = urlsplit(
                                discovered
                            ).path.casefold()
                            if discovered_path.endswith(
                                _HTTP_CRAWL_SKIP_SUFFIXES
                            ):
                                continue
                            queue.append((discovered, depth + 1))
                            queued.add(discovered)
            except (
                aiohttp.ClientError,
                asyncio.TimeoutError,
                OSError,
                ValueError,
            ) as exc:
                print(
                    "[LogicSentry AI] HTTP crawl skipped a page after "
                    f"{type(exc).__name__}.",
                    file=sys.stderr,
                )
            if queue_index < len(queue):
                await asyncio.sleep(HTTP_CRAWL_DELAY_SECONDS)

    if not entries:
        raise OSError("HTTP crawl did not receive any in-scope responses")
    document = {
        "log": {
            "version": "1.2",
            "creator": {"name": "LogicSentry AI", "version": "1.0"},
            "entries": entries,
        }
    }
    har_path.write_text(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    return len(entries)


def _execute_http_har_fallback(
    target_url: str,
    har_path: Path,
    reason: str,
) -> bool:
    """Capture a bounded same-origin crawl without downloading a browser."""
    print(
        f"[LogicSentry AI] {reason}; using the built-in HTTP crawler instead. "
        "JavaScript-generated requests will not be captured."
    )
    try:
        page_count = asyncio.run(
            _capture_http_crawl_har(target_url, har_path)
        )
    except Exception as exc:
        print(
            "[LogicSentry AI] HTTP URL capture failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        try:
            har_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False
    if os.name == "posix":
        try:
            har_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    print(
        f"[LogicSentry AI] HTTP crawler captured {page_count} same-origin "
        f"page(s) to {har_path}."
    )
    return True


_PLAYWRIGHT_CHILD_SCRIPT = r'''
import asyncio
import sys
from playwright.async_api import async_playwright


async def capture_har(target_url, har_path, timeout_ms):
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                record_har_path=har_path,
                record_har_mode="full",
                record_har_content="embed",
            )
            try:
                page = await context.new_page()
                response = await page.goto(
                    target_url,
                    wait_until="networkidle",
                    timeout=timeout_ms,
                )
                if response is None:
                    raise RuntimeError("navigation returned no HTTP response")
            finally:
                await context.close()
        finally:
            await browser.close()


asyncio.run(capture_har(sys.argv[1], sys.argv[2], int(sys.argv[3])))
'''


def _playwright_is_initialized() -> bool:
    """Return whether the Python package and Chromium executable can launch."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


async def _run_embedded_capture_subprocess(
    target_url: str,
    output_har_path: Path,
) -> tuple[int, bytes, bytes, bool]:
    """Run the isolated browser process with asynchronous I/O and a timeout."""
    process_options: dict[str, object] = {}
    if os.name == "posix":
        process_options["start_new_session"] = True
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        _PLAYWRIGHT_CHILD_SCRIPT,
        target_url,
        str(output_har_path),
        str(HAR_CAPTURE_NAVIGATION_TIMEOUT_MS),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        **process_options,
    )
    communication = asyncio.create_task(process.communicate())
    try:
        stdout, stderr = await asyncio.wait_for(
            asyncio.shield(communication),
            timeout=HAR_CAPTURE_PROCESS_TIMEOUT_SECONDS,
        )
        return process.returncode or 0, stdout, stderr, False
    except asyncio.TimeoutError:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
        except OSError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.shield(communication), timeout=5
            )
        except asyncio.TimeoutError:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except OSError:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            stdout, stderr = await communication
        return process.returncode or -1, stdout, stderr, True


def _execute_embedded_har_capture(
    target_url: str,
    output_har_path: Path,
) -> bool:
    """Use cached Chromium or a bounded HTTP-only crawl to create a HAR."""
    if not isinstance(target_url, str):
        print("[LogicSentry AI] Capture URL must be a string.", file=sys.stderr)
        return False
    cleaned_url = target_url.strip()
    try:
        url_parts = urlsplit(cleaned_url)
        hostname = url_parts.hostname
    except ValueError as exc:
        print(f"[LogicSentry AI] Invalid capture URL: {exc}", file=sys.stderr)
        return False
    if (
        url_parts.scheme.casefold() not in {"http", "https"}
        or not hostname
        or url_parts.username is not None
        or url_parts.password is not None
    ):
        print(
            "[LogicSentry AI] Capture URL must be an absolute HTTP(S) URL "
            "without embedded credentials.",
            file=sys.stderr,
        )
        return False

    try:
        har_path = Path(output_har_path).expanduser().resolve()
        har_path.parent.mkdir(parents=True, exist_ok=True)
    except (OSError, TypeError, ValueError) as exc:
        print(f"[LogicSentry AI] Cannot prepare HAR path: {exc}", file=sys.stderr)
        return False

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        print(
            "[LogicSentry AI] HAR capture must be invoked outside an active "
            "asyncio event loop.",
            file=sys.stderr,
        )
        return False

    if not _playwright_is_initialized():
        return _execute_http_har_fallback(
            cleaned_url,
            har_path,
            "No cached Playwright Chromium is available; no browser download "
            "will be attempted",
        )

    try:
        return_code, _stdout, stderr, timed_out = asyncio.run(
            _run_embedded_capture_subprocess(cleaned_url, har_path)
        )
    except Exception as exc:
        print(
            "[LogicSentry AI] Browser capture subprocess failed: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return _execute_http_har_fallback(
            cleaned_url, har_path, "Browser capture failed"
        )
    if timed_out or return_code != 0:
        error_text = stderr.decode("utf-8", errors="replace").strip()
        details = error_text[-2_000:] if error_text else "no browser details"
        message = (
            "timed out"
            if timed_out
            else f"exited with status {return_code}"
        )
        print(
            f"[LogicSentry AI] Browser navigation {message}; HAR capture failed. "
            f"{details}",
            file=sys.stderr,
        )
        return _execute_http_har_fallback(
            cleaned_url, har_path, "Browser navigation failed"
        )

    try:
        if not har_path.is_file() or har_path.stat().st_size == 0:
            raise OSError("browser did not produce a non-empty HAR file")
    except OSError as exc:
        print(f"[LogicSentry AI] HAR capture failed: {exc}", file=sys.stderr)
        return _execute_http_har_fallback(
            cleaned_url, har_path, "Browser HAR was not usable"
        )
    if os.name == "posix":
        try:
            har_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    print(f"[LogicSentry AI] Browser HAR capture saved to {har_path}.")
    print(
        "[LogicSentry AI] HAR files can contain session cookies and personal "
        "data; protect the recording."
    )
    return True


def _run_local_ai_triage(
    ai_pipeline: Any | None,
    execution_context: str,
    strategy: str,
    mutation_or_route: str,
    baseline_status: object = "N/A",
    baseline_body: object = "N/A",
    attack_status: object = "N/A",
    attack_body: object = "N/A",
    file_path: str = "N/A",
    source_language: str = "N/A",
    extracted_code_block: str = "N/A",
) -> tuple[bool, str]:
    """Run offline JSON triage; fail open so analysis cannot erase findings."""
    try:
        if ai_pipeline is None:
            raise RuntimeError("local model is not available")
        raw_values: dict[str, object] = {
            "execution_context": execution_context,
            "strategy": strategy,
            "mutation_or_route": mutation_or_route,
            "baseline_status": baseline_status,
            "baseline_body": _compact_ai_response_body(
                baseline_body, 6_000
            ),
            "attack_status": attack_status,
            "attack_body": _compact_ai_response_body(attack_body, 6_000),
            "file_path": file_path,
            "source_language": source_language,
            "extracted_code_block": _bounded_ai_text(
                extracted_code_block, 12_000
            ),
        }
        prompt_values = {
            key: (
                _bounded_ai_text(value)
                if key == "extracted_code_block"
                else _compact_ai_value(value)
            )
            for key, value in raw_values.items()
        }
        tokenizer = getattr(ai_pipeline, "tokenizer", None)
        prompt = _format_ai_prompt(prompt_values, tokenizer)
        with _AI_PIPELINE_LOCK:
            generation = ai_pipeline(
                prompt,
                max_new_tokens=160,
                do_sample=False,
                temperature=0.0,
                return_full_text=False,
            )
        if isinstance(generation, list):
            if not generation or not isinstance(generation[0], Mapping):
                raise ValueError("model returned no generated text")
            generated_text = generation[0].get("generated_text")
        elif isinstance(generation, Mapping):
            generated_text = generation.get("generated_text")
        else:
            generated_text = generation
        if not isinstance(generated_text, str):
            raise ValueError("model generated text is not a string")
        if generated_text.startswith(prompt):
            generated_text = generated_text[len(prompt) :]
        payload = _extract_ai_payload(generated_text.strip())
        is_vulnerable = payload.get("is_vulnerable")
        reasoning = payload.get("reasoning")
        if not isinstance(is_vulnerable, bool):
            raise ValueError("model JSON is missing a boolean verdict")
        if not isinstance(reasoning, str) or not reasoning.strip():
            raise ValueError("model JSON is missing reasoning")
        return is_vulnerable, " ".join(reasoning.split())
    except Exception as exc:
        # Includes malformed model output, RAM exhaustion, and torch CUDA OOM;
        # AI failures must never suppress a heuristic vulnerability finding.
        return (
            True,
            "AI triage failed open; heuristic finding retained "
            f"({type(exc).__name__}).",
        )


def _installed_version(distribution: str) -> tuple[int, int, int] | None:
    """Read a distribution's numeric version without extra dependencies."""
    try:
        version = importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None
    match = re.match(r"^\s*(\d+(?:\.\d+)*)", version)
    if match is None:
        return None
    parts = tuple(int(part) for part in match.group(1).split(".")[:3])
    return (parts + (0, 0, 0))[:3]


def _missing_requirements() -> list[str]:
    missing: list[str] = []
    for distribution, (minimum, maximum) in _VERSION_RULES.items():
        version = _installed_version(distribution)
        if (
            version is None
            or version < minimum
            or (maximum is not None and version >= maximum)
        ):
            missing.append(distribution)
    return missing


def _ensure_dependencies() -> None:
    """Validate core dependencies without performing network side effects."""
    missing = _missing_requirements()
    if not missing:
        return
    requirements = ", ".join(_CORE_REQUIREMENTS)
    print(
        "[LogicSentry AI] Missing or incompatible core dependencies: "
        + ", ".join(missing),
        file=sys.stderr,
    )
    print(
        "[LogicSentry AI] Install them explicitly with: "
        f"{sys.executable} -m pip install {requirements}",
        file=sys.stderr,
    )
    raise SystemExit(1)


_ensure_dependencies()


# These third-party imports intentionally follow the dependency bootstrap.
import aiohttp  # noqa: E402
from aiohttp import ClientTimeout, DummyCookieJar, TCPConnector  # noqa: E402
from pydantic import (  # noqa: E402
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)
from rich.console import Console  # noqa: E402
from rich.progress import (  # noqa: E402
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402

# ============================================================================
# Data models and validation
# ============================================================================
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _normalize_headers(value: object) -> dict[str, str]:
    """Validate and normalize a HAR-style header mapping."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("headers must be a mapping of names to values")

    normalized: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        if not name or not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid HTTP header name: {name!r}")
        header_value = "" if raw_value is None else str(raw_value)
        if "\r" in header_value or "\n" in header_value:
            raise ValueError(f"header {name!r} contains a newline")
        normalized[name] = header_value
    return normalized


class SourceCodeFinding(BaseModel):
    """One static-analysis business-logic observation."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    line_number: int = Field(ge=1)
    vulnerable_code: str
    logic_gap_type: str
    severity: str
    rule_id: Optional[str] = None
    route_path: Optional[str] = None


class SourceRoute(BaseModel):
    """A route signature extracted from application source."""

    model_config = ConfigDict(extra="forbid")

    file_path: str
    line_number: int = Field(ge=1)
    path: str
    methods: list[str]
    handler: str
    parameters: list[str] = Field(default_factory=list)
    source_language: str


class SASTReport(BaseModel):
    """Consolidated static scan output."""

    model_config = ConfigDict(extra="forbid")

    files_scanned: int = Field(default=0, ge=0)
    routes: list[SourceRoute] = Field(default_factory=list)
    findings: list[SourceCodeFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class HTTPRequest(BaseModel):
    """A replayable HTTP request captured from a HAR file."""

    model_config = ConfigDict(extra="forbid")

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None

    @field_validator("method")
    @classmethod
    def validate_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method or not _HEADER_NAME_RE.fullmatch(method):
            raise ValueError("method must be a valid HTTP token")
        return method

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        url = value.strip()
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
        except ValueError as exc:
            raise ValueError("url is malformed") from exc
        if parts.scheme.lower() not in {"http", "https"} or not hostname:
            raise ValueError("url must be an absolute HTTP or HTTPS URL")
        return url

    @field_validator("headers", mode="before")
    @classmethod
    def validate_headers(cls, value: object) -> dict[str, str]:
        return _normalize_headers(value)


class HTTPResponse(BaseModel):
    """The HTTP response captured in a HAR or received during replay."""

    model_config = ConfigDict(extra="forbid")

    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_length: int = Field(ge=0)

    @field_validator("headers", mode="before")
    @classmethod
    def validate_headers(cls, value: object) -> dict[str, str]:
        return _normalize_headers(value)


class WorkflowStep(BaseModel):
    """A request/response pair in the order it appeared in the HAR."""

    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0)
    request: HTTPRequest
    baseline_response: HTTPResponse
    has_baseline: bool = True
    source_route: Optional[str] = None
    source_parameters: list[str] = Field(default_factory=list)
    source_path_parameters: dict[str, str] = Field(default_factory=dict)


class VulnerabilityType(str, Enum):
    """Business-logic test families supported by LogicSentry AI."""

    PARAMETER_MANIPULATION = "parameter_manipulation"
    STEP_SKIPPING = "step_skipping"
    PRIVILEGE_FLAW = "privilege_flaw"
    PRIVILEGE_ESCALATION_BOLA = "privilege_escalation_bola"
    RACE_CONDITION = "race_condition"


class ScanResult(BaseModel):
    """A finding with the complete request and response evidence."""

    model_config = ConfigDict(extra="forbid")

    step_index: int = Field(ge=0)
    strategy: VulnerabilityType
    description: str
    severity: str
    baseline_status: int = Field(ge=100, le=599)
    attack_status: int = Field(ge=100, le=599)
    evidence: str

    # Full HTTP evidence makes JSON/Markdown reports independently reviewable.
    request_method: Optional[str] = None
    request_url: Optional[str] = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None
    baseline_request_url: Optional[str] = None
    baseline_request_headers: dict[str, str] = Field(default_factory=dict)
    baseline_request_body: Optional[str] = None
    mutation: Optional[str] = None
    baseline_response_headers: dict[str, str] = Field(default_factory=dict)
    baseline_response_body: str = ""
    baseline_content_length: int = Field(default=0, ge=0)
    attack_response_headers: dict[str, str] = Field(default_factory=dict)
    attack_response_body: str = ""
    attack_content_length: int = Field(default=0, ge=0)
    concurrent_responses: list[HTTPResponse] = Field(default_factory=list)
    sequential_responses: list[HTTPResponse] = Field(default_factory=list)
    replay_mode: Optional[Literal["synchronized", "sequential"]] = None
    concurrent_request_count: int = Field(default=0, ge=0)
    concurrent_success_count: int = Field(default=0, ge=0)
    source_route: Optional[str] = None
    has_har_baseline: bool = True
    body_similarity: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    length_similarity: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    confidence_score: float = Field(default=0.75, ge=0.0, le=1.0)

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        normalized = value.strip().capitalize()
        if normalized not in {"Critical", "High", "Medium", "Low", "Info"}:
            raise ValueError(
                "severity must be Critical, High, Medium, Low, or Info"
            )
        return normalized


# ============================================================================
# HAR parser
# ============================================================================


class HARParseError(Exception):
    """Raised when a HAR file cannot be loaded or has an invalid root shape."""


class HARParser:
    """Parse an HTTP Archive into an ordered, in-scope workflow.

    ``target_pattern`` is a regular expression applied to the request hostname.
    The CLI escapes its ``--target`` substring before passing it here; callers
    using this class directly can provide a more specific host regular
    expression.
    """

    STATIC_EXTENSIONS = (
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".gif",
    )
    TRACKING_DOMAIN_MARKERS = (
        "google-analytics",
        "doubleclick",
        "mixpanel",
    )
    DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

    def __init__(
        self,
        har_path: str | Path,
        target_pattern: str,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.har_path = Path(har_path)
        if not target_pattern:
            raise ValueError("target_pattern must not be empty")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        try:
            self._target_re = re.compile(target_pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(
                f"invalid target-domain regular expression: {exc}"
            ) from exc
        self.max_response_bytes = max_response_bytes
        self.warnings: list[str] = []

    def parse(self) -> list[WorkflowStep]:
        """Load the HAR and return valid in-scope request/response steps."""
        try:
            with self.har_path.open("r", encoding="utf-8-sig") as har_file:
                document = json.load(har_file)
        except FileNotFoundError as exc:
            raise HARParseError(
                f"HAR file does not exist: {self.har_path}"
            ) from exc
        except PermissionError as exc:
            raise HARParseError(
                f"HAR file is not readable: {self.har_path}"
            ) from exc
        except UnicodeError as exc:
            raise HARParseError("HAR file is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise HARParseError(
                f"invalid HAR JSON at line {exc.lineno}, column {exc.colno}: "
                f"{exc.msg}"
            ) from exc
        except OSError as exc:
            raise HARParseError(f"could not read HAR file: {exc}") from exc

        if not isinstance(document, Mapping):
            raise HARParseError("HAR root must be a JSON object")
        log_data = document.get("log")
        entries = (
            log_data.get("entries") if isinstance(log_data, Mapping) else None
        )
        if not isinstance(entries, list):
            raise HARParseError("HAR must contain log.entries as an array")

        workflow: list[WorkflowStep] = []
        self.warnings.clear()
        for entry_number, entry in enumerate(entries, start=1):
            if not isinstance(entry, Mapping):
                self._warn(entry_number, "entry is not an object")
                continue
            request_data = entry.get("request")
            response_data = entry.get("response")
            if not isinstance(request_data, Mapping) or not isinstance(
                response_data, Mapping
            ):
                self._warn(entry_number, "missing request or response object")
                continue

            raw_url = request_data.get("url")
            if not isinstance(raw_url, str):
                self._warn(
                    entry_number, "request URL is missing or not a string"
                )
                continue
            if self._is_noise(raw_url) or not self._is_in_scope(raw_url):
                continue

            try:
                request = self._build_request(request_data, raw_url)
                response = self._build_response(response_data)
                workflow.append(
                    WorkflowStep(
                        index=len(workflow),
                        request=request,
                        baseline_response=response,
                    )
                )
            except (
                ValueError,
                TypeError,
                ValidationError,
                binascii.Error,
            ) as exc:
                self._warn(entry_number, f"invalid HTTP entry ({exc})")

        return workflow

    def _is_in_scope(self, url: str) -> bool:
        try:
            hostname = urlsplit(url).hostname
        except ValueError:
            return False
        return bool(hostname and self._target_re.search(hostname))

    def _is_noise(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            hostname = (parts.hostname or "").casefold()
            path = parts.path.casefold()
        except ValueError:
            return True
        if path.endswith(self.STATIC_EXTENSIONS):
            return True
        return any(
            marker in hostname for marker in self.TRACKING_DOMAIN_MARKERS
        )

    def _build_request(self, raw: Mapping[str, Any], url: str) -> HTTPRequest:
        method = raw.get("method")
        if not isinstance(method, str):
            raise ValueError("request method is missing")
        headers = self._headers(raw.get("headers"))
        post_data = raw.get("postData")
        body = self._request_body(post_data)
        return HTTPRequest(method=method, url=url, headers=headers, body=body)

    def _build_response(self, raw: Mapping[str, Any]) -> HTTPResponse:
        try:
            status_code = int(raw.get("status"))
        except (TypeError, ValueError) as exc:
            raise ValueError("response status is missing or invalid") from exc
        headers = self._headers(raw.get("headers"))
        content = raw.get("content")
        content = content if isinstance(content, Mapping) else {}
        body, decoded_length = self._decode_response_body(content)
        raw_length = content.get("size")
        try:
            content_length = int(raw_length)
            if content_length < 0:
                content_length = decoded_length
        except (TypeError, ValueError):
            content_length = decoded_length
        return HTTPResponse(
            status_code=status_code,
            headers=headers,
            body=body,
            content_length=content_length,
        )

    @staticmethod
    def _headers(raw_headers: object) -> dict[str, str]:
        if not isinstance(raw_headers, list):
            return {}
        headers: dict[str, str] = {}
        for header in raw_headers:
            if not isinstance(header, Mapping):
                continue
            name = header.get("name")
            if name is None:
                continue
            value = header.get("value")
            headers[str(name)] = "" if value is None else str(value)
        return headers

    @staticmethod
    def _request_body(post_data: object) -> str | None:
        if not isinstance(post_data, Mapping):
            return None
        text = post_data.get("text")
        if text is not None:
            if not isinstance(text, str):
                return str(text)
            return text

        # Some HAR producers put form fields in ``params`` without serializing
        # the request body. Preserve field order when rebuilding it.
        params = post_data.get("params")
        if isinstance(params, list):
            pairs: list[tuple[str, str]] = []
            for item in params:
                if not isinstance(item, Mapping) or item.get("name") is None:
                    continue
                name = str(item["name"])
                value = item.get("value", "")
                pairs.append((name, "" if value is None else str(value)))
            if pairs:
                return urlencode(pairs)
        return None

    def _decode_response_body(
        self, content: Mapping[str, Any]
    ) -> tuple[str, int]:
        text = content.get("text", "")
        if text is None:
            text = ""
        if not isinstance(text, str):
            text = str(text)

        if str(content.get("encoding", "")).casefold() == "base64":
            try:
                raw_body = base64.b64decode(text, validate=False)
            except (binascii.Error, ValueError):
                raw_body = text.encode("utf-8", errors="replace")
        else:
            raw_body = text.encode("utf-8", errors="replace")

        decoded_length = len(raw_body)
        truncated = decoded_length > self.max_response_bytes
        if truncated:
            raw_body = raw_body[: self.max_response_bytes]
        body = raw_body.decode("utf-8", errors="replace")
        if truncated:
            body += "\n...[LogicSentry AI truncated HAR response body]"
        return body, decoded_length

    def _warn(self, entry_number: int, message: str) -> None:
        self.warnings.append(f"HAR entry {entry_number}: {message}")


# ============================================================================
# Static source review engine (SAST)
# ============================================================================


class SASTScanError(Exception):
    """Raised when the source archive cannot be safely scanned."""


class SASTScanner:
    """Inspect Python, JavaScript/TypeScript, and PHP source inside a ZIP.

    Files are read directly from the archive and are never extracted to disk.
    Python routes use the standard-library AST; JavaScript/TypeScript and PHP
    use bounded framework-aware patterns because no external parser is needed.
    Findings are heuristic review leads, not proof of exploitability.
    """

    SUPPORTED_EXTENSIONS = frozenset(
        {
            ".py",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".ts",
            ".tsx",
            ".php",
            ".java",
        }
    )
    MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
    MAX_ARCHIVE_ENTRIES = 10_000
    MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
    MAX_TOTAL_SOURCE_BYTES = 50 * 1024 * 1024
    MAX_COMPRESSION_RATIO = 500
    BUSINESS_KEYS = frozenset(
        {"price", "quantity", "amount", "total", "discount", "role", "isadmin"}
    )
    IDENTIFIER_KEYS = frozenset(
        {
            "id",
            "userid",
            "accountid",
            "orderid",
            "itemid",
            "productid",
            "ownerid",
            "tenantid",
            "customerid",
            "resourceid",
            "invoiceid",
            "recordid",
            "documentid",
        }
    )
    ROUTE_PARAMETER_RE = re.compile(
        r"<(?:[^:<>]+:)?([^<>]+)>"
        r"|\{([^{}:]+)(?::[^{}]+)?\}"
        r"|(?<!\w):([A-Za-z0-9_.-]+)"
    )
    BUSINESS_RE = re.compile(
        r"\b(price|quantity|amount|total|discount|role|isadmin)\b",
        re.IGNORECASE,
    )
    ID_FIELD_RE = re.compile(
        r"\b([A-Za-z_]\w*(?:_id|Id))\b|\b(id)\b", re.IGNORECASE
    )
    SOURCE_FIELD_RE = re.compile(
        r"\b(?:request|req)\s*(?:->|\.)\s*"
        r"(?:input|args|form|query|query_params|params|json|body|data)\s*"
        r"(?:"
        r"(?:->|\.)\s*get\s*\(\s*['\"]([A-Za-z_]\w*)['\"]"
        r"|(?:->|\.)\s*([A-Za-z_]\w*)"
        r"|\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\]"
        r"|\(\s*['\"]([A-Za-z_]\w*)['\"]"
        r")",
        re.IGNORECASE,
    )
    OBJECT_FIELD_RE = re.compile(
        r"""\b(?:body|data|payload|params|query|form)\s*(?:"""
        r"""\.get\s*\(\s*['\"]([A-Za-z_]\w*)['\"]"""
        r"""|\.\s*([A-Za-z_]\w*)"""
        r"""|\[\s*['\"]([A-Za-z_]\w*)['\"]\s*\])""",
        re.IGNORECASE,
    )
    AUTH_RE = re.compile(
        r"\b(?:login_required|jwt_required|auth_required|requires_auth|"
        r"authenticated|authenticate|authentication_required|authmiddleware|"
        r"require_auth|require_role|require_permission|permission_required|"
        r"authorize|authorization|check_auth|check_permission|verify_jwt|"
        r"verify_token|current_user|currentuser|is_authenticated|"
        r"get_current_user|Depends\s*\(|Security\s*\(|UseGuards\s*\(|"
        r"AuthGuard|RolesGuard|PreAuthorize|Secured|RolesAllowed|"
        r"SecurityContextHolder|AuthenticationPrincipal|"
        r"authorizeHttpRequests|middleware\s*\(\s*['\"]auth)",
        re.IGNORECASE,
    )
    STATE_WRITE_RE = re.compile(
        r"\.(?:save|commit|insert|update|delete|create|add|set|increment|"
        r"decrement|remove|flush)\s*\(|\b(?:balance|role|isadmin|is_admin)"
        r"\s*(?:\+?=|-=)",
        re.IGNORECASE,
    )
    JS_ROUTE_RE = re.compile(
        r"\b(?:app|router|server|api)\s*\.\s*"
        r"(get|post|put|patch|delete|all)\s*\(\s*(['\"`])"
        r"([^'\"`]+)\2",
        re.IGNORECASE,
    )
    JS_CHAIN_ROUTE_RE = re.compile(
        r"\b(?:app|router|server|api)\s*\.\s*route\s*\(\s*"
        r"(['\"`])([^'\"`]+)\1\s*\)\s*\.\s*"
        r"(get|post|put|patch|delete)\s*\(",
        re.IGNORECASE,
    )
    NEST_ROUTE_RE = re.compile(
        r"@(Get|Post|Put|Patch|Delete)\s*\(\s*"
        r"(?:['\"`]([^'\"`]*)['\"`])?\s*\)",
        re.IGNORECASE,
    )
    CONTROLLER_RE = re.compile(
        r"@Controller\s*\(\s*(?:['\"`]([^'\"`]*)['\"`])?\s*\)",
        re.IGNORECASE,
    )
    PHP_ROUTE_RE = re.compile(
        r"\bRoute\s*::\s*(get|post|put|patch|delete|any)\s*\(\s*"
        r"(['\"])(.*?)\2",
        re.IGNORECASE,
    )

    FASTAPI_ROUTE_RE = re.compile(
        r"""@\b(?:app|router)\b\.(get|post|put|patch|delete)"""
        r"""\s*\(\s*(['"])(.*?)\2""",
        re.IGNORECASE,
    )
    SPRING_BOOT_ROUTE_RE = re.compile(
        r"@(?:Get|Post|Put|Patch|Delete)Mapping\b"
        r"(?:\s*\((?P<arguments>[^)]*)\))?",
        re.IGNORECASE,
    )
    SPRING_PARAMETER_RE = re.compile(
        r"@(?:RequestParam|PathVariable|RequestHeader|RequestBody)\s*"
        r"(?:\([^)]*\)\s*)?(?:final\s+)?"
        r"[A-Za-z_$][\w.$<>?,\[\] ]*?\s+([A-Za-z_$][\w$]*)",
        re.IGNORECASE,
    )

    SPRING_REQUEST_MAPPING_RE = re.compile(
        r"@RequestMapping\b\s*\((?P<arguments>[^)]*)\)",
        re.IGNORECASE,
    )
    SPRING_MAPPING_PATH_RE = re.compile(
        r"(?:value|path)\s*=\s*(['\"])(.*?)\1"
        r"|^\s*(['\"])(.*?)\3",
        re.IGNORECASE,
    )
    SPRING_CONTROLLER_RE = re.compile(
        r"@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?(['\"])(.*?)\1",
        re.IGNORECASE,
    )

    def __init__(
        self,
        archive_path: str | Path,
        *,
        max_source_file_bytes: int = MAX_SOURCE_FILE_BYTES,
        max_total_source_bytes: int = MAX_TOTAL_SOURCE_BYTES,
    ) -> None:
        self.archive_path = Path(archive_path)
        if max_source_file_bytes < 1 or max_total_source_bytes < 1:
            raise ValueError("source byte limits must be positive")
        self.max_source_file_bytes = max_source_file_bytes
        self.max_total_source_bytes = max_total_source_bytes
        self._routes: list[SourceRoute] = []
        self._findings: list[SourceCodeFinding] = []
        self._warnings: list[str] = []
        self._finding_keys: set[tuple[str, int, str, str]] = set()
        self._route_keys: set[tuple[str, int, str, tuple[str, ...]]] = set()
        self._source_texts: dict[str, str] = {}
        self._ai_pipeline: Any | None = _load_local_ai_pipeline()

    def scan(self) -> SASTReport:
        """Read eligible archive members and scan each source file safely."""
        try:
            archive_size = self.archive_path.stat().st_size
        except OSError as exc:
            raise SASTScanError(
                f"Cannot access source ZIP {self.archive_path}: {exc}"
            ) from exc
        if archive_size > self.MAX_ARCHIVE_BYTES:
            raise SASTScanError(
                f"Source ZIP exceeds the {self.MAX_ARCHIVE_BYTES}-byte limit."
            )
        try:
            archive = zipfile.ZipFile(self.archive_path, mode="r")
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
            raise SASTScanError(
                f"Cannot open source ZIP {self.archive_path}: {exc}"
            ) from exc

        with archive:
            infos = archive.infolist()
            if len(infos) > self.MAX_ARCHIVE_ENTRIES:
                self._warnings.append(
                    "Archive entry limit exceeded; only the first "
                    f"{self.MAX_ARCHIVE_ENTRIES} entries were considered."
                )
                infos = infos[: self.MAX_ARCHIVE_ENTRIES]

            total_bytes = 0
            for info in infos:
                safe_name = self._safe_member_name(info.filename)
                if safe_name is None or info.is_dir():
                    continue
                if (
                    Path(safe_name).suffix.casefold()
                    not in self.SUPPORTED_EXTENSIONS
                ):
                    continue
                if self._is_symlink(info):
                    self._warnings.append(
                        f"Skipped symbolic link: {safe_name}"
                    )
                    continue
                if info.flag_bits & 0x1:
                    self._warnings.append(
                        f"Skipped encrypted source: {safe_name}"
                    )
                    continue
                if info.file_size > self.max_source_file_bytes:
                    self._warnings.append(
                        f"Skipped oversized source file: {safe_name} "
                        f"({info.file_size} bytes)."
                    )
                    continue
                if (
                    info.file_size > 1024 * 1024
                    and info.file_size / max(info.compress_size, 1)
                    > self.MAX_COMPRESSION_RATIO
                ):
                    self._warnings.append(
                        f"Skipped suspiciously compressed source: {safe_name}"
                    )
                    continue
                if total_bytes + info.file_size > self.max_total_source_bytes:
                    self._warnings.append(
                        "Total source byte limit reached; remaining archive "
                        "members were not read."
                    )
                    break
                try:
                    with archive.open(info, mode="r") as member:
                        raw = member.read(self.max_source_file_bytes + 1)
                except (
                    OSError,
                    RuntimeError,
                    EOFError,
                    KeyError,
                    NotImplementedError,
                    zlib.error,
                    zipfile.BadZipFile,
                ) as exc:
                    self._warnings.append(
                        f"Could not read {safe_name}: {type(exc).__name__}."
                    )
                    continue
                if len(raw) > self.max_source_file_bytes:
                    self._warnings.append(
                        f"Skipped source exceeding read limit: {safe_name}"
                    )
                    continue
                total_bytes += len(raw)
                if b"\x00" in raw:
                    self._warnings.append(
                        f"Skipped binary-looking file: {safe_name}"
                    )
                    continue
                self._source_texts[safe_name] = raw.decode(
                    "utf-8-sig", errors="replace"
                )

        for file_path, source in self._source_texts.items():
            suffix = Path(file_path).suffix.casefold()
            if suffix == ".py":
                self._scan_python_file(file_path, source)
            else:
                self._scan_regex_file(file_path, source, suffix)

        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Info": 4,
        }
        self._findings.sort(
            key=lambda item: (
                severity_order.get(item.severity, 5),
                item.file_path.casefold(),
                item.line_number,
                item.logic_gap_type,
            )
        )
        self._routes.sort(
            key=lambda item: (
                item.file_path.casefold(),
                item.line_number,
                item.path,
            )
        )
        if not self._source_texts:
            self._warnings.append(
                "No supported source files were found in the ZIP."
            )
        return SASTReport(
            files_scanned=len(self._source_texts),
            routes=self._routes,
            findings=self._findings,
            warnings=self._warnings,
        )

    @staticmethod
    def _safe_member_name(name: str) -> Optional[str]:
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if path.is_absolute() or any(
            part in {"", ".", ".."} for part in path.parts
        ):
            return None
        if re.match(r"^[A-Za-z]:", normalized):
            return None
        return path.as_posix()

    @staticmethod
    def _is_symlink(info: zipfile.ZipInfo) -> bool:
        mode = info.external_attr >> 16
        return stat.S_ISLNK(mode)

    @staticmethod
    def _line_number(source: str, offset: int) -> int:
        return source.count("\n", 0, max(offset, 0)) + 1

    @staticmethod
    def _snippet(source: str, line_number: int, limit: int = 240) -> str:
        lines = source.splitlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1].strip()[:limit]
        return ""

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.casefold())

    @classmethod
    def _is_business_key(cls, name: str) -> bool:
        return cls._normalize_key(name) in cls.BUSINESS_KEYS

    @classmethod
    def _is_fuzzable_parameter(cls, name: str) -> bool:
        normalized = cls._normalize_key(name)
        return cls._is_business_key(name) or normalized in cls.IDENTIFIER_KEYS

    def _add_route(self, route: SourceRoute) -> None:
        key = (
            route.file_path,
            route.line_number,
            route.path,
            tuple(sorted(route.methods)),
        )
        if key not in self._route_keys:
            self._route_keys.add(key)
            self._routes.append(route)

    def _add_finding(self, finding: SourceCodeFinding) -> None:
        key = (
            finding.file_path,
            finding.line_number,
            finding.logic_gap_type,
            finding.route_path or "",
        )
        if key in self._finding_keys:
            return
        source = self._source_texts.get(finding.file_path, "")
        source_lines = source.splitlines()
        # line_number is 1-based; these slices include five adjacent lines on
        # either side of the AST match while staying inside the source file.
        context_start = max(finding.line_number - 6, 0)
        context_end = min(finding.line_number + 5, len(source_lines))
        extracted_code = "\n".join(source_lines[context_start:context_end])
        suffix = Path(finding.file_path).suffix.casefold()
        source_language = {
            ".py": "Python",
            ".js": "JavaScript",
            ".jsx": "JavaScript/JSX",
            ".mjs": "JavaScript",
            ".cjs": "JavaScript",
            ".ts": "TypeScript",
            ".tsx": "TypeScript/TSX",
            ".php": "PHP",
            ".java": "Java/Spring Boot",
        }.get(suffix, "Unknown")
        is_vulnerable, reasoning = _run_local_ai_triage(
            self._ai_pipeline,
            execution_context="SAST",
            strategy=finding.logic_gap_type,
            mutation_or_route=finding.route_path or "N/A",
            file_path=finding.file_path,
            source_language=source_language,
            extracted_code_block=extracted_code or finding.vulnerable_code,
        )
        if not is_vulnerable:
            finding = finding.model_copy(update={"severity": "Info"})
            self._warnings.append(
                "Serverless AI triage demoted static finding to Info at "
                f"{finding.file_path}:{finding.line_number}: {reasoning}"
            )

        self._finding_keys.add(key)
        self._findings.append(finding)

    @staticmethod
    def _ast_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            return SASTScanner._ast_name(node.func)
        return ""

    @staticmethod
    def _ast_string(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _python_route_specs(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[str, list[str], int]]:
        specs: list[tuple[str, list[str], int]] = []
        direct_methods = {"get", "post", "put", "patch", "delete"}
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            callee = call.func if call is not None else decorator
            name = self._ast_name(callee).casefold()
            if name not in direct_methods | {"route", "api_route"}:
                continue
            route_path: Optional[str] = None
            methods: list[str] = []
            if call is not None:
                for argument in call.args:
                    route_path = self._ast_string(argument)
                    if route_path is not None:
                        break
                for keyword in call.keywords:
                    if keyword.arg in {"path", "rule"}:
                        route_path = (
                            self._ast_string(keyword.value) or route_path
                        )
                    if keyword.arg == "methods" and isinstance(
                        keyword.value, (ast.List, ast.Tuple, ast.Set)
                    ):
                        methods = [
                            value.value.upper()
                            for value in keyword.value.elts
                            if isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                        ]
            if route_path is None:
                continue
            if name in direct_methods:
                methods = [name.upper()]
            elif not methods:
                methods = ["GET"]
            methods = sorted(
                {
                    method
                    for method in methods
                    if method in {"GET", "POST", "PUT", "PATCH", "DELETE"}
                }
            )
            if methods:
                specs.append((route_path, methods, decorator.lineno))
        return specs

    def _scan_python_file(self, file_path: str, source: str) -> None:
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as exc:
            line_number = max(exc.lineno or 1, 1)
            message = (exc.msg or "invalid syntax").strip()
            self._add_finding(
                SourceCodeFinding(
                    file_path=file_path,
                    line_number=line_number,
                    vulnerable_code=self._snippet(source, line_number)
                    or f"SyntaxError: {message}"[:240],
                    logic_gap_type="syntax_error",
                    severity="Low",
                    rule_id="SAST-PY-SYNTAX",
                )
            )
            self._warnings.append(
                f"Python parse failed for "
                f"{file_path}:{line_number}: {message}."
            )
            self._scan_regex_file(file_path, source, ".py")
            return

        functions = sorted(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ),
            key=lambda item: item.lineno,
        )
        for node in functions:
            start_line = min(
                [node.lineno]
                + [decorator.lineno for decorator in node.decorator_list]
            )
            end_line = getattr(node, "end_lineno", node.lineno) or node.lineno
            code = "\n".join(source.splitlines()[start_line - 1 : end_line])
            specs = self._python_route_specs(node)
            args = [
                argument.arg
                for argument in (
                    list(node.args.posonlyargs)
                    + list(node.args.args)
                    + list(node.args.kwonlyargs)
                )
                if argument.arg.casefold()
                not in {
                    "self",
                    "cls",
                    "request",
                    "req",
                    "response",
                    "res",
                    "db",
                    "session",
                    "current_user",
                    "user",
                    "args",
                    "kwargs",
                    "context",
                    "ctx",
                }
            ]
            if node.args.vararg is not None:
                args.append(node.args.vararg.arg)
            if node.args.kwarg is not None:
                args.append(node.args.kwarg.arg)

            if specs:
                for route_path, methods, route_line in specs:
                    parameters = self._collect_parameters(
                        code, route_path, args
                    )
                    self._add_route(
                        SourceRoute(
                            file_path=file_path,
                            line_number=route_line,
                            path=route_path,
                            methods=methods,
                            handler=node.name,
                            parameters=parameters,
                            source_language="Python",
                        )
                    )
                    self._audit_function(
                        file_path,
                        source,
                        code,
                        start_line,
                        route_path,
                        methods,
                        self._python_has_auth(node, code),
                        parameters,
                    )
            else:
                parameters = self._collect_parameters(code, "", args)
                self._audit_business_bounds(
                    file_path, source, code, start_line, None, parameters
                )

    def _python_has_auth(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, code: str
    ) -> bool:
        names = [
            self._ast_name(item).casefold() for item in node.decorator_list
        ]
        auth_markers = (
            "login_required",
            "jwt_required",
            "auth_required",
            "requires_auth",
            "permission_required",
            "require_role",
            "require_permission",
            "authenticated",
            "staff_member_required",
        )
        return any(
            marker in name for name in names for marker in auth_markers
        ) or bool(self.AUTH_RE.search(code))

    def _collect_parameters(
        self, code: str, route_path: str, arguments: Sequence[str] = ()
    ) -> list[str]:
        names: set[str] = set()
        for match in self.BUSINESS_RE.finditer(code):
            names.add(match.group(1))
        for match in self.ID_FIELD_RE.finditer(code):
            candidate = match.group(1) or match.group(2)
            if candidate and self._is_fuzzable_parameter(candidate):
                names.add(candidate)
        for match in self.SOURCE_FIELD_RE.finditer(code):
            names.update(
                candidate for candidate in match.groups() if candidate
            )
        for match in self.OBJECT_FIELD_RE.finditer(code):
            names.update(
                candidate for candidate in match.groups() if candidate
            )
        for argument in arguments:
            if argument.isidentifier():
                names.add(argument)
        for match in self.ROUTE_PARAMETER_RE.finditer(route_path):
            candidate = next(
                (group for group in match.groups() if group), None
            )
            if candidate:
                names.add(candidate)
        return sorted(names, key=str.casefold)

    def _audit_function(
        self,
        file_path: str,
        source: str,
        code: str,
        start_line: int,
        route_path: str,
        methods: Sequence[str],
        has_auth: bool,
        parameters: Sequence[str],
    ) -> None:
        self._audit_business_bounds(
            file_path, source, code, start_line, route_path, parameters
        )
        is_mutating = bool(
            set(methods) & {"POST", "PUT", "PATCH", "DELETE"}
        ) or bool(self.STATE_WRITE_RE.search(code))
        if is_mutating and not has_auth:
            self._add_finding(
                SourceCodeFinding(
                    file_path=file_path,
                    line_number=start_line,
                    vulnerable_code=self._snippet(source, start_line),
                    logic_gap_type="missing_access_control",
                    severity="High",
                    rule_id="SAST-ACCESS-001",
                    route_path=route_path,
                )
            )

    def _audit_business_bounds(
        self,
        file_path: str,
        source: str,
        code: str,
        start_line: int,
        route_path: Optional[str],
        parameters: Sequence[str],
    ) -> None:
        names: set[str] = {
            match.group(1).casefold()
            for match in self.BUSINESS_RE.finditer(code)
        }
        names.update(
            name.casefold()
            for name in parameters
            if self._is_business_key(name)
        )
        for name in sorted(names):
            if self._has_bounds_validation(code, name):
                continue
            relative_line = 1
            for index, line in enumerate(code.splitlines(), start=1):
                if re.search(rf"\b{re.escape(name)}\b", line, re.IGNORECASE):
                    relative_line = index
                    break
            line_number = max(start_line + relative_line - 1, 1)
            severity = (
                "High"
                if name in {"price", "amount", "total", "discount"}
                else "Medium"
            )
            self._add_finding(
                SourceCodeFinding(
                    file_path=file_path,
                    line_number=line_number,
                    vulnerable_code=self._snippet(source, line_number),
                    logic_gap_type="missing_business_validation",
                    severity=severity,
                    rule_id=f"SAST-BIZ-{name.upper()}",
                    route_path=route_path,
                )
            )

    def _has_bounds_validation(self, code: str, key: str) -> bool:
        escaped = re.escape(key)
        numeric = r"-?\d+(?:\.\d+)?"
        comparisons = (
            rf"\b{escaped}\b\s*(?:<=|<|>=|>)\s*{numeric}",
            rf"{numeric}\s*(?:<=|<|>=|>)\s*\b{escaped}\b",
            rf"\b{escaped}\b[^\n;]{{0,100}}"
            rf"\b(?:Field|conint|confloat|PositiveInt|NonNegativeInt)\s*"
            rf"\([^)]*\b(?:ge|gt|le|lt|min|max)\s*=",
        )
        if any(
            re.search(pattern, code, re.IGNORECASE) for pattern in comparisons
        ):
            return True
        # A Pydantic-style field declaration may live beside, rather than
        # inside, the endpoint function. Require the same key and a bound.
        schema_pattern = (
            rf"\b{escaped}\b\s*:\s*[^\n;]{{0,180}}"
            rf"\b(?:Field|conint|confloat)\s*\([^)]*"
            rf"\b(?:ge|gt|le|lt|min|max)\s*="
        )
        return bool(re.search(schema_pattern, code, re.IGNORECASE))

    def _scan_regex_file(
        self, file_path: str, source: str, suffix: str
    ) -> None:
        matches: list[tuple[re.Match[str], str, str, str]] = []
        if suffix == ".php":
            for match in self.PHP_ROUTE_RE.finditer(source):
                method = match.group(1).upper()
                methods = (
                    ["GET", "POST", "PUT", "PATCH", "DELETE"]
                    if method == "ANY"
                    else [method]
                )
                matches.append(
                    (match, match.group(3), ", ".join(methods), "PHP")
                )
        elif suffix == ".py":
            for match in self.FASTAPI_ROUTE_RE.finditer(source):
                matches.append(
                    (
                        match,
                        match.group(3),
                        match.group(1).upper(),
                        "Python/FastAPI regex fallback",
                    )
                )
        elif suffix == ".java":
            spring_mappings = list(
                self.SPRING_REQUEST_MAPPING_RE.finditer(source)
            )
            controller_prefixes = [
                match
                for match in spring_mappings
                if re.search(
                    r"\bmethod\s*=", match.group("arguments"), re.I
                )
                is None
            ]
            for match in self.SPRING_BOOT_ROUTE_RE.finditer(source):
                method_name = re.match(
                    r"@([A-Za-z]+)Mapping", match.group(0)
                )
                if method_name is None:
                    continue
                prefix = ""
                for controller in controller_prefixes:
                    if controller.start() < match.start():
                        path_match = self.SPRING_MAPPING_PATH_RE.search(
                            controller.group("arguments")
                        )
                        if path_match is not None:
                            prefix = (
                                path_match.group(2)
                                or path_match.group(4)
                                or ""
                            )
                    else:
                        break
                arguments = match.group("arguments") or ""
                annotation_path = self.SPRING_MAPPING_PATH_RE.search(
                    arguments
                )
                route_suffix = ""
                if annotation_path is not None:
                    route_suffix = (
                        annotation_path.group(2)
                        or annotation_path.group(4)
                        or ""
                    )
                route_path = self._join_route_paths(prefix, route_suffix)
                matches.append(
                    (
                        match,
                        route_path,
                        method_name.group(1).upper(),
                        "Java/Spring Boot",
                    )
                )
            for match in spring_mappings:
                arguments = match.group("arguments")
                methods = re.findall(
                    r"\bRequestMethod\.(GET|POST|PUT|PATCH|DELETE)\b",
                    arguments,
                    re.IGNORECASE,
                )
                if not methods:
                    continue
                path_match = self.SPRING_MAPPING_PATH_RE.search(arguments)
                if path_match is None:
                    continue
                route_suffix = path_match.group(2) or path_match.group(4) or ""
                prefix = ""
                for controller in controller_prefixes:
                    if controller.start() < match.start():
                        parent_path = self.SPRING_MAPPING_PATH_RE.search(
                            controller.group("arguments")
                        )
                        if parent_path is not None:
                            prefix = (
                                parent_path.group(2)
                                or parent_path.group(4)
                                or ""
                            )
                    else:
                        break
                route_path = self._join_route_paths(prefix, route_suffix)
                matches.append(
                    (
                        match,
                        route_path,
                        ", ".join(method.upper() for method in methods),
                        "Java/Spring Boot",
                    )
                )
        else:
            for match in self.JS_ROUTE_RE.finditer(source):
                method = match.group(1).upper()
                methods = (
                    ["GET", "POST", "PUT", "PATCH", "DELETE"]
                    if method == "ALL"
                    else [method]
                )
                matches.append(
                    (
                        match,
                        match.group(3),
                        ", ".join(methods),
                        "JavaScript/TypeScript",
                    )
                )
            for match in self.JS_CHAIN_ROUTE_RE.finditer(source):
                matches.append(
                    (
                        match,
                        match.group(2),
                        match.group(3).upper(),
                        "JavaScript/TypeScript",
                    )
                )
            controllers = list(self.CONTROLLER_RE.finditer(source))
            for match in self.NEST_ROUTE_RE.finditer(source):
                prefix = ""
                for controller in controllers:
                    if controller.start() < match.start():
                        prefix = controller.group(1) or ""
                    else:
                        break
                route_path = self._join_route_paths(
                    prefix, match.group(2) or ""
                )
                matches.append(
                    (
                        match,
                        route_path,
                        match.group(1).upper(),
                        "JavaScript/TypeScript",
                    )
                )

        seen: set[tuple[int, str, str]] = set()
        for match, route_path, method_text, language in sorted(
            matches, key=lambda item: item[0].start()
        ):
            methods = [
                item.strip() for item in method_text.split(",") if item.strip()
            ]
            unique_key = (match.start(), route_path, ",".join(methods))
            if unique_key in seen:
                continue
            seen.add(unique_key)
            block, handler = self._regex_handler_block(source, match, suffix)
            line_number = self._line_number(source, match.start())
            route_parameters = self._collect_parameters(block, route_path)
            if not block:
                route_parameters = self._collect_parameters(
                    source[max(0, match.start() - 300) : match.end() + 300],
                    route_path,
                )
                self._warnings.append(
                    f"Could not resolve handler body for "
                    f"{file_path}:{line_number} ({route_path}); "
                    "access-control "
                    "review is limited to the route declaration."
                )
            if suffix == ".java":
                signature_context = source[
                    match.end() : match.end() + 1600
                ]
                signature_end = re.search(
                    r"\)\s*(?:throws\s+[^{]+)?\{",
                    signature_context,
                    re.DOTALL,
                )
                if signature_end is not None:
                    signature_context = signature_context[:signature_end.end()]
                route_parameters.extend(
                    parameter.group(1)
                    for parameter in self.SPRING_PARAMETER_RE.finditer(
                        signature_context
                    )
                )
                route_parameters = sorted(
                    set(route_parameters), key=str.casefold
                )
            self._add_route(
                SourceRoute(
                    file_path=file_path,
                    line_number=line_number,
                    path=route_path,
                    methods=methods,
                    handler=handler or "<unresolved>",
                    parameters=route_parameters,
                    source_language=language,
                )
            )
            audit_code = block or source[match.start() : match.end()]
            self._audit_business_bounds(
                file_path,
                source,
                audit_code,
                self._line_number(source, match.start()),
                route_path,
                route_parameters,
            )
            auth_context = (
                source[max(0, match.start() - 1000) : match.start()]
                + source[match.start() : min(len(source), match.end() + 500)]
                + "\n"
                + block
            )
            mutating = bool(
                set(methods) & {"POST", "PUT", "PATCH", "DELETE"}
            ) or bool(self.STATE_WRITE_RE.search(audit_code))
            if mutating and not self.AUTH_RE.search(auth_context):
                self._add_finding(
                    SourceCodeFinding(
                        file_path=file_path,
                        line_number=line_number,
                        vulnerable_code=self._snippet(source, line_number),
                        logic_gap_type="missing_access_control",
                        severity="High",
                        rule_id="SAST-ACCESS-001",
                        route_path=route_path,
                    )
                )

    @staticmethod
    def _join_route_paths(prefix: str, path: str) -> str:
        pieces = [
            piece.strip("/") for piece in (prefix, path) if piece.strip("/")
        ]
        return "/" + "/".join(pieces) if pieces else "/"

    def _regex_handler_block(
        self, source: str, match: re.Match[str], suffix: str
    ) -> tuple[str, str]:
        tail_start = match.end()
        tail = source[tail_start : tail_start + 12_000]
        if suffix == ".py":
            function_match = re.search(
                r"(?m)^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*"
                r"\([^)]*\)\s*:",
                tail,
                re.DOTALL,
            )
            if function_match is not None:
                function_start = tail_start + function_match.start()
                function_source = source[function_start:]
                function_lines = function_source.splitlines(keepends=True)
                definition_indent = len(function_lines[0]) - len(
                    function_lines[0].lstrip()
                )
                body_lines = [function_lines[0]]
                for line in function_lines[1:]:
                    if (
                        line.strip()
                        and len(line) - len(line.lstrip()) <= definition_indent
                    ):
                        break
                    body_lines.append(line)
                return "".join(body_lines), function_match.group(1)
        if suffix == ".java":
            java_method = re.search(
                r"(?m)^\s*(?:(?:public|protected|private|static|final|"
                r"synchronized|abstract)\s+)*"
                r"[\w.$<>?,\[\] ]+\s+([A-Za-z_$][\w$]*)"
                r"\s*\([^{}]*\)\s*(?:throws [^{]+)?\{",
                tail,
                re.DOTALL,
            )
            if java_method is not None:
                open_brace = tail_start + java_method.end() - 1
                block = self._extract_braced_block(source, open_brace)
                if block:
                    return block, java_method.group(1)
        if match.re.pattern == self.NEST_ROUTE_RE.pattern:
            nest_method = re.search(
                r"(?m)^\s*(?:(?:public|private|protected|static|async)\s+)*"
                r"([A-Za-z_$][\w$]*)\s*\([^{}]*\)\s*"
                r"(?::[^{}]+)?\{",
                tail,
            )
            if nest_method is not None:
                open_brace = tail_start + nest_method.end() - 1
                block = self._extract_braced_block(source, open_brace)
                if block:
                    return block, nest_method.group(1)
        callback = re.search(
            r"(?:\bfunction\b[^{}]*|(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)\s*\{",
            tail,
            re.DOTALL,
        )
        if callback is not None:
            open_brace = tail_start + callback.end() - 1
            block = self._extract_braced_block(source, open_brace)
            if block:
                name_match = re.search(
                    r"\bfunction\s+([A-Za-z_$][\w$]*)", callback.group(0)
                )
                return block, name_match.group(1) if name_match else "<inline>"

        # Resolve common Express/Laravel references such as createOrder or
        # [CartController::class, 'store'] within the same ZIP project.
        reference_text = source[match.end() : match.end() + 600]
        reference = None
        if suffix == ".php":
            php_ref = re.search(
                r"['\"]([A-Za-z_]\w*)['\"]\s*\]", reference_text
            )
            reference = php_ref.group(1) if php_ref else None
        else:
            js_ref = re.search(
                r",\s*(?:[A-Za-z_$][\w$]*\s*,\s*)*"
                r"(?:[A-Za-z_$][\w$]*\s*\.\s*)?([A-Za-z_$][\w$]*)\s*[),]",
                reference_text,
            )
            reference = js_ref.group(1) if js_ref else None
        if reference:
            resolved = self._resolve_named_handler(reference)
            if resolved:
                return resolved, reference
        return "", ""

    def _resolve_named_handler(self, name: str) -> str:
        patterns = (
            re.compile(
                rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
                re.IGNORECASE,
            ),
            re.compile(
                rf"\b{re.escape(name)}\s*=\s*(?:async\s*)?"
                rf"(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{{",
                re.IGNORECASE,
            ),
            re.compile(
                rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
                re.IGNORECASE,
            ),
        )
        for candidate in self._source_texts.values():
            for pattern in patterns:
                found = pattern.search(candidate)
                if found:
                    open_brace = found.end() - 1
                    block = self._extract_braced_block(candidate, open_brace)
                    if block:
                        return block
        return ""

    @staticmethod
    def _extract_braced_block(source: str, open_brace: int) -> str:
        if (
            open_brace < 0
            or open_brace >= len(source)
            or source[open_brace] != "{"
        ):
            return ""
        depth = 0
        quote: Optional[str] = None
        escaped = False
        line_comment = False
        block_comment = False
        index = open_brace
        while index < len(source):
            char = source[index]
            next_char = source[index + 1] if index + 1 < len(source) else ""
            if line_comment:
                if char == "\n":
                    line_comment = False
                index += 1
                continue
            if block_comment:
                if char == "*" and next_char == "/":
                    block_comment = False
                    index += 2
                else:
                    index += 1
                continue
            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                index += 1
                continue
            if char == "/" and next_char == "/":
                line_comment = True
                index += 2
                continue
            if char == "/" and next_char == "*":
                block_comment = True
                index += 2
                continue
            if char in {"'", '"', "`"}:
                quote = char
                index += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return source[open_brace : index + 1]
            index += 1
        return source[open_brace:]


# ============================================================================
# Mutation and replay engine
# ============================================================================
BUSINESS_KEYS = frozenset(
    {"price", "quantity", "amount", "total", "discount", "role", "isadmin"}
)

PRIVILEGE_KEYS = frozenset(
    {
        "role",
        "isadmin",
        "admin",
        "issuperuser",
        "superuser",
        "ownerid",
        "permissions",
    }
)

HIGH_PRIVILEGE_ASSIGNMENTS: tuple[tuple[str, Any], ...] = (
    ("is_admin", True),
    ("role", "admin"),
    ("admin", True),
    ("is_superuser", True),
    ("permissions", ["*"]),
    ("owner_id", 1),
)
MAX_MASS_ASSIGNMENT_TARGETS = 12
MAX_MASS_ASSIGNMENT_DEPTH = 4

TRANSACTION_HINTS = frozenset(
    {
        "order",
        "transaction",
        "checkout",
        "purchase",
        "payment",
        "charge",
        "invoice",
        "transfer",
        "withdraw",
        "deposit",
        "refund",
        "redeem",
        "coupon",
        "cart",
        "quantity",
        "amount",
        "balance",
        "subscription",
        "booking",
        "reservation",
        "inventory",
        "stock",
        "giftcard",
    }
)

QUERY_MUTATION_VALUES = ("0", "-1", "99999", "true", "admin")

JSON_MUTATION_VALUES: tuple[Any, ...] = (0, -1, 99999, True, "true", "admin")

SESSION_PARAMETER_KEYS = frozenset(
    {
        "session",
        "sessionid",
        "sid",
        "jsessionid",
        "phpsessid",
        "token",
        "tokenid",
        "bearer",
        "bearertoken",
        "access",
        "accesstoken",
        "idtoken",
        "identitytoken",
        "jwt",
        "jwttoken",
        "auth",
        "authtoken",
        "authorization",
        "authentication",
        "authz",
    }
)

COOKIE_HEADER_NAMES = frozenset({"cookie", "cookie2"})

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


@dataclass(frozen=True)
class TestCase:
    """A single replay request and the HAR response used as its baseline."""

    step: WorkflowStep
    strategy: VulnerabilityType
    request: HTTPRequest
    description: str
    mutation: str
    apply_state: bool = True


@dataclass(frozen=True)
class RaceTestGroup:
    """An N-request synchronized pool for one transactional workflow step."""

    step: WorkflowStep
    requests: tuple[HTTPRequest, ...]
    description: str
    mutation: str


@dataclass(frozen=True)
class SequentialReplayGroup:
    """A two-request anti-replay check sent strictly one request at a time."""

    step: WorkflowStep
    request: HTTPRequest
    description: str
    mutation: str


TestWorkItem = Union[TestCase, RaceTestGroup, SequentialReplayGroup]


class WorkflowStateTracker:
    """Extract and refresh anti-CSRF, nonce, and state values across steps."""

    MAX_TOKEN_LENGTH = 4096
    _ASSIGNMENT_RE = re.compile(
        r"""(?i)["']?([A-Za-z0-9_$.-]*(?:csrf|xsrf|nonce|state|"""
        r"""antireplay|requestverification|authenticity)[A-Za-z0-9_$.-]*)"""
        r"""["']?\s*[:=]\s*["']([^"'\r\n<>]{1,4096})["']"""
    )
    _TAG_RE = re.compile(r"(?is)<(?:input|meta)\b[^>]*>")
    _ATTRIBUTE_RE = re.compile(
        r"""(?is)([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"""
    )

    def __init__(self, workflow: Sequence[WorkflowStep]) -> None:
        self._baseline_by_step: dict[int, dict[str, str]] = {}
        self._runtime_by_step: dict[int, dict[str, str]] = {}
        cumulative: dict[str, str] = {}
        for step in workflow:
            self._baseline_by_step[step.index] = dict(cumulative)
            cumulative.update(self.extract(step.baseline_response))

    @classmethod
    def _family(cls, name: str) -> str | None:
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        if "xsrf" in normalized:
            return "xsrf"
        if any(token in normalized for token in ("csrf", "authenticity")):
            return "csrf"
        if "requestverification" in normalized:
            return "csrf"
        if any(token in normalized for token in ("nonce", "antireplay")):
            return "nonce"
        if "state" in normalized:
            return "state"
        return None

    @classmethod
    def _store(cls, tokens: dict[str, str], name: str, value: Any) -> None:
        family = cls._family(name)
        if family is None or value is None or isinstance(value, (dict, list)):
            return
        text = str(value).strip()
        if text and len(text) <= cls.MAX_TOKEN_LENGTH:
            tokens[family] = text

    @classmethod
    def _walk_json(
        cls, value: Any, tokens: dict[str, str], depth: int = 0
    ) -> None:
        if depth >= 128:
            return
        if isinstance(value, dict):
            for name, item in value.items():
                cls._store(tokens, str(name), item)
                cls._walk_json(item, tokens, depth + 1)
        elif isinstance(value, list):
            for item in value:
                cls._walk_json(item, tokens, depth + 1)

    @classmethod
    def extract(cls, response: HTTPResponse) -> dict[str, str]:
        """Extract state values from headers, JSON, HTML, or scripts."""
        tokens: dict[str, str] = {}
        for name, value in response.headers.items():
            cls._store(tokens, name, value)
            if name.casefold() == "set-cookie":
                cookie = SimpleCookie()
                try:
                    cookie.load(value)
                except Exception:
                    continue
                for cookie_name, morsel in cookie.items():
                    cls._store(tokens, cookie_name, morsel.value)

        body = response.body
        if not body:
            return tokens
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, TypeError, RecursionError):
            payload = None
        if payload is not None:
            cls._walk_json(payload, tokens)

        for match in cls._ASSIGNMENT_RE.finditer(body):
            cls._store(tokens, match.group(1), match.group(2))
        for tag in cls._TAG_RE.findall(body):
            attributes: dict[str, str] = {}
            for match in cls._ATTRIBUTE_RE.finditer(tag):
                raw_value = next(
                    (
                        group
                        for group in match.groups()[1:]
                        if group is not None
                    ),
                    "",
                )
                attributes[match.group(1).casefold()] = raw_value
            key = (
                attributes.get("name")
                or attributes.get("id")
                or attributes.get("property")
            )
            value = attributes.get("value") or attributes.get("content")
            if key and value:
                cls._store(tokens, key, value)
        return tokens

    def observe(self, step_index: int, response: HTTPResponse) -> None:
        """Update live tokens as each replay response completes."""
        extracted = self.extract(response)
        if extracted:
            self._runtime_by_step.setdefault(step_index, {}).update(extracted)

    def tokens_for_step(self, step_index: int) -> dict[str, str]:
        """Return captured prior-step state plus fresh runtime values."""
        tokens = dict(self._baseline_by_step.get(step_index, {}))
        for prior_index in sorted(self._runtime_by_step):
            if prior_index <= step_index:
                tokens.update(self._runtime_by_step[prior_index])
        return tokens

    def apply(self, request: HTTPRequest, step_index: int) -> HTTPRequest:
        """Refresh state tokens already represented in a request."""
        tokens = self.tokens_for_step(step_index)
        if not tokens:
            return request

        headers = dict(request.headers)
        for name, value in list(headers.items()):
            if name.casefold() == "cookie":
                headers[name] = self._patch_cookie(value, tokens)
                continue
            family = self._family(name)
            if family in tokens:
                headers[name] = tokens[family]

        url = self._patch_url(request.url, tokens)
        body = self._patch_body(request.body, headers, tokens)
        return HTTPRequest(
            method=request.method,
            url=url,
            headers=headers,
            body=body,
        )

    @classmethod
    def _patch_cookie(cls, value: str, tokens: Mapping[str, str]) -> str:
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:
            return value
        if not cookie:
            return value
        changed = False
        for name, morsel in cookie.items():
            family = cls._family(name)
            if family in tokens:
                cookie[name] = tokens[family]
                changed = True
        if not changed:
            return value
        return "; ".join(
            f"{name}={morsel.value}" for name, morsel in cookie.items()
        )

    @classmethod
    def _patch_url(cls, url: str, tokens: Mapping[str, str]) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        changed = False
        patched: list[tuple[str, str]] = []
        for name, value in pairs:
            family = cls._family(name)
            if family in tokens:
                value = tokens[family]
                changed = True
            patched.append((name, value))
        if not changed:
            return url
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(patched),
                parts.fragment,
            )
        )

    @classmethod
    def _patch_body(
        cls,
        body: str | None,
        headers: Mapping[str, str],
        tokens: Mapping[str, str],
    ) -> str | None:
        if not body:
            return body
        content_type = next(
            (
                value.casefold()
                for name, value in headers.items()
                if name.casefold() == "content-type"
            ),
            "",
        )
        if "json" in content_type or body.lstrip().startswith(("{", "[")):
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, TypeError, RecursionError):
                return body
            patched, changed = cls._patch_json(payload, tokens)
            if changed:
                return json.dumps(
                    patched, ensure_ascii=False, separators=(",", ":")
                )
            return body
        if "application/x-www-form-urlencoded" in content_type or "=" in body:
            pairs = parse_qsl(body, keep_blank_values=True)
            changed = False
            patched_pairs: list[tuple[str, str]] = []
            for name, value in pairs:
                family = cls._family(name)
                if family in tokens:
                    value = tokens[family]
                    changed = True
                patched_pairs.append((name, value))
            return urlencode(patched_pairs) if changed else body
        return body

    @classmethod
    def _patch_json(
        cls,
        value: Any,
        tokens: Mapping[str, str],
        depth: int = 0,
    ) -> tuple[Any, bool]:
        if depth >= 128:
            return value, False
        if isinstance(value, dict):
            changed = False
            result: dict[str, Any] = {}
            for name, item in value.items():
                family = cls._family(str(name))
                if family in tokens and not isinstance(item, (dict, list)):
                    result[name] = tokens[family]
                    changed = True
                else:
                    result[name], item_changed = cls._patch_json(
                        item, tokens, depth + 1
                    )
                    changed = changed or item_changed
            return result, changed
        if isinstance(value, list):
            result_list: list[Any] = []
            changed = False
            for item in value:
                patched, item_changed = cls._patch_json(
                    item, tokens, depth + 1
                )
                result_list.append(patched)
                changed = changed or item_changed
            return result_list, changed
        return value, False


class _VisibleTextParser(HTMLParser):
    """Extract visible-ish HTML text without requiring a third-party parser."""

    _HIDDEN_TAGS = frozenset({"script", "style", "noscript"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._hidden_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        del attrs
        if tag.casefold() in self._HIDDEN_TAGS:
            self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in self._HIDDEN_TAGS and self._hidden_depth:
            self._hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._hidden_depth:
            self.parts.append(data)


class LogicEngine:
    """Generate bounded mutation cases and replay them concurrently.

    The engine never reuses response cookies between test cases. Requests carry
    only explicitly present headers, and redirects are not followed. This keeps
    a scoped HAR request from silently replaying to a different endpoint.
    """

    DEFAULT_CONCURRENCY = 6
    DEFAULT_TIMEOUT_SECONDS = 15.0
    DEFAULT_MAX_MUTATIONS = 250
    DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
    DEFAULT_RACE_COUNT = 10
    MAX_RACE_COUNT = 50
    BODY_SIMILARITY_THRESHOLD = 0.92
    LENGTH_SIMILARITY_THRESHOLD = 0.97
    MAX_COMPARISON_CHARS = 25_000

    def __init__(
        self,
        workflow: Sequence[WorkflowStep],
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_mutations: int = DEFAULT_MAX_MUTATIONS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        source_steps: Sequence[WorkflowStep] = (),
        delay_seconds: float = 0.0,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_mutations < 1:
            raise ValueError("max_mutations must be at least 1")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        if not math.isfinite(delay_seconds) or delay_seconds < 0:
            raise ValueError(
                "delay_seconds must be a finite non-negative value"
            )
        self.workflow = list(workflow)
        self.source_steps = list(source_steps)
        self.concurrency = concurrency
        self.timeout_seconds = timeout_seconds
        self.max_mutations = max_mutations
        self.max_response_bytes = max_response_bytes
        self.delay_seconds = delay_seconds
        self._rate_limit_lock: asyncio.Lock | None = None
        self._next_request_at = 0.0
        self.state_tracker = WorkflowStateTracker(
            self.workflow + self.source_steps
        )
        self.execution_errors: list[str] = []
        try:
            self._ai_pipeline: Any | None = _load_local_ai_pipeline()
        except Exception:
            self._ai_pipeline = None

    def _internal_ai_triage(
        self,
        execution_context: str,
        strategy: str,
        mutation_or_route: str,
        baseline_status: object = "N/A",
        baseline_body: object = "N/A",
        attack_status: object = "N/A",
        attack_body: object = "N/A",
        file_path: str = "N/A",
        source_language: str = "N/A",
        extracted_code_block: str = "N/A",
    ) -> tuple[bool, str]:
        """Use the cached local model to triage a finding, failing open."""
        return _run_local_ai_triage(
            self._ai_pipeline,
            execution_context,
            strategy,
            mutation_or_route,
            baseline_status,
            baseline_body,
            attack_status,
            attack_body,
            file_path,
            source_language,
            extracted_code_block,
        )

    def refresh_headers(self, overrides: Mapping[str, str]) -> int:
        """Replace or add the named headers on every workflow request.

        Header names are matched case-insensitively. The returned number is the
        number of requests updated (not the number of individual headers).
        """
        cleaned: list[tuple[str, str]] = []
        for raw_name, raw_value in overrides.items():
            name = str(raw_name).strip()
            value = str(raw_value)
            if not name or not re.fullmatch(
                r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name
            ):
                raise ValueError(f"invalid header name: {name!r}")
            if "\r" in value or "\n" in value:
                raise ValueError(f"header {name!r} contains a newline")
            cleaned.append((name, value))

        def refreshed_steps(
            steps: Sequence[WorkflowStep],
        ) -> list[WorkflowStep]:
            refreshed: list[WorkflowStep] = []
            for step in steps:
                headers = dict(step.request.headers)
                for name, value in cleaned:
                    for existing in list(headers):
                        if existing.casefold() == name.casefold():
                            del headers[existing]
                    headers[name] = value
                refreshed.append(
                    step.model_copy(
                        update={
                            "request": step.request.model_copy(
                                update={"headers": headers}
                            )
                        }
                    )
                )
            return refreshed

        self.workflow = refreshed_steps(self.workflow)
        self.source_steps = refreshed_steps(self.source_steps)
        self.state_tracker = WorkflowStateTracker(
            self.workflow + self.source_steps
        )
        return len(self.workflow) if cleaned else 0

    def build_test_cases(
        self,
        secondary_headers: Mapping[str, str] | None = None,
        test_race: bool = False,
        race_count: int = DEFAULT_RACE_COUNT,
    ) -> list[TestWorkItem]:
        """Create mutation, identity, skip, replay, and optional race tests."""
        if test_race and not 2 <= race_count <= self.MAX_RACE_COUNT:
            raise ValueError(
                f"race_count must be between 2 and {self.MAX_RACE_COUNT}"
            )

        cases: list[TestWorkItem] = []
        mutation_count = 0
        # Grey-box source-derived requests run first so the extra coverage is
        # not starved by a large HAR when the mutation budget is bounded.
        for step in self.source_steps + self.workflow:
            if mutation_count >= self.max_mutations:
                break
            for case in self._parameter_mutations(step):
                if mutation_count >= self.max_mutations:
                    break
                cases.append(case)
                mutation_count += 1

        for step in self.source_steps:
            if not step.has_baseline:
                cases.append(
                    TestCase(
                        step=step,
                        strategy=VulnerabilityType.PARAMETER_MANIPULATION,
                        request=step.request,
                        description=(
                            "Probe a SAST-discovered route/method absent from "
                            "the HAR using source-derived default parameters."
                        ),
                        mutation="source-discovered route reachability probe",
                    )
                )

        for step in self.workflow:
            if self._is_transactional_business_request(step.request):
                cases.append(
                    SequentialReplayGroup(
                        step=step,
                        request=step.request.model_copy(deep=True),
                        description=(
                            f"Replay transactional step {step.index} twice "
                            "in sequence to check for missing anti-replay or "
                            "idempotency controls."
                        ),
                        mutation=(
                            "two identical replays sent sequentially, not "
                            "behind a concurrency barrier"
                        ),
                    )
                )

        if secondary_headers:
            secondary_names = ", ".join(secondary_headers)
            for step in self.workflow:
                bola_request = self._for_secondary_identity(
                    step.request, secondary_headers
                )
                removed_names = [
                    name
                    for name in step.request.headers
                    if self._is_identity_header(name)
                ]
                removed_text = ", ".join(removed_names) or "none"
                cases.append(
                    TestCase(
                        step=step,
                        strategy=VulnerabilityType.PRIVILEGE_ESCALATION_BOLA,
                        request=bola_request,
                        description=(
                            f"Replay step {step.index} as User B after "
                            "replacing User A identity headers."
                        ),
                        mutation=(
                            f"Removed A identity headers: {removed_text}; "
                            f"applied User B headers: {secondary_names}."
                        ),
                        apply_state=False,
                    )
                )

        if len(self.workflow) > 1:
            final_step = self.workflow[-1]
            skipped_request = self._without_prior_session_state(
                final_step.request
            )
            cases.append(
                TestCase(
                    step=final_step,
                    strategy=VulnerabilityType.STEP_SKIPPING,
                    request=skipped_request,
                    description=(
                        "Replay the final captured request without earlier "
                        "cookies or session IDs; refresh anti-CSRF state."
                    ),
                    mutation=(
                        "Removed cookies/session IDs; retained refreshable "
                        "CSRF and nonce values."
                    ),
                )
            )

        if test_race:
            for step in self.workflow + self.source_steps:
                has_source_business_key = any(
                    self._is_business_key(name)
                    for name in step.source_parameters
                )
                if not (
                    self._is_transactional_business_request(step.request)
                    or has_source_business_key
                ):
                    continue
                request_pool = tuple(
                    step.request.model_copy(deep=True)
                    for _ in range(race_count)
                )
                cases.append(
                    RaceTestGroup(
                        step=step,
                        requests=request_pool,
                        description=(
                            f"Send {race_count} synchronized requests for "
                            f"transactional step {step.index}."
                        ),
                        mutation=(
                            f"{race_count} identical requests released from "
                            "one async barrier."
                        ),
                    )
                )
        return cases

    @staticmethod
    def _is_identity_header(name: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]", "", name.casefold())
        if "csrf" in normalized or "xsrf" in normalized:
            return False
        identity_markers = (
            "authorization",
            "cookie",
            "auth",
            "token",
            "session",
            "apikey",
            "userid",
            "user",
            "identity",
            "principal",
            "tenant",
            "accountid",
            "customerid",
            "ownerid",
            "subject",
            "clientid",
            "organization",
            "orgid",
            "groupid",
            "impersonat",
            "role",
        )
        return any(marker in normalized for marker in identity_markers)

    def _for_secondary_identity(
        self,
        request: HTTPRequest,
        secondary_headers: Mapping[str, str],
    ) -> HTTPRequest:
        """Strip User A identity headers and apply User B's headers."""
        headers = {
            name: value
            for name, value in request.headers.items()
            if not self._is_identity_header(name)
        }
        for raw_name, raw_value in secondary_headers.items():
            name = raw_name.strip()
            value = str(raw_value)
            if not name or "\r" in value or "\n" in value:
                raise ValueError("invalid secondary header name or value")
            for existing in list(headers):
                if existing.casefold() == name.casefold():
                    del headers[existing]
            headers[name] = value
        return self._copy_request(request, headers=headers)

    @classmethod
    def _contains_transaction_hint(cls, value: Any, depth: int = 0) -> bool:
        if depth >= 32:
            return False
        if isinstance(value, dict):
            for name, item in value.items():
                normalized = cls._normalize_key(str(name))
                if any(hint in normalized for hint in TRANSACTION_HINTS):
                    return True
                if cls._contains_transaction_hint(item, depth + 1):
                    return True
        elif isinstance(value, list):
            return any(
                cls._contains_transaction_hint(item, depth + 1)
                for item in value
            )
        return False

    def _is_transactional_business_request(self, request: HTTPRequest) -> bool:
        if request.method.upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            return False
        parts = urlsplit(request.url)
        location = self._normalize_key(parts.path)
        if any(hint in location for hint in TRANSACTION_HINTS):
            return True
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        if any(
            self._is_business_key(name)
            or any(
                hint in self._normalize_key(name)
                for hint in TRANSACTION_HINTS
            )
            for name, _ in query_pairs
        ):
            return True
        if not request.body:
            return False
        content_type = self._header_value(
            request.headers, "content-type"
        ).casefold()
        if "json" in content_type or request.body.lstrip().startswith(
            ("{", "[")
        ):
            try:
                payload = json.loads(request.body)
            except (json.JSONDecodeError, TypeError, RecursionError):
                return False
            return self._contains_transaction_hint(payload) or any(
                self._sensitive_json_values(payload)
            )
        if (
            "application/x-www-form-urlencoded" in content_type
            or "=" in request.body
        ):
            return any(
                self._is_business_key(name)
                or any(
                    hint in self._normalize_key(name)
                    for hint in TRANSACTION_HINTS
                )
                for name, _ in parse_qsl(
                    request.body, keep_blank_values=True
                )
            )
        return False

    async def _wait_for_rate_limit(self) -> None:
        """Reserve a globally spaced start time for one ordinary replay."""
        if self.delay_seconds <= 0:
            return
        if self._rate_limit_lock is None:
            self._rate_limit_lock = asyncio.Lock()
        lock = self._rate_limit_lock
        loop = asyncio.get_running_loop()
        async with lock:
            now = loop.time()
            scheduled_at = max(now, self._next_request_at)
            self._next_request_at = scheduled_at + self.delay_seconds
            wait_seconds = scheduled_at - now
        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)

    async def scan(
        self,
        test_cases: Sequence[TestWorkItem] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> list[ScanResult]:
        """Run ordinary/race tests concurrently and replay sequentially."""
        self.execution_errors.clear()
        cases = (
            list(test_cases)
            if test_cases is not None
            else self.build_test_cases()
        )
        if not cases:
            return []

        self._rate_limit_lock = asyncio.Lock()
        self._next_request_at = 0.0
        timeout = ClientTimeout(total=self.timeout_seconds)
        connector = TCPConnector(limit=self.concurrency)
        semaphore = asyncio.Semaphore(self.concurrency)
        race_pool_lock = asyncio.Lock()
        results: list[ScanResult] = []
        sequential_items = [
            item for item in cases if isinstance(item, SequentialReplayGroup)
        ]
        ordinary_items = [
            item
            for item in cases
            if not isinstance(item, SequentialReplayGroup)
        ]
        completed_count = 0

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=DummyCookieJar(),
            trust_env=False,
            raise_for_status=False,
        ) as session:
            tasks = [
                asyncio.create_task(
                    self._run_work_item(
                        session, semaphore, race_pool_lock, item
                    )
                )
                for item in ordinary_items
            ]
            for completed in asyncio.as_completed(tasks):
                finding = await completed
                completed_count += 1
                if finding is not None:
                    results.append(finding)
                if on_progress is not None:
                    on_progress(completed_count, len(cases))

            # Keep the pair isolated from concurrent mutations and race pools;
            # each group sends its two identical requests one after another.
            for item in sequential_items:
                finding = await self._run_sequential_replay_group(
                    session, item
                )
                completed_count += 1
                if finding is not None:
                    results.append(finding)
                if on_progress is not None:
                    on_progress(completed_count, len(cases))

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return sorted(
            results,
            key=lambda finding: (
                severity_order.get(finding.severity.casefold(), 5),
                finding.step_index,
                finding.strategy.value,
            ),
        )

    def _parameter_mutations(self, step: WorkflowStep) -> Iterable[TestCase]:
        """Mutate query, form, JSON, and GraphQL business variables."""
        request = step.request
        query_pairs = parse_qsl(
            urlsplit(request.url).query,
            keep_blank_values=True,
        )
        for parameter_index, (name, original_value) in enumerate(query_pairs):
            if not self._is_step_target_key(name, step):
                continue
            for value in QUERY_MUTATION_VALUES:
                if original_value == value:
                    continue
                pairs = list(query_pairs)
                pairs[parameter_index] = (name, value)
                parts = urlsplit(request.url)
                mutated_url = urlunsplit(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        urlencode(pairs),
                        parts.fragment,
                    )
                )
                strategy = (
                    VulnerabilityType.PRIVILEGE_FLAW
                    if self._is_privilege_key(name)
                    else VulnerabilityType.PARAMETER_MANIPULATION
                )
                mutation = (
                    f"query parameter {name!r}: "
                    f"{original_value!r} -> {value!r}"
                )
                yield TestCase(
                    step=step,
                    strategy=strategy,
                    request=self._copy_request(request, url=mutated_url),
                    description=f"Mutate {mutation}.",
                    mutation=mutation,
                )

        yield from self._graphql_query_mutations(step)
        query_mass_cases = list(
            self._mass_assignment_query_mutations(step, query_pairs)
        )

        if step.source_path_parameters:
            parts = urlsplit(request.url)
            for (
                parameter_name,
                original_value,
            ) in step.source_path_parameters.items():
                if not self._is_step_target_key(parameter_name, step):
                    continue
                for value in QUERY_MUTATION_VALUES:
                    if original_value == value:
                        continue
                    segments = parts.path.split("/")
                    replaced = False
                    for index, segment in enumerate(segments):
                        if segment == original_value:
                            segments[index] = value
                            replaced = True
                    if not replaced:
                        continue
                    mutated_url = urlunsplit(
                        (
                            parts.scheme,
                            parts.netloc,
                            "/".join(segments),
                            parts.query,
                            parts.fragment,
                        )
                    )
                    mutation = (
                        f"source-discovered path parameter "
                        f"{parameter_name!r}: {original_value!r} -> "
                        f"{value!r}"
                    )
                    yield TestCase(
                        step=step,
                        strategy=VulnerabilityType.PARAMETER_MANIPULATION,
                        request=self._copy_request(request, url=mutated_url),
                        description=f"Fuzz {mutation}.",
                        mutation=mutation,
                    )

        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            yield from query_mass_cases
            return
        content_type = self._header_value(
            request.headers, "content-type"
        ).casefold()
        body = request.body or ""
        if not body and "json" in content_type:
            body = "{}"
        elif (
            not body
            and "application/x-www-form-urlencoded" not in content_type
        ):
            yield from query_mass_cases
            return
        looks_json = "json" in content_type or body.lstrip().startswith(
            ("{", "[")
        )
        if looks_json:
            try:
                json_body = json.loads(body)
            except (json.JSONDecodeError, TypeError, RecursionError):
                # Invalid JSON is skipped; query mutations remain usable.
                yield from query_mass_cases
                return

            is_graphql = self._is_graphql_request(request, json_body)
            variables_are_string = False
            if is_graphql and isinstance(json_body, dict):
                variables = json_body.get("variables")
                variables_are_string = isinstance(variables, str)
                if variables_are_string:
                    try:
                        mutation_root = json.loads(variables)
                    except (json.JSONDecodeError, TypeError, RecursionError):
                        yield from query_mass_cases
                        return
                else:
                    mutation_root = variables
                if not isinstance(mutation_root, (dict, list)):
                    yield from query_mass_cases
                    return
                path_prefix: tuple[str | int, ...] = ("variables",)
            elif is_graphql:
                yield from query_mass_cases
                return
            else:
                mutation_root = json_body
                path_prefix = ()

            for path, name, original_value in self._sensitive_json_values(
                mutation_root, extra_keys=step.source_parameters
            ):
                for value in JSON_MUTATION_VALUES:
                    if (
                        type(value) is type(original_value)
                        and value == original_value
                    ):
                        continue
                    changed_root = copy.deepcopy(mutation_root)
                    self._set_json_path(changed_root, path, value)
                    changed_payload = copy.deepcopy(json_body)
                    if is_graphql and variables_are_string:
                        changed_payload["variables"] = json.dumps(
                            changed_root,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    elif is_graphql:
                        self._set_json_path(
                            changed_payload,
                            path_prefix + path,
                            value,
                        )
                    else:
                        changed_payload = changed_root
                    mutated_body = json.dumps(
                        changed_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    strategy = (
                        VulnerabilityType.PRIVILEGE_FLAW
                        if self._is_privilege_key(name)
                        else VulnerabilityType.PARAMETER_MANIPULATION
                    )
                    full_path = path_prefix + path
                    path_text = self._format_json_path(full_path)
                    field_type = (
                        "GraphQL variable" if is_graphql else "JSON field"
                    )
                    mutation = (
                        f"{field_type} {path_text} ({name!r}): "
                        f"{original_value!r} -> {value!r}"
                    )
                    yield TestCase(
                        step=step,
                        strategy=strategy,
                        request=self._copy_request(
                            request,
                            body=mutated_body,
                        ),
                        description=f"Mutate {mutation}.",
                        mutation=mutation,
                    )

            for target_path, target in self._mass_assignment_targets(
                mutation_root
            ):
                present_names = {
                    self._normalize_key(str(name)) for name in target
                }
                for field_name, injected_value in HIGH_PRIVILEGE_ASSIGNMENTS:
                    if self._normalize_key(field_name) in present_names:
                        continue
                    changed_root = copy.deepcopy(mutation_root)
                    self._set_json_path(
                        changed_root,
                        target_path + (field_name,),
                        copy.deepcopy(injected_value),
                    )
                    changed_payload = copy.deepcopy(json_body)
                    if is_graphql and variables_are_string:
                        changed_payload["variables"] = json.dumps(
                            changed_root,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                    elif is_graphql:
                        changed_payload["variables"] = changed_root
                    else:
                        changed_payload = changed_root
                    mutated_body = json.dumps(
                        changed_payload,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )
                    full_path = path_prefix + target_path + (field_name,)
                    path_text = self._format_json_path(full_path)
                    mutation = (
                        f"mass-assignment injection -> {path_text}: "
                        f"{self._mutation_text(injected_value)}"
                    )
                    yield TestCase(
                        step=step,
                        strategy=VulnerabilityType.PRIVILEGE_FLAW,
                        request=self._copy_request(
                            request,
                            body=mutated_body,
                        ),
                        description=f"Test {mutation} in JSON data.",
                        mutation=mutation,
                    )
            yield from query_mass_cases
            return

        looks_form = "application/x-www-form-urlencoded" in content_type or (
            not content_type and "=" in body
        )
        if not looks_form:
            yield from query_mass_cases
            return
        pairs = parse_qsl(body, keep_blank_values=True)
        for parameter_index, (name, original_value) in enumerate(pairs):
            if not self._is_step_target_key(name, step):
                continue
            for value in QUERY_MUTATION_VALUES:
                if original_value == value:
                    continue
                changed_pairs = list(pairs)
                changed_pairs[parameter_index] = (name, value)
                mutated_body = urlencode(changed_pairs)
                strategy = (
                    VulnerabilityType.PRIVILEGE_FLAW
                    if self._is_privilege_key(name)
                    else VulnerabilityType.PARAMETER_MANIPULATION
                )
                mutation = (
                    f"form field {name!r}: {original_value!r} -> {value!r}"
                )
                yield TestCase(
                    step=step,
                    strategy=strategy,
                    request=self._copy_request(request, body=mutated_body),
                    description=f"Mutate {mutation}.",
                    mutation=mutation,
                )

        present_names = {self._normalize_key(name) for name, _ in pairs}
        for field_name, injected_value in HIGH_PRIVILEGE_ASSIGNMENTS:
            if self._normalize_key(field_name) in present_names:
                continue
            changed_pairs = list(pairs)
            changed_pairs.append(
                (field_name, self._mutation_text(injected_value))
            )
            mutated_body = urlencode(changed_pairs)
            mutation = (
                f"mass-assignment injection -> {field_name}: "
                f"{self._mutation_text(injected_value)}"
            )
            yield TestCase(
                step=step,
                strategy=VulnerabilityType.PRIVILEGE_FLAW,
                request=self._copy_request(request, body=mutated_body),
                description=f"Test {mutation} in form data.",
                mutation=mutation,
            )
        yield from query_mass_cases

    def _mass_assignment_query_mutations(
        self,
        step: WorkflowStep,
        query_pairs: Sequence[tuple[str, str]],
    ) -> Iterable[TestCase]:
        """Append absent privilege-bearing keys to captured request queries."""
        existing = {self._normalize_key(name) for name, _ in query_pairs}
        parts = urlsplit(step.request.url)
        for name, injected_value in HIGH_PRIVILEGE_ASSIGNMENTS:
            if self._normalize_key(name) in existing:
                continue
            changed_pairs = list(query_pairs)
            changed_pairs.append((name, self._mutation_text(injected_value)))
            mutated_url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(changed_pairs),
                    parts.fragment,
                )
            )
            mutation = (
                f"mass-assignment injection -> {name}: "
                f"{self._mutation_text(injected_value)}"
            )
            yield TestCase(
                step=step,
                strategy=VulnerabilityType.PRIVILEGE_FLAW,
                request=self._copy_request(step.request, url=mutated_url),
                description=f"Test {mutation} in query parameters.",
                mutation=mutation,
            )

    @staticmethod
    def _mutation_text(value: Any) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return str(value)

    @classmethod
    def _mass_assignment_targets(
        cls, value: Any
    ) -> list[tuple[tuple[str | int, ...], dict[str, Any]]]:
        """Return a bounded set of JSON objects eligible for added fields."""
        targets: list[tuple[tuple[str | int, ...], dict[str, Any]]] = []
        pending: list[tuple[tuple[str | int, ...], Any, int]] = [
            ((), value, 0)
        ]
        while pending and len(targets) < MAX_MASS_ASSIGNMENT_TARGETS:
            path, current, depth = pending.pop()
            if isinstance(current, dict):
                targets.append((path, current))
                if depth >= MAX_MASS_ASSIGNMENT_DEPTH:
                    continue
                children = [
                    (path + (str(key),), item, depth + 1)
                    for key, item in current.items()
                    if isinstance(item, (dict, list))
                ]
                pending.extend(reversed(children))
            elif (
                isinstance(current, list)
                and depth < MAX_MASS_ASSIGNMENT_DEPTH
            ):
                children = [
                    (path + (index,), item, depth + 1)
                    for index, item in enumerate(current)
                    if isinstance(item, (dict, list))
                ]
                pending.extend(reversed(children))
        return targets

    def _is_graphql_request(self, request: HTTPRequest, payload: Any) -> bool:
        content_type = self._header_value(
            request.headers, "content-type"
        ).casefold()
        path = urlsplit(request.url).path.casefold().rstrip("/")
        return (
            "graphql" in content_type
            or path.endswith("/graphql")
            or (
                isinstance(payload, dict)
                and isinstance(payload.get("query"), str)
                and "variables" in payload
            )
        )

    def _graphql_query_mutations(
        self, step: WorkflowStep
    ) -> Iterable[TestCase]:
        """Mutate nested variables JSON encoded in a GraphQL GET URL."""
        request = step.request
        parts = urlsplit(request.url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        is_graphql = parts.path.casefold().rstrip("/").endswith(
            "/graphql"
        ) or any(name.casefold() == "query" for name, _ in query_pairs)
        if not is_graphql:
            return

        for index, (name, raw_variables) in enumerate(query_pairs):
            if name.casefold() != "variables":
                continue
            try:
                variables = json.loads(raw_variables)
            except (json.JSONDecodeError, TypeError, RecursionError):
                continue
            if not isinstance(variables, (dict, list)):
                continue
            for (
                path,
                business_key,
                original_value,
            ) in self._sensitive_json_values(
                variables, extra_keys=step.source_parameters
            ):
                for value in JSON_MUTATION_VALUES:
                    if (
                        type(value) is type(original_value)
                        and value == original_value
                    ):
                        continue
                    changed_variables = copy.deepcopy(variables)
                    self._set_json_path(changed_variables, path, value)
                    changed_pairs = list(query_pairs)
                    changed_pairs[index] = (
                        name,
                        json.dumps(
                            changed_variables,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    )
                    mutated_url = urlunsplit(
                        (
                            parts.scheme,
                            parts.netloc,
                            parts.path,
                            urlencode(changed_pairs),
                            parts.fragment,
                        )
                    )
                    strategy = (
                        VulnerabilityType.PRIVILEGE_FLAW
                        if self._is_privilege_key(business_key)
                        else VulnerabilityType.PARAMETER_MANIPULATION
                    )
                    full_path = ("variables",) + path
                    mutation = (
                        "GraphQL variable "
                        f"{self._format_json_path(full_path)} "
                        f"({business_key!r}): "
                        f"{original_value!r} -> {value!r}"
                    )
                    yield TestCase(
                        step=step,
                        strategy=strategy,
                        request=self._copy_request(request, url=mutated_url),
                        description=f"Mutate {mutation}.",
                        mutation=mutation,
                    )

            for target_path, target in self._mass_assignment_targets(
                variables
            ):
                present_names = {
                    self._normalize_key(str(key)) for key in target
                }
                for (
                    field_name,
                    injected_value,
                ) in HIGH_PRIVILEGE_ASSIGNMENTS:
                    if self._normalize_key(field_name) in present_names:
                        continue
                    changed_variables = copy.deepcopy(variables)
                    self._set_json_path(
                        changed_variables,
                        target_path + (field_name,),
                        copy.deepcopy(injected_value),
                    )
                    changed_pairs = list(query_pairs)
                    changed_pairs[index] = (
                        name,
                        json.dumps(
                            changed_variables,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    )
                    mutated_url = urlunsplit(
                        (
                            parts.scheme,
                            parts.netloc,
                            parts.path,
                            urlencode(changed_pairs),
                            parts.fragment,
                        )
                    )
                    full_path = (
                        ("variables",) + target_path + (field_name,)
                    )
                    mutation = (
                        "mass-assignment injection -> "
                        f"{self._format_json_path(full_path)}: "
                        f"{self._mutation_text(injected_value)}"
                    )
                    yield TestCase(
                        step=step,
                        strategy=VulnerabilityType.PRIVILEGE_FLAW,
                        request=self._copy_request(
                            request, url=mutated_url
                        ),
                        description=(
                            f"Test {mutation} in GraphQL variables."
                        ),
                        mutation=mutation,
                    )

    def _without_prior_session_state(
        self, request: HTTPRequest
    ) -> HTTPRequest:
        headers = {
            name: value
            for name, value in request.headers.items()
            if name.casefold() not in COOKIE_HEADER_NAMES
            and not self._is_session_header(name)
        }
        url = self._remove_session_query_parameters(request.url)
        body = request.body
        content_type = self._header_value(headers, "content-type").casefold()
        if body:
            if "json" in content_type or body.lstrip().startswith(("{", "[")):
                try:
                    payload = json.loads(body)
                except (json.JSONDecodeError, TypeError):
                    payload = None
                if payload is not None:
                    cleaned = self._remove_session_json_fields(payload)
                    body = json.dumps(
                        cleaned, ensure_ascii=False, separators=(",", ":")
                    )
            elif (
                "application/x-www-form-urlencoded" in content_type
                or "=" in body
            ):
                pairs = parse_qsl(body, keep_blank_values=True)
                filtered = [
                    (name, value)
                    for name, value in pairs
                    if not self._is_session_parameter(name)
                ]
                body = urlencode(filtered)
        return self._copy_request(request, url=url, headers=headers, body=body)

    @staticmethod
    def _remove_session_query_parameters(url: str) -> str:
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        filtered = [
            (name, value)
            for name, value in pairs
            if not LogicEngine._is_session_parameter(name)
        ]
        if len(filtered) == len(pairs):
            return url
        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urlencode(filtered),
                parts.fragment,
            )
        )

    @classmethod
    def _remove_session_json_fields(cls, value: Any, depth: int = 0) -> Any:
        if depth >= 128:
            return value
        if isinstance(value, dict):
            return {
                key: cls._remove_session_json_fields(item, depth + 1)
                for key, item in value.items()
                if not cls._is_session_parameter(str(key))
            }
        if isinstance(value, list):
            return [
                cls._remove_session_json_fields(item, depth + 1)
                for item in value
            ]
        return value

    @staticmethod
    def _sensitive_json_values(
        value: Any,
        path: tuple[str | int, ...] = (),
        depth: int = 0,
        extra_keys: Sequence[str] = (),
    ) -> Iterable[tuple[tuple[str | int, ...], str, Any]]:
        if depth >= 128:
            return
        normalized_extra = {
            LogicEngine._normalize_key(name) for name in extra_keys
        }
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key)
                next_path = path + (key_text,)
                if (
                    LogicEngine._is_business_key(key_text)
                    or LogicEngine._normalize_key(key_text) in normalized_extra
                ):
                    yield next_path, key_text, item
                yield from LogicEngine._sensitive_json_values(
                    item, next_path, depth + 1, extra_keys
                )
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from LogicEngine._sensitive_json_values(
                    item, path + (index,), depth + 1, extra_keys
                )

    @staticmethod
    def _set_json_path(
        value: Any, path: tuple[str | int, ...], replacement: Any
    ) -> None:
        cursor = value
        for component in path[:-1]:
            cursor = cursor[component]
        cursor[path[-1]] = replacement

    @staticmethod
    def _format_json_path(path: tuple[str | int, ...]) -> str:
        result = "$"
        for component in path:
            if isinstance(component, int):
                result += f"[{component}]"
            else:
                result += f".{component}"
        return result

    @staticmethod
    def _normalize_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.casefold())

    @classmethod
    def _is_business_key(cls, key: str) -> bool:
        return cls._normalize_key(key) in BUSINESS_KEYS

    @classmethod
    def _is_step_target_key(cls, key: str, step: WorkflowStep) -> bool:
        source_keys = {
            cls._normalize_key(name) for name in step.source_parameters
        }
        return (
            cls._is_business_key(key) or cls._normalize_key(key) in source_keys
        )

    @classmethod
    def _is_privilege_key(cls, key: str) -> bool:
        return cls._normalize_key(key) in PRIVILEGE_KEYS

    @classmethod
    def _is_session_parameter(cls, key: str) -> bool:
        normalized = cls._normalize_key(key)
        return normalized in SESSION_PARAMETER_KEYS or "session" in normalized

    @classmethod
    def _is_session_header(cls, name: str) -> bool:
        normalized = cls._normalize_key(name)
        return "session" in normalized

    @staticmethod
    def _header_value(headers: Mapping[str, str], name: str) -> str:
        for header_name, value in headers.items():
            if header_name.casefold() == name.casefold():
                return value
        return ""

    @staticmethod
    def _copy_request(
        request: HTTPRequest,
        *,
        url: str | None = None,
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
    ) -> HTTPRequest:
        return HTTPRequest(
            method=request.method,
            url=url if url is not None else request.url,
            headers=(
                dict(headers) if headers is not None else dict(request.headers)
            ),
            body=body if body is not None else request.body,
        )

    async def _run_work_item(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        race_pool_lock: asyncio.Lock,
        item: TestWorkItem,
    ) -> ScanResult | None:
        if isinstance(item, RaceTestGroup):
            async with race_pool_lock:
                return await self._run_race_group(item)
        if isinstance(item, SequentialReplayGroup):
            return await self._run_sequential_replay_group(session, item)
        return await self._run_case(session, semaphore, item)

    async def _run_case(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        case: TestCase,
    ) -> ScanResult | None:
        async with semaphore:
            try:
                await self._wait_for_rate_limit()
                effective_request, attack_response = await self._send_request(
                    session,
                    case.request,
                    case.step.index,
                    apply_state=case.apply_state,
                    update_state=case.apply_state,
                )
            except (
                aiohttp.ClientError,
                asyncio.TimeoutError,
                OSError,
                ValueError,
            ) as exc:
                location = self._safe_location(case.request.url)
                self.execution_errors.append(
                    f"Step {case.step.index} {case.request.method} "
                    f"{location}: {type(exc).__name__}"
                )
                return None
            except Exception as exc:
                location = self._safe_location(case.request.url)
                self.execution_errors.append(
                    f"Step {case.step.index} {case.request.method} "
                    f"{location}: unexpected {type(exc).__name__}"
                )
                return None

        effective_case = TestCase(
            step=case.step,
            strategy=case.strategy,
            request=effective_request,
            description=case.description,
            mutation=case.mutation,
            apply_state=case.apply_state,
        )
        finding = self._analyze(effective_case, attack_response)
        if finding is not None and finding.severity in {
            "Medium",
            "High",
            "Critical",
        }:
            try:
                loop = asyncio.get_running_loop()
                is_vulnerable, reasoning = await loop.run_in_executor(
                    None,
                    self._internal_ai_triage,
                    "DAST",
                    finding.strategy.value,
                    case.mutation,
                    finding.baseline_status,
                    finding.baseline_response_body,
                    finding.attack_status,
                    finding.attack_response_body,
                    "N/A",
                    "N/A",
                    "N/A",
                )
            except Exception as exc:
                is_vulnerable = True
                reasoning = (
                    "AI triage executor failed open; heuristic finding "
                    f"retained ({type(exc).__name__})."
                )
            if not is_vulnerable:
                finding = finding.model_copy(
                    update={
                        "severity": "Info",
                        "description": (
                            finding.description
                            + " [Serverless AI Triage: Suppressed False "
                            f"Positive - {reasoning}]"
                        ),
                    }
                )
        return finding

    async def _run_sequential_replay_group(
        self,
        session: aiohttp.ClientSession,
        group: SequentialReplayGroup,
    ) -> ScanResult | None:
        """Send two identical requests serially and assess acceptance."""
        prepared_request = self.state_tracker.apply(
            group.request, group.step.index
        )
        responses: list[HTTPResponse] = []
        for attempt in range(2):
            try:
                await self._wait_for_rate_limit()
                _, response = await self._send_request(
                    session,
                    prepared_request,
                    group.step.index,
                    apply_state=False,
                    update_state=True,
                )
                responses.append(response)
            except Exception as exc:
                location = self._safe_location(prepared_request.url)
                self.execution_errors.append(
                    f"Sequential replay step {group.step.index}, "
                    f"request {attempt + 1}/2 {location}: "
                    f"{type(exc).__name__}"
                )
                break
        if len(responses) != 2:
            return None
        finding = self._analyze_sequential_replay(
            group, prepared_request, responses
        )
        if finding is None or finding.severity not in {
            "Medium",
            "High",
            "Critical",
        }:
            return finding

        first_response, second_response = responses
        body_similarity = (
            "N/A"
            if finding.body_similarity is None
            else f"{finding.body_similarity:.3f}"
        )
        length_similarity = (
            "N/A"
            if finding.length_similarity is None
            else f"{finding.length_similarity:.3f}"
        )
        replay_context = (
            f"{group.mutation}; identical requests were replayed "
            "sequentially; "
            f"first status={first_response.status_code}, "
            f"second status={second_response.status_code}; "
            f"body similarity={body_similarity}; "
            f"length similarity={length_similarity}"
        )
        try:
            loop = asyncio.get_running_loop()
            is_vulnerable, reasoning = await loop.run_in_executor(
                None,
                self._internal_ai_triage,
                "DAST",
                f"{finding.strategy.value} sequential replay",
                replay_context,
                first_response.status_code,
                first_response.body,
                second_response.status_code,
                second_response.body,
                "N/A",
                "N/A",
                "N/A",
            )
        except Exception as exc:
            is_vulnerable = True
            reasoning = (
                "AI triage executor failed open; heuristic finding "
                f"retained ({type(exc).__name__})."
            )
        if not is_vulnerable:
            finding = finding.model_copy(
                update={
                    "severity": "Info",
                    "description": (
                        finding.description
                        + " [Serverless AI Triage: Suppressed False "
                        f"Positive - {reasoning}]"
                    ),
                }
            )
        return finding

    def _analyze_sequential_replay(
        self,
        group: SequentialReplayGroup,
        request: HTTPRequest,
        responses: Sequence[HTTPResponse],
    ) -> ScanResult | None:
        if len(responses) != 2:
            return None
        first_response, second_response = responses
        if not all(
            200 <= response.status_code < 300 for response in responses
        ):
            return None
        body_similarity, length_similarity = self._response_similarities(
            first_response, second_response
        )
        evidence = (
            "The same transaction request was sent twice sequentially; "
            f"responses returned HTTP {first_response.status_code} and "
            f"{second_response.status_code}. Both were successful, so check "
            "whether the operation was duplicated or lacks idempotency "
            "protection."
        )
        baseline = group.step.baseline_response or first_response
        baseline_request = group.step.request
        return ScanResult(
            step_index=group.step.index,
            strategy=VulnerabilityType.RACE_CONDITION,
            description=group.description,
            severity="Medium",
            baseline_status=baseline.status_code,
            attack_status=second_response.status_code,
            evidence=evidence,
            request_method=request.method,
            request_url=request.url,
            request_headers=dict(request.headers),
            request_body=request.body,
            baseline_request_url=baseline_request.url,
            baseline_request_headers=dict(baseline_request.headers),
            baseline_request_body=baseline_request.body,
            mutation=group.mutation,
            baseline_response_headers=dict(baseline.headers),
            baseline_response_body=baseline.body,
            baseline_content_length=baseline.content_length,
            attack_response_headers=dict(second_response.headers),
            attack_response_body=second_response.body,
            attack_content_length=second_response.content_length,
            sequential_responses=list(responses),
            replay_mode="sequential",
            source_route=group.step.source_route,
            has_har_baseline=group.step.has_baseline,
            confidence_score=0.9 if group.step.has_baseline else 0.65,
            body_similarity=body_similarity,
            length_similarity=length_similarity,
        )

    async def _run_race_group(self, group: RaceTestGroup) -> ScanResult | None:
        """Release a bounded pool of transaction requests together."""
        request_count = len(group.requests)
        if request_count < 2:
            return None

        # Freeze one fresh token snapshot so every racing request is identical.
        prepared_request = self.state_tracker.apply(
            group.requests[0], group.step.index
        )
        release = asyncio.Event()
        ready_count = 0
        timeout = ClientTimeout(total=self.timeout_seconds)
        connector = TCPConnector(limit=request_count, force_close=True)
        responses: list[HTTPResponse] = []

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            cookie_jar=DummyCookieJar(),
            trust_env=False,
            raise_for_status=False,
        ) as race_session:

            async def send_at_barrier() -> Union[HTTPResponse, BaseException]:
                nonlocal ready_count
                ready_count += 1
                if ready_count == request_count:
                    release.set()
                await release.wait()
                try:
                    _, response = await self._send_request(
                        race_session,
                        prepared_request,
                        group.step.index,
                        apply_state=False,
                        update_state=True,
                    )
                    return response
                except Exception as exc:
                    return exc

            tasks = [
                asyncio.create_task(send_at_barrier())
                for _ in range(request_count)
            ]
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)

        for index, outcome in enumerate(outcomes):
            if isinstance(outcome, HTTPResponse):
                responses.append(outcome)
                continue
            error = outcome if isinstance(outcome, BaseException) else None
            error_name = (
                type(error).__name__ if error is not None else "UnknownError"
            )
            location = self._safe_location(prepared_request.url)
            self.execution_errors.append(
                f"Race step {group.step.index}, request "
                f"{index + 1}/{request_count} "
                f"{location}: {error_name}"
            )

        return self._analyze_race_group(group, prepared_request, responses)

    def _analyze_race_group(
        self,
        group: RaceTestGroup,
        request: HTTPRequest,
        responses: Sequence[HTTPResponse],
    ) -> ScanResult | None:
        successful = [
            (index, response)
            for index, response in enumerate(responses)
            if 200 <= response.status_code < 300
        ]
        matching_pair: Optional[
            tuple[
                tuple[int, HTTPResponse],
                tuple[int, HTTPResponse],
                Optional[float],
                Optional[float],
            ]
        ] = None
        for first_index, first_response in enumerate(successful):
            for second in successful[first_index + 1 :]:
                body_similarity, length_similarity = (
                    self._response_similarities(first_response[1], second[1])
                )
                structurally_equal = (
                    body_similarity is not None
                    and body_similarity >= self.BODY_SIMILARITY_THRESHOLD
                ) or (
                    length_similarity is not None
                    and length_similarity >= self.LENGTH_SIMILARITY_THRESHOLD
                )
                if structurally_equal:
                    matching_pair = (
                        first_response,
                        second,
                        body_similarity,
                        length_similarity,
                    )
                    break
            if matching_pair is not None:
                break

        if matching_pair is None:
            return None
        first, second, body_similarity, length_similarity = matching_pair
        sample = first[1]
        similarity_evidence = (
            f"body structure/text similarity={body_similarity:.3f}"
            if body_similarity is not None
            else "body structure/text similarity unavailable"
        )
        length_evidence = (
            f"body-length similarity={length_similarity:.3f}"
            if length_similarity is not None
            else "body-length similarity unavailable"
        )
        description = (
            f"At least two of {len(group.requests)} synchronized requests "
            "returned successful, structurally matching responses. Review the "
            "transaction state for duplicate application or withdrawal."
        )
        evidence = (
            f"Successful responses: {len(successful)}/{len(group.requests)}; "
            f"matching response indexes: {first[0]} and {second[0]}; "
            f"statuses: {first[1].status_code}/{second[1].status_code}; "
            f"{similarity_evidence}; {length_evidence}. "
            "concurrent_responses are in request order; failed sends are "
            "listed in replay_errors."
        )
        baseline = group.step.baseline_response or sample
        return ScanResult(
            step_index=group.step.index,
            strategy=VulnerabilityType.RACE_CONDITION,
            description=description,
            severity="Critical",
            baseline_status=baseline.status_code,
            attack_status=sample.status_code,
            evidence=evidence,
            request_method=request.method,
            request_url=request.url,
            request_headers=dict(request.headers),
            request_body=request.body,
            baseline_request_url=group.step.request.url,
            baseline_request_headers=dict(group.step.request.headers),
            baseline_request_body=group.step.request.body,
            mutation=group.mutation,
            baseline_response_headers=dict(baseline.headers),
            baseline_response_body=baseline.body,
            baseline_content_length=baseline.content_length,
            attack_response_headers=dict(sample.headers),
            attack_response_body=sample.body,
            attack_content_length=sample.content_length,
            concurrent_responses=list(responses),
            replay_mode="synchronized",
            concurrent_request_count=len(group.requests),
            concurrent_success_count=len(successful),
            source_route=group.step.source_route,
            has_har_baseline=group.step.has_baseline,
            confidence_score=0.9 if group.step.has_baseline else 0.65,
            body_similarity=body_similarity,
            length_similarity=length_similarity,
        )

    async def _send_request(
        self,
        session: aiohttp.ClientSession,
        request: HTTPRequest,
        step_index: int,
        *,
        apply_state: bool = True,
        update_state: bool = True,
    ) -> tuple[HTTPRequest, HTTPResponse]:
        effective_request = (
            self.state_tracker.apply(request, step_index)
            if apply_state
            else request
        )
        headers = {
            name: value
            for name, value in effective_request.headers.items()
            if name.casefold() not in HOP_BY_HOP_HEADERS
        }
        data = (
            effective_request.body.encode("utf-8")
            if effective_request.body is not None
            else None
        )
        async with session.request(
            method=effective_request.method,
            url=effective_request.url,
            headers=headers,
            data=data,
            allow_redirects=False,
        ) as response:
            raw_body = await response.content.read(self.max_response_bytes + 1)
            truncated = len(raw_body) > self.max_response_bytes
            if truncated:
                raw_body = raw_body[: self.max_response_bytes]
            charset = response.charset or "utf-8"
            try:
                body = raw_body.decode(charset, errors="replace")
            except LookupError:
                body = raw_body.decode("utf-8", errors="replace")
            if truncated:
                body += "\n...[LogicSentry AI truncated replay response body]"

            try:
                content_length = int(
                    response.headers.get("Content-Length", "")
                )
                if content_length < 0:
                    content_length = len(raw_body)
            except (TypeError, ValueError):
                content_length = len(raw_body)
            attack_response = HTTPResponse(
                status_code=response.status,
                headers={
                    str(key): str(value)
                    for key, value in response.headers.items()
                },
                body=body,
                content_length=content_length,
            )
        if update_state:
            self.state_tracker.observe(step_index, attack_response)
        return effective_request, attack_response

    def _analyze(
        self, case: TestCase, attack: HTTPResponse
    ) -> ScanResult | None:
        baseline = case.step.baseline_response
        baseline_rejected = (
            400 <= baseline.status_code <= 599 and attack.status_code == 200
        )
        body_similarity, length_similarity = self._response_similarities(
            baseline, attack
        )
        successful_baseline = 200 <= baseline.status_code < 300
        successful_attack = 200 <= attack.status_code < 300
        structural_match = (
            successful_baseline
            and successful_attack
            and (
                (
                    body_similarity is not None
                    and body_similarity >= self.BODY_SIMILARITY_THRESHOLD
                )
                or (
                    length_similarity is not None
                    and length_similarity >= self.LENGTH_SIMILARITY_THRESHOLD
                )
            )
        )

        if not case.step.has_baseline:
            if not successful_attack:
                return None
            signal = (
                "source-discovered route accepted a successful request; "
                "no HAR baseline is available"
            )
            description = (
                f"{case.description} The SAST-discovered route returned a "
                "successful response, but no captured HAR baseline exists; "
                "treat this as a triage candidate and verify authorization, "
                "validation, and resulting state."
            )
            severity = (
                "Info"
                if case.mutation
                == "source-discovered route reachability probe"
                else (
                    "High"
                    if case.strategy == VulnerabilityType.PRIVILEGE_FLAW
                    else "Medium"
                )
            )
        elif case.strategy == VulnerabilityType.PRIVILEGE_ESCALATION_BOLA:
            if not structural_match:
                return None
            signal = (
                "User B received a successful response matching User A's "
                "captured transaction structure"
            )
            description = (
                f"{case.description} User B's response matched User A's "
                "successful baseline structure; verify object ownership and "
                "authorization at the server."
            )
            severity = "High"
        elif baseline_rejected:
            signal = (
                f"captured HTTP {baseline.status_code} rejection changed "
                "to HTTP 200"
            )
            description = (
                f"{case.description} The captured "
                f"{baseline.status_code} response became HTTP 200 after "
                "this input change."
            )
            severity = "High"
        elif structural_match:
            signal = (
                "mutated response matches the successful baseline structure"
            )
            similarity_text = (
                f"body structure/text similarity={body_similarity:.3f}"
                if body_similarity is not None
                else "body structure/text similarity unavailable"
            )
            length_text = (
                f"body-length similarity={length_similarity:.3f}"
                if length_similarity is not None
                else "body-length similarity unavailable"
            )
            description = (
                f"{case.description} The successful response retained "
                f"the captured structure ({similarity_text}; {length_text}); "
                "verify server-side business-rule enforcement and state."
            )
            severity = (
                "High"
                if case.strategy
                in {
                    VulnerabilityType.PRIVILEGE_FLAW,
                    VulnerabilityType.STEP_SKIPPING,
                }
                else "Medium"
            )
        else:
            return None

        evidence = (
            f"Signal: {signal}. Mutation: {case.mutation} "
            f"Baseline status/body length: {baseline.status_code}/"
            f"{baseline.content_length}; attack status/body length: "
            f"{attack.status_code}/{attack.content_length}. "
            f"Body similarity={body_similarity}; "
            f"length similarity={length_similarity}."
        )
        return ScanResult(
            step_index=case.step.index,
            strategy=case.strategy,
            description=description,
            severity=severity,
            baseline_status=baseline.status_code,
            attack_status=attack.status_code,
            evidence=evidence,
            request_method=case.request.method,
            request_url=case.request.url,
            request_headers=dict(case.request.headers),
            request_body=case.request.body,
            baseline_request_url=case.step.request.url,
            baseline_request_headers=dict(case.step.request.headers),
            baseline_request_body=case.step.request.body,
            mutation=case.mutation,
            baseline_response_headers=dict(baseline.headers),
            baseline_response_body=baseline.body,
            baseline_content_length=baseline.content_length,
            attack_response_headers=dict(attack.headers),
            attack_response_body=attack.body,
            attack_content_length=attack.content_length,
            source_route=case.step.source_route,
            has_har_baseline=case.step.has_baseline,
            confidence_score=0.95 if case.step.has_baseline else 0.7,
            body_similarity=body_similarity,
            length_similarity=length_similarity,
        )

    def _response_similarities(
        self, baseline: HTTPResponse, attack: HTTPResponse
    ) -> tuple[Optional[float], Optional[float]]:
        baseline_length = baseline.content_length or len(
            baseline.body.encode("utf-8", errors="replace")
        )
        attack_length = attack.content_length or len(
            attack.body.encode("utf-8", errors="replace")
        )
        length_similarity: Optional[float] = None
        if baseline_length > 0 and attack_length > 0:
            length_similarity = min(baseline_length, attack_length) / max(
                baseline_length, attack_length
            )

        body_similarity: Optional[float] = None
        if self._looks_like_html(baseline) and self._looks_like_html(attack):
            baseline_text = self._visible_html_text(baseline.body)
            attack_text = self._visible_html_text(attack.body)
            if baseline_text and attack_text:
                body_similarity = difflib.SequenceMatcher(
                    None,
                    baseline_text[: self.MAX_COMPARISON_CHARS],
                    attack_text[: self.MAX_COMPARISON_CHARS],
                    autojunk=True,
                ).ratio()
        elif self._looks_like_json(baseline) and self._looks_like_json(attack):
            try:
                baseline_json = json.loads(baseline.body)
                attack_json = json.loads(attack.body)
                baseline_shape = json.dumps(
                    self._json_shape(baseline_json),
                    sort_keys=True,
                    separators=(",", ":"),
                )[: self.MAX_COMPARISON_CHARS]
                attack_shape = json.dumps(
                    self._json_shape(attack_json),
                    sort_keys=True,
                    separators=(",", ":"),
                )[: self.MAX_COMPARISON_CHARS]
                body_similarity = difflib.SequenceMatcher(
                    None, baseline_shape, attack_shape, autojunk=True
                ).ratio()
            except (json.JSONDecodeError, TypeError, RecursionError):
                body_similarity = None
        return body_similarity, length_similarity

    @classmethod
    def _json_shape(cls, value: Any, depth: int = 0) -> Any:
        """Return a bounded JSON shape with scalar values removed."""
        if depth >= 64:
            return "<deep>"
        if isinstance(value, dict):
            return {
                str(key): cls._json_shape(item, depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._json_shape(item, depth + 1) for item in value]
        if isinstance(value, bool):
            return "<boolean>"
        if isinstance(value, (int, float)):
            return "<number>"
        if isinstance(value, str):
            return "<string>"
        if value is None:
            return "<null>"
        return "<value>"

    @staticmethod
    def _looks_like_json(response: HTTPResponse) -> bool:
        content_type = LogicEngine._header_value(
            response.headers, "content-type"
        ).casefold()
        if "json" in content_type:
            return True
        return response.body.lstrip().startswith(("{", "["))

    @staticmethod
    def _looks_like_html(response: HTTPResponse) -> bool:
        content_type = LogicEngine._header_value(
            response.headers, "content-type"
        )
        if "html" in content_type.casefold():
            return True
        sample = response.body[:2048].casefold()
        return "<html" in sample or "<!doctype html" in sample

    @staticmethod
    def _visible_html_text(body: str) -> str:
        parser = _VisibleTextParser()
        try:
            parser.feed(body)
            parser.close()
        except Exception:
            return " ".join(body.split()).casefold()
        return " ".join(" ".join(parser.parts).split()).casefold()

    @staticmethod
    def _safe_location(url: str) -> str:
        try:
            parts = urlsplit(url)
            return f"{parts.hostname or 'unknown'}{parts.path or '/'}"
        except ValueError:
            return "unknown endpoint"


# ============================================================================
# Grey-box synergy and CLI assets
# ============================================================================
BANNER = r"""
============================================================
                      LogicSentry AI
============================================================
"""


class GreyBoxBridge:
    """Correlate source-declared routes/fields with HAR coverage.

    Matched routes receive source-only parameter and path-ID variations using
    their real HAR response as the baseline. Uncaptured route/method pairs use
    the HAR origin and session headers but have no trusted baseline; the DAST
    engine labels successful replies as triage candidates, not confirmations.
    """

    MAX_SOURCE_STEPS = 250

    @staticmethod
    def _normalize_key(name: str) -> str:
        return re.sub(r"[^a-z0-9]", "", name.casefold())

    @classmethod
    def _is_fuzzable(cls, name: str) -> bool:
        normalized = cls._normalize_key(name)
        if not normalized:
            return False
        return normalized not in {
            "self",
            "cls",
            "request",
            "response",
            "req",
            "res",
            "db",
            "session",
            "currentuser",
            "user",
            "args",
            "kwargs",
            "context",
            "ctx",
        }

    @classmethod
    def _route_regex(
        cls, route_path: str
    ) -> tuple[re.Pattern[str], list[tuple[str, str]]]:
        path = route_path if route_path.startswith("/") else "/" + route_path
        pieces: list[str] = []
        groups: list[tuple[str, str]] = []
        cursor = 0
        for index, match in enumerate(
            SASTScanner.ROUTE_PARAMETER_RE.finditer(path)
        ):
            pieces.append(re.escape(path[cursor : match.start()]))
            name = next(
                (value for value in match.groups() if value), f"param{index}"
            )
            group_name = f"p{index}"
            wildcard = match.group(0).casefold().startswith("<path:")
            pieces.append(f"(?P<{group_name}>{'.+' if wildcard else '[^/]+'})")
            groups.append((name, group_name))
            cursor = match.end()
        pieces.append(re.escape(path[cursor:].rstrip("/")))
        expression = "^" + "".join(pieces) + r"/?$"
        return re.compile(expression), groups

    @classmethod
    def _route_specificity(
        cls, route_path: str
    ) -> tuple[int, int, int, int, int]:
        """Rank literal structure above parameter and catch-all routes."""
        path = route_path if route_path.startswith("/") else "/" + route_path
        segments = [
            segment
            for segment in path.strip("/").split("/")
            if segment
        ]
        literal_segments = 0
        literal_characters = 0
        parameter_count = 0
        wildcard_count = 0
        for segment in segments:
            parameters = list(SASTScanner.ROUTE_PARAMETER_RE.finditer(segment))
            parameter_count += len(parameters)
            if not parameters:
                literal_segments += 1
                literal_characters += len(segment)
                continue
            literal_characters += len(
                SASTScanner.ROUTE_PARAMETER_RE.sub("", segment)
            )
            wildcard_count += sum(
                match.group(0).casefold().startswith("<path:")
                for match in parameters
            )
        return (
            literal_segments,
            -wildcard_count,
            -parameter_count,
            literal_characters,
            len(segments),
        )

    @classmethod
    def _match_path(
        cls, route_path: str, actual_path: str
    ) -> Optional[dict[str, str]]:
        pattern, groups = cls._route_regex(route_path)
        match = pattern.fullmatch(actual_path or "/")
        if match is None:
            return None
        return {name: match.group(group) for name, group in groups}

    @classmethod
    def build_source_steps(
        cls,
        routes: Sequence[SourceRoute],
        workflow: Sequence[WorkflowStep],
    ) -> list[WorkflowStep]:
        """Build bounded DAST steps from source-only route knowledge."""
        if not routes or not workflow:
            return []
        origin = urlsplit(workflow[0].request.url)
        if not origin.scheme or not origin.netloc:
            return []
        next_index = max(step.index for step in workflow) + 1
        output: list[WorkflowStep] = []
        seen: set[tuple[str, str, int]] = set()

        # Resolve each captured request to only its most structurally specific
        # source route. A catch-all therefore cannot also claim traffic already
        # explained by a literal or narrower parameterized route.
        route_matches: dict[
            tuple[str, str], list[tuple[WorkflowStep, dict[str, str]]]
        ] = {}
        route_observed_pairs: set[tuple[str, str]] = set()
        for step in workflow:
            method = step.request.method.upper()
            candidates: list[
                tuple[
                    SourceRoute,
                    dict[str, str],
                    tuple[int, int, int, int, int],
                ]
            ] = []
            for candidate in routes:
                if method not in {item.upper() for item in candidate.methods}:
                    continue
                captures = cls._match_path(
                    candidate.path, urlsplit(step.request.url).path
                )
                if captures is not None:
                    route_observed_pairs.add((candidate.path, method))
                    candidates.append(
                        (
                            candidate,
                            captures,
                            cls._route_specificity(candidate.path),
                        )
                    )
            if not candidates:
                continue
            best_specificity = max(item[2] for item in candidates)
            for candidate, captures, specificity in candidates:
                if specificity == best_specificity:
                    route_matches.setdefault(
                        (candidate.path, method), []
                    ).append((step, captures))

        for route in routes:
            if len(output) >= cls.MAX_SOURCE_STEPS:
                break
            for method in route.methods:
                if len(output) >= cls.MAX_SOURCE_STEPS:
                    break
                method = method.upper()
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                matched = route_matches.get((route.path, method), [])

                fuzzable = [
                    name for name in route.parameters if cls._is_fuzzable(name)
                ]
                if matched:
                    baseline_step, path_parameters = max(
                        matched, key=lambda pair: pair[0].index
                    )
                    signature = (route.path, method, baseline_step.index)
                    if signature in seen:
                        continue
                    seen.add(signature)
                    observed = cls._request_parameter_names(
                        baseline_step.request
                    )
                    path_names = {
                        cls._normalize_key(name) for name in path_parameters
                    }
                    missing = [
                        name
                        for name in fuzzable
                        if cls._normalize_key(name) not in observed
                        and cls._normalize_key(name) not in path_names
                    ]
                    # Source-known non-business fields already present in
                    # JSON/form data still deserve dedicated variants; the
                    # ordinary HAR mutator only covers its business-key set.
                    observed_source_fields = [
                        name
                        for name in fuzzable
                        if cls._normalize_key(name) in observed
                        and cls._normalize_key(name) not in path_names
                        and not LogicEngine._is_business_key(name)
                    ]
                    source_parameters = list(
                        dict.fromkeys(
                            missing
                            + list(path_parameters)
                            + observed_source_fields
                        )
                    )
                    if not source_parameters:
                        continue
                    request = cls._add_parameters(
                        baseline_step.request, missing
                    )
                    output.append(
                        WorkflowStep(
                            index=next_index,
                            request=request,
                            baseline_response=baseline_step.baseline_response,
                            has_baseline=True,
                            source_route=route.path,
                            source_parameters=source_parameters,
                            source_path_parameters=path_parameters,
                        )
                    )
                    next_index += 1
                    continue

                if (route.path, method) in route_observed_pairs:
                    # This broad route matched HAR traffic, but a more
                    # specific source route owns that request association.
                    continue

                # No HAR pair exercised this route/method. Construct one
                # in-scope request from the first captured origin/session.
                signature = (route.path, method, -1)
                if signature in seen:
                    continue
                seen.add(signature)
                resolved_path, path_parameters = cls._resolve_path(route.path)
                path_names = {
                    cls._normalize_key(name) for name in path_parameters
                }
                body_or_query_parameters = [
                    name
                    for name in fuzzable
                    if cls._normalize_key(name) not in path_names
                ]
                request = cls._new_request(
                    workflow[0].request,
                    method,
                    resolved_path,
                    body_or_query_parameters,
                )
                placeholder = HTTPResponse(
                    status_code=404,
                    headers={},
                    body=(
                        "No HAR baseline exists for this "
                        "source-discovered route."
                    ),
                    content_length=0,
                )
                output.append(
                    WorkflowStep(
                        index=next_index,
                        request=request,
                        baseline_response=placeholder,
                        has_baseline=False,
                        source_route=route.path,
                        source_parameters=list(
                            dict.fromkeys(fuzzable + list(path_parameters))
                        ),
                        source_path_parameters=path_parameters,
                    )
                )
                next_index += 1
        return output

    @classmethod
    def _request_parameter_names(cls, request: HTTPRequest) -> set[str]:
        names = {
            cls._normalize_key(name)
            for name, _ in parse_qsl(
                urlsplit(request.url).query, keep_blank_values=True
            )
        }
        if not request.body:
            return names
        content_type = LogicEngine._header_value(
            request.headers, "content-type"
        ).casefold()
        if "json" in content_type or request.body.lstrip().startswith(
            ("{", "[")
        ):
            try:
                payload = json.loads(request.body)
            except (json.JSONDecodeError, TypeError, RecursionError):
                return names

            def walk(value: Any, depth: int = 0) -> None:
                if depth >= 64:
                    return
                if isinstance(value, dict):
                    for key, item in value.items():
                        names.add(cls._normalize_key(str(key)))
                        walk(item, depth + 1)
                elif isinstance(value, list):
                    for item in value:
                        walk(item, depth + 1)

            walk(payload)
        else:
            names.update(
                cls._normalize_key(name)
                for name, _ in parse_qsl(request.body, keep_blank_values=True)
            )
        return names

    @staticmethod
    def _default_value(name: str) -> str:
        normalized = GreyBoxBridge._normalize_key(name)
        if normalized in {"price", "amount", "total"}:
            return "100"
        if normalized == "discount":
            return "10"
        if normalized == "quantity":
            return "1"
        if normalized == "role":
            return "user"
        if normalized == "isadmin":
            return "false"
        return "1"

    @classmethod
    def _add_parameters(
        cls, request: HTTPRequest, names: Sequence[str]
    ) -> HTTPRequest:
        if not names:
            return request
        content_type = LogicEngine._header_value(
            request.headers, "content-type"
        ).casefold()
        headers = dict(request.headers)
        if request.method in {"GET", "HEAD"}:
            parts = urlsplit(request.url)
            pairs = parse_qsl(parts.query, keep_blank_values=True)
            present = {cls._normalize_key(name) for name, _ in pairs}
            for name in names:
                if cls._normalize_key(name) not in present:
                    pairs.append((name, cls._default_value(name)))
            url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(pairs),
                    parts.fragment,
                )
            )
            return request.model_copy(update={"url": url})

        body = request.body or ""
        if "json" in content_type or body.lstrip().startswith(("{", "[")):
            try:
                payload = json.loads(body) if body else {}
            except (json.JSONDecodeError, TypeError, RecursionError):
                payload = {}
            if isinstance(payload, dict) and "variables" in payload:
                variables = payload.get("variables")
                variables_as_string = isinstance(variables, str)
                if variables_as_string:
                    try:
                        variables = json.loads(variables)
                    except (json.JSONDecodeError, TypeError, RecursionError):
                        variables = {}
                if isinstance(variables, dict):
                    cls._insert_fields(variables, names)
                    payload["variables"] = (
                        json.dumps(variables, ensure_ascii=False)
                        if variables_as_string
                        else variables
                    )
                else:
                    cls._insert_fields(payload, names)
            elif isinstance(payload, dict):
                cls._insert_fields(payload, names)
            else:
                payload = {name: cls._default_value(name) for name in names}
            body = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            )
            cls._set_header(headers, "Content-Type", "application/json")
        elif (
            "application/x-www-form-urlencoded" in content_type or "=" in body
        ):
            pairs = parse_qsl(body, keep_blank_values=True)
            present = {cls._normalize_key(name) for name, _ in pairs}
            for name in names:
                if cls._normalize_key(name) not in present:
                    pairs.append((name, cls._default_value(name)))
            body = urlencode(pairs)
        else:
            body = json.dumps(
                {name: cls._default_value(name) for name in names},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            cls._set_header(headers, "Content-Type", "application/json")
        parts = urlsplit(request.url)
        url = request.url
        is_graphql = (
            "graphql" in parts.path.casefold() or "graphql" in content_type
        )
        if not is_graphql:
            query_pairs = parse_qsl(parts.query, keep_blank_values=True)
            present_query = {
                cls._normalize_key(name) for name, _ in query_pairs
            }
            for name in names:
                if cls._normalize_key(name) not in present_query:
                    query_pairs.append((name, cls._default_value(name)))
            url = urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urlencode(query_pairs),
                    parts.fragment,
                )
            )
        return request.model_copy(
            update={"url": url, "headers": headers, "body": body}
        )

    @staticmethod
    def _insert_fields(payload: dict[str, Any], names: Sequence[str]) -> None:
        present = {GreyBoxBridge._normalize_key(str(key)) for key in payload}
        for name in names:
            if GreyBoxBridge._normalize_key(name) not in present:
                payload[name] = GreyBoxBridge._default_value(name)

    @staticmethod
    def _set_header(headers: dict[str, str], name: str, value: str) -> None:
        for existing in list(headers):
            if existing.casefold() == name.casefold():
                del headers[existing]
        headers[name] = value

    @classmethod
    def _resolve_path(cls, route_path: str) -> tuple[str, dict[str, str]]:
        path = route_path if route_path.startswith("/") else "/" + route_path
        parameters: dict[str, str] = {}

        def replace(match: re.Match[str]) -> str:
            name = next((value for value in match.groups() if value), "param")
            value = "1"
            parameters[name] = value
            return value

        return SASTScanner.ROUTE_PARAMETER_RE.sub(replace, path), parameters

    @classmethod
    def _new_request(
        cls,
        template: HTTPRequest,
        method: str,
        path: str,
        parameters: Sequence[str],
    ) -> HTTPRequest:
        origin = urlsplit(template.url)
        headers = {
            name: value
            for name, value in template.headers.items()
            if name.casefold()
            not in {"host", "content-length", "transfer-encoding"}
        }
        graphql_route = "graphql" in path.casefold()
        query = (
            ""
            if graphql_route
            else urlencode(
                [(name, cls._default_value(name)) for name in parameters]
            )
        )
        if method == "GET":
            body = None
        else:
            body = json.dumps(
                {name: cls._default_value(name) for name in parameters},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            cls._set_header(headers, "Content-Type", "application/json")
        url = urlunsplit((origin.scheme, origin.netloc, path, query, ""))
        return HTTPRequest(method=method, url=url, headers=headers, body=body)


# ============================================================================
# Rich CLI and consolidated reporting
# ============================================================================


def _parse_header_option(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            "header must use the format 'Name: value'"
        )
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
        raise argparse.ArgumentTypeError("header name is invalid")
    if "\r" in header_value or "\n" in header_value:
        raise argparse.ArgumentTypeError("header value contains a newline")
    return name, header_value


_GITHUB_ACTIONS_WORKFLOW = r'''
# LogicSentry AI security workflow: local SAST with opt-in active DAST.
# Set LOGICSENTRY_AI_TARGET_URL to enable URL-driven active DAST. Only set it
# for an authorized, isolated test environment.
name: LogicSentry AI security scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

# Read-only token permissions are sufficient for checkout and artifact upload.
permissions:
  contents: read

concurrency:
  group: logicsentry-ai-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  security-scan:
    name: SAST and optional DAST
    runs-on: ubuntu-latest
    timeout-minutes: 60
    env:
      # Configure this variable in repository Settings > Secrets and variables
      # > Actions > Variables. An empty value keeps the job SAST-only.
      LOGICSENTRY_AI_TARGET_URL: ${{ vars.LOGICSENTRY_AI_TARGET_URL }}

    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install LogicSentry AI core dependencies
        run: python -m pip install --disable-pip-version-check pydantic>=2,<3 aiohttp>=3.9,<4 rich>=13

      # Build an archive containing only supported source files. Generated
      # folders, virtual environments, and common credential files are omitted.
      - name: Bundle source safely for LogicSentry AI
        run: |
          python - <<'PY'
          import os
          from pathlib import Path
          from zipfile import ZIP_DEFLATED, ZipFile

          root = Path.cwd()
          archive_path = root / ".logicsentry-ai-source.zip"
          source_extensions = {
              ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
              ".php", ".java",
          }
          excluded_directories = {
              ".git", ".venv", "venv", "node_modules", "__pycache__",
              "dist", "build", "target", "coverage", "vendor",
          }
          excluded_names = {
              ".env", "credentials", "id_rsa", "id_ed25519", "secrets.json",
          }
          excluded_suffixes = {".pem", ".key", ".p12", ".pfx", ".jks"}

          with ZipFile(archive_path, "w", compression=ZIP_DEFLATED) as archive:
              for current, directories, filenames in os.walk(
                  root, followlinks=False
              ):
                  current_path = Path(current)
                  directories[:] = [
                      name for name in directories
                      if name not in excluded_directories
                      and not (current_path / name).is_symlink()
                  ]
                  for filename in filenames:
                      path = current_path / filename
                      if path.is_symlink() or path == archive_path:
                          continue
                      if (
                          path.name in excluded_names
                          or path.name.startswith(".env")
                      ):
                          continue
                      if path.suffix.casefold() in excluded_suffixes:
                          continue
                      if path.suffix.casefold() not in source_extensions:
                          continue
                      archive.write(path, path.relative_to(root).as_posix())
          print(f"Created source archive: {archive_path}")
          PY

      # Setting this authorized target URL opts into active DAST. LogicSentry AI
      # derives the hostname scope directly from the URL.
      - name: Run LogicSentry AI
        shell: bash
        run: |
          set -euo pipefail
          if [[ -n "${LOGICSENTRY_AI_TARGET_URL:-}" ]]; then
            scan_args=(
              --src .logicsentry-ai-source.zip
              --auto-capture-url "$LOGICSENTRY_AI_TARGET_URL"
              --output logicsentry-ai-report.json
              --fail-on High
            )
            python LogicSentryAI.py "${scan_args[@]}"
          else
            scan_args=(
              --src .logicsentry-ai-source.zip
              --output logicsentry-ai-report.json
              --fail-on High
            )
            python LogicSentryAI.py "${scan_args[@]}"
          fi

      - name: Generate SARIF report
        if: always()
        run: |
          if test -f logicsentry-ai-report.json; then
            python - <<'PY'
          import json
          from pathlib import Path
          data = json.loads(Path("logicsentry-ai-report.json").read_text())
          results = []
          rules = {}
          for section in ("static", "dynamic"):
              block = data.get(section, {})
              for item in block.get("findings", []) if isinstance(block, dict) else []:
                  rule = str(item.get("logic_gap_type") or item.get("strategy") or "logicsentry-ai-finding").lower().replace(" ", "-")
                  rules.setdefault(rule, {"id": rule, "name": rule, "shortDescription": {"text": "LogicSentry AI finding"}})
                  sev = item.get("severity", "Info")
                  results.append({"ruleId": rule, "level": "error" if sev in ("Critical", "High") else "warning" if sev == "Medium" else "note", "message": {"text": str(item.get("description") or item.get("vulnerable_code") or "LogicSentry AI finding")}})
          sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "LogicSentry AI", "rules": list(rules.values())}}, "results": results}]}
          Path("logicsentry-ai-report.sarif").write_text(json.dumps(sarif, indent=2), encoding="utf-8")
          PY
          fi

      - name: Upload LogicSentry AI reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: logicsentry-ai-security-reports
          path: |
            logicsentry-ai-report.json
            logicsentry-ai-report.sarif
          if-no-files-found: ignore
          retention-days: 14
'''


def _write_github_actions_pipeline() -> Path:
    """Create the repository's self-contained LogicSentry AI Actions workflow."""
    workflow_path = (
        Path.cwd().resolve()
        / ".github"
        / "workflows"
        / "logicsentry-ai-scan.yml"
    )
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(_GITHUB_ACTIONS_WORKFLOW, encoding="utf-8")
    return workflow_path


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="LogicSentry AI",
        description=(
            "Combined SAST and DAST business-logic analyzer for authorized "
            "application security testing."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--generate-pipeline",
        action="store_true",
        help=(
            "Generate .github/workflows/logicsentry-ai-scan.yml and exit."
        ),
    )
    parser.add_argument(
        "--src",
        type=Path,
        help=(
            "ZIP archive containing Python, JavaScript/TypeScript, PHP, "
            "or Java source."
        ),
    )
    dast_input = parser.add_mutually_exclusive_group()
    dast_input.add_argument(
        "--har",
        "--file",
        dest="har",
        type=Path,
        help=(
            "HAR capture for active DAST; requires --target and "
            "--confirm-active (legacy alias: --file)."
        ),
    )
    dast_input.add_argument(
        "--auto-capture-url",
        metavar="URL",
        help=(
            "Infer the target hostname, capture same-origin traffic from this "
            "HTTP(S) URL, and run active DAST. A cached browser is used when "
            "available; otherwise a bounded HTTP crawl is used. This option "
            "implies --confirm-active; use only on authorized targets."
        ),
    )
    parser.add_argument(
        "--target",
        help=(
            "Hostname substring for HAR scope (required with --har); "
            "inferred from --auto-capture-url when omitted."
        ),
    )
    parser.add_argument(
        "--confirm-active",
        action="store_true",
        help=(
            "Acknowledge active DAST for a supplied HAR file; "
            "--auto-capture-url implies this acknowledgement."
        ),
    )
    parser.add_argument(
        "--header",
        action="append",
        type=_parse_header_option,
        default=[],
        metavar="NAME:VALUE",
        help="Override/add an HTTP header (repeatable; User A credentials).",
    )
    parser.add_argument(
        "--secondary-header",
        action="append",
        type=_parse_header_option,
        default=[],
        metavar="NAME:VALUE",
        help="Repeatable User B identity header for BOLA checks.",
    )
    parser.add_argument(
        "--test-race",
        action="store_true",
        help="Run synchronized concurrent tests on transactional requests.",
    )
    parser.add_argument(
        "--race-count",
        type=int,
        default=LogicEngine.DEFAULT_RACE_COUNT,
        help="Concurrent requests per race pool (2–50).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=LogicEngine.DEFAULT_CONCURRENCY,
        help="Concurrent replay cases.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=LogicEngine.DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout in seconds.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help=(
            "Minimum seconds between ordinary dynamic replay request starts; "
            "synchronized race tests are not delayed."
        ),
    )
    parser.add_argument(
        "--max-mutations",
        type=int,
        default=LogicEngine.DEFAULT_MAX_MUTATIONS,
        help="Maximum parameter replay variations.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Unified report path ending in .md, .markdown, .json, .html, or .sarif.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Previous LogicSentry AI JSON report used to identify new/fixed findings.",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Only retain dynamic findings at or above this confidence score (0-1).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["Critical", "High", "Medium", "Low", "Info"],
        help="Exit non-zero when a finding at or above this severity is present.",
    )
    parser.add_argument(
        "--fail-on-new-findings",
        action="store_true",
        help="Exit non-zero when --baseline identifies any new findings.",
    )
    parser.add_argument(
        "--debug-components",
        action="store_true",
        help="Print route/workflow population diagnostics and skipped-item reasons.",
    )
    return parser


def _display_static_findings(console: Console, report: SASTReport) -> None:
    console.print("\n[bold cyan]Static Logic Gaps (SAST)[/bold cyan]")
    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=29)
    table.add_column("File:Line", width=34)
    table.add_column("Route", width=26)
    table.add_column("Code", overflow="fold")
    for finding in report.findings:
        style = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "cyan",
            "Info": "dim",
        }.get(finding.severity, "white")
        table.add_row(
            f"[{style}]{finding.severity}[/{style}]",
            finding.logic_gap_type,
            f"{finding.file_path}:{finding.line_number}",
            finding.route_path or "—",
            finding.vulnerable_code or "—",
        )
    if report.findings:
        console.print(table)
    else:
        console.print("[green]No static logic gaps were identified.[/green]")

    route_table = Table(
        title="Source Route Map", show_lines=False, expand=True
    )
    route_table.add_column("Methods", style="cyan", width=18)
    route_table.add_column("Path", style="bold", width=32)
    route_table.add_column("Handler", width=24)
    route_table.add_column("File:Line", width=34)
    route_table.add_column("Source parameters", overflow="fold")
    for route in report.routes:
        route_table.add_row(
            ", ".join(route.methods),
            route.path,
            route.handler,
            f"{route.file_path}:{route.line_number}",
            ", ".join(route.parameters) or "—",
        )
    if report.routes:
        console.print(route_table)
    else:
        console.print(
            "[dim]No supported route declarations were mapped.[/dim]"
        )
    for warning in report.warnings[:8]:
        console.print(f"[yellow]SAST warning:[/yellow] {warning}")
    if len(report.warnings) > 8:
        console.print(
            f"[dim]... and {len(report.warnings) - 8} "
            "more SAST warnings.[/dim]"
        )


def _display_findings(
    console: Console, findings: Sequence[ScanResult]
) -> None:
    console.print(
        "\n[bold cyan]Dynamic Replay Vulnerabilities (DAST)[/bold cyan]"
    )
    table = Table(show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Step", justify="right", width=6)
    table.add_column("Type", width=27)
    table.add_column("Replay mode", width=13)
    table.add_column("HTTP", width=10)
    table.add_column("Source route", width=22)
    table.add_column("Description", overflow="fold")
    for finding in findings:
        style = {
            "Critical": "bold red",
            "High": "red",
            "Medium": "yellow",
            "Low": "cyan",
            "Info": "dim",
        }.get(finding.severity, "white")
        strategy = finding.strategy.value.replace("_", " ").title()
        table.add_row(
            f"[{style}]{finding.severity}[/{style}]",
            str(finding.step_index),
            strategy,
            finding.replay_mode or "—",
            f"{finding.baseline_status} → {finding.attack_status}",
            finding.source_route or "—",
            finding.description,
        )
    if findings:
        console.print(table)
    else:
        console.print(
            "[green]No dynamic differential findings were identified.[/green]"
        )


_SEVERITY_RANK = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
_SENSITIVE_HEADER_NAMES = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
}
_SENSITIVE_BODY_KEY_RE = re.compile(r"(?i)(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie|session)")

def _redact_text(value: object) -> object:
    if not isinstance(value, str):
        return value
    value = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(basic\s+)[^\s]+", r"\1[REDACTED]", value)
    return value

def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: "[REDACTED]" if name.casefold() in _SENSITIVE_HEADER_NAMES else str(_redact_text(value))
        for name, value in headers.items()
    }

def _redact_body(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_BODY_KEY_RE.search(str(key)) else _redact_body(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_body(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return _redact_text(value)
        return json.dumps(_redact_body(parsed), ensure_ascii=False)
    return value

def _redact_finding(item: dict[str, object]) -> dict[str, object]:
    result = dict(item)
    for key in ("request_headers", "baseline_request_headers", "baseline_response_headers", "attack_response_headers"):
        if isinstance(result.get(key), dict):
            result[key] = _redact_headers(result[key])
    for key in ("request_body", "baseline_request_body", "baseline_response_body", "attack_response_body", "evidence", "mutation"):
        if key in result:
            result[key] = _redact_body(result[key])
    return result

def _redact_static_finding(item: dict[str, object]) -> dict[str, object]:
    result = dict(item)
    for key in ("vulnerable_code", "description", "evidence"):
        if key in result:
            result[key] = _redact_text(result[key])
    return result

def _report_document(
    *,
    mode: str,
    source_path: Optional[Path],
    sast_report: SASTReport,
    har_path: Optional[Path],
    target: Optional[str],
    workflow_count: int,
    source_step_count: int,
    findings: Sequence[ScanResult],
    errors: Sequence[str],
    parser_warnings: Sequence[str],
    secondary_header_names: Sequence[str],
    test_race: bool,
    race_count: int,
    delay_seconds: float,
) -> dict[str, object]:
    static_findings = [
        _redact_static_finding(item.model_dump(mode="json"))
        for item in sast_report.findings
    ]
    routes = [item.model_dump(mode="json") for item in sast_report.routes]
    dynamic_findings = [_redact_finding(item.model_dump(mode="json")) for item in findings]
    sequential_findings = sum(
        item.replay_mode == "sequential" for item in findings
    )
    synchronized_findings = sum(
        item.replay_mode == "synchronized" for item in findings
    )
    return {
        "tool": "LogicSentry AI",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "target": target,
        "summary": {
            "source_files_scanned": sast_report.files_scanned,
            "source_routes_mapped": len(sast_report.routes),
            "static_findings": len(sast_report.findings),
            "har_workflow_steps": workflow_count,
            "source_derived_dast_steps": source_step_count,
            "dynamic_findings": len(findings),
            "sequential_replay_findings": sequential_findings,
            "synchronized_race_findings": synchronized_findings,
        },
        "static": {
            "archive": source_path.name if source_path else None,
            "files_scanned": sast_report.files_scanned,
            "routes": routes,
            "findings": static_findings,
            "warnings": list(sast_report.warnings),
        },
        "dynamic": {
            "har_file": har_path.name if har_path else None,
            "workflow_steps": workflow_count,
            "source_derived_steps": source_step_count,
            "test_race": test_race,
            "race_request_count": race_count if test_race else 0,
            "delay_seconds": delay_seconds,
            "secondary_header_names": list(secondary_header_names),
            "findings": dynamic_findings,
            "replay_errors": list(errors),
            "parser_warnings": list(parser_warnings),
        },
        "interpretation_note": (
            "SAST results are heuristic code-review leads. DAST differential "
            "matches and source-only route reachability require manual review "
            "before treating them as vulnerabilities."
        ),
        "report_warning": (
            "Reports may contain credentials, cookies, source snippets, and "
            "response data. Store and share them securely."
        ),
    }


def _markdown_report(document: dict[str, object]) -> str:
    summary = document.get("summary", {})
    static = document.get("static", {})
    dynamic = document.get("dynamic", {})
    assert isinstance(summary, dict)
    assert isinstance(static, dict)
    assert isinstance(dynamic, dict)
    static_findings = static.get("findings", [])
    routes = static.get("routes", [])
    dynamic_findings = dynamic.get("findings", [])
    lines = [
        "# LogicSentry AI SAST + DAST Report",
        "",
        f"- **Mode:** {document.get('mode', '')}",
        f"- **Target:** {document.get('target') or 'Not applicable'}",
        f"- **Generated:** {document.get('generated_at', '')}",
        f"- **Source files scanned:** "
        f"{summary.get('source_files_scanned', 0)}",
        f"- **Source routes mapped:** "
        f"{summary.get('source_routes_mapped', 0)}",
        f"- **HAR workflow steps:** {summary.get('har_workflow_steps', 0)}",
        f"- **Source-derived DAST steps:** "
        f"{summary.get('source_derived_dast_steps', 0)}",
        f"- **Static findings:** {summary.get('static_findings', 0)}",
        f"- **Dynamic findings:** {summary.get('dynamic_findings', 0)}",
        f"- **Sequential replay findings:** "
        f"{summary.get('sequential_replay_findings', 0)}",
        f"- **Synchronized race findings:** "
        f"{summary.get('synchronized_race_findings', 0)}",
        f"- **Ordinary replay delay:** "
        f"{dynamic.get('delay_seconds', 0)} seconds",
        "",
        f"> **Sensitive evidence:** {document.get('report_warning', '')}",
        f"> **Interpretation:** {document.get('interpretation_note', '')}",
        "",
        "## Static Logic Gaps",
        "",
    ]
    if not static_findings:
        lines.append("No static logic gaps were identified.")
    else:
        lines.extend(
            [
                "| Severity | Type | File:Line | Route | Vulnerable code |",
                "|---|---|---|---|---|",
            ]
        )
        for item in static_findings:
            assert isinstance(item, dict)
            code = str(item.get("vulnerable_code", "")).replace("|", "\\|")
            route = str(item.get("route_path") or "—").replace("|", "\\|")
            lines.append(
                f"| {item.get('severity', '')} | "
                f"{item.get('logic_gap_type', '')} | "
                f"{item.get('file_path', '')}:{item.get('line_number', '')} | "
                f"{route} | `{code}` |"
            )

    lines.extend(["", "## Source Route Map", ""])
    if not routes:
        lines.append("No supported route declarations were mapped.")
    else:
        lines.extend(
            [
                "| Methods | Path | Handler | File:Line | Source parameters |",
                "|---|---|---|---|---|",
            ]
        )
        for item in routes:
            assert isinstance(item, dict)
            methods = ", ".join(
                str(value) for value in item.get("methods", [])
            )
            parameters = (
                ", ".join(str(value) for value in item.get("parameters", []))
                or "—"
            )
            lines.append(
                f"| {methods} | {item.get('path', '')} | "
                f"{item.get('handler', '')} | {item.get('file_path', '')}:"
                f"{item.get('line_number', '')} | {parameters} |"
            )

    lines.extend(["", "## Dynamic Replay Vulnerabilities", ""])
    if not dynamic_findings:
        lines.append("No dynamic differential findings were identified.")
    else:
        lines.extend(
            [
                (
                    "| Severity | Step | Strategy | Replay mode | HTTP | "
                    "Source route | Description |"
                ),
                "|---|---:|---|---|---:|---|---|",
            ]
        )
        for item in dynamic_findings:
            assert isinstance(item, dict)
            description = str(item.get("description", "")).replace("|", "\\|")
            strategy = str(item.get("strategy", "")).replace("_", " ").title()
            replay_mode = str(item.get("replay_mode") or "—")
            route = str(item.get("source_route") or "—").replace("|", "\\|")
            lines.append(
                f"| {item.get('severity', '')} | "
                f"{item.get('step_index', '')} | "
                f"{strategy} | {replay_mode} | "
                f"{item.get('baseline_status', '')} → "
                f"{item.get('attack_status', '')} | {route} | {description} |"
            )
        lines.extend(["", "### Detailed HTTP evidence", ""])
        for index, item in enumerate(dynamic_findings, start=1):
            assert isinstance(item, dict)
            evidence = json.dumps(item, ensure_ascii=False, indent=2)
            fence = "`" * max(
                3,
                max(
                    (
                        len(match.group(0))
                        for match in re.finditer(r"`+", evidence)
                    ),
                    default=2,
                )
                + 1,
            )
            strategy_label = (
                str(item.get("strategy", "")).replace("_", " ").title()
            )
            lines.extend(
                [
                    f"#### {index}. {item.get('severity', '')} — "
                    f"{strategy_label}",
                    "",
                    f"{fence}json",
                    evidence,
                    fence,
                    "",
                ]
            )

    for key, title in (
        ("warnings", "SAST warnings"),
        ("replay_errors", "Replay errors"),
        ("parser_warnings", "HAR parser warnings"),
    ):
        if key == "warnings":
            entries = static.get(key, [])
        else:
            entries = dynamic.get(key, [])
        if entries:
            lines.extend(["", f"## {title}", ""])
            lines.extend(f"- {entry}" for entry in entries)
    return "\n".join(lines).rstrip() + "\n"


def _finding_key(item: Mapping[str, object]) -> str:
    """Stable identity for regression comparisons, excluding volatile evidence."""
    payload = {
        "strategy": item.get("strategy"),
        "step_index": item.get("step_index"),
        "source_route": item.get("source_route"),
        "request_url": item.get("request_url"),
        "mutation": item.get("mutation"),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _apply_baseline(document: dict[str, object], baseline_path: Optional[Path]) -> None:
    if baseline_path is None:
        return
    if not baseline_path.exists():
        raise ValueError(f"baseline file not found: {baseline_path}")
    try:
        old = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read baseline: {exc}") from exc
    old_items = []
    if isinstance(old, dict):
        static = old.get("static", {})
        dynamic = old.get("dynamic", {})
        if isinstance(static, dict) and isinstance(static.get("findings"), list):
            old_items.extend(x for x in static["findings"] if isinstance(x, dict))
        if isinstance(dynamic, dict) and isinstance(dynamic.get("findings"), list):
            old_items.extend(x for x in dynamic["findings"] if isinstance(x, dict))
    current_items = []
    static = document.get("static", {})
    dynamic = document.get("dynamic", {})
    if isinstance(static, dict) and isinstance(static.get("findings"), list):
        current_items.extend(x for x in static["findings"] if isinstance(x, dict))
    if isinstance(dynamic, dict) and isinstance(dynamic.get("findings"), list):
        current_items.extend(x for x in dynamic["findings"] if isinstance(x, dict))
    old_keys = {_finding_key(x) for x in old_items}
    new_keys = {_finding_key(x) for x in current_items}
    document["baseline"] = {
        "file": baseline_path.name,
        "previous_findings": len(old_keys),
        "current_findings": len(new_keys),
        "new_findings": len(new_keys - old_keys),
        "fixed_findings": len(old_keys - new_keys),
        "unchanged_findings": len(old_keys & new_keys),
        "regression_status": "failed" if (new_keys - old_keys) else "passed",
    }

def _sarif_report(document: dict[str, object]) -> str:
    """Emit SARIF 2.1.0 with stable rules and evidence locations when available."""
    results = []
    rules = {}
    for section in ("static", "dynamic"):
        block = document.get(section, {})
        if not isinstance(block, dict):
            continue
        items = block.get("findings", [])
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("logic_gap_type") or item.get("strategy") or "logicsentry-ai-finding").lower().replace(" ", "-")
            severity = str(item.get("severity") or "Info")
            level = "error" if severity in {"Critical", "High"} else "warning" if severity == "Medium" else "note"
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"LogicSentry AI {rule_id}"},
                "properties": {"security-severity": severity},
            })
            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": str(item.get("description") or item.get("vulnerable_code") or "LogicSentry AI finding")},
                "properties": {
                    "severity": severity,
                    "confidence": item.get("confidence_score"),
                    "section": section,
                },
            }
            if section == "static" and item.get("file_path"):
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(item["file_path"])}, "region": {"startLine": int(item.get("line_number") or 1)}}}]
            elif section == "dynamic" and item.get("request_url"):
                result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(item["request_url"])}}}]
            results.append(result)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "LogicSentry AI", "version": "production", "rules": list(rules.values())}}, "results": results}],
    }, ensure_ascii=False, indent=2) + "\n"

def _write_report(path: Path, document: dict[str, object]) -> None:
    extension = path.suffix.casefold()
    if extension not in {".md", ".markdown", ".json", ".html", ".sarif"}:
        raise ValueError("report path must end in .md, .markdown, .json, .html, or .sarif")
    path.parent.mkdir(parents=True, exist_ok=True)
    if extension == ".json":
        content = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    elif extension in {".md", ".markdown"}:
        content = _markdown_report(document)
    elif extension == ".html":
        body = _markdown_report(document)
        escaped = (body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
        content = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>LogicSentry AI Report</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem}"
            "pre{white-space:pre-wrap;background:#f5f5f5;padding:1rem;border-radius:8px}"
            "</style></head><body><pre>" + escaped + "</pre></body></html>\n"
        )
    else:
        content = _sarif_report(document)
    path.write_text(content, encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_argument_parser()
    args = parser.parse_args(argv)
    console = Console()
    if not 0.0 <= args.min_confidence <= 1.0:
        parser.error("--min-confidence must be between 0 and 1")
    if args.generate_pipeline:
        try:
            workflow_path = _write_github_actions_pipeline()
        except OSError as exc:
            console.print(
                f"[bold red]Could not generate workflow:[/bold red] {exc}"
            )
            return 1
        console.print(
            f"[bold green]GitHub Actions workflow created:[/bold green] "
            f"{workflow_path}"
        )
        console.print(
            "[dim]Set LOGICSENTRY_AI_TARGET_URL in repository Variables to "
            "enable authorized URL-based DAST.[/dim]"
        )
        return 0

    console.print(Text(BANNER.rstrip("\n"), style="bold cyan"))
    console.print(
        "[dim]Business-logic SAST + DAST · authorized testing only[/dim]\n"
    )

    if args.auto_capture_url is not None:
        cleaned_capture_url = args.auto_capture_url.strip()
        if not cleaned_capture_url:
            parser.error("--auto-capture-url cannot be empty")
        try:
            capture_parts = urlsplit(cleaned_capture_url)
            capture_hostname = capture_parts.hostname
            capture_port = capture_parts.port
        except ValueError as exc:
            parser.error(f"invalid --auto-capture-url: {exc}")
        if capture_port == 0:
            parser.error("--auto-capture-url port must be between 1 and 65535")
        if (
            capture_parts.scheme.casefold() not in {"http", "https"}
            or not capture_hostname
            or capture_parts.username is not None
            or capture_parts.password is not None
        ):
            parser.error(
                "--auto-capture-url must be an absolute HTTP(S) URL "
                "without embedded credentials"
            )
        args.auto_capture_url = cleaned_capture_url
        args.target = (
            args.target.strip()
            if args.target and args.target.strip()
            else capture_hostname
        )
        if args.output is None:
            safe_hostname = re.sub(
                r"[^A-Za-z0-9._-]+", "_", capture_hostname
            ).strip("._-") or "target"
            timestamp = datetime.now(timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            args.output = Path(
                f"logicsentry-ai-{safe_hostname}-{timestamp}-report.md"
            )
        console.print(
            "[yellow]--auto-capture-url authorizes active DAST for "
            f"{args.target}; use only on an authorized target.[/yellow]"
        )
    if not args.src and not args.har and not args.auto_capture_url:
        parser.error("provide --src, --har, or --auto-capture-url")
    if args.har and not args.target:
        parser.error("--target is required when --har is used")
    if args.har and not args.confirm_active and not args.auto_capture_url:
        parser.error("DAST replay requires --confirm-active")
    if not args.har and not args.auto_capture_url and (
        args.header or args.secondary_header or args.test_race or args.delay
    ):
        parser.error(
            "headers, --delay, and --test-race require --har or "
            "--auto-capture-url"
        )
    if (
        args.concurrency < 1
        or not math.isfinite(args.timeout)
        or args.timeout <= 0
        or args.max_mutations < 1
    ):
        parser.error(
            "concurrency, timeout, and max-mutations must be positive"
        )
    if not math.isfinite(args.delay) or args.delay < 0:
        parser.error("--delay must be a finite non-negative number")
    if args.test_race and not (
        2 <= args.race_count <= LogicEngine.MAX_RACE_COUNT
    ):
        parser.error(
            f"--race-count must be between 2 and {LogicEngine.MAX_RACE_COUNT}"
        )

    capture_warning: str | None = None
    if args.auto_capture_url:
        capture_destination = Path("./internal_automated_capture.har")
        try:
            capture_succeeded = _execute_embedded_har_capture(
                args.auto_capture_url,
                capture_destination,
            )
        except KeyboardInterrupt:
            console.print("\\n[yellow]HAR capture interrupted.[/yellow]")
            return 130
        except Exception as exc:
            console.print(
                "[yellow]Automatic URL capture failed: "
                f"{type(exc).__name__}[/yellow]"
            )
            capture_succeeded = False
        if capture_succeeded:
            args.har = capture_destination
        else:
            args.har = None
            capture_warning = (
                "Automatic URL traffic capture failed; DAST replay was "
                "skipped."
            )
            console.print(f"[yellow]{capture_warning}[/yellow]")
            if not args.src:
                return 2

    mode = (
        "combined" if args.src and args.har else "sast" if args.src else "dast"
    )
    sast_report = SASTReport()
    har_parser: Optional[HARParser] = None
    workflow: list[WorkflowStep] = []
    source_steps: list[WorkflowStep] = []
    findings: list[ScanResult] = []
    errors: list[str] = []
    har_warnings: list[str] = []
    engine: Optional[LogicEngine] = None

    try:
        if args.src:
            try:
                sast_report = SASTScanner(args.src).scan()
                if capture_warning:
                    sast_report.warnings.append(capture_warning)
            except SASTScanError as exc:
                if not args.har:
                    console.print(f"[bold red]SAST error:[/bold red] {exc}")
                    return 2
                sast_report.warnings.append(str(exc))
            _display_static_findings(console, sast_report)

        if args.har:
            assert args.target is not None
            target = args.target.strip()
            if not target:
                parser.error("--target cannot be empty")
            har_parser = HARParser(args.har, target_pattern=re.escape(target))
            workflow = har_parser.parse()
            har_warnings = list(har_parser.warnings)
            if not workflow:
                message = (
                    "No valid in-scope HTTP request/response pairs were found."
                )
                if args.src:
                    sast_report.warnings.append(message)
                    console.print(
                        f"[yellow]{message} "
                        "SAST results remain available.[/yellow]"
                    )
                else:
                    console.print(f"[bold yellow]{message}[/bold yellow]")
                    return 2
            else:
                if args.src:
                    source_steps = GreyBoxBridge.build_source_steps(
                        sast_report.routes, workflow
                    )
                    if len(source_steps) == GreyBoxBridge.MAX_SOURCE_STEPS:
                        sast_report.warnings.append(
                            "Grey-box DAST source-step limit reached; some "
                            "source routes may not have been replayed."
                        )
                engine = LogicEngine(
                    workflow,
                    concurrency=args.concurrency,
                    timeout_seconds=args.timeout,
                    max_mutations=args.max_mutations,
                    source_steps=source_steps,
                    delay_seconds=args.delay,
                )
                if args.header:
                    engine.refresh_headers(dict(args.header))
                test_cases = engine.build_test_cases(
                    secondary_headers=(
                        dict(args.secondary_header)
                        if args.secondary_header
                        else None
                    ),
                    test_race=args.test_race,
                    race_count=args.race_count,
                )
                sequential_check_count = sum(
                    isinstance(item, SequentialReplayGroup)
                    for item in test_cases
                )
                if sequential_check_count:
                    console.print(
                        "[bold yellow]Sequential replay checks send each "
                        "qualifying transaction twice; use only on an "
                        "authorized test environment.[/bold yellow]"
                    )
                if args.test_race:
                    console.print(
                        "[bold yellow]Race tests can repeat transactions; use "
                        "only on an authorized test environment.[/bold yellow]"
                    )
                console.print(
                    f"[cyan]Scope:[/cyan] {target}  "
                    f"[cyan]HAR steps:[/cyan] {len(workflow)}  "
                    f"[cyan]Source-derived steps:[/cyan] {len(source_steps)}  "
                    f"[cyan]Variations:[/cyan] {len(test_cases)}"
                )
                if args.header:
                    console.print(
                        f"[dim]Applied {len(args.header)} fresh header "
                        "override(s) to captured and source-derived "
                        "requests.[/dim]"
                    )
                if test_cases:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        TimeElapsedColumn(),
                        console=console,
                    ) as progress:
                        task_id = progress.add_task(
                            "Replaying test variations", total=len(test_cases)
                        )

                        def update_progress(
                            completed: int, total: int
                        ) -> None:
                            progress.update(
                                task_id,
                                completed=completed,
                                description=(
                                    f"Replaying variations "
                                    f"({completed}/{total})"
                                ),
                            )

                        findings = asyncio.run(
                            engine.scan(test_cases, update_progress)
                        )
                if args.min_confidence > 0:
                    findings = [
                        finding for finding in findings
                        if finding.confidence_score >= args.min_confidence
                    ]
                _display_findings(console, findings)
                errors = list(engine.execution_errors)
                if errors:
                    console.print(
                        f"\n[yellow]Replay errors: {len(errors)} "
                        "(unreachable hosts, timeouts, or rejected "
                        "requests).[/yellow]"
                    )
                    for error in errors[:8]:
                        console.print(f"  [dim]- {error}[/dim]")
                    if len(errors) > 8:
                        console.print(
                            f"  [dim]... and {len(errors) - 8} "
                            "more; see report.[/dim]"
                        )
                if har_warnings:
                    console.print(
                        f"[dim]Skipped {len(har_warnings)} malformed HAR "
                        "entry/entries.[/dim]"
                    )

        if args.output:
            report = _report_document(
                mode=mode,
                source_path=args.src,
                sast_report=sast_report,
                har_path=args.har,
                target=args.target.strip() if args.target else None,
                workflow_count=len(workflow),
                source_step_count=len(source_steps),
                findings=findings,
                errors=errors,
                parser_warnings=har_warnings,
                secondary_header_names=[
                    name for name, _ in args.secondary_header
                ],
                test_race=args.test_race,
                race_count=args.race_count,
                delay_seconds=args.delay,
            )
            _apply_baseline(report, args.baseline)
            if args.debug_components:
                console.print(
                    f"[cyan]Population diagnostics:[/cyan] "
                    f"routes={len(sast_report.routes)}, workflow_steps={len(workflow)}, "
                    f"source_derived_steps={len(source_steps)}, test_cases="
                    f"{len(test_cases) if engine is not None else 0}, findings={len(findings)}"
                )
                if not workflow and args.har:
                    console.print("[yellow]No workflow entries populated from HAR; check target scope and HAR format.[/yellow]")
                if args.src and not sast_report.routes:
                    console.print("[yellow]No source routes populated; verify the archive contains supported Python/JS/TS/PHP/Java route declarations.[/yellow]")
            _write_report(args.output, report)
            console.print(f"\n[green]Report written:[/green] {args.output}")
            console.print(
                "[yellow]Reports redact common credentials/tokens in exported evidence; "
                "protect report files anyway.[/yellow]"
            )
            if args.fail_on_new_findings:
                baseline_block = report.get("baseline")
                if args.baseline is None or not isinstance(baseline_block, dict):
                    console.print("[bold red]Regression failure:[/bold red] --fail-on-new-findings requires a valid --baseline and --output.")
                    return 3
                if int(baseline_block.get("new_findings", 0)) > 0:
                    console.print("[bold red]Regression failure:[/bold red] new findings were detected against the baseline.")
                    return 3
        elif args.fail_on_new_findings:
            console.print("[bold red]Regression failure:[/bold red] --fail-on-new-findings requires --output.")
            return 3
        if args.fail_on:
            threshold = _SEVERITY_RANK[args.fail_on]
            blocking = [
                finding for finding in findings
                if _SEVERITY_RANK.get(finding.severity, 0) >= threshold
            ] + [
                finding for finding in sast_report.findings
                if _SEVERITY_RANK.get(finding.severity, 0) >= threshold
            ]
            if blocking:
                console.print(f"[bold red]Policy failure:[/bold red] {len(blocking)} finding(s) meet --fail-on {args.fail_on}.")
                return 3
        return 0
    except (HARParseError, SASTScanError, OSError, ValueError) as exc:
        console.print(f"[bold red]LogicSentry AI error:[/bold red] {exc}")
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
