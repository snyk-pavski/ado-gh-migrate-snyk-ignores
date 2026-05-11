"""Snyk REST API client: auth, version pin, pagination, 429/5xx retry."""
from __future__ import annotations

import logging
from typing import Any, Iterator

import httpx
from tenacity import (
    Retrying,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

logger = logging.getLogger(__name__)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status == 429 or 500 <= status < 600
    return isinstance(
        exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError)
    )


class SnykClient:
    """Synchronous Snyk REST client with pagination + retry baked in."""

    def __init__(self, base: str, token: str, version: str, timeout: float = 30.0):
        self._base = base.rstrip("/")
        self._host_root = self._base.rsplit("/rest", 1)[0]
        self._version = version
        self._client = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.api+json",
            },
        )

    def __enter__(self) -> "SnykClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self._client.close()

    def close(self) -> None:
        self._client.close()

    def _absolute(self, path_or_url: str) -> str:
        if path_or_url.startswith("http"):
            return path_or_url
        if path_or_url.startswith("/rest/"):
            return f"{self._host_root}{path_or_url}"
        normalized = path_or_url if path_or_url.startswith("/") else f"/{path_or_url}"
        return f"{self._base}{normalized}"

    def get(self, path_or_url: str, params: dict[str, Any] | None = None) -> dict:
        """GET one page. If `path_or_url` already has a query string (e.g. a
        `links.next` continuation), `params` is ignored — the URL is final."""
        url = self._absolute(path_or_url)
        if "?" in url:
            request_params = None
        else:
            merged: dict[str, Any] = {"version": self._version}
            if params:
                merged.update(params)
            request_params = merged

        for attempt in Retrying(
            stop=stop_after_attempt(5),
            wait=wait_random_exponential(multiplier=1, max=30),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        ):
            with attempt:
                logger.debug("GET %s params=%s", url, request_params)
                r = self._client.get(url, params=request_params)
                r.raise_for_status()
        return r.json()

    def get_paginated(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Iterator[dict]:
        """Yield each `data[]` element across all pages following links.next."""
        url = path
        first = True
        while True:
            payload = self.get(url, params if first else None)
            for item in payload.get("data") or []:
                yield item
            nxt = (payload.get("links") or {}).get("next")
            if not nxt:
                break
            url = nxt
            first = False

    def _write(
        self, method: str, path: str, body: dict, params: dict[str, Any] | None = None
    ) -> dict:
        url = self._absolute(path)
        merged: dict[str, Any] = {"version": self._version}
        if params:
            merged.update(params)
        for attempt in Retrying(
            stop=stop_after_attempt(5),
            wait=wait_random_exponential(multiplier=1, max=30),
            retry=retry_if_exception(_is_retryable),
            reraise=True,
        ):
            with attempt:
                logger.debug("%s %s body=%s", method, url, body)
                r = self._client.request(
                    method,
                    url,
                    params=merged,
                    json=body,
                    headers={"Content-Type": "application/vnd.api+json"},
                )
                r.raise_for_status()
        return r.json() if r.content else {}

    def post(self, path: str, body: dict, params: dict[str, Any] | None = None) -> dict:
        return self._write("POST", path, body, params)

    def patch(self, path: str, body: dict, params: dict[str, Any] | None = None) -> dict:
        return self._write("PATCH", path, body, params)
