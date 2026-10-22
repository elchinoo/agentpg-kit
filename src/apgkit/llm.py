"""One HTTP path for every outbound call to an OpenAI-compatible provider.

Retries transient failures, never follows redirects, bounds the response, checks user-entered URLs with the URL guard on
every call and redacts the API key from every message it raises.
"""
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from . import vault as vault_mod
from .netguard import NetGuard, UnsafeURL

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class LLMError(RuntimeError):
    """A failure whose message is safe to show to users: it never contains the API key."""


@dataclass(frozen=True)
class ChatConfig:
    base_url: str
    model: str
    label: str
    trusted: bool = False                 # True only for operator-set environment config (skips the URL guard)
    key_plain: str = ""
    key_enc: str | None = None

    def api_key(self, vault: vault_mod.Vault | None = None) -> str:
        if self.key_enc:
            if vault is None:
                raise vault_mod.VaultError("no vault to decrypt the stored key")
            return vault.decrypt(self.key_enc)
        return self.key_plain


def redact(text: str, api_key: str) -> str:
    return text.replace(api_key, "***") if api_key else text


class LLMClient:
    def __init__(self, guard: NetGuard, vault: vault_mod.Vault | None = None,
                 http_factory: Callable[[], httpx.Client] | None = None):
        self.guard, self.vault = guard, vault
        self._http = http_factory or (lambda: httpx.Client(timeout=60, follow_redirects=False))

    def post_json(self, base_url: str, path: str, api_key: str, body: dict, *, trusted: bool, retries: int = 3) -> httpx.Response:
        if not trusted:
            try:
                base_url = self.guard.check(base_url)
            except UnsafeURL as exc:
                raise LLMError(f"provider URL rejected: {exc}") from exc
        url = f"{base_url.rstrip('/')}{path}"
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        with self._http() as client:
            for attempt in range(retries + 1):
                try:
                    resp = client.post(url, headers=headers, json=body)
                except httpx.TransportError as exc:
                    if attempt == retries:
                        raise LLMError(f"could not reach the provider: {type(exc).__name__}") from exc
                else:
                    if resp.is_redirect:
                        raise LLMError("the provider URL redirected; use the final URL directly")
                    if len(resp.content) > MAX_RESPONSE_BYTES:
                        raise LLMError("provider response too large")
                    if resp.status_code not in _RETRY_STATUS or attempt == retries:
                        return resp
                time.sleep(min(2**attempt, 8))
        raise AssertionError("unreachable")

    def chat(self, cfg: ChatConfig, messages: list[dict], max_tokens: int = 700, temperature: float = 0.1) -> dict:
        try:
            key = cfg.api_key(self.vault)
        except vault_mod.VaultLocked:
            raise
        except vault_mod.VaultError as exc:
            raise LLMError(str(exc)) from exc
        body = {"model": cfg.model, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
        resp = self.post_json(cfg.base_url, "/chat/completions", key, body, trusted=cfg.trusted)
        if resp.status_code >= 400:
            raise LLMError(f"chat endpoint returned HTTP {resp.status_code}: {redact(resp.text[:300], key)}")
        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise LLMError("unexpected response from the chat endpoint (no choices[0].message.content)") from exc
        if not isinstance(text, str) or not text.strip():
            raise LLMError("the chat endpoint returned an empty answer")
        return {"text": text.strip(), "usage": data.get("usage")}
