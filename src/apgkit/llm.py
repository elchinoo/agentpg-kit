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


class LLMTimeout(LLMError):
    """The provider did not answer in time."""


class LLMUnreachable(LLMError):
    """The provider could not be reached (DNS, connection refused, TLS...)."""


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


def empty_answer_error(data: dict | None, max_tokens: int | None = None) -> LLMError:
    """An actionable LLMError for a chat response that has no answer text.

    Uses only the response's own metadata (`finish_reason`, `usage.completion_tokens`, whether the model produced
    `reasoning_content`); the prompt and the API key never appear in the message.
    """
    data = data if isinstance(data, dict) else {}
    try:
        choice = data["choices"][0]
        finish = choice.get("finish_reason")
        message = choice.get("message") or {}
    except (KeyError, IndexError, TypeError, AttributeError):
        finish, message = None, {}
    reasoning = message.get("reasoning_content") if isinstance(message, dict) else None
    usage = data.get("usage")
    used = usage.get("completion_tokens") if isinstance(usage, dict) else None
    used = used if isinstance(used, int) and not isinstance(used, bool) else None
    thinking = isinstance(reasoning, str) and bool(reasoning.strip())
    details = ", ".join(x for x in (f"finish_reason={finish}" if finish else "",
                                    f"completion_tokens={used}" if used is not None else "") if x)
    if finish == "length" or thinking:
        budget = used if used is not None else max_tokens
        spent = f"all {budget} completion tokens" if budget is not None else "its whole completion token budget"
        if thinking and finish != "length":
            head = "the model produced only reasoning and no answer"
        else:
            head = f"the model used {spent} before answering"
        return LLMError(f"{head} ({details or 'finish_reason=length'}): raise max tokens or use a model without a thinking phase")
    return LLMError("the chat endpoint returned an empty answer" + (f" ({details})" if details else ""))


def answer_text(data: dict, max_tokens: int | None = None) -> str:
    """The stripped answer text of a chat-completions response, or a typed LLMError (see `empty_answer_error`)."""
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMError("unexpected response from the chat endpoint (no choices[0].message.content)") from exc
    if not isinstance(text, str) or not text.strip():
        raise empty_answer_error(data, max_tokens)
    return text.strip()


class LLMClient:
    def __init__(self, guard: NetGuard, vault: vault_mod.Vault | None = None,
                 http_factory: Callable[[], httpx.Client] | None = None):
        self.guard, self.vault = guard, vault
        self._http = http_factory or (lambda: httpx.Client(timeout=60, follow_redirects=False))

    @staticmethod
    def _bounded_post(client: httpx.Client, url: str, headers: dict, body: dict, extensions: dict | None = None) -> httpx.Response:
        """POST and read the answer in chunks, refusing it as soon as it passes MAX_RESPONSE_BYTES (a hostile provider cannot make us
        buffer an unbounded body)."""
        with client.stream("POST", url, headers=headers, json=body, extensions=extensions or {}) as r:
            if r.is_redirect:
                return r
            data = bytearray()
            for chunk in r.iter_bytes():
                data += chunk
                if len(data) > MAX_RESPONSE_BYTES:
                    raise LLMError("provider response too large")
            kept = {k: v for k, v in r.headers.items() if k.lower() not in {"content-encoding", "content-length", "transfer-encoding"}}
            return httpx.Response(r.status_code, headers=kept, content=bytes(data), request=r.request)

    def post_json(self, base_url: str, path: str, api_key: str, body: dict, *, trusted: bool, retries: int = 3) -> httpx.Response:
        pin_headers: dict[str, str] = {}
        extensions: dict = {}
        url = f"{base_url.rstrip('/')}{path}"
        if not trusted:
            try:
                target = self.guard.resolve(base_url)       # resolved once; the request below goes to this exact address
            except UnsafeURL as exc:
                raise LLMError(f"provider URL rejected: {exc}") from exc
            url, pin_headers, extensions = target.request_args(path)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        headers.update(pin_headers)
        with self._http() as client:
            for attempt in range(retries + 1):
                try:
                    resp = self._bounded_post(client, url, headers, body, extensions)
                except httpx.TimeoutException as exc:
                    if attempt == retries:
                        raise LLMTimeout("the provider did not answer in time") from exc
                except httpx.TransportError as exc:
                    if attempt == retries:
                        raise LLMUnreachable(f"could not reach the provider: {type(exc).__name__}") from exc
                else:
                    if resp.is_redirect:
                        raise LLMError("the provider URL redirected; use the final URL directly")
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
        except ValueError as exc:
            raise LLMError("unexpected response from the chat endpoint (no choices[0].message.content)") from exc
        return {"text": answer_text(data, max_tokens), "usage": data.get("usage") if isinstance(data, dict) else None}
