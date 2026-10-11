from dataclasses import dataclass, field
import os
from urllib.parse import urlparse

from .security_policy import POLICY
from .prompt import PromptConfigurationError, load_system_prompt


@dataclass(frozen=True)
class Settings:
    service_token: str = field(default="", repr=False)
    mode: str = "replay"
    model: str = ""
    api_key: str = field(default="", repr=False)
    base_url: str = "https://api.openai.com/v1"
    prompt_path: str = ""
    private_documents_path: str = ""
    model_timeout_seconds: float = 25.0
    max_parallel: int = POLICY["modelConcurrency"]
    max_request_bytes: int = POLICY["internalRequestMaxBytes"]
    _system_prompt: str | None = field(default=None, init=False, repr=False)
    _prompt_error: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if not 0 < self.model_timeout_seconds <= 25 or not 1 <= self.max_parallel <= POLICY["modelConcurrency"]:
            raise ValueError("model resource limits exceed policy")
        if not 1 <= self.max_request_bytes <= POLICY["internalRequestMaxBytes"]:
            raise ValueError("request limit exceeds policy")
        # Load once per process configuration. Capture hashes and provider calls
        # must use identical bytes even if the file changes during a request.
        # Synthetic modes never read private files.
        if self.mode == "live":
            try:
                object.__setattr__(self, "_system_prompt", load_system_prompt(self.prompt_path))
            except PromptConfigurationError as exc:
                object.__setattr__(self, "_prompt_error", str(exc))

    def system_prompt(self) -> str:
        if self._system_prompt is None:
            raise PromptConfigurationError(self._prompt_error or "private system text is unavailable")
        return self._system_prompt

    @classmethod
    def from_env(cls, *, mode: str | None = None):
        return cls(service_token=os.getenv("FUSE_SERVICE_TOKEN", ""),
                   mode=mode if mode is not None else os.getenv("FUSE_KYC_MODE", "replay").lower(),
                   model=os.getenv("FUSE_LLM_MODEL", ""),
                   api_key=os.getenv("FUSE_LLM_API_KEY", ""),
                   prompt_path=os.getenv("FUSE_KYC_PROMPT_PATH", ""),
                   private_documents_path=os.getenv("FUSE_PRIVATE_DOCUMENTS_PATH", ""),
                   base_url=os.getenv("FUSE_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/"))

    def errors(self) -> list[str]:
        errors = []
        if len(self.service_token.encode("utf-8")) < 32 or self.service_token == "CHANGE_ME" or any(c.isspace() or c == "," for c in self.service_token):
            errors.append("FUSE_SERVICE_TOKEN is required")
        if self.mode not in {"replay", "offline", "live"}:
            errors.append("FUSE_KYC_MODE must be replay, offline, or live")
        if self.mode == "live":
            if self._prompt_error:
                errors.append(self._prompt_error)
            if not self.model or not self.api_key or self.api_key == "CHANGE_ME":
                errors.append("live mode requires FUSE_LLM_MODEL and FUSE_LLM_API_KEY")
            url = urlparse(self.base_url)
            if self.base_url != "https://api.openai.com/v1":
                errors.append("model endpoint is not registered")
            if url.username or url.password or url.query or url.fragment:
                errors.append("model endpoint must not contain credentials, query, or fragment")
        return errors
