"""OSINT agent — self-hosted model layer.

Provider interface so the model can be swapped without touching the
agent core. Ollama-first; any OpenAI-compatible local endpoint
(LM Studio, llama.cpp server, vLLM) works via the same interface.

No cloud API keys are required. By default no data leaves the machine:
the model runs on localhost. If no model is reachable, the agent runs
in no-model mode — tools still run, the LLM step is skipped with a
clear note, and the report says so.
"""
import json
import urllib.error
import urllib.request

DEFAULT_TIMEOUT = 120


class LLMError(Exception):
    pass


class LLMProvider:
    """Base provider. Subclasses implement chat()."""

    name = "base"

    def chat(self, system, user, temperature=0.2):
        raise NotImplementedError

    def ping(self):
        """True if the model endpoint answers, False otherwise."""
        try:
            self.chat("You are a test.", "Reply with the single word: ok",
                      temperature=0.0)
            return True
        except Exception:
            return False


class NullProvider(LLMProvider):
    """No-model provider. Used in dry-run / no-Ollama mode."""

    name = "none"

    def chat(self, system, user, temperature=0.2):
        raise LLMError("no model configured — running in no-model mode; "
                       "LLM step skipped, tools and verifier still ran")


def _post_json(url, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:500]
        raise LLMError(f"model endpoint HTTP {exc.code}: {body}")
    except urllib.error.URLError as exc:
        raise LLMError(f"cannot reach model endpoint {url}: {exc.reason}")
    except TimeoutError:
        raise LLMError(f"model endpoint timed out after {timeout}s")


class OllamaProvider(LLMProvider):
    """Ollama — POST /api/chat. Default endpoint http://localhost:11434."""

    name = "ollama"

    def __init__(self, endpoint="http://localhost:11434", model="llama3.1:8b",
                 timeout=DEFAULT_TIMEOUT):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    def chat(self, system, user, temperature=0.2):
        out = _post_json(f"{self.endpoint}/api/chat", {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": temperature},
        }, self.timeout)
        try:
            return out["message"]["content"].strip()
        except (KeyError, TypeError):
            raise LLMError(f"unexpected Ollama response: {str(out)[:300]}")


class OpenAICompatibleProvider(LLMProvider):
    """Any OpenAI-compatible local endpoint: LM Studio, llama.cpp, vLLM.

    Endpoint is the base URL, e.g. http://localhost:1234/v1
    """

    name = "openai-compatible"

    def __init__(self, endpoint="http://localhost:1234/v1",
                 model="local-model", timeout=DEFAULT_TIMEOUT, api_key=""):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.api_key = api_key

    def chat(self, system, user, temperature=0.2):
        out = _post_json(f"{self.endpoint}/chat/completions", {
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "temperature": temperature,
        }, self.timeout)
        try:
            return out["choices"][0]["message"]["content"].strip()
        except (KeyError, TypeError, IndexError):
            raise LLMError(f"unexpected response: {str(out)[:300]}")


def build_provider(config):
    """Build the provider named in config. Unknown / unreachable model
    does not raise here — the agent checks reachability at run time
    and falls back to NullProvider with a note in the report."""
    kind = (config.get("model", {}).get("provider") or "ollama").lower()
    model_cfg = config.get("model", {})
    if kind == "ollama":
        return OllamaProvider(
            endpoint=model_cfg.get("endpoint", "http://localhost:11434"),
            model=model_cfg.get("name", "llama3.1:8b"),
            timeout=model_cfg.get("timeout_seconds", DEFAULT_TIMEOUT))
    if kind in ("openai-compatible", "lmstudio", "lm_studio"):
        return OpenAICompatibleProvider(
            endpoint=model_cfg.get("endpoint", "http://localhost:1234/v1"),
            model=model_cfg.get("name", "local-model"),
            timeout=model_cfg.get("timeout_seconds", DEFAULT_TIMEOUT),
            api_key=model_cfg.get("api_key_env") or "")
    if kind in ("none", "null", "dry-run"):
        return NullProvider()
    raise ValueError(f"unknown model provider in config: {kind!r} "
                     "(use ollama, openai-compatible, or none)")


# Prompts the agent sends to the model. The model never decides what is
# verified — it only drafts analysis; the 6-gate verifier decides.
SYSTEM_PROMPT = (
    "You are an OSINT analyst assistant. Lawful public OSINT only: "
    "no hacking, no bypassing private settings, no DMs, location or "
    "phone data, no contacting targets. Evidence first: name confidence "
    "(High / Medium / Low / Unverified / Cannot determine), separate "
    "confirmed facts from inferences from unknowns, never merge people "
    "on name alone, never present a clue as a fact. If evidence is "
    "missing, say so plainly."
)

PLAN_PROMPT = (
    "Given the case intake and the available tools, propose an ordered "
    "investigation plan. Keep sweeps small (<=5 posts, >=5s apart), "
    "stop on HTTP 429, and list what would confirm or disprove each "
    "key claim. Return the plan as a numbered list, one step per line."
)

SYNTHESIS_PROMPT = (
    "Given the tool results below (each with source, date and "
    "confidence), draft the findings section of an OSINT report. "
    "Separate Confirmed / Inferred / Unverified. Do not invent "
    "evidence, do not upgrade a clue to a fact, and flag every claim "
    "whose timing or identity is unverified."
)
