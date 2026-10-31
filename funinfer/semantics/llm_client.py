"""LLM access layer: OpenAI-compatible chat endpoint with retries and
robust JSON extraction."""
import json
import logging
import re

from openai import OpenAI

from funinfer.config import Config
from funinfer.semantics.prompts import PromptBuilder

logger = logging.getLogger(__name__)

_JSON_RE = re.compile(r'\{.*?\}', re.DOTALL)


class LLMClient:
    def __init__(self):
        self.client = OpenAI(api_key=Config.LLM_API_KEY,
                             base_url=Config.LLM_BASE_URL,
                             timeout=Config.LLM_TIMEOUT)
        self.infer_model = Config.INFER_MODEL

    def _safe_request(self, system_prompt: str, user_content: str,
                      model: str, retries: int = Config.LLM_RETRIES) -> dict:
        for attempt in range(retries + 1):
            try:
                completion = self.client.chat.completions.create(
                    model=model,
                    temperature=0,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_content}
                    ]
                )
                content_raw = completion.choices[0].message.content
            except Exception as e:
                logger.error(f"Attempt {attempt + 1}: request error - {str(e)[:120]}")
                continue

            match = _JSON_RE.search(content_raw)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError as e:
                    logger.error(f"Attempt {attempt + 1}: JSON decode error - {e}")
            else:
                logger.error(f"Attempt {attempt + 1}: no JSON found in response.")
        return {}

    def query_name(self, code: str, parent_params: dict = None,
                   is_pure_body: bool = False) -> dict:
        prompt = PromptBuilder.build_inference_prompt(code, parent_params, is_pure_body)
        return self._safe_request("You provide programming suggestions.",
                                  prompt, self.infer_model)

    def query_summary(self, code: str, parent_params: dict = None,
                      is_pure_body: bool = False) -> str:
        prompt = PromptBuilder.build_summary_prompt(code, parent_params,
                                                    is_pure_body, Config.LSUMMARY)
        res = self._safe_request("You provide programming suggestions.",
                                 prompt, self.infer_model)
        return res.get('summary', '')

    def enhance_summary(self, summary: str, parent_params: dict) -> str:
        """Backtracking step: rewrite a summary so it also encodes how the
        parent contexts use the function."""
        prompt = PromptBuilder.build_backtrack_prompt(summary, parent_params,
                                                      Config.LSUMMARY)
        res = self._safe_request("You provide programming suggestions.",
                                 prompt, self.infer_model)
        return res.get('summary', '')
