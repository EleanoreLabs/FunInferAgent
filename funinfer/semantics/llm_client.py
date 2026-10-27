import json
import logging
from openai import OpenAI
from funinfer.config import Config
from funinfer.semantics.prompts import PromptBuilder

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(self):
        self.client = OpenAI(api_key=Config.LLM_API_KEY, base_url=Config.LLM_BASE_URL)
        self.infer_model = Config.INFER_MODEL

    def _safe_request(self, system_prompt: str, user_content: str, model: str) -> dict:
        try:
            completion = self.client.chat.completions.create(
                model=model,
                temperature=0,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ]
            )
            content_raw = completion.choices[0].message.content.replace('\n', '')
            head, tail = content_raw.find('{'), content_raw.rfind('}')
            
            if head == -1 or tail == -1:
                return {}
                
            return json.loads(content_raw[head:tail + 1])
        except Exception as e:
            logger.error(f"LLM Error: {e}")
            return {}

    def query_name(self, code: str, parent_params: dict = None) -> dict:
        prompt = PromptBuilder.build_inference_prompt(code, parent_params)
        return self._safe_request("You provide programming suggestions.", prompt, self.infer_model)

    def query_summary(self, code: str, parent_params: dict = None) -> str:
        prompt = PromptBuilder.build_summary_prompt(code, parent_params)
        res = self._safe_request("You provide programming suggestions.", prompt, self.infer_model)
        return res.get('summary', '')