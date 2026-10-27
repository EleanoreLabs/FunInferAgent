import json
import logging
from openai import OpenAI
from funinfer.config import Config

class SemanticEvaluator:
    def __init__(self):
        self.client = OpenAI(api_key=Config.LLM_API_KEY, base_url=Config.LLM_BASE_URL)
        self.model = Config.EVAL_MODEL

    def get_score(self, origin_name: str, predict_name: str) -> float:
        content = f"""You are an experienced C/C++ reverse engineer.
Please rate the match between the original function name '{origin_name}' and the predicted function name '{predict_name}' on a scale from 0 to 100.
The evaluation should focus on the semantic alignment.
Output the score in a single JSON dictionary. Do not use any markdown formatting. Example: {{"score":"100"}}"""

        try:
            completion = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You provide programming suggestions."},
                    {"role": "user", "content": content}
                ]
            )
            content_raw = completion.choices[0].message.content.replace('\n', '')
            head, tail = content_raw.find('{'), content_raw.rfind('}')
            res = json.loads(content_raw[head:tail+1])
            return float(res.get("score", 0))
        except Exception as e:
            logging.error(f"Scoring failed: {e}")
            return 0.0