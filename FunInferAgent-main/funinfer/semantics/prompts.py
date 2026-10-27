class PromptBuilder:
    @staticmethod
    def build_inference_prompt(code: str, parent_params: dict) -> str:
        prompt = f"""Analyze the code snippet and its parent function call context.
Parent call contexts show how this function is actually used. Focus on parameter usage patterns.
Output the old name and its new name in a *single* JSON dictionary.
Example: {{"old_name": "new_name"}}\n{code}"""
        
        if parent_params:
            prompt += "\n//Parent Call Contexts:\n"
            for i, (func_name, contexts) in enumerate(parent_params.items()):
                prompt += f"// From the No.{i+1} parent function code snippet:\n"
                for ctx in contexts:
                    prompt += f"/*\n{ctx['context']}\n*/\n"
        return prompt

    @staticmethod
    def build_summary_prompt(code: str, parent_params: dict) -> str:
        prompt = f"""Help me summarize the code snippet in the following C code in one sentence. 
Output the summary in a *single* JSON dictionary. Do not exceed 100 words.
Use format: {{"summary": "..."}}\n{code}"""

        if parent_params:
            prompt += "\nParent Call Contexts:\n"
            for func_name, contexts in parent_params.items():
                prompt += f"From {func_name}:\n"
                for ctx in contexts:
                    prompt += f"// Called at {ctx['call_address']}:\n{ctx['context']}\n"
        return prompt