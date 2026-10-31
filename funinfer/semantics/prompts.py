"""Prompt templates used by the FunInferAgent pipeline."""


class PromptBuilder:
    @staticmethod
    def build_inference_prompt(code: str, parent_params: dict = None,
                               is_pure_body: bool = False) -> str:
        if is_pure_body:
            prompt = """Analyze the code snippet. This is a base-level computational function without external library calls. Focus exclusively on its internal body semantics, data flow, and algorithmic logic.
Propose a concise, specific snake_case name that reflects what the function DOES (e.g. parse_cfg, free_buffer, validate_signature). Avoid generic names such as doStuff, callSub, helper, process, func.
CRITICAL: Preserve recognizable library/API prefixes and specific domain terms VISIBLE in the decompiled code (called library functions, string literals, struct/field names). Match the codebase's naming convention: e.g. if the code calls sqlite3BtreeNew/sqlite3_xxx, name it sqlite3_<action>; if x264_encoder_open/x264_xxx, use x264_<action>; if EVP_/OSSL_/ssh_/dav1d_, use that prefix. Use the concrete nouns/verbs from the code; do NOT replace a visible domain term with a generic word like handle/get_value/process_data.
If this is a compiler-generated init/fini stub, use the conventional name: deregister_tm_clones, register_tm_clones, frame_dummy, do_global_dtors_aux, __cxa_finalize.
Output the mapping from the CURRENT function name to the proposed name in a *single* JSON dictionary.
Example: {{"sub_401000": "parse_cfg"}}\n{code}""".format(code=code)
        else:
            prompt = """Analyze the code snippet and its parent function call context.
Parent call contexts show how this function is actually used.
Focus on parameter usage patterns in the contexts.
Propose a concise, specific snake_case name that reflects what the function DOES (e.g. parse_cfg, free_buffer, validate_signature). Avoid generic names such as doStuff, callSub, helper, process, func.
CRITICAL: Preserve recognizable library/API prefixes and specific domain terms VISIBLE in the decompiled code (called library functions, string literals, struct/field names). Match the codebase's naming convention: e.g. if the code calls sqlite3BtreeNew/sqlite3_xxx, name it sqlite3_<action>; if x264_encoder_open/x264_xxx, use x264_<action>; if EVP_/OSSL_/ssh_/dav1d_, use that prefix. Use the concrete nouns/verbs from the code; do NOT replace a visible domain term with a generic word like handle/get_value/process_data.
If this is a compiler-generated init/fini stub, use the conventional name: deregister_tm_clones, register_tm_clones, frame_dummy, do_global_dtors_aux, __cxa_finalize.
Output the mapping from the CURRENT function name to the proposed name in a *single* JSON dictionary.
Example: {{"sub_401000": "parse_cfg"}}\n{code}""".format(code=code)

        if parent_params and not is_pure_body:
            prompt += "\n//Parent Call Contexts:\n"
            for i, (func_name, contexts) in enumerate(parent_params.items()):
                prompt += f"// From the No.{i+1} parent function code snippet:\n"
                for ctx in contexts:
                    prompt += f"/*\n{ctx['context']}\n*/\n"
        return prompt

    @staticmethod
    def build_summary_prompt(code: str, parent_params: dict = None,
                             is_pure_body: bool = False,
                             lsummary: int = 100) -> str:
        if is_pure_body:
            prompt = """Help me summarize the code snippet in the following C code in one sentence.
This function contains purely internal logic without library anchors. Focus strictly on its algorithmic operations.
Output the summary in a *single* JSON dictionary. Do not exceed {lsummary} words.
Use format: {{"summary": "..."}}\n{code}""".format(code=code, lsummary=lsummary)
        else:
            prompt = """Help me summarize the code snippet in the following C code in one sentence.
Output the summary in a *single* JSON dictionary. Do not exceed {lsummary} words.
Use format: {{"summary": "..."}}\n{code}""".format(code=code, lsummary=lsummary)

        if parent_params and not is_pure_body:
            prompt += "\nParent Call Contexts:\n"
            for func_name, contexts in parent_params.items():
                prompt += f"From {func_name}:\n"
                for ctx in contexts:
                    prompt += f"// Called at {ctx['call_address']}:\n{ctx['context']}\n"
        return prompt

    @staticmethod
    def build_backtrack_prompt(summary: str, parent_params: dict,
                               lsummary: int = 100) -> str:
        """Rewrite a function summary so it also reflects how callers use it."""
        context_str = ""
        for func_name, contexts in parent_params.items():
            for ctx in contexts:
                context_str += f"/* {ctx['context']} */\n"

        return f"""Rewrite and refine the following function summary by incorporating insights from its parent call context.
Original Summary: {summary}
Parent Call Contexts:
{context_str}
Create a unified, single-sentence summary (max {lsummary} words) that describes both what the function does and how it is used.
Output format: {{"summary": "..."}}"""
