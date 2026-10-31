"""Central configuration for FunInferAgent.

No credentials or machine-specific endpoints are stored in this file.
Every setting can be overridden through environment variables, e.g.:

    export FUNINFER_LLM_BASE_URL="http://127.0.0.1:11434/v1"
    export FUNINFER_MODEL="qwen2.5-coder:32b"

Copy `config.template.env` (repo root), adjust it and `source` it — or set
the variables directly — before running `main_ida_pipeline.py`.
"""
import os


def _int_env(names, default):
    for n in names:
        v = os.environ.get(n)
        if v is not None:
            return int(v)
    return default


class Config:
    # ----- LLM endpoint (OpenAI-compatible: Ollama, vLLM, OpenAI, ...) -----
    LLM_BASE_URL = os.environ.get(
        "FUNINFER_LLM_BASE_URL",
        os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434/v1"))
    # Local servers (Ollama/vLLM) ignore the key; pass any non-empty string.
    LLM_API_KEY = os.environ.get("FUNINFER_LLM_API_KEY", "ollama")
    INFER_MODEL = os.environ.get("FUNINFER_MODEL", "qwen2.5-coder:32b")

    # ----- Semantic evaluation (LLM-as-judge) -----
    EVAL_MODEL = os.environ.get("FUNINFER_EVAL_MODEL", "qwen2.5-coder:32b")
    EVAL_THRESHOLD = float(os.environ.get("FUNINFER_EVAL_THRESHOLD", "80"))

    # ----- Request behaviour -----
    LLM_TIMEOUT = _int_env(["FUNINFER_LLM_TIMEOUT"], 1800)   # seconds
    LLM_RETRIES = _int_env(["FUNINFER_LLM_RETRIES"], 3)

    # ----- Binary analysis scope -----
    BYPASS_SECTIONS = ['extern', '.fini', '.init', '.plt.sec', '.plt']

    # ----- Context extraction -----
    # Sliding window: lines of decompiled code kept around each call site.
    CONTEXT_WINDOW_SIZE = _int_env(["FUNINFER_CONTEXT_WINDOW"], 5)
    # Max parent call contexts per function (parameter sensitivity axis LPARENT).
    MAX_CONTEXT_COUNT = _int_env(["LPARENT", "FUNINFER_MAX_CONTEXT_COUNT"], 5)
    # Max words of each callee summary (sensitivity axis LSUMMARY).
    LSUMMARY = _int_env(["LSUMMARY", "FUNINFER_LSUMMARY"], 100)

    # ----- Ablation switch: "" (full) | "wo_s1" | "wo_s2" | "wo_s3" -----
    #   wo_s1: remove callee (sub-function) summaries  (S1)
    #   wo_s2: remove local decompiled code            (S2)
    #   wo_s3: remove parent call contexts             (S3)
    ABLATION = os.environ.get("FUNINFER_ABLATION", "").strip().lower()
