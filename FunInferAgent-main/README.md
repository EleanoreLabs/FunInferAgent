# FunInferAgent: Inferring Function Names via Bidirectional Semantic Transfer

This repository contains the official implementation of **FunInferAgent**, a framework that infers stripped binary function names via bidirectional semantic transfer and Large Language Models.

## Features
* **Bidirectional Semantic Extraction**: Integrates contextual information from both caller (parent) and callee (sub-function) functions along the call chain.
* **Dynamic Sliding Window**: Efficiently extracts semantic features from decompiled code snippets proximal to function call sites.
* **Multi-level Semantic Fusion**: Aggregates internal semantics ($S_2$), sub-function semantics ($S_1$), and parent function calling contexts ($S_3$).
* **LLM-Driven Inference**: Utilizes instruction-tuned models (e.g., Qwen2.5-Coder) for semantic alignment and prediction.

## Prerequisites
* IDA Pro (7.5+ recommended, with Hex-Rays decompiler) 
* Python 3.10+
* `pip install -r requirements.txt`

## Usage

1. **Configure Environment**: Update `funinfer/config.py` with your LLM API endpoint and model settings.
2. **Automated Pipeline**: Run the external automation script to process your binaries:
   ```bash
   python run_automation.py -s main_ida_pipeline.py -b /path/to/binary