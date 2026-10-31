# FunInferAgent: Inferring Function Names via Bidirectional Semantic Transfer

The implementation of **FunInferAgent**, a framework that recovers names of
functions in stripped binaries by fusing three semantic sources through
bidirectional transfer, driven by an LLM:

* **S1 — callee summaries**: natural-language summaries of already-processed
  sub-functions, injected as comments;
* **S2 — local body**: the function's own Hex-Rays decompiled code;
* **S3 — parent contexts**: sliding-window decompiled snippets around every
  call site in caller functions.

## Repository layout

```
main_ida_pipeline.py        IDA entry point (runs inside idat64)
run_automation.py           Single-binary automation wrapper
config.template.env         Configuration template (no credentials)
funinfer/
  config.py                 All settings, env-overridable (Config)
  core/bidirectional_bfs.py FunInferPipeline — the layer-by-layer BFS engine
  extraction/ida_analyzer.py    Function discovery, call-graph queries, renaming
  extraction/context_parser.py  Sliding-window decompiler context extraction
  semantics/llm_client.py       LLM requests with retries + robust JSON parsing
  semantics/prompts.py          All prompt templates
baselines/general_baseline.py   Vanilla LLM baseline (S2 only, no transfer)
scripts/
  run_pipeline.py             End-to-end driver over the 4 evaluation binaries
  parse_rename_log.py         Pipeline log -> {address: name} JSON
  eval_semantic.py            Semantic P/R/F1 (CodeWordNet-style judge)
  build_dataset.sh            stripped binary + ground-truth CSV builder
assets/segmentation.model     SentencePiece model used by eval_semantic.py
```

## Prerequisites

* IDA Pro 7.5+ with Hex-Rays (headless `idat64`; the IDA user directory must
  contain an accepted EULA — run IDA once in the GUI, or set `IDAUSR`)
* Python 3.10+
* An OpenAI-compatible LLM endpoint: [Ollama](https://ollama.com),
  [vLLM](https://docs.vllm.ai), or a hosted API
* `pip install -r requirements.txt`

## Configuration

Copy `config.template.env`, edit it, and `source` it (or export the variables
directly). No credentials are stored in the repository; `funinfer/config.py`
contains only defaults and reads every value from the environment.

Minimum:

```bash
export FUNINFER_LLM_BASE_URL=""   # your endpoint
export FUNINFER_MODEL=""                  # your model
export IDAT64=/path/to/idat64
```

## Evaluation data: how to obtain or construct it

The evaluation set consists of per project, built from
public open-source projects (any recent source release works).

Build each project from source with symbols retained, then produce the pair
(stripped input + ground truth) with:

```bash
scripts/build_dataset.sh /path/to/built/openssl dataset/crypto openssl
# -> dataset/crypto/openssl.strip   (input)
# -> dataset/crypto/openssl.gt.csv  (ground truth: "address,name" from nm)
```

Expected layout (paths overridable via `FUNINFER_DATASET`):

```
dataset/{crypto,database,network,video}/binaries
dataset/{crypto,database,network,video}/binaries
```

## Running the experiments

### Main experiment (FunInferAgent, full pipeline)

```bash
python scripts/run_pipeline.py --jobs 4
```

This runs IDA auto-analysis, the bidirectional BFS pipeline, log parsing, and
the token-overlap P/R/F1 for all binaries. Semantic P/R/F1:

```bash
python scripts/eval_semantic.py dataset/crypto/openssl.gt.csv \
    dataset/crypto/openssl.strip.i64.recover_map.json
```

`eval_semantic.py` implements both evaluation methods from the paper
(§4.1.4) and selects one via the `THRESHOLD` env var:
`THRESHOLD=0` (default) — token-based CodeWordNet-LLM P/R/F1;
`THRESHOLD=80` — score-based LLM-judge P/R/F1. The judge endpoint/model
are the `FUNINFER_LLM_BASE_URL` / `FUNINFER_EVAL_MODEL` variables.

### Comparison against the Vanilla-LLM baseline

```bash
python run_automation.py -s baselines/general_baseline.py -b dataset/crypto/openssl.strip
```

then evaluate the resulting `.general_baseline.log.txt` the same way
(`parse_rename_log.py` + `eval_semantic.py`).

### External baselines: AsmDepictor, Nero, SymLM, XFL

The four external baselines are vendored under `baselines/`:

| method      | repository                                    | native prediction output |
|-------------|-----------------------------------------------|--------------------------|
| AsmDepictor | `baselines/AsmDepictor-main/AsmDepictor-main` | `predicted_output/prediction.txt` |
| Nero        | `baselines/Nero-main/Nero-main`               | `<save>_9999_log.txt` |
| SymLM       | `baselines/SymLM-main/SymLM-main`             | `training_evaluation/prediction_evaluation/evaluation_input.txt` |
| XFL         | `baselines/xfl-main/xfl-main/xfl-r/XFL`       | `deduction.log` (XFL-R) |

None of the four baselines prints the function start address next to the
predicted name, so each run must additionally produce an *address sidecar*
that maps the method's native sample order or identifier to the function
address in the stripped binary. `baselines/method_baseline.py` accepts this
sidecar as JSON (ordered list, or identifier→address mapping), converts the
native output into the unified `{address: name}` recover map, and evaluates
it with the same FunInferAgent evaluator. Pretrained models and method-specific
databases are not bundled in this repository and must be obtained from the
upstream projects before running the baselines.

```bash
python baselines/method_baseline.py \
    --method symlm \
    --gt    dataset/crypto/openssl.gt.csv \
    --prediction work/symlm/evaluation_input.txt \
    --sidecar    work/symlm/address_sidecar.json \
    --output     work/symlm/recover_map.json \
    --threshold  80
```

To run all four baselines when the work directory contains one folder per
method, use the `{method}` placeholder:

```bash
python baselines/method_baseline.py \
    --method all \
    --gt    dataset/crypto/openssl.gt.csv \
    --prediction work/{method}/prediction.txt \
    --sidecar    work/{method}/address_sidecar.json \
    --output     work/{method}/recover_map.json \
    --threshold  80
```

`--threshold` is forwarded to `scripts/eval_semantic.py` as `THRESHOLD`
(`0` = token-based CodeWordNet-LLM, `>0` = score-based LLM judge).

### Ablation studies (RQ3)

```bash
FUNINFER_ABLATION=wo_s1 python scripts/run_pipeline.py   # w/o callee summaries (S1)
FUNINFER_ABLATION=wo_s2 python scripts/run_pipeline.py   # w/o local decompiled code (S2)
FUNINFER_ABLATION=wo_s3 python scripts/run_pipeline.py   # w/o parent contexts (S3)
```

### Parameter sensitivity (§4.4.2)

One-factor-at-a-time over the two prompt budgets:

```bash
LPARENT=0  LSUMMARY=100 python scripts/run_pipeline.py   # LPARENT in {0,1,2,3,5,8,10}
LPARENT=5  LSUMMARY=50  python scripts/run_pipeline.py   # LSUMMARY in {10,25,50,100,200}
```

## Data availability

Binaries are freely available from their official repositories under their respective open-source licenses.

The stripped binaries and ground-truth CSVs used in our experiments can be
regenerated exactly with `scripts/build_dataset.sh` as described above; no
proprietary or access-restricted data is required.

The complete evaluation dataset (stripped binaries, ground-truth CSVs, and the
`assets/segmentation.model` SentencePiece file) and the full source code are
publicly released on the project's GitHub Releases page:

* Repository: https://github.com/EleanoreLabs/FunInferAgent
* Datasets release (direct download):
  https://github.com/EleanoreLabs/FunInferAgent/releases/tag/datasets
