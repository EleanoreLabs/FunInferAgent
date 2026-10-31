#!/usr/bin/env python3
"""Semantic P/R/F1 for recovered function names.

Faithful adaptation of the paper's CodeWordNet-LLM evaluation. Only
environment-specific bits changed:
  - segmentation.model path -> <repo>/assets/segmentation.model
  - LLM endpoint  -> $FUNINFER_LLM_BASE_URL ,
  - judge model   -> $FUNINFER_EVAL_MODEL ,
    default qwen2.5-coder:32b
  - inputs via argv (origin_csv, predict_csv_or_json); robust no-header read
  - LLM judge calls parallelized (deterministic, temp=0 -> identical results)

Scoring logic (func_name_preprocessing + get_result_from_openai + TP/FP/FN sum)
is reproduced verbatim from the original evaluation script.

Usage:
  THRESHOLD=0  (default) token-based CodeWordNet-LLM P/R/F1
  THRESHOLD=80 score-based LLM-judge P/R/F1 (Table 3 style)
"""
import os, sys, json, re, time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import sentencepiece as spm
import nltk
from nltk.stem.wordnet import WordNetLemmatizer
from nltk.corpus import wordnet
from openai import OpenAI

def _env(names, default):
    """First defined environment variable among `names`, else `default`."""
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default

OLLAMA_URL = _env(["FUNINFER_LLM_BASE_URL", "OLLAMA_URL"],
                  "")
EVAL_MODEL = _env(["FUNINFER_EVAL_MODEL", "EVAL_MODEL"], "qwen2.5-coder:32b")
SEG_MODEL = os.environ.get("SEG_MODEL", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets", "segmentation.model"))
JOBS = int(os.environ.get("EVAL_JOBS", "8"))
API_KEY = _env(["FUNINFER_LLM_API_KEY"], "ollama")  # local servers ignore it

client = OpenAI(api_key=API_KEY, base_url=OLLAMA_URL)
sp = spm.SentencePieceProcessor()
sp.load(SEG_MODEL)
lem = WordNetLemmatizer()
# Functional guard: only download if actual use raises LookupError (nltk.data.find
# gives false negatives for renamed resources and can hang on network downloads).
def _ensure_nltk():
    try:
        from nltk.corpus import wordnet as _w; _w.synsets("test")
    except LookupError:
        nltk.download("wordnet", quiet=True)
    try:
        nltk.pos_tag(["test"])
    except LookupError:
        nltk.download("averaged_perceptron_tagger_eng", quiet=True)
_ensure_nltk()

def get_pos(treebank_tag):
    if treebank_tag.startswith('J'): return wordnet.ADJ
    elif treebank_tag.startswith('V'): return wordnet.VERB
    elif treebank_tag.startswith('N'): return wordnet.NOUN
    elif treebank_tag.startswith('R'): return wordnet.ADV
    else: return None

def func_name_segmentation(word):
    res = sp.encode_as_pieces(word)
    res[0] = res[0][1:]
    return res

def func_name_preprocessing(func_name):
    func_name = func_name.lower().replace('_', ' ')
    tmp = ''
    for c in func_name:
        if not c.isalpha(): tmp = tmp + ' '
        elif c.isupper(): tmp = tmp + ' ' + c
        else: tmp = tmp + c
    tmp = tmp.strip().split(' ')
    res = []
    i = 0
    while i < len(tmp):
        cap = ''; t = tmp[i]
        while i < len(tmp) and len(tmp[i]) == 1:
            cap = cap + tmp[i]; i += 1
        if len(cap) == 0: res.append(t); i += 1
        else: res.append(cap)
    words = [w for w in res if isinstance(w, str) and w != '']
    tokens = nltk.pos_tag(words)
    res = []
    for word, tag in tokens:
        wntag = get_pos(tag)
        word = lem.lemmatize(word) if wntag is None else lem.lemmatize(word, pos=wntag)
        res.append(word)
    final_words = []
    for word in res:
        if not isinstance(word, str) or word == '': continue
        for w in func_name_segmentation(word):
            if isinstance(w, str) and w != '': final_words.append(w)
    if len(final_words) == 0: return None
    return ' '.join(final_words).lower()

def get_score_from_openai(origin_name, predict_name):
    """LLM scores 0-100 how well predicted matches origin (LLM Evaluator, Table 3)."""
    content = f"""
You are an experienced C/C++ reverse engineer.
Please act as an impartial judge and evaluate the quality of function names.
Please rate the match between the original function name '{origin_name}' and the predicted function name '{predict_name}' on a scale from 0 to 100, where 0 means completely unrelated and 100 means they are identical or very similar.
The evaluation should focus on the semantic alignment and the ability of the predicted name '{predict_name}' to accurately represent the functionality described by the original name '{origin_name}'.
When comparing semantics, case and separator are not sensitive.
91-100: identical or interchangeable. 81-90: roughly summarizes. 71-80: includes + basic summary. 60-70: related but different. 0-59: minimal correlation.
Output in a single JSON dictionary: {{"score":"100"}}
Now rate: """
    try:
        payload = json.dumps({
            "model": EVAL_MODEL, "temperature": 0,
            "messages": [{"role": "system", "content": "You provide the programming suggestions."},
                         {"role": "user", "content": content}]
        }).encode("utf-8")
        req = urllib.request.Request(OLLAMA_URL + "/chat/completions", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as resp:
            raw = json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
        m = re.search(r'"score"\s*:\s*"?(\d+)', raw)
        return float(m.group(1)) if m else 0.0
    except Exception as e:
        print(f"get_score ERR: {str(e)[:120]}  url={OLLAMA_URL}  model={EVAL_MODEL}", flush=True)
        return 0.0

def semantic_evaluation_score(origin_list, predict_list, threshold=80):
    """Score-based eval: LLM scores each pair 0-100; score >= threshold = TP."""
    TP = FP = FN = 0
    n = min(len(origin_list), len(predict_list))
    done = 0
    def judge(o, p):
        return get_score_from_openai(o, p)
    with ThreadPoolExecutor(max_workers=JOBS) as ex:
        futs = {ex.submit(judge, origin_list[i], predict_list[i]): i for i in range(n)}
        scores = [0.0] * n
        for f in as_completed(futs):
            idx = futs[f]; scores[idx] = f.result(); done += 1
            if done % 100 == 0:
                tp = sum(1 for s in scores[:done] if s >= threshold)
                print(f"  scored {done}/{n}  TP={tp}", flush=True)
    for s in scores:
        if s >= threshold: TP += 1
        else: FP += 1; FN += 1
    # GT without predicted (not matched) → FN; predicted without GT → FP
    FN += max(0, len(origin_list) - n)
    FP += max(0, len(predict_list) - n)
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "TP": TP, "FP": FP, "FN": FN, "pairs": n}

def get_result_from_openai(origin_name, predict_name):
    content = f"""
Below are the true and predicted values of the function name after word segmentation. Please give me a list of TP, FP, and FN based on their correlation.

The predicted function name meaning is related to the original function name and can also be used as TP

For example:
Ture function name: ["oss", "cmp", "ctx", "set", "cert"]
Predicted function name: ["oss", "cmp", "ctx", "set", "log"]
Result: {{"TP":["oss", "cmp", "ctx", "set"], "FP": ["cert"], "FN": ["log"]}}

Here is your data:
Ture function name: {json.dumps(origin_name.split(' '))}
Predicted function name: {json.dumps(predict_name.split(' '))}
What is the result?
"""
    try:
        completion = client.chat.completions.create(
            model=EVAL_MODEL, temperature=0,
            messages=[{"role": "system", "content": "You provide the programming suggestions."},
                      {"role": "user", "content": content}])
        content_raw = completion.choices[0].message.content.replace('\n', '')
        head = content_raw.find('{'); tail = content_raw.find('}', head)
        if head == -1 or tail == -1: return 0, 0, 0
        content_json = content_raw[head:tail+1]
        res = json.loads(content_json)
        return len(res["TP"]), len(res["FP"]), len(res["FN"])
    except Exception as e:
        return 0, 0, 0

def semantic_evaluation(origin_names, predict_names, log_fp):
    pairs = list(zip(origin_names, predict_names))
    TP = FP = FN = 0
    def judge(o, p):
        ot = func_name_preprocessing(o) or ''
        pt = func_name_preprocessing(p) or ''
        if not ot or not pt: return (0, 0, 0)
        return get_result_from_openai(ot, pt)
    done = 0
    with ThreadPoolExecutor(max_workers=JOBS) as ex:
        futs = {ex.submit(judge, o, p): (o, p) for (o, p) in pairs}
        for f in as_completed(futs):
            tp, fp, fn = f.result()
            TP += tp; FP += fp; FN += fn
            done += 1
            if done % 50 == 0:
                print(f"  judged {done}/{len(pairs)}  TP={TP} FP={FP} FN={FN}", flush=True)
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "TP": TP, "FP": FP, "FN": FN, "pairs": len(pairs)}

def load_names(path):
    if path.endswith(".json"):
        m = json.load(open(path))
        items = sorted(m.items(), key=lambda kv: int(kv[0], 16))
        return [v for _, v in items]
    df = pd.read_csv(path)
    if 'name' not in df.columns:
        df = pd.read_csv(path, header=None, names=['address', 'name'])
    return df['name'].dropna().astype(str).tolist()

def load_addr_map(path):
    """Return {int_address: name}. Addresses normalized to int so GT csv (0x000...3f000)
    and recover_map json (0x3f000) match regardless of zero-padding."""
    m = {}
    if path.endswith(".json"):
        for a, n in json.load(open(path)).items():
            try: m[int(str(a), 16)] = n
            except Exception: pass
    else:
        df = pd.read_csv(path)
        if 'name' not in df.columns:
            df = pd.read_csv(path, header=None, names=['address', 'name'])
        for a, n in zip(df['address'], df['name']):
            try:
                if pd.notna(n): m[int(str(a), 16)] = str(n)
            except Exception: pass
    return m

if __name__ == '__main__':
    origin_file = sys.argv[1]; predict_file = sys.argv[2]
    # Optional third argument: progress log file (default: no extra log).
    log_fp = open(sys.argv[3], "w", buffering=1, encoding="utf-8",
                  errors="replace") if len(sys.argv) > 3 else None
    THRESHOLD = int(os.environ.get("THRESHOLD", "0"))  # 0 = token-based (CodeWordNet-LLM); >0 = score-based (LLM Evaluator)
    # Address-align (same function: GT name vs predicted name)
    om = load_addr_map(origin_file); pm = load_addr_map(predict_file)
    common = sorted(set(om) & set(pm))
    origin_list = [om[a] for a in common]; predict_list = [pm[a] for a in common]
    print(f"matched(by-addr)={len(common)}  origin_total={len(om)}  predict_total={len(pm)}  model={EVAL_MODEL}  jobs={JOBS}  threshold={THRESHOLD}", flush=True)
    t0 = time.time()
    if THRESHOLD > 0:
        r = semantic_evaluation_score(origin_list, predict_list, threshold=THRESHOLD)
        print(f"\n=== RESULT (LLM Evaluator, threshold={THRESHOLD}) ===", flush=True)
    else:
        r = semantic_evaluation(origin_list, predict_list, log_fp)
        print(f"\n=== RESULT (CodeWordNet-LLM, token-based) ===", flush=True)
    print(f"Precision: {r['precision']:.4f}", flush=True)
    print(f"Recall:    {r['recall']:.4f}", flush=True)
    print(f"F1-score:  {r['f1']:.4f}", flush=True)
    print(f"(TP={r['TP']} FP={r['FP']} FN={r['FN']} pairs={r['pairs']}  eval_time={time.time()-t0:.0f}s)", flush=True)
