#!/usr/bin/env python3
"""FunInferAgent end-to-end driver.

For each stripped binary (one per domain):
  1. idat64 -B <strip>                    -> generate .i64 (IDA auto-analysis)
  2. idat64 -A -L<log> -S main_ida_pipeline.py <strip>.i64
         -> bidirectional semantic transfer; writes <strip>.i64.log.txt
            with "Processing 0xADDR" + JSON names
  3. parse_rename_log.py <log> <map.json> -> predicted {addr: name}
  4. fast token-overlap P/R/F1 vs ground-truth CSV (from nm on the
     unstripped binary)

Environment:
  IDAT64            path to idat64            (default: "idat64" from PATH)
  FUNINFER_DATASET  dataset root              (default: <repo>/dataset)
  FUNINFER_MODEL / FUNINFER_LLM_BASE_URL      model + endpoint
  FUNINFER_ABLATION "" | wo_s1 | wo_s2 | wo_s3
  LPARENT / LSUMMARY                          sensitivity parameters
  IDAUSR            IDA user dir with an accepted EULA (headless runs need it)
"""
import os, sys, subprocess, json, time, argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

IDA      = os.environ.get("IDAT64", "idat64")
REPO     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT   = os.environ.get("FUNINFER_SCRIPT", REPO + "/main_ida_pipeline.py")
PARSE_PY = REPO + "/scripts/parse_rename_log.py"
TESTDIR  = os.environ.get("FUNINFER_DATASET", REPO + "/dataset")

# (domain, name, stripped_binary, ground_truth_csv)
TARGETS = [
    ("crypto",   "openssl", TESTDIR + "/crypto/openssl.strip",   TESTDIR + "/crypto/openssl.gt.csv"),
    ("database", "gzip",    TESTDIR + "/database/gzip.strip",    TESTDIR + "/database/gzip.gt.csv"),
    ("network",  "sshd",    TESTDIR + "/network/sshd.strip",     TESTDIR + "/network/sshd.gt.csv"),
    ("video",    "dav1d",   TESTDIR + "/video/dav1d.strip",      TESTDIR + "/video/dav1d.gt.csv"),
]


def ida_env(name):
    e = os.environ.copy()
    e["TVHEADLESS"] = "1"
    # Headless IDA requires an accepted EULA; give each binary its own IDAUSR
    # if a prefix is provided, so concurrent runs don't race on ida.reg.
    if e.get("IDAUSR_PREFIX"):
        e["IDAUSR"] = e["IDAUSR_PREFIX"] + "_" + name
    return e


def process_binary(dom, name, strip, gt_csv, timeout_rename=8 * 3600):
    env = ida_env(name)
    i64 = strip + ".i64"
    logtxt = i64 + ".log.txt"
    idalog = strip + ".ida.log"
    for ext in (".i64", ".id0", ".id1", ".id2", ".asm", ".nam", ".til",
                ".log.txt", ".ida.log", ".recover_map.json"):
        p = strip + ext
        if os.path.exists(p):
            os.remove(p)
    # 1. auto-analysis
    t = time.time()
    r = subprocess.run([IDA, "-B", strip], env=env, capture_output=True,
                       text=True, timeout=3600)
    tB = time.time() - t
    if not os.path.exists(i64):
        return dict(dom=dom, name=name, status="FAIL-B", tB=tB,
                    err=(r.stderr or r.stdout or "")[-600:])
    # 2. pipeline
    t = time.time()
    r2 = subprocess.run([IDA, "-A", "-L" + idalog, "-S" + SCRIPT, i64],
                        env=env, capture_output=True, text=True,
                        timeout=timeout_rename)
    tR = time.time() - t
    if not os.path.exists(logtxt):
        return dict(dom=dom, name=name, status="FAIL-no-log", tB=tB, tR=tR,
                    err=(r2.stderr or r2.stdout or "")[-600:])
    # 3. parse
    pred_json = i64 + ".recover_map.json"
    subprocess.run([sys.executable, PARSE_PY, logtxt, pred_json],
                   capture_output=True, text=True)
    n_pred = 0
    if os.path.exists(pred_json):
        try:
            n_pred = len(json.load(open(pred_json)))
        except Exception:
            n_pred = 0
    # 4. fast token F1
    score = fast_token_f1(pred_json, gt_csv)
    return dict(dom=dom, name=name, status="OK", tB=tB, tR=tR, n_pred=n_pred,
                pred_json=pred_json, **score)


# ---------- fast token-overlap metric (strict, no LLM judge) ----------
def tokenize(name):
    name = name.lower().replace("_", " ")
    out, buf = [], ""
    for c in name:
        if c.isupper():
            if buf:
                out.append(buf)
                buf = ""
        if c.isalpha():
            buf += c
        else:
            if buf:
                out.append(buf)
                buf = ""
    if buf:
        out.append(buf)
    return [w for w in out if w]


def load_names(csv_path):
    names = set()
    if not os.path.exists(csv_path):
        return names
    for ln in open(csv_path):
        ln = ln.strip()
        if not ln or ln.startswith("address"):
            continue
        _, _, nm = ln.partition(",")
        nm = nm.strip()
        if nm and not nm.startswith("sub_") and not nm.startswith("_"):
            names.add(nm)
    return names


def fast_token_f1(pred_json, gt_csv):
    gt_names = load_names(gt_csv)
    pred_names = set()
    if os.path.exists(pred_json):
        pred_names = set(json.load(open(pred_json)).values())
    gt_tok, pr_tok = set(), set()
    for n in gt_names:
        gt_tok |= set(tokenize(n))
    for n in pred_names:
        pr_tok |= set(tokenize(n))
    tp = len(gt_tok & pr_tok)
    fp = len(pr_tok - gt_tok)
    fn = len(gt_tok - pr_tok)
    P = tp / (tp + fp) if (tp + fp) else 0.0
    R = tp / (tp + fn) if (tp + fn) else 0.0
    F1 = 2 * P * R / (P + R) if (P + R) else 0.0
    return dict(gt_names=len(gt_names), pred_names=len(pred_names),
                P=round(P, 4), R=round(R, 4), F1=round(F1, 4))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", default="crypto,database,network,video")
    ap.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    wanted = set(a.targets.split(","))
    targets = [t for t in TARGETS if t[0] in wanted]
    print(f"model={os.environ.get('FUNINFER_MODEL', '(Config default)')}  "
          f"ablation={os.environ.get('FUNINFER_ABLATION', '') or 'full'}  "
          f"targets={[t[1] for t in targets]}  jobs={a.jobs}")
    results = []
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        futs = {ex.submit(process_binary, *t): t[1] for t in targets}
        for f in as_completed(futs):
            r = f.result()
            results.append(r)
            if r["status"] == "OK":
                print(f"[{r['dom']}/{r['name']}] OK  B={r['tB']:.0f}s "
                      f"rename={r['tR']:.0f}s pred={r['n_pred']}  "
                      f"P={r['P']} R={r['R']} F1={r['F1']}", flush=True)
            else:
                print(f"[{r['dom']}/{r['name']}] {r['status']}  "
                      f"err={r.get('err', '')[:300]}", flush=True)
    print("\n=== SUMMARY ===")
    print(f"{'domain':10}{'binary':10}{'P':>8}{'R':>8}{'F1':>8}{'pred':>8}{'gt':>8}")
    for r in sorted(results, key=lambda x: x['dom']):
        if r["status"] == "OK":
            print(f"{r['dom']:10}{r['name']:10}{r['P']:>8}{r['R']:>8}"
                  f"{r['F1']:>8}{r['n_pred']:>8}{r['gt_names']:>8}")
    os.makedirs(TESTDIR, exist_ok=True)
    json.dump(results, open(TESTDIR + "/results.json", "w"), indent=2)


if __name__ == "__main__":
    main()
