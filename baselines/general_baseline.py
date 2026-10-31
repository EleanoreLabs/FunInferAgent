"""Vanilla-LLM baseline (S2 only, no bidirectional transfer).

Run inside IDA via:

    idat64 -A -L<binary>.log -S baselines/general_baseline.py <binary>.i64

Writes the machine-readable log to `<IDB>.general_baseline.log.txt` in the
same format as the main pipeline (`Processing 0x...` + raw LLM name dicts),
so scripts/parse_rename_log.py and the evaluation scripts apply unchanged.
"""
import ida_loader
import idc
import ida_hexrays
import logging
import sys
from funinfer.extraction.ida_analyzer import IDAAnalyzer
from funinfer.semantics.llm_client import LLMClient

class GeneralBaselinePipeline:
    def __init__(self):
        self.analyzer = IDAAnalyzer()
        self.llm = LLMClient()

    def run(self):
        logging.info("Starting General Baseline (Vanilla LLM without context transfer)...")
        bottom_funcs = self.analyzer.get_bottom_functions()

        for func_info in bottom_funcs:
            item = func_info['address']
            logging.info(f"Processing {hex(item)}")

            # Extract ONLY local internal semantics (S2)
            try:
                cfunc = ida_hexrays.decompile(item)
                if not cfunc:
                    continue
                decompiler_output = str(cfunc)
            except Exception as e:
                logging.warning(f"Failed to decompile {hex(item)}: {e}")
                continue

            # Direct LLM query with NO parent_params or sub-function summaries
            new_names = self.llm.query_name(decompiler_output, parent_params=None)
            # Raw LLM answer into the log, same format as the main pipeline.
            print(new_names)

            # Rename in IDA
            if new_names:
                self.analyzer.rename_to_ida(item, new_names)

if __name__ == '__main__':
    idc.auto_wait()

    database_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    log_file = open(f"{database_path}.general_baseline.log.txt", "w", buffering=1,
                    encoding="utf-8", errors="replace")
    sys.stdout = log_file
    # Bare message format into the log file, matching the main pipeline
    # (see main_ida_pipeline.py): keeps `^Processing 0x...` parseable.
    logging.basicConfig(level=logging.INFO, format='%(message)s',
                        stream=log_file)

    print('-----BEGIN OUTPUT-----')

    try:
        pipeline = GeneralBaselinePipeline()
        pipeline.run()
    except Exception as e:
        logging.error(f"General baseline execution failed: {e}")
    finally:
        log_file.flush()
        sys.stdout = sys.__stdout__
        log_file.close()

    print('-----END OUTPUT-----')
    idc.qexit(0)
