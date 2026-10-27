import ida_loader
import idc
import ida_hexrays
import logging
import sys
from funinfer.extraction.ida_analyzer import IDAAnalyzer
from funinfer.semantics.llm_client import LLMClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
            
            # Rename in IDA
            if new_names:
                self.analyzer.rename_to_ida(item, new_names)

if __name__ == '__main__':
    idc.auto_wait()
    print('-----BEGIN OUTPUT-----')
    
    database_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    log_file = open(f"{database_path}.general_baseline.log.txt", "w", buffering=1)
    sys.stdout = log_file
    
    try:
        pipeline = GeneralBaselinePipeline()
        pipeline.run()
    except Exception as e:
        logging.error(f"General baseline execution failed: {e}")
    finally:
        log_file.close()
        
    print('-----END OUTPUT-----')
    idc.qexit(0)