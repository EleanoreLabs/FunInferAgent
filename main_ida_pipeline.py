import ida_loader
import idc
import logging
from funinfer.core.bidirectional_bfs import FunInferPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == '__main__':
    idc.auto_wait()
    print('-----BEGIN OUTPUT-----')
    
    pipeline = FunInferPipeline()
    pipeline.run()
    
    print('-----END OUTPUT-----')
    idc.qexit(0)