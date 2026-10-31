"""IDA entry point: run inside IDA via

    idat64 -A -L<binary>.log -S main_ida_pipeline.py <binary>.i64

Writes the machine-readable pipeline log to `<IDB>.log.txt`
(`Processing 0x...` lines + the raw LLM name dicts), consumed by
scripts/parse_rename_log.py.

Note: all logging output is routed into `<IDB>.log.txt` with a bare
`%(message)s` format, so the `Processing 0x...` lines stay parseable.
"""
import ida_loader
import idc
import logging
import sys

from funinfer.core.bidirectional_bfs import FunInferPipeline

if __name__ == '__main__':
    idc.auto_wait()

    database_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    log_file = open(f"{database_path}.log.txt", "w", buffering=1,
                    encoding="utf-8", errors="replace")
    sys.stdout = log_file
    # Route every log record into the pipeline log with a bare message
    # format: scripts/parse_rename_log.py matches `^Processing 0x...`
    # exactly, so a timestamp/level prefix (the logging default, on stderr)
    # would make the log unparseable.
    logging.basicConfig(level=logging.INFO, format='%(message)s',
                        stream=log_file)

    print('-----BEGIN OUTPUT-----')
    try:
        pipeline = FunInferPipeline()
        pipeline.run()
    except Exception as e:
        logging.error(f"FunInfer pipeline failed: {e}")
    finally:
        log_file.flush()
        sys.stdout = sys.__stdout__
        log_file.close()

    print('-----END OUTPUT-----')
    idc.qexit(0)
