"""FunInferAgent: inferring stripped-binary function names via bidirectional
semantic transfer.

Only the host-safe configuration surface is re-exported here. The pipeline
(`funinfer.core`) and IDA helpers (`funinfer.extraction`) import IDAPython
modules (`idaapi`, `idautils`, ...) and are therefore imported lazily — use
them from inside IDA, e.g. via `main_ida_pipeline.py`.
"""
from funinfer.config import Config  # noqa: F401

__version__ = "1.0.0"
__all__ = ["Config"]
