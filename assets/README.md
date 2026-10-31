# assets

This directory holds the prebuilt resource files required to run FunInferAgent.

## segmentation.model

### Source

This file was downloaded from the SymGen project:

- Repository: https://github.com/OSUSecLab/SymGen
- Path: `scripts/evaluation/segmentation_model/segmentation.model`

The `segmentation.model` file in this directory is the verbatim copy of the file at the path above in the SymGen repository. It has not been modified in any way.

### Description

`segmentation.model` is a SentencePiece tokenizer model file. The file header contains the typical SentencePiece special tokens (`<unk>` / `<s>` / `</s>`), and its vocabulary includes common programming-language keywords such as `get`, `set`, `create`, `add`, `from`, `with`, `list`, and `by`, indicating that the tokenizer was trained for source-code / function-level text segmentation.

In FunInferAgent, this tokenizer is used to subword-tokenize the input function (source code), providing a unified token sequence for the downstream function-semantic segmentation and inference pipeline.

### Usage

Load it with SentencePiece:

```python
import sentencepiece as spm

sp = spm.SentencePieceProcessor()
sp.load("assets/segmentation.model")

tokens = sp.encode("def foo(x): return x + 1")
print(tokens)
print(sp.decode(tokens))
```

### License

This file originates from the third-party project [OSUSecLab/SymGen](https://github.com/OSUSecLab/SymGen). Its copyright and licensing terms are governed by the original repository. Please consult the original repository's LICENSE before redistributing or using it for commercial purposes.
