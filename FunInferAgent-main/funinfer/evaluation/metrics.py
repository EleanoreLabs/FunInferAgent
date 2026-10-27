import pandas as pd
import numpy as np
from scipy.optimize import linear_sum_assignment
from funinfer.evaluation.evaluator import SemanticEvaluator
from funinfer.config import Config

def calculate_metrics(origin_names: list, predict_names: list, threshold=Config.EVAL_THRESHOLD):
    evaluator = SemanticEvaluator()
    score_matrix = np.zeros((len(predict_names), len(origin_names)))
    
    print("Generating semantic similarity matrix...")
    for i, predict_name in enumerate(predict_names):
        for j, origin_name in enumerate(origin_names):
            score_matrix[i, j] = evaluator.get_score(origin_name, predict_name)
        print(f"Progress: {i+1}/{len(predict_names)}")

    row_ind, col_ind = linear_sum_assignment(-score_matrix)
    
    TP = 0
    matched_origin, matched_predict = set(), set()
    
    for r, c in zip(row_ind, col_ind):
        if score_matrix[r, c] >= threshold:
            TP += 1
            matched_origin.add(c)
            matched_predict.add(r)

    FP = len([r for r in range(len(predict_names)) if r not in matched_predict and np.max(score_matrix[r]) >= threshold])
    FN = len([c for c in range(len(origin_names)) if c not in matched_origin and np.max(score_matrix[:, c]) >= threshold])

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "score_matrix": score_matrix,
        "matches": list(zip(row_ind, col_ind))
    }