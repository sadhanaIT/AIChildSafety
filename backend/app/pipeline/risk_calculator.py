"""
Risk Calculation and Decision Engine Module
-------------------------------------------
Implements:
1. Weighted Rule-Based Scoring Algorithm
2. Rule-Based Decision Algorithm (ALLOW / WARN / BLOCK)
"""

from typing import List, Dict, Any, Tuple


def calculate_risk_score(
        pii_list: List[str],
        harm_score: float,
        emotion: str,
        age_group: str = "child"
) -> float:
    """
    Weighted Rule-Based Scoring Algorithm.

    Formula:
    - Base PII Factor: +0.4 if any PII is detected
    - Harm Factor: Harm ML Probability * 0.5
    - Distress Emotion Factor: +0.1 if emotional distress is detected
    - Age Risk Factor: +0.1 if user is classified as a young child
    """
    risk_score = 0.0

    # 1. PII Presence Check (Weight: 0.4)
    if pii_list and len(pii_list) > 0:
        risk_score += 0.4

    # 2. Transformer Harm Classifier Output (Weight: 0.5)
    # Assumes harm_score is a normalized probability between 0.0 and 1.0 from RoBERTa
    risk_score += (max(0.0, min(1.0, harm_score)) * 0.5)

    # 3. Emotional Distress Adjustment (Weight: 0.1)
    distress_emotions = ["fear", "sadness", "anger", "distress"]
    if emotion.lower() in distress_emotions:
        risk_score += 0.1

    # 4. Age Group Adjustment (Weight: 0.1 for younger tiers)
    if age_group.lower() in ["young_child", "under_10", "child"]:
        risk_score += 0.05  # Slight sensitivity multiplier for younger children

    # Normalize final score between 0.0 and 1.0
    final_score = min(round(risk_score, 2), 1.0)
    return final_score


def make_safety_decision(risk_score: float) -> str:
    """
    Rule-Based Decision Algorithm.

    Thresholds:
    - Score >= 0.70  --> BLOCK (High Risk)
    - Score >= 0.40  --> WARN  (Moderate Risk)
    - Score < 0.40   --> ALLOW (Safe)
    """
    if risk_score >= 0.70:
        return "BLOCK"
    elif risk_score >= 0.40:
        return "WARN"
    else:
        return "ALLOW"


def evaluate_input_safety(
        pii_list: List[str],
        harm_score: float,
        emotion: str,
        age_group: str = "child"
) -> Dict[str, Any]:
    """
    Main evaluation pipeline wrapper function for input safety.

    Returns structured results containing score, decision, and detailed flags.
    """
    calculated_risk = calculate_risk_score(
        pii_list=pii_list,
        harm_score=harm_score,
        emotion=emotion,
        age_group=age_group
    )

    decision = make_safety_decision(calculated_risk)

    return {
        "risk_score": calculated_risk,
        "decision": decision,
        "details": {
            "pii_count": len(pii_list),
            "raw_harm_score": harm_score,
            "flagged_emotion": emotion,
            "age_group": age_group
        }
    }


# Quick test block for PyCharm verification
if __name__ == "__main__":
    # Test Case 1: High Risk (PII + Harm)
    test_1 = evaluate_input_safety(
        pii_list=["phone:1234567890"],
        harm_score=0.85,
        emotion="anger"
    )
    print("Test 1 (High Risk):", test_1)

    # Test Case 2: Moderate Risk (PII only)
    test_2 = evaluate_input_safety(
        pii_list=["email:test@example.com"],
        harm_score=0.05,
        emotion="neutral"
    )
    print("Test 2 (Moderate Risk):", test_2)

    # Test Case 3: Low Risk (Safe input)
    test_3 = evaluate_input_safety(
        pii_list=[],
        harm_score=0.02,
        emotion="joy"
    )
    print("Test 3 (Low Risk):", test_3)