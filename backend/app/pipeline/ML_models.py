from transformers import pipeline

# Initialize HuggingFace Pipelines (Cached locally on first run)
print("Loading Safety Machine Learning Models...")

# 1. RoBERTa Toxicity / Harm Classifier
harm_classifier = pipeline(
    "text-classification",
    model="unitary/toxic-bert",
    return_all_scores=False
)

# 2. DistilBERT Emotion Classifier
emotion_classifier = pipeline(
    "text-classification",
    model="j-hartmann/emotion-english-distilroberta-base",
    return_all_scores=False
)


def evaluate_harm_and_emotion(text: str) -> dict:
    """
    Evaluates text using actual Transformer models.
    Returns harm score (0.0 to 1.0) and dominant emotion.
    """
    try:
        # Run Harm/Toxicity Detection
        harm_result = harm_classifier(text)[0]
        harm_score = harm_result['score'] if harm_result['label'].lower() in ['toxic', 'severe_toxic', 'obscene',
                                                                              'threat', 'insult',
                                                                              'identity_hate'] else 0.0

        # If model label is 'toxic' or similar, use its confidence score, else keep it low
        if harm_result['label'].lower() != 'neutral' and harm_result['score'] > 0.5:
            harm_score = harm_result['score']
        else:
            harm_score = 0.05

        # Run Emotion Detection
        emotion_result = emotion_classifier(text)[0]
        detected_emotion = emotion_result['label'].lower()

    except Exception as e:
        print(f"ML Model Inference Error: {e}")
        harm_score = 0.0
        detected_emotion = "neutral"

    return {
        "harm_score": round(float(harm_score), 2),
        "emotion": detected_emotion
    }