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
        label = harm_result['label'].lower()
        score = float(harm_result['score'])

        # Toxic-bert labels: toxic, severe_toxic, obscene, threat, insult, identity_hate.
        # If the detected label is one of these and confidence is high, assign the score.
        # Otherwise, treat normal text as safe (low baseline score).
        toxic_labels = ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']

        if label in toxic_labels and score > 0.4:
            harm_score = score
        else:
            harm_score = 0.01

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