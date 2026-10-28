# AI Child Digital Safety Platform

An AI-powered digital safety platform designed to identify harmful text, detect emotional signals, protect personally identifiable information (PII), and analyse images for inappropriate content and exposed sensitive information.

## Overview

The AI Child Digital Safety Platform is designed to add a safety layer to AI-powered digital interactions. It combines machine learning, text analysis, image analysis, and risk assessment to evaluate content and determine appropriate safety actions.

The system is designed to analyse user inputs and AI-generated responses within the configured workflow, helping reduce exposure to harmful content and sensitive personal information.

## Key Features

### 1. Harmful Text Detection
- Analyses text to identify potentially harmful or unsafe content.
- Uses machine-learning-based detection to support content safety decisions.

### 2. Emotion Detection
- Analyses emotional signals expressed in text.
- Helps provide additional context for safety evaluation.

### 3. Personally Identifiable Information (PII) Detection
- Detects sensitive information such as email addresses and phone numbers.
- Identifies configured categories of sensitive data, including identification and payment-related information.
- Supports privacy protection by flagging potentially exposed personal information.

### 4. Image Safety Analysis
- Uses an image classification model to identify potentially inappropriate visual content.
- Applies configurable thresholds to help determine the appropriate safety action.

### 5. OCR-Based Image Analysis
- Uses Optical Character Recognition (OCR) to extract text from images.
- Analyses extracted text for potentially exposed personal or sensitive information.

### 6. Risk Assessment
- Combines relevant detection results to calculate a risk score.
- Classifies content into three configurable decisions:
  - **ALLOW** — Content meets the configured criteria for proceeding.
  - **WARN** — Content requires caution or additional attention.
  - **BLOCK** — Content meets the configured criteria for blocking.

### 7. AI Response Integration
- Integrates the Groq API to generate AI responses.
- Connects AI response generation with the platform's safety workflow, where implemented.

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React |
| Backend | Python, FastAPI |
| AI Response Generation | Groq API |
| Machine Learning | Transformers |
| Image Safety | Falconsai NSFW Image Detection model |
| OCR | Tesseract OCR |
| API Development | REST API |
| Version Control | Git, GitHub |

## System Workflow

1. The user submits text or an image through the application.
2. The backend processes the request through the relevant detection modules.
3. Text is analysed for harmful content, emotional signals, and personally identifiable information.
4. Images are analysed for potentially inappropriate content, and OCR extracts text for sensitive-information detection.
5. The risk calculator evaluates the available detection results.
6. The system determines whether the content should be allowed, flagged with a warning, or blocked.
7. The Groq API generates AI responses as configured in the chatbot workflow, with safety checks applied at the appropriate stages.

## Project Structure

The backend includes modules such as:

- `ML_models.py` — Text analysis and machine-learning functionality.
- `pii_detector.py` — Detection of personally identifiable information.
- `risk_calculator.py` — Risk scoring and safety decisions.
- `image_analyzer.py` — Image safety analysis and OCR-based inspection.
- `llm_connector.py` — Integration with the Groq API.
- `routes/chat.py` — Chat-related API endpoints.

The exact directory structure and responsibilities may vary with the current implementation.

## Getting Started

### Prerequisites

- Python
- Node.js and npm
- Git
- A Groq API key
- Tesseract OCR installed if image OCR is required

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/sadhanaIT/AIChildSafety.git
cd AIChildSafety
```

**2. Set up the Python environment**

```bash
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

**3. Install backend dependencies**

If the repository contains a `requirements.txt` file, run:

```bash
pip install -r requirements.txt
```

If it does not, install the dependencies specified by the project's current backend configuration.

**4. Configure environment variables**

Create a `.env` file in the appropriate backend directory and add your Groq API key using the variable name expected by your application.

Example:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Replace the placeholder with your own key. Never publish the actual key.

**5. Start the backend**

Run the FastAPI application using the correct module and application name for your project. For example, if the entry point is `main.py` and the FastAPI instance is named `app`:

```bash
uvicorn main:app --reload
```

**6. Start the frontend**

If the React frontend has its own `package.json`, open a separate terminal, navigate to that directory, and run:

```bash
npm install
npm run dev
```

Use the actual paths and startup commands configured in the repository.

## Security Considerations

- Store API keys and credentials in environment variables.
- Keep `.env` files containing secrets out of version control.
- Avoid committing personal information or sensitive test data.
- Review detection thresholds and test safety decisions before relying on them in real-world situations.

## Future Enhancements

Potential future improvements include:

- Parent and administrator dashboards.
- User authentication and role-based access control.
- Improved detection accuracy and risk-score calibration.
- Safety reports and monitoring dashboards.
- Expanded testing against different harmful-content and privacy scenarios.

## Contributors

This project was collaboratively developed by:

- **Sadhana Devi Rajak**
- **Yashashri Narkar**

Both contributors collaborated on the development of the AI Child Digital Safety Platform.

## Repository

[AIChildSafety on GitHub](https://github.com/sadhanaIT/AIChildSafety)

---

*This project is intended to support digital safety. Detection systems may produce false positives or miss harmful content, so their decisions should be tested and evaluated carefully.*
