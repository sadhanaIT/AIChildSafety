# AI Child Digital Safety Platform

An AI-powered digital safety layer designed to identify harmful content, detect emotional signals, protect personally identifiable information (PII), and assess the safety of text and images before allowing content to proceed.

## Overview

The AI Child Digital Safety Platform integrates AI-based content analysis with a rule-based risk assessment system to help make digital interactions safer. It evaluates user inputs and, where configured, AI-generated responses to determine an appropriate safety action.

## Key Features

- **Harmful Text Detection:** Identifies potentially harmful or unsafe text.
- **Emotion Detection:** Analyses emotional signals in text.
- **PII Detection:** Detects sensitive information such as phone numbers, email addresses, identification numbers, and payment-related details.
- **Image Safety Analysis:** Uses an image classification model to identify potentially inappropriate images.
- **OCR-Based Image Analysis:** Extracts text from images to help detect exposed personal information.
- **Risk Scoring:** Calculates risk levels based on detected safety concerns.
- **Safety Decisions:** Classifies content using ALLOW, WARN, or BLOCK decisions.
- **LLM Integration:** Uses the Groq API to generate AI responses within the safety workflow.

## Technology Stack

- **Frontend:** React
- **Backend:** Python, FastAPI
- **AI Integration:** Groq API
- **Machine Learning:** Transformers and an image classification model
- **Image Processing:** Tesseract OCR
- **Development Tools:** PyCharm, Git, GitHub

## System Workflow

1. The user submits text or an image.
2. The backend processes the input through the relevant safety detection modules.
3. Harmful content, emotional signals, and sensitive information are analysed.
4. The risk calculator determines the appropriate safety decision.
5. The system allows, warns about, or blocks content according to configured rules.
6. The Groq API generates AI responses as part of the configured chatbot workflow, with safety checks applied where implemented.

## Project Structure

The backend includes modules such as:

- `ML_models.py` — text safety and machine-learning functionality
- `pii_detector.py` — personally identifiable information detection
- `risk_calculator.py` — risk assessment and safety decisions
- `image_analyzer.py` — image classification and OCR-based analysis
- `llm_connector.py` — integration with the Groq API
- `routes/chat.py` — chat-related API endpoints

## Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/sadhanaIT/AIChildSafety.git
   ```

2. Navigate to the project directory:

   ```bash
   cd AIChildSafety
   ```

3. Install the backend dependencies listed in the project's requirements file.

4. Configure the required environment variables in a `.env` file, including your Groq API key.

5. Start the FastAPI backend using the project's configured entry point.

6. Start the React frontend using its package scripts.

Refer to the project configuration and dependency files for the exact commands and requirements.

## Security Note

Never commit API keys, passwords, or other secrets to GitHub. Store credentials in environment variables and keep `.env` files containing secrets out of version control.

## Future Enhancements

- Parent and administrator dashboards
- User authentication and access control
- Improved safety detection and risk calibration
- Safety monitoring and reporting features

## Author

**Sadhana Devi Rajak**

B.Sc. Information Technology Student
