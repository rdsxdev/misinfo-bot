import os, re, hashlib, logging, pytesseract, io
from datetime import datetime, timezone
from typing import Dict
from PIL import Image
from fastapi import FastAPI, Form, BackgroundTasks
from starlette.responses import JSONResponse
from google.cloud import firestore
from twilio.rest import Client
import httpx
import openai
import langid
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = FastAPI(title="WhatsApp Misinformation Bot")

# Config
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

try:
    db = firestore.Client()
except Exception as e:
    logger.error(f"Firestore init failed: {e}")
    db = None

SCAM_KEYWORDS = [
    "congratulations", "winner", "lottery", "prize", "urgent", "click here",
    "limited time", "act now", "free money", "bitcoin", "investment opportunity",
    "guaranteed profit", "make money fast", "work from home", "debt relief",
    "credit repair", "tax refund", "government grant", "stimulus check"
]
SUSPICIOUS_URL_PATTERN = re.compile(
    r'https?://(?:bit\.ly|tinyurl\.com|t\.co|short\.link|[a-z0-9-]+\.tk|[a-z0-9-]+\.ml|cutt\.ly|is\.gd|rb\.gy|buff\.ly)',
    re.IGNORECASE
)

def hash_phone_number(phone: str) -> str:
    return hashlib.sha256(phone.encode()).hexdigest()[:16]

def check_scam_heuristics(text: str) -> Dict[str, any]:
    risk_score = 0
    triggers = []
    text_lower = (text or "").lower()

    keyword_matches = [kw for kw in SCAM_KEYWORDS if kw in text_lower]
    if keyword_matches:
        risk_score += len(keyword_matches) * 10
        triggers.append(f"Scam keywords: {', '.join(keyword_matches)}")

    url_matches = SUSPICIOUS_URL_PATTERN.findall(text_lower)
    if url_matches:
        risk_score += len(url_matches) * 20
        triggers.append(f"Suspicious URLs: {', '.join(url_matches)}")

    risk_level = "high" if risk_score >= 30 else "medium" if risk_score >= 15 else "low"
    return {"risk_level": risk_level, "risk_score": risk_score, "triggers": triggers}

def send_whatsapp_message(to_number: str, body: str):
    try:
        twilio_client.messages.create(
            from_=TWILIO_WHATSAPP_NUMBER,
            to=f"whatsapp:{to_number}",
            body=body
        )
        logger.info(f"Sent message to {hash_phone_number(to_number)}")
    except Exception as e:
        logger.error(f"Error sending Twilio message: {e}")

def log_message_to_firestore(message_data: Dict, analysis_result: Dict):
    if db is None:
        return
    try:
        doc_data = {**message_data, "analysis": analysis_result, "processed_at": datetime.now(timezone.utc)}
        doc_data.pop("phone_number", None)
        db.collection("messages").document(message_data["message_id"]).set(doc_data)
    except Exception as e:
        logger.error(f"Error logging to Firestore: {e}")

async def ai_explanation(text: str, lang: str):
    prompt = f"""
    You are a fact-checking assistant. The user sent this message: "{text}".
    1. Say if it is likely true, misleading, or a scam.
    2. Give 3 short reasons why.
    3. Suggest what the user should do.
    Reply in {lang}.
    """
    resp = await openai.ChatCompletion.acreate(
        model="gpt-3.5-turbo",
        messages=[{"role": "system", "content": "You are a helpful misinformation detection assistant."},
                  {"role": "user", "content": prompt}]
    )
    return resp.choices[0].message["content"]

@app.post("/webhook")
async def receive_message(
    background_tasks: BackgroundTasks,
    From: str = Form(...),
    Body: str = Form(""),
    NumMedia: str = Form("0"),
    MediaUrl0: str = Form(None)
):
    phone_number = From.replace("whatsapp:", "")
    message_text = Body or ""

    if NumMedia != "0" and MediaUrl0:
        async with httpx.AsyncClient() as client:
            img_bytes = (await client.get(MediaUrl0, auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN))).content
        img = Image.open(io.BytesIO(img_bytes))
        ocr_text = pytesseract.image_to_string(img)
        message_text += f" {ocr_text}"

    try:
        lang = "Hindi" if langid.classify(message_text)[0] == "hi" else "English"
    except:
        lang = "English"

    analysis_result = check_scam_heuristics(message_text)
    ai_reply = await ai_explanation(message_text, lang)
    send_whatsapp_message(phone_number, ai_reply)

    message_data = {
        "message_id": hashlib.sha256((From + Body).encode()).hexdigest()[:16],
        "phone_number": phone_number,
        "phone_hash": hash_phone_number(phone_number),
        "raw_text": message_text,
        "media_urls": [MediaUrl0] if NumMedia != "0" else [],
        "timestamp": datetime.now(timezone.utc),
        "status": "received"
    }
    background_tasks.add_task(log_message_to_firestore, message_data, analysis_result)

    return JSONResponse({"status": "processed", "reply": ai_reply})

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
def root():
    return {"status": "ok"}


