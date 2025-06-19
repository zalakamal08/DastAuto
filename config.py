import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found. Please set it in your .env file or environment.")

genai.configure(api_key=GEMINI_API_KEY)
MODEL_NAME = 'gemini-2.0-flash'

def get_gemini_model():
    return genai.GenerativeModel(MODEL_NAME)