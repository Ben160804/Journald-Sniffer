from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))


def classify_with_llm(buf):
    messages_text = "\n".join(f"- {m}" for m in buf.messages if m)

    prompt = f"""You are a security analyst reviewing an auth session.
Program: {buf.program}
Source IP: {buf.src_ip}
Messages:
{messages_text}
Classify this session. Reply with exactly one word: success, failure, suspicious, or unknown."""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
    )
    outcome = response.choices[0].message.content.strip().lower().split()[0]

    VALID = {"success", "failure", "suspicious", "unknown"}
    return outcome if outcome in VALID else "unknown"
