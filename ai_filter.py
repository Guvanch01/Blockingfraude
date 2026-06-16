"""
AI Filter - Advanced Scam + Sexual Content + Account Checker
Uses xAI Grok for smart detection with human review fallback.
"""

import os
import re
import json
import logging
import asyncio
import aiohttp
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

GROK_API_KEY = os.getenv("GROK_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")  # Backup AI

# ─────────────────────────────────────────────────────
# PROMPT (emoji-free inside Python string, only in JSON output)
# ─────────────────────────────────────────────────────

PROMPT_TEMPLATE = """You are an elite AI Content Moderator for Telegram groups. Your job is to detect REAL scams and sexual spam — but NEVER block legitimate users.

MESSAGE TO ANALYZE:
<message>{text}</message>

USER PROFILE (may be empty):
<profile>
Bio: {bio}
Username: {username}
Profile has photo: {has_photo}
</profile>

=== BLOCK THIS (is_harmful: true) ===

SCAM / FRAUD:
- Promises of FAST MONEY: "легкий заработок", "быстрый доход", "100% гарантия прибыли"
- "от 17 лет", "вакансия" + no real company name + asks to write in DM
- Requests for card numbers, CVV, OTP/SMS codes, passwords
- Crypto/forex/investment "guarantees": "утроим деньги", "гарантированный доход"
- Links to phishing sites or unknown bots that ask for login

SEXUAL SPAM:
- "qiziqarli video", "profilimda video bor", "kutib qolaman"
- Offers of intimate/nude/adult content (OnlyFans, etc.)
- Seductive DM invites with suggestive emojis when combined with profile offers
- Links to adult sites or suspicious bots

ACCOUNT HIJACKING / PHISHING:
- Links with suspicious domains (not t.me/official)
- "Verify your account", "Your account will be deleted", fake Telegram notifications
- Bots pretending to be official Telegram

=== DO NOT BLOCK (is_harmful: false) ===

LEGITIMATE CURRENCY EXCHANGE (very common in CIS):
- "Karta pul gecirseniz men nalichni berjek" = cash exchange service, NOT scam
- "Plan yerde dollar bersem, barde manat berjek" = legitimate currency swap
- These are normal peer-to-peer exchange offers — ALLOW THEM

REAL JOB POSTINGS:
- Named company + specific role + salary + location = real job
- "Satyjy gerek", "ofisiant gerek", "kuryer gerek" with details = real
- Someone asking for job recommendations = real

NORMAL CONVERSATIONS:
- Help requests, questions, greetings
- Buying/selling goods with clear descriptions
- Event announcements, community posts

=== DECISION LOGIC (step by step) ===
1. Is there a SPECIFIC company name AND job details? -> Not scam
2. Is it a currency/money exchange with no pressure? -> Not scam
3. Does it promise FAST/EASY money without real work? -> Scam
4. Does it offer intimate/adult content or profile videos? -> Sexual spam
5. Does it ask for sensitive data (card, password, code)? -> Phishing scam
6. Does it send suspicious links asking for login? -> Phishing
7. Is it unclear / borderline? -> Return category: "review" for human check

Respond ONLY in JSON:
{{
  "is_harmful": true or false,
  "category": "scam" | "sexual" | "phishing" | "none" | "review",
  "reason": "clear short reason under 15 words",
  "confidence": 0.75
}}
"""

# ─────────────────────────────────────────────────────
# Quick Keyword Lists (no emoji in variable names)
# ─────────────────────────────────────────────────────

QUICK_SEXUAL_KEYWORDS = [
    "qiziqarli video", "qiziqarli videolar", "profilimda video",
    "profilimde video", "kutib qolaman", "intimate", "onlyfans",
    "nude", "18+", "xxx", "porno", "adult content",
    "goreng video", "yalangach", "yalanach",
]

QUICK_SEXUAL_EMOJIS = ["\U0001f351", "\U0001f525", "\U0001f48b"]  # peach, fire, kiss

QUICK_SCAM_KEYWORDS = [
    "pul gerek", "pul ber", "pul iber",
    "kart belgisi", "kart nomeri", "cvv", "sms kod", "otp kod",
    "ot 17 let", "\u043e\u0442 17 \u043b\u0435\u0442",  # от 17 лет
    "\u043b\u0451\u0433\u043a\u0438\u0439 \u0437\u0430\u0440\u0430\u0431\u043e\u0442\u043e\u043a",  # лёгкий заработок
    "\u043b\u0435\u0433\u043a\u0438\u0439 \u0437\u0430\u0440\u0430\u0431\u043e\u0442\u043e\u043a",  # легкий заработок
    "100% \u0433\u0430\u0440\u0430\u043d\u0442\u0438\u044f",  # 100% гарантия
    "\u0431\u044b\u0441\u0442\u0440\u044b\u0439 \u0437\u0430\u0440\u0430\u0431\u043e\u0442\u043e\u043a",  # быстрый заработок
    "garantiyanly girdeji", "utrup berjek", "utub berjek",
    "+7967", "+7 967", "+7963", "+7 963",
]

QUICK_PHISHING_PATTERNS = [
    r"t\.me\/[a-z0-9_]{1,4}bot",  # suspicious short bot links
    r"verify.*account",
    r"akkaunt.*o'chiriladi",
    r"akkaunt.*bloklaner",
    r"telegram.*verify",
    r"http[s]?://(?!t\.me)[^\s]{5,}(?:login|verify|confirm|secure)",
]

# Legitimate exchange patterns - these should NOT be blocked
LEGIT_EXCHANGE_PATTERNS = [
    r"karta.*nalich",
    r"nalich.*karta",
    r"dollar.*manat",
    r"manat.*dollar",
    r"ruble.*nalich",
    r"plan.*dollar",
    r"dollar.*plan",
    r"transfer.*nalichniy",
    r"obmen",  # exchange in Russian
    r"kurs.*dollar",
    r"dollar.*kurs",
]


def _parse_result(raw: str) -> dict:
    raw = raw.replace("```json", "").replace("```", "").strip()
    try:
        result = json.loads(raw)
        return {
            "is_harmful": bool(result.get("is_harmful", False)),
            "category": result.get("category", "none"),
            "reason": result.get("reason", "AI detected harmful content"),
            "confidence": float(result.get("confidence", 0.8)),
        }
    except Exception as e:
        logger.error(f"JSON parse error: {e} | raw: {raw[:200]}")
        return {"is_harmful": False, "category": "none", "reason": "parse error", "confidence": 0.4}


class AIFilter:
    def __init__(self):
        self.compiled_phishing = [re.compile(p, re.IGNORECASE) for p in QUICK_PHISHING_PATTERNS]
        self.compiled_legit = [re.compile(p, re.IGNORECASE) for p in LEGIT_EXCHANGE_PATTERNS]

    # ── Quick checks ────────────────────────────────

    def _is_legit_exchange(self, text: str) -> bool:
        """Check if message is a legitimate currency/money exchange."""
        text_lower = text.lower()
        for pattern in self.compiled_legit:
            if pattern.search(text_lower):
                return True
        return False

    def quick_check(self, text: str) -> dict | None:
        if not text:
            return None
        text_lower = text.lower()

        # First: is it a legitimate exchange? -> never block
        if self._is_legit_exchange(text_lower):
            return {"is_harmful": False, "category": "none", "reason": "Legitimate exchange", "confidence": 0.9}

        # Sexual keyword check
        for kw in QUICK_SEXUAL_KEYWORDS:
            if kw in text_lower:
                return {
                    "is_harmful": True,
                    "category": "sexual",
                    "reason": f"Sexual spam keyword: {kw}",
                    "confidence": 0.94,
                }

        # Emoji-based sexual spam (only if combined with profile-type words)
        profile_words = ["profil", "video", "kanal", "channel", "bio"]
        has_profile_word = any(pw in text_lower for pw in profile_words)
        has_sexual_emoji = any(e in text for e in QUICK_SEXUAL_EMOJIS)
        if has_profile_word and has_sexual_emoji:
            return {
                "is_harmful": True,
                "category": "sexual",
                "reason": "Sexual profile promotion with emojis",
                "confidence": 0.91,
            }

        # Phishing link check
        for pattern in self.compiled_phishing:
            if pattern.search(text):
                return {
                    "is_harmful": True,
                    "category": "phishing",
                    "reason": "Suspicious link / phishing attempt",
                    "confidence": 0.92,
                }

        # Scam keyword check
        for kw in QUICK_SCAM_KEYWORDS:
            if kw in text_lower:
                return {
                    "is_harmful": True,
                    "category": "scam",
                    "reason": f"Scam keyword detected",
                    "confidence": 0.93,
                }

        return None

    # ── Account/profile check ───────────────────────

    async def check_profile(self, bot, chat_id: int, user_id: int) -> dict:
        """
        Check user's profile for suspicious indicators.
        Returns a risk dict.
        """
        risk_score = 0
        indicators = []

        try:
            member = await bot.get_chat_member(chat_id, user_id)
            user = member.user

            # Check profile photo
            photos = await bot.get_user_profile_photos(user_id, limit=1)
            has_photo = photos.total_count > 0

            # Check bio (only works if bot has user's full info via get_chat)
            try:
                chat_info = await bot.get_chat(user_id)
                bio = chat_info.bio or ""
            except Exception:
                bio = ""

            username = user.username or ""

            # Suspicious bio keywords
            sexual_bio_keywords = [
                "onlyfans", "18+", "adult", "nsfw", "qiziqarli",
                "video", "foto", "intimate", "sexy", "hot girl",
            ]
            for kw in sexual_bio_keywords:
                if kw.lower() in bio.lower():
                    risk_score += 30
                    indicators.append(f"Suspicious bio keyword: {kw}")

            # No username + no photo = slightly suspicious
            if not username and not has_photo:
                risk_score += 10
                indicators.append("No username and no photo")

            # New account indicators (no last name, very short username)
            if username and len(username) <= 4:
                risk_score += 5
                indicators.append("Very short username")

            return {
                "risk_score": risk_score,
                "indicators": indicators,
                "bio": bio,
                "username": username,
                "has_photo": has_photo,
            }

        except Exception as e:
            logger.warning(f"Profile check failed for {user_id}: {e}")
            return {"risk_score": 0, "indicators": [], "bio": "", "username": "", "has_photo": False}

    # ── Main analyze ────────────────────────────────

    async def analyze(self, text: str, bio: str = "", username: str = "", has_photo: bool = True) -> dict:
        if len(text.strip()) < 3:
            return {"is_harmful": False, "category": "none", "reason": "Too short", "confidence": 1.0}

        # 1. Quick keyword check
        quick = self.quick_check(text)
        if quick:
            return quick

        # 2. Full AI analysis (Grok)
        result = await self._xai_grok(text, bio=bio, username=username, has_photo=has_photo)
        if result:
            return result

        # 3. Fallback: OpenAI if Grok fails
        if GEMINI_API_KEY:
            result = await self._openai_fallback(text)
            if result:
                return result

        return {"is_harmful": False, "category": "none", "reason": "AI unavailable", "confidence": 0.4}

    # ── xAI Grok ────────────────────────────────────

    async def _xai_grok(self, text: str, bio: str = "", username: str = "", has_photo: bool = True) -> dict | None:
        if not GROK_API_KEY:
            logger.warning("GROK_API_KEY not set in .env")
            return None

        prompt = PROMPT_TEMPLATE.format(
            text=text[:1000],
            bio=bio[:200] if bio else "empty",
            username=username or "no username",
            has_photo="yes" if has_photo else "no",
        )

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    "https://api.x.ai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {GROK_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "grok-3",
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 300,
                        "temperature": 0.0,
                    },
                    timeout=aiohttp.ClientTimeout(total=25),
                )
                data = await resp.json()

                if resp.status != 200:
                    logger.error(f"Grok API error {resp.status}: {data}")
                    return None

                raw = data["choices"][0]["message"]["content"]
                result = _parse_result(raw)
                logger.info(f"Grok result: {result}")
                return result

        except asyncio.TimeoutError:
            logger.error("Grok API timeout")
            return None
        except Exception as e:
            logger.error(f"Grok error: {e}")
            return None

    # ── OpenAI Fallback ──────────────────────────────

    async def _gemini_fallback(self, text: str) -> dict | None:
        if not GEMINI_API_KEY:
            return None

        simple_prompt = (
            "Analyze this Telegram message. Is it scam, sexual spam, phishing, or safe?\n\n"
            f"Message: {text[:800]}\n\n"
            'Reply ONLY JSON: {"is_harmful": true/false, "category": "scam"|"sexual"|"phishing"|"none"|"review", '
            '"reason": "short reason", "confidence": 0.85}'
        )

        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}",
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": simple_prompt}]}],
                        "generationConfig": {"temperature": 0.0, "maxOutputTokens": 200}
                    },
                    timeout=aiohttp.ClientTimeout(total=20),
                )
                data = await resp.json()
                raw = data["candidates"][0]["content"]["parts"][0]["text"]
                return _parse_result(raw)
        except Exception as e:
            logger.error(f"Gemini fallback error: {e}")
            return None