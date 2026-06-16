"""
Blockfraude — Professional Telegram Group Protection Bot
Automatically blocks Scam, Sexual content, Phishing.
Sends uncertain cases to admin for manual review.
"""

import logging
import os
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, MessageHandler, CommandHandler,
    CallbackQueryHandler, filters, ContextTypes
)
from telegram.constants import ParseMode

from database import Database
from ai_filter import AIFilter
from payments import PaymentManager

load_dotenv()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID", "6581335835"))  # Your Telegram user ID
ADMIN_IDS = [int(x) for x in os.getenv("ADMIN_IDS", str(OWNER_ID)).split(",") if x.strip()]

db = Database()
ai = AIFilter()
payments = PaymentManager(db)


# ─────────────────────────────────────────
# Helper: Ban user
# ─────────────────────────────────────────

async def ban_user(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE, reason: str) -> bool:
    try:
        await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
        logger.info(f"BANNED user {user_id} from chat {chat_id} | Reason: {reason}")
        return True
    except Exception as e:
        logger.error(f"Ban failed for {user_id}: {e}")
        return False


async def delete_message_safe(message) -> bool:
    try:
        await message.delete()
        return True
    except Exception as e:
        logger.warning(f"Could not delete message: {e}")
        return False


# ─────────────────────────────────────────
# Helper: Notify admins — auto block
# ─────────────────────────────────────────

async def notify_admins_blocked(
    chat_id: int, user_id: int, username: str,
    category: str, reason: str, text_preview: str,
    context: ContextTypes.DEFAULT_TYPE
):
    """Notify admins when someone was automatically blocked."""
    cat_emoji = {"scam": "SCAM", "sexual": "SEXUAL SPAM", "phishing": "PHISHING"}.get(category, category.upper())
    msg = (
        f"<b>AUTO BLOCK: {cat_emoji}</b>\n\n"
        f"User: @{username or user_id} (<code>{user_id}</code>)\n"
        f"Group: <code>{chat_id}</code>\n"
        f"Reason: {reason}\n"
        f"Message: <i>{text_preview[:150]}</i>\n"
        f"Time: {datetime.now().strftime('%H:%M, %d.%m.%Y')}"
    )
    await _send_to_admins(chat_id, msg, context)


async def _send_to_admins(chat_id: int, msg: str, context: ContextTypes.DEFAULT_TYPE, keyboard=None):
    """Send message to all group admins."""
    try:
        admins = await context.bot.get_chat_administrators(chat_id)
        for admin in admins:
            if not admin.user.is_bot:
                try:
                    await context.bot.send_message(
                        chat_id=admin.user.id,
                        text=msg,
                        parse_mode=ParseMode.HTML,
                        reply_markup=keyboard,
                    )
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Notify admins error: {e}")


# ─────────────────────────────────────────
# Helper: Send review request to OWNER
# ─────────────────────────────────────────

async def send_review_request(
    chat_id: int, user_id: int, username: str,
    message_id: int, reason: str, text_preview: str,
    context: ContextTypes.DEFAULT_TYPE
):
    """
    Send uncertain message to owner for manual review.
    Owner sees: Block button | Real (safe) button
    """
    callback_block = f"review_block:{chat_id}:{user_id}:{message_id}"
    callback_safe = f"review_safe:{chat_id}:{user_id}:{message_id}"

    # Telegram callback_data max 64 bytes — truncate if needed
    callback_block = callback_block[:64]
    callback_safe = callback_safe[:64]

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("BLOCK (Ban)", callback_data=callback_block),
            InlineKeyboardButton("Real (Safe)", callback_data=callback_safe),
        ]
    ])

    msg = (
        f"<b>REVIEW NEEDED</b>\n\n"
        f"Group: <code>{chat_id}</code>\n"
        f"User: @{username or user_id} (<code>{user_id}</code>)\n"
        f"AI Reason: {reason}\n\n"
        f"Message:\n<i>{text_preview[:400]}</i>\n\n"
        f"Time: {datetime.now().strftime('%H:%M, %d.%m.%Y')}"
    )

    try:
        await context.bot.send_message(
            chat_id=OWNER_ID,
            text=msg,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        logger.info(f"Review request sent to owner for user {user_id}")
    except Exception as e:
        logger.error(f"Could not send review to owner: {e}")


# ─────────────────────────────────────────
# Callback: Owner presses Block or Real
# ─────────────────────────────────────────

async def handle_review_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    if not query or query.from_user.id != OWNER_ID:
        await query.answer("You are not authorized.")
        return

    await query.answer()
    data = query.data

    try:
        action, chat_id_str, user_id_str, msg_id_str = data.split(":")
        chat_id = int(chat_id_str)
        user_id = int(user_id_str)
        message_id = int(msg_id_str)
    except Exception:
        await query.edit_message_text("Error parsing callback data.")
        return

    if action == "review_block":
        # Ban user
        banned = await ban_user(chat_id, user_id, context, "Manual block by owner")
        # Try delete original message
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception:
            pass

        db.log_action(
            chat_id=chat_id, user_id=user_id, username=str(user_id),
            reason="Manual block by owner", confidence=1.0,
            message_preview="[owner decision]", category="manual_block"
        )
        status = "BLOCKED and banned." if banned else "Ban failed (maybe already left)."
        await query.edit_message_text(f"Action taken: {status}")

    elif action == "review_safe":
        db.log_action(
            chat_id=chat_id, user_id=user_id, username=str(user_id),
            reason="Marked safe by owner", confidence=1.0,
            message_preview="[owner decision]", category="safe"
        )
        await query.edit_message_text("Marked as SAFE. Message kept.")


# ─────────────────────────────────────────
# Main Message Handler
# ─────────────────────────────────────────

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.effective_chat:
        return

    chat = update.effective_chat
    user = update.effective_user
    message = update.message

    if chat.type not in ("group", "supergroup"):
        return

    # Check if group is registered and subscription active
    if not db.get_group(chat.id) or not payments.is_subscription_active(chat.id):
        return

    # Skip admins and group owner
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
        if member.status in ("administrator", "creator"):
            return
    except Exception:
        pass

    # Build text to analyze
    text = message.text or message.caption or ""

    if message.forward_origin:
        text += " [FORWARDED]"

    # Short messages with no media — skip
    if len(text.strip()) < 3 and not message.photo and not message.video:
        return

    # Get user profile info for AI context
    profile = await ai.check_profile(context.bot, chat.id, user.id)
    bio = profile.get("bio", "")
    username = profile.get("username", "")
    has_photo = profile.get("has_photo", True)
    profile_risk = profile.get("risk_score", 0)

    # If profile alone is very suspicious (e.g. sexual bio), note it in text
    if profile_risk >= 30:
        text += f" [PROFILE RISK: {', '.join(profile.get('indicators', []))}]"

    # AI Analysis
    result = await ai.analyze(text, bio=bio, username=username, has_photo=has_photo)

    category = result.get("category", "none")
    reason = result.get("reason", "Harmful content")
    confidence = result.get("confidence", 0.75)
    is_harmful = result.get("is_harmful", False)

    logger.info(
        f"MSG from {user.id} in {chat.id} | category={category} | "
        f"harmful={is_harmful} | confidence={confidence:.2f}"
    )

    # ── Case 1: Clearly harmful — auto block ──────────
    if is_harmful and confidence >= 0.88:
        await delete_message_safe(message)
        banned = await ban_user(chat.id, user.id, context, reason)

        db.log_action(
            chat_id=chat.id, user_id=user.id,
            username=user.username or str(user.id),
            reason=reason, confidence=confidence,
            message_preview=text[:150], category=category
        )

        if banned:
            await notify_admins_blocked(
                chat_id=chat.id, user_id=user.id,
                username=user.username or str(user.id),
                category=category, reason=reason,
                text_preview=text, context=context
            )

    # ── Case 2: Uncertain — send to owner for review ──
    elif category == "review" or (is_harmful and confidence < 0.88):
        await send_review_request(
            chat_id=chat.id, user_id=user.id,
            username=user.username or str(user.id),
            message_id=message.message_id,
            reason=reason, text_preview=text,
            context=context
        )

    # ── Case 3: Safe — do nothing ─────────────────────
    # else: message is fine, no action needed


# ─────────────────────────────────────────
# Commands
# ─────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type == "private":
        msg = (
            "<b>Welcome to GuardBot!</b>\n\n"
            "I automatically protect Telegram groups from:\n"
            "  Scam and fraud messages\n"
            "  Sexual spam\n"
            "  Phishing links and fake bots\n\n"
            "<b>How to start:</b>\n"
            "1. Add me to your group as Administrator\n"
            "2. Type /register in the group\n"
            "3. Get 30 days free trial instantly!\n\n"
            "/help — all commands"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
    else:
        await update.message.reply_text("Use /register to activate protection for this group.")


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "<b>GuardBot — Help</b>\n\n"
        "I use AI to detect and auto-block:\n"
        "  Scam and fraud\n"
        "  Sexual / adult spam\n"
        "  Phishing links and fake bots\n\n"
        "Uncertain cases are sent to the group owner for manual review "
        "with BLOCK / Real buttons.\n\n"
        "<b>Commands:</b>\n"
        "/register — Register your group\n"
        "/stats — View ban statistics\n"
        "/status — Check subscription status\n"
        "/pricing — View plans and pricing\n"
        "/pay — Payment instructions\n"
        "/help — This message"
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def cmd_register(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    user = update.effective_user

    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Use this command inside a group.")
        return

    member = await context.bot.get_chat_member(chat.id, user.id)
    if member.status not in ("administrator", "creator"):
        await update.message.reply_text("Only group admins can register.")
        return

    success = db.register_group(chat.id, chat.title, user.id)
    if success:
        payments.start_free_trial(chat.id)
        await update.message.reply_text(
            f"<b>{chat.title}</b> registered!\n\n"
            "30-day free trial started.\n"
            "GuardBot is now active and protecting this group.",
            parse_mode=ParseMode.HTML
        )
    else:
        await update.message.reply_text("This group is already registered.")


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    user = update.effective_user

    if chat.type not in ("group", "supergroup"):
        await update.message.reply_text("Use this command in a group.")
        return

    member = await context.bot.get_chat_member(chat.id, user.id)
    if member.status not in ("administrator", "creator"):
        await update.message.reply_text("Only admins can view statistics.")
        return

    stats = db.get_stats(chat.id)
    sub = payments.get_subscription_info(chat.id)

    await update.message.reply_text(
        f"<b>Statistics — {chat.title}</b>\n\n"
        f"Total Banned: {stats['total_bans']}\n"
        f"  Scam: {stats['scam_bans']}\n"
        f"  Sexual: {stats['sexual_bans']}\n"
        f"  Phishing: {stats['phishing_bans']}\n"
        f"  Manual blocks: {stats['manual_bans']}\n\n"
        f"Subscription: {sub['status']}\n"
        f"Expires: {sub['expires_at']}",
        parse_mode=ParseMode.HTML
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_chat.type != "private":
        await update.message.reply_text("Use /status in private chat with the bot.")
        return

    user = update.effective_user
    groups = db.get_user_groups(user.id)

    if not groups:
        await update.message.reply_text("You haven't registered any groups yet.")
        return

    text = "<b>Your Groups:</b>\n\n"
    for g in groups:
        sub = payments.get_subscription_info(g["chat_id"])
        text += f"<b>{g['title']}</b>\n  Status: {sub['status']}\n  Expires: {sub['expires_at']}\n\n"

    await update.message.reply_text(text, parse_mode=ParseMode.HTML)


async def cmd_pricing(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "<b>GuardBot Pricing</b>\n\n"
        "Free Trial — 30 days (no payment needed)\n\n"
        "Monthly Plans:\n"
        "  Starter — $2/month (up to 5,000 members)\n"
        "  Basic — $5/month (up to 30,000 members)\n"
        "  Standard — $7/month (up to 50,000 members)\n"
        "  Pro — $10/month (up to 100,000 members)\n"
        "  Business — $20/month (up to 1M members)\n"
        "  Enterprise — $45/month (up to 5M members)\n\n"
        "Yearly plans save 58%! Ask via /pay."
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


async def cmd_pay(update: Update, context: ContextTypes.DEFAULT_TYPE):
    from payments import OWNER_TELEGRAM
    msg = (
        "<b>Payment Instructions</b>\n\n"
        "1. Choose your plan: /pricing\n"
        "2. Contact the developer to arrange payment\n"
        f"3. Reach us at: {OWNER_TELEGRAM}\n\n"
        "Your group will be activated within 1 hour after payment."
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.HTML)


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def main():
    if not BOT_TOKEN:
        raise ValueError("BOT_TOKEN not set in .env file!")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("register", cmd_register))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("pricing", cmd_pricing))
    app.add_handler(CommandHandler("pay", cmd_pay))

    # Inline button handler (owner review)
    app.add_handler(CallbackQueryHandler(handle_review_callback, pattern=r"^review_(block|safe):"))

    # Message handler
    app.add_handler(MessageHandler(
        (filters.TEXT | filters.CAPTION | filters.PHOTO | filters.VIDEO) & ~filters.COMMAND,
        handle_message
    ))

    logger.info("GuardBot started.")
    import asyncio
    asyncio.run(app.run_polling(drop_pending_updates=True))


if __name__ == "__main__":
    main()
