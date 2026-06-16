"""
Payment and subscription management.
30 days free trial, then paid plans.
"""

import logging
from datetime import datetime, timedelta
from database import Database

logger = logging.getLogger(__name__)

OWNER_TELEGRAM = "@AGO050101"


class PaymentManager:
    FREE_TRIAL_DAYS = 30

    PLANS = {
        "starter":    {"price_monthly": 2,  "price_yearly": 10,  "min_members": 500,    "max_members": 5000,    "label": "Starter"},
        "basic":      {"price_monthly": 5,  "price_yearly": 25,  "min_members": 5000,   "max_members": 30000,   "label": "Basic"},
        "standard":   {"price_monthly": 7,  "price_yearly": 35,  "min_members": 30000,  "max_members": 50000,   "label": "Standard"},
        "pro":        {"price_monthly": 10, "price_yearly": 50,  "min_members": 50000,  "max_members": 100000,  "label": "Pro"},
        "business":   {"price_monthly": 20, "price_yearly": 100, "min_members": 100000, "max_members": 1000000, "label": "Business"},
        "enterprise": {"price_monthly": 45, "price_yearly": 225, "min_members": 1000000,"max_members": 5000000, "label": "Enterprise"},
    }

    def __init__(self, db: Database):
        self.db = db

    # ── Free trial ───────────────────────────────────

    def start_free_trial(self, chat_id: int):
        expires = (datetime.now() + timedelta(days=self.FREE_TRIAL_DAYS)).isoformat()
        self.db.set_subscription(chat_id=chat_id, plan="trial", expires_at=expires)
        logger.info(f"Free trial started for chat {chat_id}, expires {expires}")

    # ── Check subscription ────────────────────────────

    def is_subscription_active(self, chat_id: int) -> bool:
        sub = self.db.get_subscription(chat_id)
        if not sub or not sub["is_active"]:
            return False
        if sub["expires_at"]:
            expires = datetime.fromisoformat(sub["expires_at"])
            if datetime.now() > expires:
                self.db.deactivate_subscription(chat_id)
                return False
        return True

    def get_subscription_info(self, chat_id: int) -> dict:
        sub = self.db.get_subscription(chat_id)
        if not sub:
            return {"status": "Not registered", "expires_at": "—"}

        active = self.is_subscription_active(chat_id)
        plan_name = {
            "trial":      "Free Trial (30 days)",
            "starter":    "Starter ($2/mo)",
            "basic":      "Basic ($5/mo)",
            "standard":   "Standard ($7/mo)",
            "pro":        "Pro ($10/mo)",
            "business":   "Business ($20/mo)",
            "enterprise": "Enterprise ($45/mo)",
        }.get(sub["plan"], sub["plan"])

        if not active:
            return {"status": "Expired", "expires_at": sub["expires_at"][:10]}

        expires_str = sub["expires_at"][:10] if sub["expires_at"] else "Unlimited"
        return {
            "status": f"Active — {plan_name}",
            "expires_at": expires_str,
            "plan": sub["plan"],
        }

    def get_plan_for_members(self, member_count: int) -> str | None:
        for plan_id, plan in self.PLANS.items():
            if plan["min_members"] <= member_count <= plan["max_members"]:
                return plan_id
        return None

    # ── Activate paid plan ────────────────────────────

    def activate_paid_plan(self, chat_id: int, plan: str, months: int = 1) -> bool:
        if plan not in self.PLANS:
            return False
        sub = self.db.get_subscription(chat_id)
        if sub and sub["is_active"] and sub["expires_at"]:
            current_expiry = datetime.fromisoformat(sub["expires_at"])
            base = max(current_expiry, datetime.now())
        else:
            base = datetime.now()

        new_expiry = (base + timedelta(days=30 * months)).isoformat()
        self.db.set_subscription(chat_id=chat_id, plan=plan, expires_at=new_expiry)
        logger.info(f"Activated {plan} for chat {chat_id} until {new_expiry}")
        return True
