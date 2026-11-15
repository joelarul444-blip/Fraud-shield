#!/usr/bin/env python3
"""
================================================================================
CP-004 FraudShield: Rule-Based UPI Transaction Risk Engine
================================================================================
A rule-based UPI transaction risk engine built as a Python console application.

FraudShield evaluates each transaction against nine independent, weighted fraud
rules, combines them into a 0-100 risk score, and returns an explainable decision
of ALLOW, REVIEW, or BLOCK with detailed reasons for every fired rule.

Author: Antigravity AI (Google DeepMind)
Domain: Banking & FinTech / Payment Security
Standard Library Only (Python 3.8+)
================================================================================
"""

import sys
import os
import json
import re
import math
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Tuple, Any

# ==============================================================================
# ANSI Color Formatting Helper
# ==============================================================================
class Colors:
    """Terminal ANSI colors with graceful fallback."""
    ENABLED = True

    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.DIM = ''
        cls.UNDERLINE = ''
        cls.RESET = ''
        cls.ENABLED = False

# Enable ANSI escape sequences on Windows if supported
if os.name == 'nt':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        # If terminal doesn't support ANSI, leave Colors as is or disable if redirected
        pass

if not sys.stdout.isatty():
    Colors.disable()


# ==============================================================================
# CONFIGURATION BLOCK
# Adjustable thresholds and weights in a single block
# ==============================================================================
DEFAULT_CONFIG: Dict[str, Any] = {
    # ---------------------------------------------------------
    # Decision Score Cutoffs (0 - 100 Scale)
    # ---------------------------------------------------------
    "THRESHOLD_REVIEW": 30.0,   # Score >= 30 requires manual review (FLAGGED)
    "THRESHOLD_BLOCK": 60.0,    # Score >= 60 triggers instant block (BLOCKED)

    # ---------------------------------------------------------
    # Rule 1: Velocity Burst
    # Flag user making more than N transactions within T seconds
    # ---------------------------------------------------------
    "RULE_VELOCITY_BURST_WEIGHT": 30.0,
    "VELOCITY_WINDOW_SECONDS": 120,       # 2 minutes window
    "VELOCITY_MAX_TXNS": 3,               # Flag if > 3 txns in window

    # ---------------------------------------------------------
    # Rule 2: Amount Anomaly
    # Flag when amount > multiplier * user's historical average
    # ---------------------------------------------------------
    "RULE_AMOUNT_ANOMALY_WEIGHT": 30.0,
    "AMOUNT_ANOMALY_MULTIPLIER": 5.0,     # > 5x historical average
    "AMOUNT_ANOMALY_MIN_HISTORY": 2,      # Need at least 2 past txns

    # ---------------------------------------------------------
    # Rule 3: New Payee with Large Amount
    # Flag first transfer to an unseen receiver above threshold
    # ---------------------------------------------------------
    "RULE_NEW_PAYEE_LARGE_WEIGHT": 25.0,
    "NEW_PAYEE_LARGE_THRESHOLD": 10000.0, # ₹10,000 threshold for new payee

    # ---------------------------------------------------------
    # Rule 4: Odd Hours
    # Flag transactions initiated during high-risk night hours
    # ---------------------------------------------------------
    "RULE_ODD_HOURS_WEIGHT": 15.0,
    "ODD_HOURS_START": 0,                 # 00:00 (Midnight)
    "ODD_HOURS_END": 5,                   # 05:00 AM

    # ---------------------------------------------------------
    # Rule 5: New Device
    # Flag when user transacts from an unseen device
    # ---------------------------------------------------------
    "RULE_NEW_DEVICE_WEIGHT": 15.0,

    # ---------------------------------------------------------
    # Rule 6: Location Jump / Unfamiliar City
    # Flag unseen city or physically impossible transit between cities
    # ---------------------------------------------------------
    "RULE_LOCATION_JUMP_WEIGHT": 30.0,
    "IMPOSSIBLE_TRAVEL_WINDOW_HOURS": 2.0, # Jump between different cities < 2 hrs

    # ---------------------------------------------------------
    # Rule 7: Repeated Transfers to One Receiver
    # Flag multiple transfers to same receiver in short time (smurfing)
    # ---------------------------------------------------------
    "RULE_REPEAT_PAYEE_WEIGHT": 30.0,
    "REPEAT_PAYEE_WINDOW_SECONDS": 300,   # 5 minutes window
    "REPEAT_PAYEE_MAX_TXNS": 2,           # > 2 txns to same payee in window

    # ---------------------------------------------------------
    # Rule 8: Daily UPI Limit
    # Standard cumulative daily transaction ceiling
    # ---------------------------------------------------------
    "RULE_DAILY_LIMIT_WEIGHT": 30.0,
    "DAILY_LIMIT_THRESHOLD": 100000.0,    # ₹1,00,000 per calendar day

    # ---------------------------------------------------------
    # Rule 9: Large Round Amount
    # Clean round sums frequently seen in fraud drains & mule tests
    # ---------------------------------------------------------
    "RULE_LARGE_ROUND_WEIGHT": 10.0,
    "LARGE_ROUND_MIN_AMOUNT": 10000.0,    # Above ₹10,000
    "LARGE_ROUND_STEP": 1000.0,           # Exact multiple of ₹1,000

    # ---------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------
    "DATA_FILE": "fraudshield_data.json"
}

# Active configuration (starts with copy of default config)
CONFIG: Dict[str, Any] = dict(DEFAULT_CONFIG)


# ==============================================================================
# INPUT VALIDATION
# ==============================================================================
class Validator:
    """Validates UPI IDs, monetary amounts, timestamps, and metadata."""

    # UPI ID standard: user@handle (alphanumeric with dots, underscores, hyphens)
    UPI_REGEX = re.compile(r'^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-_]{2,}$')

    @classmethod
    def validate_upi_id(cls, upi_id: str, field_name: str = "UPI ID") -> Tuple[bool, str]:
        """Validate UPI ID format (e.g., user@bank, 9876543210@paytm) and normalize to lowercase."""
        upi_id = upi_id.strip().lower()
        if not upi_id:
            return False, f"{field_name} cannot be empty."
        if not cls.UPI_REGEX.match(upi_id):
            return False, f"{field_name} '{upi_id}' is invalid. Expected format: username@bank (e.g., priya@okaxis)."
        return True, upi_id

    @classmethod
    def validate_amount(cls, amount_input: Any) -> Tuple[bool, float, str]:
        """Validate transaction amount is a positive number."""
        try:
            amt = float(amount_input)
            if math.isnan(amt) or math.isinf(amt):
                return False, 0.0, "Amount must be a real finite number."
            if amt <= 0:
                return False, 0.0, "Amount must be greater than zero."
            if amt > 10_000_000:
                return False, 0.0, "Amount exceeds system maximum transaction cap (₹10,000,000)."
            return True, round(amt, 2), ""
        except (ValueError, TypeError):
            return False, 0.0, "Amount must be a valid numeric value (e.g. 500 or 1250.50)."

    @classmethod
    def validate_timestamp(cls, ts_input: str) -> Tuple[bool, Optional[datetime], str]:
        """
        Validate and parse transaction timestamp.
        Supports:
          - ISO / Standard: YYYY-MM-DD HH:MM:SS, YYYY-MM-DD HH:MM
          - Time only: HH:MM, HH:MM:SS (uses current date)
          - Blank: returns current system time
        """
        ts_input = ts_input.strip()
        now = datetime.now()

        if not ts_input:
            return True, now, ""

        formats_full = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
            "%d-%m-%Y %H:%M:%S",
            "%d-%m-%Y %H:%M",
        ]
        for fmt in formats_full:
            try:
                dt = datetime.strptime(ts_input, fmt)
                return True, dt, ""
            except ValueError:
                continue

        formats_time = ["%H:%M:%S", "%H:%M"]
        for fmt in formats_time:
            try:
                t = datetime.strptime(ts_input, fmt).time()
                dt = datetime.combine(now.date(), t)
                return True, dt, ""
            except ValueError:
                continue

        return False, None, "Invalid timestamp format. Accepted: 'YYYY-MM-DD HH:MM[:SS]' or 'HH:MM[:SS]'."

    @classmethod
    def validate_text(cls, text: str, field_name: str) -> Tuple[bool, str]:
        """Validate non-empty alphanumeric text (e.g., city, device ID)."""
        text = text.strip()
        if not text:
            return False, f"{field_name} cannot be empty."
        if len(text) > 60:
            return False, f"{field_name} exceeds maximum length (60 characters)."
        return True, text


# ==============================================================================
# DATA MODELS
# ==============================================================================
class RuleTrigger:
    """Represents a rule that was evaluated against a transaction."""
    def __init__(self, rule_id: str, name: str, weight: float, triggered: bool, reason: str):
        self.rule_id = rule_id
        self.name = name
        self.weight = weight
        self.triggered = triggered
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "weight": self.weight,
            "triggered": self.triggered,
            "reason": self.reason
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RuleTrigger':
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            weight=data["weight"],
            triggered=data["triggered"],
            reason=data["reason"]
        )


class Transaction:
    """Represents a UPI transaction and its risk evaluation outcome."""
    def __init__(
        self,
        transaction_id: str,
        sender_upi: str,
        receiver_upi: str,
        amount: float,
        timestamp: datetime,
        city: str,
        device_id: str,
        risk_score: float = 0.0,
        decision: str = "ALLOW",
        triggered_rules: Optional[List[RuleTrigger]] = None,
        is_false_alarm: bool = False,
        analyst_notes: str = ""
    ):
        self.transaction_id = transaction_id
        self.sender_upi = sender_upi
        self.receiver_upi = receiver_upi
        self.amount = amount
        self.timestamp = timestamp
        self.city = city
        self.device_id = device_id
        self.risk_score = risk_score
        self.decision = decision
        self.triggered_rules = triggered_rules or []
        self.is_false_alarm = is_false_alarm
        self.analyst_notes = analyst_notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "sender_upi": self.sender_upi,
            "receiver_upi": self.receiver_upi,
            "amount": self.amount,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "city": self.city,
            "device_id": self.device_id,
            "risk_score": self.risk_score,
            "decision": self.decision,
            "triggered_rules": [r.to_dict() for r in self.triggered_rules],
            "is_false_alarm": self.is_false_alarm,
            "analyst_notes": self.analyst_notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        dt = datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
        rules = [RuleTrigger.from_dict(r) for r in data.get("triggered_rules", [])]
        return cls(
            transaction_id=data["transaction_id"],
            sender_upi=data["sender_upi"],
            receiver_upi=data["receiver_upi"],
            amount=data["amount"],
            timestamp=dt,
            city=data["city"],
            device_id=data.get("device_id", "UNKNOWN_DEV"),
            risk_score=data.get("risk_score", 0.0),
            decision=data.get("decision", "ALLOW"),
            triggered_rules=rules,
            is_false_alarm=data.get("is_false_alarm", False),
            analyst_notes=data.get("analyst_notes", "")
        )


# ==============================================================================
# RULE EVALUATOR & RISK ENGINE
# ==============================================================================
class FraudShieldEngine:
    """
    Core risk engine implementing nine weighted fraud detection rules.
    Maintains historical transaction records, evaluates new transactions,
    and calculates explainable risk scores.
    """

    def __init__(self, data_file: Optional[str] = None):
        self.data_file = data_file or CONFIG["DATA_FILE"]
        self.transactions: List[Transaction] = []
        self.txn_counter: int = 1000

    def load_data(self) -> bool:
        """Load stored transactions from JSON file."""
        if not os.path.exists(self.data_file):
            return False
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)

            if not isinstance(raw_data, list):
                raise ValueError("Stored data is not a JSON list of transactions.")

            self.transactions = [Transaction.from_dict(item) for item in raw_data]
            # Update counter to avoid ID collisions
            for txn in self.transactions:
                match = re.search(r'\d+', txn.transaction_id)
                if match:
                    num = int(match.group())
                    if num >= self.txn_counter:
                        self.txn_counter = num + 1
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Error loading data from {self.data_file}: {e}{Colors.RESET}")
            self.transactions = []
            return False

    def save_data(self) -> bool:
        """Persist transaction records to JSON file."""
        try:
            directory = os.path.dirname(os.path.abspath(self.data_file))
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump([txn.to_dict() for txn in self.transactions], f, indent=2)
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Error saving data to {self.data_file}: {e}{Colors.RESET}")
            return False

    def clear_data(self):
        """Reset all in-memory and persisted transactions."""
        self.transactions.clear()
        self.txn_counter = 1000
        if os.path.exists(self.data_file):
            try:
                os.remove(self.data_file)
            except OSError:
                pass

    def generate_next_id(self) -> str:
        """Generate a sequential unique transaction ID."""
        self.txn_counter += 1
        return f"TXN-{self.txn_counter:04d}"

    def get_user_history(self, user_upi: str) -> List[Transaction]:
        """Get all past transactions initiated by a user (chronological, case-insensitive)."""
        clean_user = user_upi.strip().lower()
        history = [t for t in self.transactions if t.sender_upi.lower() == clean_user]
        return sorted(history, key=lambda x: x.timestamp)

    # --------------------------------------------------------------------------
    # NINE FRAUD DETECTION RULES
    # --------------------------------------------------------------------------

    def check_rule_1_velocity_burst(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 1: Velocity Burst
        Flag if user makes more than VELOCITY_MAX_TXNS within VELOCITY_WINDOW_SECONDS.
        """
        rule_id = "R1_VELOCITY"
        name = "Velocity Burst"
        weight = CONFIG["RULE_VELOCITY_BURST_WEIGHT"]
        window_sec = CONFIG["VELOCITY_WINDOW_SECONDS"]
        max_txns = CONFIG["VELOCITY_MAX_TXNS"]

        cutoff_time = txn.timestamp - timedelta(seconds=window_sec)
        recent_txns = [t for t in user_history if cutoff_time <= t.timestamp <= txn.timestamp]
        count = len(recent_txns) + 1  # Including current transaction

        if count > max_txns:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Rapid transaction burst: User initiated {count} transactions within "
                    f"{window_sec}s (threshold: > {max_txns})."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Velocity within safe threshold ({count}/{max_txns} transactions within {window_sec}s)."
        )

    def check_rule_2_amount_anomaly(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 2: Amount Anomaly
        Flag when amount > AMOUNT_ANOMALY_MULTIPLIER * user's historical average.
        """
        rule_id = "R2_AMOUNT_ANOMALY"
        name = "Amount Anomaly"
        weight = CONFIG["RULE_AMOUNT_ANOMALY_WEIGHT"]
        multiplier = CONFIG["AMOUNT_ANOMALY_MULTIPLIER"]
        min_history = CONFIG["AMOUNT_ANOMALY_MIN_HISTORY"]

        prior_history = [t for t in user_history if t.timestamp <= txn.timestamp]
        if len(prior_history) < min_history:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=False,
                reason=(
                    f"Insufficient baseline: User has {len(prior_history)} past transaction(s); "
                    f"minimum {min_history} required to establish spending average."
                )
            )

        avg_amount = sum(t.amount for t in prior_history) / len(prior_history)
        if avg_amount <= 0:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=False,
                reason=(
                    f"Historical spending baseline is zero or invalid; cannot compare anomaly against "
                    f"a non-positive average (avg ₹{avg_amount:,.2f})."
                )
            )

        threshold = avg_amount * multiplier

        if txn.amount > threshold:
            ratio = txn.amount / avg_amount
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Unusually large amount: ₹{txn.amount:,.2f} is {ratio:.1f}x the user's historical "
                    f"average of ₹{avg_amount:,.2f} (threshold: > {multiplier:.1f}x = ₹{threshold:,.2f})."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Amount is within normal range (₹{txn.amount:,.2f} vs avg ₹{avg_amount:,.2f})."
        )

    def check_rule_3_new_payee_large_amount(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 3: New Payee with Large Amount
        Flag first transfer to an unseen receiver when amount >= NEW_PAYEE_LARGE_THRESHOLD.
        """
        rule_id = "R3_NEW_PAYEE_LARGE"
        name = "New Payee with Large Amount"
        weight = CONFIG["RULE_NEW_PAYEE_LARGE_WEIGHT"]
        threshold = CONFIG["NEW_PAYEE_LARGE_THRESHOLD"]

        prior_history = [t for t in user_history if t.timestamp <= txn.timestamp]
        known_payees = {t.receiver_upi.lower() for t in prior_history}
        is_new_payee = txn.receiver_upi.lower() not in known_payees

        if is_new_payee and txn.amount >= threshold:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"High-value first-time transfer: ₹{txn.amount:,.2f} sent to never-before-seen "
                    f"payee '{txn.receiver_upi}' (threshold: >= ₹{threshold:,.2f})."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=(
                "Payee is previously known" if not is_new_payee
                else f"New payee transfer is below high-value threshold (₹{txn.amount:,.2f} < ₹{threshold:,.2f})."
            )
        )

    def check_rule_4_odd_hours(self, txn: Transaction) -> RuleTrigger:
        """
        Rule 4: Odd Hours
        Flag transactions initiated during unusual late-night / early-morning hours.
        """
        rule_id = "R4_ODD_HOURS"
        name = "Odd Hours Activity"
        weight = CONFIG["RULE_ODD_HOURS_WEIGHT"]
        start_hour = CONFIG["ODD_HOURS_START"]
        end_hour = CONFIG["ODD_HOURS_END"]

        hour = txn.timestamp.hour
        is_odd = (start_hour <= hour < end_hour) if start_hour < end_hour else (hour >= start_hour or hour < end_hour)

        time_str = txn.timestamp.strftime("%H:%M:%S")
        if is_odd:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Odd hours transaction: Initiated at {time_str} inside high-risk nocturnal "
                    f"window ({start_hour:02d}:00 - {end_hour:02d}:00)."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Transaction initiated during standard operational hours ({time_str})."
        )

    def check_rule_5_new_device(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 5: New Device
        Flag when an established user transacts from an unseen device ID.
        """
        rule_id = "R5_NEW_DEVICE"
        name = "Unrecognized Device"
        weight = CONFIG["RULE_NEW_DEVICE_WEIGHT"]

        prior_history = [t for t in user_history if t.timestamp <= txn.timestamp]
        if not prior_history:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=False,
                reason="First transaction for user; registering initial device as trusted."
            )

        known_devices = {t.device_id for t in prior_history if t.device_id}
        if txn.device_id not in known_devices:
            devices_list = ", ".join(f"'{d}'" for d in sorted(known_devices))
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Device anomaly: '{txn.device_id}' has never been used by this user before "
                    f"(known device(s): {devices_list})."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Device '{txn.device_id}' matches user's verified device history."
        )

    def check_rule_6_location_jump(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 6: Location Jump / Unfamiliar City
        Flag when user transacts from an unfamiliar city or exhibits impossible travel velocity.
        """
        rule_id = "R6_LOCATION_JUMP"
        name = "Location Jump / Unfamiliar City"
        weight = CONFIG["RULE_LOCATION_JUMP_WEIGHT"]
        jump_window_hours = CONFIG["IMPOSSIBLE_TRAVEL_WINDOW_HOURS"]

        prior_history = [t for t in user_history if t.timestamp <= txn.timestamp]
        if not prior_history:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=False,
                reason="First transaction for user; registering initial city as base location."
            )

        known_cities = {t.city.strip().lower() for t in prior_history if t.city}
        current_city = txn.city.strip().lower()
        is_new_city = current_city not in known_cities

        # Check for impossible travel from the most recent transaction
        latest_past_txn = max(prior_history, key=lambda t: t.timestamp)
        time_diff = txn.timestamp - latest_past_txn.timestamp
        time_diff_hours = time_diff.total_seconds() / 3600.0

        if is_new_city:
            cities_display = ", ".join(sorted(list({t.city.title() for t in prior_history if t.city})))
            # Impossible travel check
            if 0 <= time_diff_hours < jump_window_hours and latest_past_txn.city.lower() != current_city:
                minutes = int(time_diff.total_seconds() // 60)
                return RuleTrigger(
                    rule_id=rule_id,
                    name=name,
                    weight=weight,
                    triggered=True,
                    reason=(
                        f"Impossible travel detected: User transacted in '{latest_past_txn.city}' then '{txn.city}' "
                        f"just {minutes} minutes later (impossible physical transit < {jump_window_hours} hrs)."
                    )
                )
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Unfamiliar city: First transaction from '{txn.city}' for this user "
                    f"(previous transacted cities: {cities_display})."
                )
            )

        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"City '{txn.city}' matches user's established geographic history."
        )

    def check_rule_7_repeated_transfers(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 7: Repeated Transfers to One Receiver
        Flag rapid consecutive payments to the same payee within REPEAT_PAYEE_WINDOW_SECONDS.
        """
        rule_id = "R7_REPEAT_PAYEE"
        name = "Repeated Transfers to Single Payee"
        weight = CONFIG["RULE_REPEAT_PAYEE_WEIGHT"]
        window_sec = CONFIG["REPEAT_PAYEE_WINDOW_SECONDS"]
        max_txns = CONFIG["REPEAT_PAYEE_MAX_TXNS"]

        cutoff_time = txn.timestamp - timedelta(seconds=window_sec)
        same_payee_txns = [
            t for t in user_history
            if t.receiver_upi.lower() == txn.receiver_upi.lower()
            and cutoff_time <= t.timestamp <= txn.timestamp
        ]
        count = len(same_payee_txns) + 1

        if count > max_txns:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Smurfing / repeated transfer pattern: {count} transactions sent to payee "
                    f"'{txn.receiver_upi}' within {window_sec}s (threshold: > {max_txns})."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Transfer frequency to payee is normal ({count}/{max_txns} within {window_sec}s)."
        )

    def check_rule_8_daily_limit(
        self, txn: Transaction, user_history: List[Transaction]
    ) -> RuleTrigger:
        """
        Rule 8: Daily UPI Limit
        Flag if user's cumulative transactions on the same calendar day exceed DAILY_LIMIT_THRESHOLD.
        """
        rule_id = "R8_DAILY_LIMIT"
        name = "Daily Transaction Limit Exceeded"
        weight = CONFIG["RULE_DAILY_LIMIT_WEIGHT"]
        limit = CONFIG["DAILY_LIMIT_THRESHOLD"]

        txn_date = txn.timestamp.date()
        today_txns = [t for t in user_history if t.timestamp.date() == txn_date]
        prior_total = sum(t.amount for t in today_txns)
        projected_total = prior_total + txn.amount

        if projected_total > limit:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Daily UPI ceiling breached: Projected cumulative daily total is ₹{projected_total:,.2f} "
                    f"(previous today: ₹{prior_total:,.2f} + current: ₹{txn.amount:,.2f}), exceeding "
                    f"daily limit of ₹{limit:,.2f}."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=(
                f"Cumulative daily total ₹{projected_total:,.2f} is within limit of ₹{limit:,.2f}."
            )
        )

    def check_rule_9_large_round_amount(self, txn: Transaction) -> RuleTrigger:
        """
        Rule 9: Large Round Amount
        Flag clean round values (e.g. ₹25,000, ₹50,000) >= LARGE_ROUND_MIN_AMOUNT.
        """
        rule_id = "R9_ROUND_AMOUNT"
        name = "Large Round Amount"
        weight = CONFIG["RULE_LARGE_ROUND_WEIGHT"]
        min_amount = CONFIG["LARGE_ROUND_MIN_AMOUNT"]
        step = CONFIG["LARGE_ROUND_STEP"]

        is_large = txn.amount >= min_amount
        is_round = (txn.amount % step == 0)

        if is_large and is_round:
            return RuleTrigger(
                rule_id=rule_id,
                name=name,
                weight=weight,
                triggered=True,
                reason=(
                    f"Suspicious round figure: ₹{txn.amount:,.2f} is an exact multiple of ₹{step:,.0f} "
                    f"above ₹{min_amount:,.2f} (common signature of account draining / cash-out)."
                )
            )
        return RuleTrigger(
            rule_id=rule_id,
            name=name,
            weight=weight,
            triggered=False,
            reason=f"Amount does not match high-value round number pattern (₹{txn.amount:,.2f})."
        )

    # --------------------------------------------------------------------------
    # EVALUATION ORCHESTRATOR
    # --------------------------------------------------------------------------

    def evaluate_transaction(self, txn: Transaction, commit: bool = True) -> Transaction:
        """
        Evaluate a transaction against all 9 rules, calculate combined risk score,
        determine ALLOW / REVIEW / BLOCK decision, and record in memory.
        """
        user_history = self.get_user_history(txn.sender_upi)

        # Run all 9 rules
        rule_results: List[RuleTrigger] = [
            self.check_rule_1_velocity_burst(txn, user_history),
            self.check_rule_2_amount_anomaly(txn, user_history),
            self.check_rule_3_new_payee_large_amount(txn, user_history),
            self.check_rule_4_odd_hours(txn),
            self.check_rule_5_new_device(txn, user_history),
            self.check_rule_6_location_jump(txn, user_history),
            self.check_rule_7_repeated_transfers(txn, user_history),
            self.check_rule_8_daily_limit(txn, user_history),
            self.check_rule_9_large_round_amount(txn)
        ]

        # Calculate composite risk score
        triggered = [r for r in rule_results if r.triggered]
        raw_score = sum(r.weight for r in triggered)
        final_score = min(100.0, max(0.0, raw_score))

        # Determine decision
        if final_score >= CONFIG["THRESHOLD_BLOCK"]:
            decision = "BLOCK"
        elif final_score >= CONFIG["THRESHOLD_REVIEW"]:
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        txn.risk_score = final_score
        txn.decision = decision
        txn.triggered_rules = triggered

        if commit:
            self.transactions.append(txn)
            self.save_data()

        return txn


# ==============================================================================
# REPORTING & ANALYTICS
# ==============================================================================
class Reporting:
    """Formats and displays console output, cards, summaries, and risk tables."""

    @staticmethod
    def get_decision_badge(decision: str) -> str:
        if decision == "ALLOW":
            return f"{Colors.GREEN}{Colors.BOLD}[ ALLOW ]{Colors.RESET}"
        elif decision == "REVIEW":
            return f"{Colors.YELLOW}{Colors.BOLD}[ REVIEW ]{Colors.RESET}"
        else:
            return f"{Colors.RED}{Colors.BOLD}[ BLOCK ]{Colors.RESET}"

    @staticmethod
    def print_transaction_card(txn: Transaction):
        """Display an explainable evaluation card for a single transaction."""
        badge = Reporting.get_decision_badge(txn.decision)
        score_color = (
            Colors.GREEN if txn.risk_score < CONFIG["THRESHOLD_REVIEW"]
            else (Colors.YELLOW if txn.risk_score < CONFIG["THRESHOLD_BLOCK"] else Colors.RED)
        )

        border = "=" * 76
        print(f"\n{Colors.CYAN}{border}{Colors.RESET}")
        print(f"{Colors.BOLD} TRANSACTION RISK ASSESSMENT REPORT {Colors.RESET} {badge}")
        print(f"{Colors.CYAN}{border}{Colors.RESET}")
        print(f"  {Colors.BOLD}Transaction ID :{Colors.RESET} {txn.transaction_id}")
        print(f"  {Colors.BOLD}Sender UPI     :{Colors.RESET} {txn.sender_upi}")
        print(f"  {Colors.BOLD}Receiver UPI   :{Colors.RESET} {txn.receiver_upi}")
        print(f"  {Colors.BOLD}Amount         :{Colors.RESET} ₹{txn.amount:,.2f}")
        print(f"  {Colors.BOLD}Timestamp      :{Colors.RESET} {txn.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  {Colors.BOLD}City / Location:{Colors.RESET} {txn.city}")
        print(f"  {Colors.BOLD}Device ID      :{Colors.RESET} {txn.device_id}")
        print(f"  {Colors.BOLD}Risk Score     :{Colors.RESET} {score_color}{txn.risk_score:.1f} / 100.0{Colors.RESET}")
        print(f"  {Colors.BOLD}Final Decision :{Colors.RESET} {badge}")
        if txn.is_false_alarm:
            print(f"  {Colors.CYAN}{Colors.BOLD}Analyst Status :{Colors.RESET} {Colors.CYAN}[ RESOLVED AS FALSE ALARM ]{Colors.RESET}")
            if txn.analyst_notes:
                print(f"  {Colors.CYAN}{Colors.BOLD}Analyst Notes  :{Colors.RESET} {txn.analyst_notes}")
        print(f"{Colors.CYAN}{'-' * 76}{Colors.RESET}")

        if not txn.triggered_rules:
            print(f"  {Colors.GREEN}✓ No fraud rules triggered. Transaction matches expected behavioral profile.{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}{Colors.BOLD}Rules Triggered ({len(txn.triggered_rules)}):{Colors.RESET}")
            for idx, rule in enumerate(txn.triggered_rules, 1):
                print(f"    {Colors.RED}[{idx}] {rule.name} (Weight: +{rule.weight:.0f}){Colors.RESET}")
                print(f"        {Colors.DIM}↳ Reason:{Colors.RESET} {rule.reason}")

        print(f"{Colors.CYAN}{border}{Colors.RESET}\n")

    @staticmethod
    def print_transactions_table(transactions: List[Transaction], title: str = "RECORDED TRANSACTIONS"):
        """Print a structured tabular view of transactions."""
        if not transactions:
            print(f"\n{Colors.YELLOW}[i] No transactions recorded yet.{Colors.RESET}\n")
            return

        print(f"\n{Colors.BOLD}{Colors.CYAN}=== {title} ({len(transactions)}) ==={Colors.RESET}")
        header = f"{'Txn ID':<10} | {'Sender UPI':<20} | {'Amount (₹)':<12} | {'Time':<8} | {'City':<12} | {'Score':<6} | {'Decision':<8}"
        sep = "-" * len(header)
        print(f"{Colors.BOLD}{header}{Colors.RESET}")
        print(sep)

        for t in transactions:
            dec_color = Colors.GREEN if t.decision == "ALLOW" else (Colors.YELLOW if t.decision == "REVIEW" else Colors.RED)
            time_str = t.timestamp.strftime("%H:%M")
            sender = t.sender_upi if len(t.sender_upi) <= 20 else t.sender_upi[:17] + "..."
            city = t.city if len(t.city) <= 12 else t.city[:10] + ".."
            dec_badge = f"{t.decision} [FA]" if t.is_false_alarm else t.decision
            print(
                f"{t.transaction_id:<10} | {sender:<20} | {t.amount:>12,.2f} | {time_str:<8} | "
                f"{city:<12} | {t.risk_score:>5.1f} | {dec_color}{dec_badge:<10}{Colors.RESET}"
            )
        print(sep + "\n")

    @staticmethod
    def print_flagged_report(transactions: List[Transaction]):
        """Display comprehensive explanation of all flagged transactions."""
        flagged = [t for t in transactions if t.decision in ("REVIEW", "BLOCK")]
        if not flagged:
            print(f"\n{Colors.GREEN}[✓] Zero flagged transactions. All transactions have been cleared as ALLOW.{Colors.RESET}\n")
            return

        print(f"\n{Colors.BOLD}{Colors.RED}=== FLAGGED TRANSACTIONS AUDIT REPORT ({len(flagged)} FLAGGED) ==={Colors.RESET}")
        Reporting.print_transactions_table(flagged, title=f"FLAGGED SUMMARY ({len(flagged)} TRANSACTIONS)")
        for t in flagged:
            Reporting.print_transaction_card(t)

    @staticmethod
    def print_user_risk_summary(engine: FraudShieldEngine):
        """Display per-user risk counts and behavioral profiles."""
        if not engine.transactions:
            print(f"\n{Colors.YELLOW}[i] No transaction history available.{Colors.RESET}\n")
            return

        users = sorted(list({t.sender_upi for t in engine.transactions}))
        print(f"\n{Colors.BOLD}{Colors.CYAN}=== USER RISK PROFILE & FLAG COUNT SUMMARY ==={Colors.RESET}")
        header = f"{'User UPI':<24} | {'Total Txns':<10} | {'Total Vol (₹)':<14} | {'Avg Txn (₹)':<12} | {'Flagged':<8} | {'Risk Level':<10}"
        sep = "-" * len(header)
        print(f"{Colors.BOLD}{header}{Colors.RESET}")
        print(sep)

        for u in users:
            txns = [t for t in engine.transactions if t.sender_upi == u]
            total_vol = sum(t.amount for t in txns)
            avg_vol = total_vol / len(txns) if txns else 0.0
            flagged_count = sum(1 for t in txns if t.decision in ("REVIEW", "BLOCK"))
            risk_rate = (flagged_count / len(txns)) * 100 if txns else 0.0

            if risk_rate >= 50 or flagged_count >= 3:
                risk_badge = f"{Colors.RED}HIGH{Colors.RESET}"
            elif flagged_count > 0:
                risk_badge = f"{Colors.YELLOW}MODERATE{Colors.RESET}"
            else:
                risk_badge = f"{Colors.GREEN}LOW{Colors.RESET}"

            display_user = u if len(u) <= 24 else u[:21] + "..."
            print(
                f"{display_user:<24} | {len(txns):<10} | {total_vol:>14,.2f} | {avg_vol:>12,.2f} | "
                f"{flagged_count:<8} | {risk_badge:<10}"
            )
        print(sep + "\n")

    @staticmethod
    def print_engine_statistics(engine: FraudShieldEngine):
        """Display aggregate system metrics and rule trigger frequencies."""
        txns = engine.transactions
        total = len(txns)

        print(f"\n{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}        FRAUDSHIELD ENGINE ANALYTICS DASHBOARD       {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")

        if total == 0:
            print(f"  {Colors.YELLOW}No transactions evaluated yet.{Colors.RESET}\n")
            return

        allow_cnt = sum(1 for t in txns if t.decision == "ALLOW")
        review_cnt = sum(1 for t in txns if t.decision == "REVIEW")
        block_cnt = sum(1 for t in txns if t.decision == "BLOCK")
        total_vol = sum(t.amount for t in txns)
        blocked_vol = sum(t.amount for t in txns if t.decision == "BLOCK")

        print(f"  Total Evaluated Transactions : {Colors.BOLD}{total}{Colors.RESET}")
        print(f"  Total Processed Volume       : ₹{total_vol:,.2f}")
        print(f"  Blocked Volume Stopped       : {Colors.RED}₹{blocked_vol:,.2f}{Colors.RESET}")
        print(f"  ----------------------------------------------------")
        print(f"  Decisions Breakdown:")
        print(f"    • {Colors.GREEN}ALLOW  :{Colors.RESET} {allow_cnt:<5} ({allow_cnt / total * 100:.1f}%)")
        print(f"    • {Colors.YELLOW}REVIEW :{Colors.RESET} {review_cnt:<5} ({review_cnt / total * 100:.1f}%)")
        print(f"    • {Colors.RED}BLOCK  :{Colors.RESET} {block_cnt:<5} ({block_cnt / total * 100:.1f}%)")
        print(f"  ----------------------------------------------------")

        # Count frequencies for each rule
        rule_counts: Dict[str, int] = {}
        for t in txns:
            for r in t.triggered_rules:
                rule_counts[r.name] = rule_counts.get(r.name, 0) + 1

        print(f"  {Colors.BOLD}Rule Trigger Frequency Distribution:{Colors.RESET}")
        if not rule_counts:
            print(f"    {Colors.GREEN}No rules have been triggered.{Colors.RESET}")
        else:
            for rule_name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
                pct = (count / total) * 100
                bar = "█" * int(pct / 5)
                print(f"    • {rule_name:<34} : {count:>2}x ({pct:>5.1f}%) {Colors.CYAN}{bar}{Colors.RESET}")

        # False alarm statistics (Stretch feature)
        total_flagged = review_cnt + block_cnt
        false_alarms = [t for t in txns if t.is_false_alarm]
        fa_count = len(false_alarms)
        fa_rate = (fa_count / total_flagged * 100) if total_flagged > 0 else 0.0

        print(f"  ----------------------------------------------------")
        print(f"  {Colors.BOLD}Analyst False-Alarm Metrics (CP-004 Stretch):{Colors.RESET}")
        print(f"    • Total Flagged Transactions : {total_flagged}")
        print(f"    • Marked as False Alarms     : {fa_count} ({fa_rate:.1f}%)")
        if fa_count > 0:
            print(f"    • False-Alarm Rate per Triggered Rule:")
            for rule_name, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
                rule_fa_count = sum(
                    1 for t in false_alarms
                    if any(r.name == rule_name for r in t.triggered_rules)
                )
                rule_fa_rate = (rule_fa_count / count * 100) if count > 0 else 0.0
                print(f"      - {rule_name:<34}: {rule_fa_count}/{count} ({rule_fa_rate:.1f}%)")

        print(f"{Colors.CYAN}===================================================={Colors.RESET}\n")


# ==============================================================================
# BUILT-IN DEMO SCENARIO
# Showcases Account Takeover, Velocity Burst, and Impossible Travel
# ==============================================================================
def run_demo_scenario(engine: FraudShieldEngine, interactive: bool = True, reset_first: bool = False):
    """
    Executes a structured end-to-end FinTech fraud simulation featuring:
      1. Legitimate baseline activity for User Priya (ALLOW)
      2. Velocity burst from User Rahul (REVIEW/BLOCK)
      3. Impossible travel / Location jump for User Amit (BLOCK)
      4. Account Takeover (ATO) attack at odd hours on Priya's account (BLOCK)
      5. Smurfing / Repeated transfer attack (REVIEW/BLOCK)
      6. Daily transaction ceiling breach (REVIEW/BLOCK)
    """
    if engine.transactions and not reset_first:
        if interactive:
            confirm = prompt_input("Reset existing records to start a fresh demo simulation? (Y/n)", default="Y")
            if confirm.lower() in ("y", "yes"):
                engine.clear_data()
                print(f"{Colors.GREEN}[✓] Data reset. Running fresh demo scenario.{Colors.RESET}\n")
        else:
            engine.clear_data()
    elif reset_first:
        engine.clear_data()

    print(f"\n{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}            STARTING BUILT-IN DEMO SCENARIO EVALUATION                  {Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.HEADER}========================================================================{Colors.RESET}")
    print("This simulation walks through realistic UPI payment flows, demonstrating")
    print("how independent rules accumulate into explainable ALLOW, REVIEW, and BLOCK decisions.\n")

    base_time = datetime(2026, 11, 15, 10, 0, 0)

    demo_txns = [
        # ----------------------------------------------------------------------
        # Phase 1: Normal Legitimate Activity (Baseline for Priya)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 1: Establishing Legitimate User Baseline",
            "narrative": "Priya buys morning coffee in Mumbai on her usual phone.",
            "sender": "priya@okhdfcbank",
            "receiver": "cafe_coffee_day@icici",
            "amount": 350.00,
            "time": base_time + timedelta(minutes=15),
            "city": "Mumbai",
            "device": "DEV_PIXEL_8"
        },
        {
            "tag": "Phase 1: Legitimate User Baseline (Cont.)",
            "narrative": "Priya pays her neighbourhood grocery store in Mumbai.",
            "sender": "priya@okhdfcbank",
            "receiver": "kirana_store@paytm",
            "amount": 850.00,
            "time": base_time + timedelta(hours=2, minutes=30),
            "city": "Mumbai",
            "device": "DEV_PIXEL_8"
        },
        {
            "tag": "Phase 1: Legitimate User Baseline (Cont.)",
            "narrative": "Priya splits a lunch bill with a colleague in Mumbai.",
            "sender": "priya@okhdfcbank",
            "receiver": "rohit.colleague@okaxis",
            "amount": 600.00,
            "time": base_time + timedelta(hours=4, minutes=10),
            "city": "Mumbai",
            "device": "DEV_PIXEL_8"
        },

        # ----------------------------------------------------------------------
        # Phase 2: Velocity Burst Attack (Rahul)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 2: Velocity Burst Attack",
            "narrative": "Rahul initiates transaction 1 of rapid sequence.",
            "sender": "rahul.verma@ybl",
            "receiver": "shop1@paytm",
            "amount": 500.00,
            "time": base_time + timedelta(hours=5, seconds=0),
            "city": "Delhi",
            "device": "DEV_SAMSUNG_S23"
        },
        {
            "tag": "Phase 2: Velocity Burst Attack",
            "narrative": "Rahul initiates transaction 2 just 25 seconds later.",
            "sender": "rahul.verma@ybl",
            "receiver": "shop2@paytm",
            "amount": 600.00,
            "time": base_time + timedelta(hours=5, seconds=25),
            "city": "Delhi",
            "device": "DEV_SAMSUNG_S23"
        },
        {
            "tag": "Phase 2: Velocity Burst Attack",
            "narrative": "Rahul initiates transaction 3 just 50 seconds after start.",
            "sender": "rahul.verma@ybl",
            "receiver": "shop3@paytm",
            "amount": 400.00,
            "time": base_time + timedelta(hours=5, seconds=50),
            "city": "Delhi",
            "device": "DEV_SAMSUNG_S23"
        },
        {
            "tag": "Phase 2: Velocity Burst Trigger",
            "narrative": "Rahul's 4th transaction within 75 seconds triggers Velocity Burst rule!",
            "sender": "rahul.verma@ybl",
            "receiver": "shop4@paytm",
            "amount": 750.00,
            "time": base_time + timedelta(hours=5, seconds=75),
            "city": "Delhi",
            "device": "DEV_SAMSUNG_S23"
        },

        # ----------------------------------------------------------------------
        # Phase 3: Impossible Travel / Location Jump (Amit)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 3: Geographic Anomaly / Impossible Travel",
            "narrative": "Amit transacts in Bengaluru from his verified phone.",
            "sender": "amit.kumar@sbi",
            "receiver": "bookstore@icici",
            "amount": 1200.00,
            "time": base_time + timedelta(hours=6, minutes=0),
            "city": "Bengaluru",
            "device": "DEV_IPHONE_15"
        },
        {
            "tag": "Phase 3: Impossible Travel Trigger",
            "narrative": "Just 20 minutes later, a transaction originates from London on an unknown device!",
            "sender": "amit.kumar@sbi",
            "receiver": "overseas_merchant@barclays",
            "amount": 25000.00,
            "time": base_time + timedelta(hours=6, minutes=20),
            "city": "London",
            "device": "DEV_UNKNOWN_LINUX"
        },

        # ----------------------------------------------------------------------
        # Phase 4: Account Takeover (ATO) Midnight Drain (Priya's compromised account)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 4: Full Account Takeover (ATO) Night Attack",
            "narrative": "Attacker hacks Priya's credentials at 02:40 AM from a rooted emulator in Kolkata,\n"
                         "attempting a massive ₹75,000 round drain to a mule account.",
            "sender": "priya@okhdfcbank",
            "receiver": "crypto_cashout@mulebank",
            "amount": 75000.00,
            "time": datetime(2026, 11, 16, 2, 40, 0), # Next day 02:40 AM
            "city": "Kolkata",
            "device": "DEV_ROOTED_EMULATOR_99"
        },

        # ----------------------------------------------------------------------
        # Phase 5: Smurfing / Repeated Payee Spam (Vikram)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 5: Smurfing / Rapid Transfers to Single Mule",
            "narrative": "Vikram transfers ₹9,000 to an unregistered entity.",
            "sender": "vikram.singh@axisbank",
            "receiver": "quick_payout@paytm",
            "amount": 9000.00,
            "time": base_time + timedelta(hours=8, minutes=0),
            "city": "Pune",
            "device": "DEV_ONEPLUS_11"
        },
        {
            "tag": "Phase 5: Smurfing (Cont.)",
            "narrative": "Second transfer of ₹9,000 to the exact same entity 40 seconds later.",
            "sender": "vikram.singh@axisbank",
            "receiver": "quick_payout@paytm",
            "amount": 9000.00,
            "time": base_time + timedelta(hours=8, minutes=0, seconds=40),
            "city": "Pune",
            "device": "DEV_ONEPLUS_11"
        },
        {
            "tag": "Phase 5: Smurfing Trigger",
            "narrative": "Third transfer to same payee in 90 seconds triggers Repeat Payee flag.",
            "sender": "vikram.singh@axisbank",
            "receiver": "quick_payout@paytm",
            "amount": 9000.00,
            "time": base_time + timedelta(hours=8, minutes=1, seconds=30),
            "city": "Pune",
            "device": "DEV_ONEPLUS_11"
        },

        # ----------------------------------------------------------------------
        # Phase 6: Daily UPI Cap Breach (Sneha)
        # ----------------------------------------------------------------------
        {
            "tag": "Phase 6: Daily Limit Ceiling Breach",
            "narrative": "Sneha sends ₹60,000 to an educational institution in Chennai.",
            "sender": "sneha.patel@icici",
            "receiver": "tuition_fees@sbi",
            "amount": 60000.00,
            "time": base_time + timedelta(hours=2, minutes=0),
            "city": "Chennai",
            "device": "DEV_SNEHA_LAPTOP"
        },
        {
            "tag": "Phase 6: Daily Limit Breach Trigger",
            "narrative": "Sneha sends another ₹55,000 on the same day, pushing total to ₹115,000 (> ₹1,00,000 daily cap).",
            "sender": "sneha.patel@icici",
            "receiver": "tuition_fees@sbi",
            "amount": 55000.00,
            "time": base_time + timedelta(hours=4, minutes=0),
            "city": "Chennai",
            "device": "DEV_SNEHA_LAPTOP"
        }
    ]

    for idx, item in enumerate(demo_txns, 1):
        txn_id = engine.generate_next_id()
        txn = Transaction(
            transaction_id=txn_id,
            sender_upi=item["sender"],
            receiver_upi=item["receiver"],
            amount=item["amount"],
            timestamp=item["time"],
            city=item["city"],
            device_id=item["device"]
        )

        print(f"\n{Colors.BOLD}{Colors.BLUE}>>> DEMO EVENT {idx}/{len(demo_txns)}: {item['tag']}{Colors.RESET}")
        print(f"    {Colors.DIM}{item['narrative']}{Colors.RESET}")

        evaluated = engine.evaluate_transaction(txn, commit=True)
        Reporting.print_transaction_card(evaluated)

        if interactive and idx < len(demo_txns):
            try:
                # Non-blocking pause for user inspection
                input(f"{Colors.DIM}Press [Enter] to evaluate next demo transaction...{Colors.RESET}")
            except (EOFError, KeyboardInterrupt):
                interactive = False

    print(f"\n{Colors.BOLD}{Colors.GREEN}[✓] Demo Scenario Completed Successfully!{Colors.RESET}")
    print(f"All transactions have been evaluated and recorded into '{engine.data_file}'.\n")
    Reporting.print_engine_statistics(engine)
    Reporting.print_user_risk_summary(engine)


# ==============================================================================
# INTERACTIVE CONSOLE MENU & CONTROLLER
# ==============================================================================
def prompt_input(prompt_text: str, default: str = "") -> str:
    """Read console input with default value support."""
    if default:
        full_prompt = f"{prompt_text} [{Colors.DIM}{default}{Colors.RESET}]: "
    else:
        full_prompt = f"{prompt_text}: "
    try:
        val = input(full_prompt).strip()
        return val if val else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def handle_add_transaction(engine: FraudShieldEngine):
    """Guide the user through entering and evaluating a new UPI transaction."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- EVALUATE NEW UPI TRANSACTION ---{Colors.RESET}")
    print("Enter the transaction details below (or press Ctrl+C to cancel):\n")

    # 1. Sender UPI
    while True:
        sender_in = prompt_input("1. Sender UPI ID (e.g. rohit@okhdfcbank)")
        valid, sender_res = Validator.validate_upi_id(sender_in, "Sender UPI")
        if valid:
            sender = sender_res
            break
        print(f"   {Colors.RED}[!]{Colors.RESET} {sender_res}")

    # 2. Receiver UPI
    while True:
        receiver_in = prompt_input("2. Receiver UPI ID (e.g. merchant@paytm)")
        valid, receiver_res = Validator.validate_upi_id(receiver_in, "Receiver UPI")
        if not valid:
            print(f"   {Colors.RED}[!]{Colors.RESET} {receiver_res}")
            continue
        if receiver_res.lower() == sender.lower():
            print(f"   {Colors.RED}[!]{Colors.RESET} Sender and Receiver cannot be identical UPI IDs.")
            continue
        receiver = receiver_res
        break

    # 3. Amount
    while True:
        amt_in = prompt_input("3. Amount in INR (e.g. 1500.00)")
        valid, amount, err = Validator.validate_amount(amt_in)
        if valid:
            break
        print(f"   {Colors.RED}[!]{Colors.RESET} {err}")

    # 4. Timestamp
    default_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    while True:
        ts_in = prompt_input("4. Timestamp (YYYY-MM-DD HH:MM:SS or HH:MM)", default=default_now)
        valid, dt, err = Validator.validate_timestamp(ts_in)
        if valid and dt is not None:
            txn_time = dt
            break
        print(f"   {Colors.RED}[!]{Colors.RESET} {err}")

    # 5. City
    while True:
        city_in = prompt_input("5. Transaction City (e.g. Mumbai, Bengaluru)", default="Mumbai")
        valid, city_res = Validator.validate_text(city_in, "City")
        if valid:
            city = city_res.title()
            break
        print(f"   {Colors.RED}[!]{Colors.RESET} {city_res}")

    # 6. Device ID
    while True:
        dev_in = prompt_input("6. Device ID (e.g. DEV_PIXEL_8)", default="DEV_DEFAULT")
        valid, dev_res = Validator.validate_text(dev_in, "Device ID")
        if valid:
            device = dev_res
            break
        print(f"   {Colors.RED}[!]{Colors.RESET} {dev_res}")

    auto_id = engine.generate_next_id()
    txn_id_in = prompt_input(f"Transaction ID (press Enter for '{auto_id}')", default=auto_id).strip().upper()
    while any(t.transaction_id.upper() == txn_id_in for t in engine.transactions):
        print(f"   {Colors.RED}[!]{Colors.RESET} Transaction ID '{txn_id_in}' already exists. Please choose a unique ID.")
        txn_id_in = prompt_input("Enter unique Transaction ID").strip().upper()
    txn_id = txn_id_in or auto_id

    txn = Transaction(
        transaction_id=txn_id,
        sender_upi=sender,
        receiver_upi=receiver,
        amount=amount,
        timestamp=txn_time,
        city=city,
        device_id=device
    )

    print(f"\n{Colors.CYAN}[*] Evaluating transaction against 9 fraud detection rules...{Colors.RESET}")
    evaluated = engine.evaluate_transaction(txn, commit=True)
    Reporting.print_transaction_card(evaluated)


def handle_lookup_id(engine: FraudShieldEngine):
    """Look up a recorded transaction by its unique ID with analyst actions (False Alarm management)."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- LOOK UP TRANSACTION BY ID ---{Colors.RESET}")
    search_id = prompt_input("Enter Transaction ID (e.g. TXN-1001)").strip().upper()
    if not search_id:
        print(f"{Colors.YELLOW}[!] Transaction ID cannot be empty.{Colors.RESET}\n")
        return

    found = next((t for t in engine.transactions if t.transaction_id.upper() == search_id), None)
    if not found:
        print(f"{Colors.RED}[!] No transaction found with ID '{search_id}'.{Colors.RESET}\n")
        return

    Reporting.print_transaction_card(found)

    # Analyst action: Mark or Unmark as False Alarm (CP-004 Stretch Feature)
    if found.decision in ("REVIEW", "BLOCK"):
        action = prompt_input(
            f"Analyst Actions: {'[U] Unmark False Alarm' if found.is_false_alarm else '[M] Mark as False Alarm (Stretch)'}, [Enter] Return",
            default=""
        ).strip().upper()

        if action == "M" and not found.is_false_alarm:
            note = prompt_input("Enter Analyst Audit Note (e.g. 'Verified genuine user transaction via OTP')")
            found.is_false_alarm = True
            found.analyst_notes = note or "Verified genuine user transaction by analyst"
            engine.save_data()
            print(f"{Colors.GREEN}[✓] Transaction {found.transaction_id} successfully marked as FALSE ALARM.{Colors.RESET}")
            Reporting.print_transaction_card(found)
        elif action == "U" and found.is_false_alarm:
            found.is_false_alarm = False
            found.analyst_notes = ""
            engine.save_data()
            print(f"{Colors.GREEN}[✓] Transaction {found.transaction_id} false-alarm status cleared.{Colors.RESET}")
            Reporting.print_transaction_card(found)


def handle_user_history(engine: FraudShieldEngine):
    """View transaction timeline and risk history for users with ledger drill-down."""
    Reporting.print_user_risk_summary(engine)
    if not engine.transactions:
        return

    user_in = prompt_input("Enter User UPI ID to view transaction ledger (or press Enter to return)").strip().lower()
    if not user_in:
        return

    history = engine.get_user_history(user_in)
    if not history:
        print(f"{Colors.YELLOW}[i] No transactions found for user '{user_in}'.{Colors.RESET}\n")
        return

    Reporting.print_transactions_table(history, title=f"HISTORY FOR {user_in}")
    flagged = [t for t in history if t.decision in ("REVIEW", "BLOCK")]
    print(f"  Summary: {len(history)} total transactions | {len(flagged)} flagged | "
          f"Cities transacted: {', '.join(sorted(set(t.city for t in history)))} | "
          f"Known devices: {', '.join(sorted(set(t.device_id for t in history)))}\n")


def handle_configure_rules():
    """Interactive threshold and weight adjustment in the CONFIG block."""
    while True:
        print(f"\n{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}       CONFIG: ADJUST RULES, THRESHOLDS & WEIGHTS   {Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}===================================================={Colors.RESET}")
        print(f"  1. Review Score Cutoff       : {CONFIG['THRESHOLD_REVIEW']}")
        print(f"  2. Block Score Cutoff        : {CONFIG['THRESHOLD_BLOCK']}")
        print(f"  3. Velocity Max Txns         : {CONFIG['VELOCITY_MAX_TXNS']} txns in {CONFIG['VELOCITY_WINDOW_SECONDS']}s (Weight: {CONFIG['RULE_VELOCITY_BURST_WEIGHT']})")
        print(f"  4. Amount Anomaly Multiplier : {CONFIG['AMOUNT_ANOMALY_MULTIPLIER']}x user average (Weight: {CONFIG['RULE_AMOUNT_ANOMALY_WEIGHT']})")
        print(f"  5. New Payee Large Threshold : ₹{CONFIG['NEW_PAYEE_LARGE_THRESHOLD']:,.2f} (Weight: {CONFIG['RULE_NEW_PAYEE_LARGE_WEIGHT']})")
        print(f"  6. Odd Hours Range           : {CONFIG['ODD_HOURS_START']:02d}:00 to {CONFIG['ODD_HOURS_END']:02d}:00 (Weight: {CONFIG['RULE_ODD_HOURS_WEIGHT']})")
        print(f"  7. New Device Rule Weight    : {CONFIG['RULE_NEW_DEVICE_WEIGHT']}")
        print(f"  8. Location Jump Window      : {CONFIG['IMPOSSIBLE_TRAVEL_WINDOW_HOURS']} hrs (Weight: {CONFIG['RULE_LOCATION_JUMP_WEIGHT']})")
        print(f"  9. Daily UPI Limit           : ₹{CONFIG['DAILY_LIMIT_THRESHOLD']:,.2f} (Weight: {CONFIG['RULE_DAILY_LIMIT_WEIGHT']})")
        print(f" 10. Large Round Step          : ₹{CONFIG['LARGE_ROUND_STEP']:,.2f} above ₹{CONFIG['LARGE_ROUND_MIN_AMOUNT']:,.2f} (Weight: {CONFIG['RULE_LARGE_ROUND_WEIGHT']})")
        print(f" 11. Reset All to Factory Defaults")
        print(f"  0. Return to Main Menu")
        print(f"{Colors.CYAN}===================================================={Colors.RESET}")

        choice = prompt_input("Select an option to adjust (0-11)")
        if choice in ("0", ""):
            break
        elif choice == "1":
            val = prompt_input("Enter new Review Score Cutoff (0-100)", str(CONFIG["THRESHOLD_REVIEW"]))
            try:
                CONFIG["THRESHOLD_REVIEW"] = float(val)
                print(f"{Colors.GREEN}[✓] Review Cutoff updated to {CONFIG['THRESHOLD_REVIEW']}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid numeric value.{Colors.RESET}")
        elif choice == "2":
            val = prompt_input("Enter new Block Score Cutoff (0-100)", str(CONFIG["THRESHOLD_BLOCK"]))
            try:
                CONFIG["THRESHOLD_BLOCK"] = float(val)
                print(f"{Colors.GREEN}[✓] Block Cutoff updated to {CONFIG['THRESHOLD_BLOCK']}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid numeric value.{Colors.RESET}")
        elif choice == "3":
            txns = prompt_input("Max transactions allowed in window", str(CONFIG["VELOCITY_MAX_TXNS"]))
            secs = prompt_input("Window duration in seconds", str(CONFIG["VELOCITY_WINDOW_SECONDS"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_VELOCITY_BURST_WEIGHT"]))
            try:
                CONFIG["VELOCITY_MAX_TXNS"] = int(txns)
                CONFIG["VELOCITY_WINDOW_SECONDS"] = int(secs)
                CONFIG["RULE_VELOCITY_BURST_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Velocity Burst parameters updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "4":
            mult = prompt_input("Amount anomaly multiplier (e.g. 5.0)", str(CONFIG["AMOUNT_ANOMALY_MULTIPLIER"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_AMOUNT_ANOMALY_WEIGHT"]))
            try:
                CONFIG["AMOUNT_ANOMALY_MULTIPLIER"] = float(mult)
                CONFIG["RULE_AMOUNT_ANOMALY_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Amount Anomaly updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "5":
            thresh = prompt_input("New Payee high-value threshold in INR", str(CONFIG["NEW_PAYEE_LARGE_THRESHOLD"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_NEW_PAYEE_LARGE_WEIGHT"]))
            try:
                CONFIG["NEW_PAYEE_LARGE_THRESHOLD"] = float(thresh)
                CONFIG["RULE_NEW_PAYEE_LARGE_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] New Payee Large Amount threshold updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "6":
            start = prompt_input("Odd hours start hour (0-23)", str(CONFIG["ODD_HOURS_START"]))
            end = prompt_input("Odd hours end hour (0-23)", str(CONFIG["ODD_HOURS_END"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_ODD_HOURS_WEIGHT"]))
            try:
                CONFIG["ODD_HOURS_START"] = int(start)
                CONFIG["ODD_HOURS_END"] = int(end)
                CONFIG["RULE_ODD_HOURS_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Odd hours window updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "7":
            wt = prompt_input("New Device rule weight", str(CONFIG["RULE_NEW_DEVICE_WEIGHT"]))
            try:
                CONFIG["RULE_NEW_DEVICE_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] New Device weight updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "8":
            hrs = prompt_input("Impossible travel window in hours", str(CONFIG["IMPOSSIBLE_TRAVEL_WINDOW_HOURS"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_LOCATION_JUMP_WEIGHT"]))
            try:
                CONFIG["IMPOSSIBLE_TRAVEL_WINDOW_HOURS"] = float(hrs)
                CONFIG["RULE_LOCATION_JUMP_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Location jump parameters updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "9":
            cap = prompt_input("Daily limit ceiling in INR", str(CONFIG["DAILY_LIMIT_THRESHOLD"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_DAILY_LIMIT_WEIGHT"]))
            try:
                CONFIG["DAILY_LIMIT_THRESHOLD"] = float(cap)
                CONFIG["RULE_DAILY_LIMIT_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Daily limit ceiling updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "10":
            step = prompt_input("Round step multiple in INR", str(CONFIG["LARGE_ROUND_STEP"]))
            min_amt = prompt_input("Minimum amount for round check", str(CONFIG["LARGE_ROUND_MIN_AMOUNT"]))
            wt = prompt_input("Rule weight", str(CONFIG["RULE_LARGE_ROUND_WEIGHT"]))
            try:
                CONFIG["LARGE_ROUND_STEP"] = float(step)
                CONFIG["LARGE_ROUND_MIN_AMOUNT"] = float(min_amt)
                CONFIG["RULE_LARGE_ROUND_WEIGHT"] = float(wt)
                print(f"{Colors.GREEN}[✓] Large round amount parameters updated.{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid input.{Colors.RESET}")
        elif choice == "11":
            CONFIG.clear()
            CONFIG.update(DEFAULT_CONFIG)
            print(f"{Colors.GREEN}[✓] All thresholds and weights reset to defaults.{Colors.RESET}")
        else:
            print(f"{Colors.RED}[!] Invalid option.{Colors.RESET}")


def handle_data_management(engine: FraudShieldEngine):
    """Save, reload, or purge stored JSON transactions."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}--- DATA & STORAGE MANAGEMENT ---{Colors.RESET}")
    print(f"Current storage file: {engine.data_file}")
    print(f"Total transactions in memory: {len(engine.transactions)}")
    print("  1. Save In-Memory Data to File")
    print("  2. Reload Data from File")
    print("  3. Clear / Reset All Transactions (Purge)")
    print("  0. Back to Main Menu")

    sub = prompt_input("Select an option (0-3)")
    if sub == "1":
        if engine.save_data():
            print(f"{Colors.GREEN}[✓] Successfully saved {len(engine.transactions)} transactions to '{engine.data_file}'.{Colors.RESET}")
    elif sub == "2":
        if engine.load_data():
            print(f"{Colors.GREEN}[✓] Successfully reloaded {len(engine.transactions)} transactions from '{engine.data_file}'.{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[i] No existing data file found to reload.{Colors.RESET}")
    elif sub == "3":
        confirm = prompt_input("Are you sure you want to clear all transaction records? (yes/no)", "no")
        if confirm.lower() in ("yes", "y"):
            engine.clear_data()
            print(f"{Colors.GREEN}[✓] All transaction records cleared.{Colors.RESET}")
        else:
            print("[i] Clear cancelled.")


# ==============================================================================
# MAIN CONSOLE LOOP
# ==============================================================================
def print_main_menu():
    """Print the primary FraudShield interactive menu."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║     FRAUDSHIELD: RULE-BASED UPI TRANSACTION RISK ENGINE          ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║     Capstone CP-004 | Explainable Multi-Rule Fraud Detection     ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[1]{Colors.RESET} Evaluate / Add a Transaction                                {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[2]{Colors.RESET} {Colors.GREEN}Load & Run Built-in Demo Scenario (ATO, Velocity, Jump){Colors.RESET}   {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[3]{Colors.RESET} View All Recorded Transactions                              {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[4]{Colors.RESET} View Flagged Transactions & Flag Reasons (Audit Report)     {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[5]{Colors.RESET} Look Up Transaction by ID                                   {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[6]{Colors.RESET} View User History & Risk Profile (Risk Count per User)      {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[7]{Colors.RESET} View Engine Analytics & Rule Trigger Statistics             {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[8]{Colors.RESET} View / Adjust Thresholds & Rule Weights (CONFIG)            {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[9]{Colors.RESET} Data Management (Save / Reload / Reset Storage)             {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.BOLD}[0]{Colors.RESET} Exit Program                                                {Colors.BOLD}{Colors.CYAN}║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}")


def main():
    """Main entry point."""
    # Check CLI arguments for automated runs or testing
    engine = FraudShieldEngine()
    engine.load_data()

    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ("--demo", "-d", "demo"):
            run_demo_scenario(engine, interactive=False)
            sys.exit(0)
        elif arg in ("--stats", "-s"):
            Reporting.print_engine_statistics(engine)
            sys.exit(0)
        elif arg in ("--help", "-h"):
            print("FraudShield: Rule-Based UPI Transaction Risk Engine")
            print("Usage:")
            print("  python fraudshield.py           Start interactive console menu")
            print("  python fraudshield.py --demo    Run automated demo scenario and exit")
            print("  python fraudshield.py --stats   Show current risk analytics and exit")
            sys.exit(0)

    # Interactive Loop
    while True:
        try:
            print_main_menu()
            choice = prompt_input("Enter choice (0-9)")

            if choice == "1":
                handle_add_transaction(engine)
            elif choice == "2":
                run_demo_scenario(engine, interactive=True)
            elif choice == "3":
                Reporting.print_transactions_table(engine.transactions, title="RECORDED TRANSACTIONS")
            elif choice == "4":
                Reporting.print_flagged_report(engine.transactions)
            elif choice == "5":
                handle_lookup_id(engine)
            elif choice == "6":
                handle_user_history(engine)
            elif choice == "7":
                Reporting.print_engine_statistics(engine)
            elif choice == "8":
                handle_configure_rules()
            elif choice == "9":
                handle_data_management(engine)
            elif choice in ("0", "exit", "quit", "q"):
                print(f"\n{Colors.CYAN}Thank you for using FraudShield. Exiting.{Colors.RESET}\n")
                break
            else:
                print(f"{Colors.RED}[!] Invalid choice '{choice}'. Please select a number from 0 to 9.{Colors.RESET}")

        except KeyboardInterrupt:
            print(f"\n\n{Colors.YELLOW}[!] Operation interrupted. Exiting FraudShield.{Colors.RESET}\n")
            break
        except Exception as e:
            print(f"\n{Colors.RED}[!] An unexpected error occurred: {e}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
