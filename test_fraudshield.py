"""
Unit tests for FraudShield: Rule-Based UPI Transaction Risk Engine
Tests all nine rules, scoring, validators, persistence, and decisions.
"""

import unittest
import os
import tempfile
from datetime import datetime, timedelta

from fraudshield import (
    CONFIG,
    DEFAULT_CONFIG,
    Validator,
    Transaction,
    RuleTrigger,
    FraudShieldEngine
)


class TestFraudShieldValidators(unittest.TestCase):
    """Test input validation functions."""

    def test_upi_validation(self):
        # Valid UPI IDs
        self.assertTrue(Validator.validate_upi_id("priya@okhdfcbank")[0])
        self.assertTrue(Validator.validate_upi_id("rahul.verma@ybl")[0])
        self.assertTrue(Validator.validate_upi_id("9876543210@paytm")[0])
        self.assertTrue(Validator.validate_upi_id("merchant_01@upi")[0])

        # Invalid UPI IDs
        self.assertFalse(Validator.validate_upi_id("")[0])
        self.assertFalse(Validator.validate_upi_id("priya")[0])
        self.assertFalse(Validator.validate_upi_id("@bank")[0])
        self.assertFalse(Validator.validate_upi_id("user@")[0])

    def test_amount_validation(self):
        # Valid amounts
        valid, val, _ = Validator.validate_amount("100")
        self.assertTrue(valid)
        self.assertEqual(val, 100.0)

        valid, val, _ = Validator.validate_amount(2500.75)
        self.assertTrue(valid)
        self.assertEqual(val, 2500.75)

        # Invalid amounts
        self.assertFalse(Validator.validate_amount("0")[0])
        self.assertFalse(Validator.validate_amount("-50")[0])
        self.assertFalse(Validator.validate_amount("abc")[0])
        self.assertFalse(Validator.validate_amount(float('nan'))[0])
        self.assertFalse(Validator.validate_amount(float('inf'))[0])

    def test_timestamp_validation(self):
        # Valid timestamps
        self.assertTrue(Validator.validate_timestamp("2026-11-15 14:30:00")[0])
        self.assertTrue(Validator.validate_timestamp("2026-11-15 14:30")[0])
        self.assertTrue(Validator.validate_timestamp("14:30")[0])
        self.assertTrue(Validator.validate_timestamp("")[0])  # Defaults to now

        # Invalid timestamps
        self.assertFalse(Validator.validate_timestamp("invalid-date")[0])
        self.assertFalse(Validator.validate_timestamp("25:00")[0])


class TestFraudShieldRules(unittest.TestCase):
    """Test all nine independent fraud rules."""

    def setUp(self):
        # Reset CONFIG to defaults
        CONFIG.clear()
        CONFIG.update(DEFAULT_CONFIG)
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_file.close()
        self.engine = FraudShieldEngine(data_file=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            try:
                os.remove(self.temp_file.name)
            except OSError:
                pass

    def test_rule_1_velocity_burst(self):
        """Test Rule 1: Velocity Burst (> 3 txns within 120s)."""
        base_time = datetime(2026, 11, 15, 12, 0, 0)
        user = "velocity_user@okhdfc"

        # Add 3 transactions within 60s
        for i in range(3):
            t = Transaction(
                transaction_id=f"T-V{i}",
                sender_upi=user,
                receiver_upi=f"merchant{i}@upi",
                amount=200.0,
                timestamp=base_time + timedelta(seconds=i * 20),
                city="Delhi",
                device_id="DEV_1"
            )
            res = self.engine.evaluate_transaction(t, commit=True)
            self.assertEqual(res.decision, "ALLOW")

        # 4th transaction within 75s (should trigger velocity burst)
        t4 = Transaction(
            transaction_id="T-V4",
            sender_upi=user,
            receiver_upi="merchant4@upi",
            amount=200.0,
            timestamp=base_time + timedelta(seconds=75),
            city="Delhi",
            device_id="DEV_1"
        )
        res4 = self.engine.evaluate_transaction(t4, commit=False)
        rule_res = [r for r in res4.triggered_rules if r.rule_id == "R1_VELOCITY"]
        self.assertEqual(len(rule_res), 1)
        self.assertTrue(rule_res[0].triggered)
        self.assertIn("Rapid transaction burst", rule_res[0].reason)

    def test_rule_2_amount_anomaly(self):
        """Test Rule 2: Amount Anomaly (> 5x user's historical average)."""
        user = "anomaly_user@icici"
        base_time = datetime(2026, 11, 15, 10, 0, 0)

        # Baseline txns averaging ₹500
        t1 = Transaction("T1", user, "payee1@upi", 400.0, base_time, "Mumbai", "DEV_A")
        t2 = Transaction("T2", user, "payee1@upi", 600.0, base_time + timedelta(hours=1), "Mumbai", "DEV_A")
        self.engine.evaluate_transaction(t1, commit=True)
        self.engine.evaluate_transaction(t2, commit=True)

        # Transaction of ₹3,000 (> 5 * 500 = 2500)
        t_high = Transaction("T3", user, "payee1@upi", 3500.0, base_time + timedelta(hours=2), "Mumbai", "DEV_A")
        res = self.engine.evaluate_transaction(t_high, commit=False)

        rule_res = [r for r in res.triggered_rules if r.rule_id == "R2_AMOUNT_ANOMALY"]
        self.assertEqual(len(rule_res), 1)
        self.assertTrue(rule_res[0].triggered)
        self.assertIn("Unusually large amount", rule_res[0].reason)

    def test_rule_3_new_payee_large_amount(self):
        """Test Rule 3: First transfer to unseen payee >= ₹10,000."""
        user = "user3@ybl"
        base_time = datetime(2026, 11, 15, 11, 0, 0)

        # Known payee
        t_known = Transaction("T1", user, "known_store@upi", 100.0, base_time, "Mumbai", "DEV_B")
        self.engine.evaluate_transaction(t_known, commit=True)

        # Transfer ₹15,000 to known payee (should NOT trigger Rule 3)
        t_known_large = Transaction("T2", user, "known_store@upi", 15000.0, base_time + timedelta(minutes=10), "Mumbai", "DEV_B")
        res = self.engine.evaluate_transaction(t_known_large, commit=False)
        r3_triggers = [r for r in res.triggered_rules if r.rule_id == "R3_NEW_PAYEE_LARGE"]
        self.assertEqual(len(r3_triggers), 0)

        # Transfer ₹15,000 to NEW payee (MUST trigger Rule 3)
        t_new_large = Transaction("T3", user, "unseen_receiver@upi", 15000.0, base_time + timedelta(minutes=20), "Mumbai", "DEV_B")
        res2 = self.engine.evaluate_transaction(t_new_large, commit=False)
        r3_triggers2 = [r for r in res2.triggered_rules if r.rule_id == "R3_NEW_PAYEE_LARGE"]
        self.assertEqual(len(r3_triggers2), 1)
        self.assertTrue(r3_triggers2[0].triggered)

    def test_rule_4_odd_hours(self):
        """Test Rule 4: Odd Hours (00:00 to 05:00)."""
        night_time = datetime(2026, 11, 15, 2, 30, 0) # 02:30 AM
        day_time = datetime(2026, 11, 15, 14, 30, 0)   # 02:30 PM

        t_night = Transaction("T1", "user4@sbi", "merchant@upi", 500.0, night_time, "Mumbai", "DEV_C")
        t_day = Transaction("T2", "user4@sbi", "merchant@upi", 500.0, day_time, "Mumbai", "DEV_C")

        res_night = self.engine.evaluate_transaction(t_night, commit=False)
        r4_night = [r for r in res_night.triggered_rules if r.rule_id == "R4_ODD_HOURS"]
        self.assertEqual(len(r4_night), 1)
        self.assertTrue(r4_night[0].triggered)

        res_day = self.engine.evaluate_transaction(t_day, commit=False)
        r4_day = [r for r in res_day.triggered_rules if r.rule_id == "R4_ODD_HOURS"]
        self.assertEqual(len(r4_day), 0)

    def test_rule_5_new_device(self):
        """Test Rule 5: New Device for an established user."""
        user = "user5@okhdfc"
        base_time = datetime(2026, 11, 15, 10, 0, 0)

        # Initial baseline on DEV_TRUSTED
        t1 = Transaction("T1", user, "shop@upi", 200.0, base_time, "Delhi", "DEV_TRUSTED")
        self.engine.evaluate_transaction(t1, commit=True)

        # Transaction on DEV_UNSEEN
        t2 = Transaction("T2", user, "shop@upi", 200.0, base_time + timedelta(hours=1), "Delhi", "DEV_UNSEEN")
        res = self.engine.evaluate_transaction(t2, commit=False)
        r5 = [r for r in res.triggered_rules if r.rule_id == "R5_NEW_DEVICE"]
        self.assertEqual(len(r5), 1)
        self.assertTrue(r5[0].triggered)

    def test_rule_6_location_jump_and_impossible_travel(self):
        """Test Rule 6: Unfamiliar City and Impossible Travel."""
        user = "user6@axis"
        base_time = datetime(2026, 11, 15, 12, 0, 0)

        # Baseline in Bengaluru
        t1 = Transaction("T1", user, "shop@upi", 300.0, base_time, "Bengaluru", "DEV_D")
        self.engine.evaluate_transaction(t1, commit=True)

        # 25 minutes later in London (impossible travel)
        t2 = Transaction("T2", user, "shop@upi", 300.0, base_time + timedelta(minutes=25), "London", "DEV_D")
        res = self.engine.evaluate_transaction(t2, commit=False)
        r6 = [r for r in res.triggered_rules if r.rule_id == "R6_LOCATION_JUMP"]
        self.assertEqual(len(r6), 1)
        self.assertTrue(r6[0].triggered)
        self.assertIn("Impossible travel", r6[0].reason)

    def test_rule_7_repeated_transfers(self):
        """Test Rule 7: Repeated transfers to one payee (> 2 in 300s)."""
        user = "user7@paytm"
        payee = "mule_payee@upi"
        base_time = datetime(2026, 11, 15, 9, 0, 0)

        t1 = Transaction("T1", user, payee, 1000.0, base_time, "Jaipur", "DEV_E")
        t2 = Transaction("T2", user, payee, 1000.0, base_time + timedelta(seconds=30), "Jaipur", "DEV_E")
        self.engine.evaluate_transaction(t1, commit=True)
        self.engine.evaluate_transaction(t2, commit=True)

        t3 = Transaction("T3", user, payee, 1000.0, base_time + timedelta(seconds=60), "Jaipur", "DEV_E")
        res = self.engine.evaluate_transaction(t3, commit=False)
        r7 = [r for r in res.triggered_rules if r.rule_id == "R7_REPEAT_PAYEE"]
        self.assertEqual(len(r7), 1)
        self.assertTrue(r7[0].triggered)

    def test_rule_8_daily_limit(self):
        """Test Rule 8: Cumulative daily amount > ₹1,00,000."""
        user = "user8@sbi"
        base_time = datetime(2026, 11, 15, 10, 0, 0)

        # Send ₹60,000
        t1 = Transaction("T1", user, "payee@upi", 60000.0, base_time, "Pune", "DEV_F")
        self.engine.evaluate_transaction(t1, commit=True)

        # Send another ₹50,000 on the same day (Total = ₹1,10,000 > ₹1,00,000)
        t2 = Transaction("T2", user, "payee@upi", 50000.0, base_time + timedelta(hours=3), "Pune", "DEV_F")
        res = self.engine.evaluate_transaction(t2, commit=False)
        r8 = [r for r in res.triggered_rules if r.rule_id == "R8_DAILY_LIMIT"]
        self.assertEqual(len(r8), 1)
        self.assertTrue(r8[0].triggered)

    def test_rule_9_large_round_amount(self):
        """Test Rule 9: Large Round Amount (>= 10,000 and multiple of 1,000)."""
        # Round 25,000
        t_round = Transaction("T1", "u@upi", "p@upi", 25000.0, datetime.now(), "City", "DEV")
        res1 = self.engine.evaluate_transaction(t_round, commit=False)
        r9_1 = [r for r in res1.triggered_rules if r.rule_id == "R9_ROUND_AMOUNT"]
        self.assertEqual(len(r9_1), 1)
        self.assertTrue(r9_1[0].triggered)

        # Non-round 25,432
        t_odd = Transaction("T2", "u@upi", "p@upi", 25432.0, datetime.now(), "City", "DEV")
        res2 = self.engine.evaluate_transaction(t_odd, commit=False)
        r9_2 = [r for r in res2.triggered_rules if r.rule_id == "R9_ROUND_AMOUNT"]
        self.assertEqual(len(r9_2), 0)

        # Small round 500 (< 10000)
        t_small_round = Transaction("T3", "u@upi", "p@upi", 500.0, datetime.now(), "City", "DEV")
        res3 = self.engine.evaluate_transaction(t_small_round, commit=False)
        r9_3 = [r for r in res3.triggered_rules if r.rule_id == "R9_ROUND_AMOUNT"]
        self.assertEqual(len(r9_3), 0)

    def test_decision_scoring_outcomes(self):
        """Verify ALLOW, REVIEW, and BLOCK thresholds."""
        # 1. ALLOW (Score < 30)
        t_allow = Transaction("T_ALLOW", "normal@upi", "merchant@upi", 150.0, datetime(2026, 11, 15, 12, 0), "Mumbai", "DEV_1")
        res_allow = self.engine.evaluate_transaction(t_allow, commit=False)
        self.assertEqual(res_allow.decision, "ALLOW")
        self.assertLess(res_allow.risk_score, 30.0)

        # 2. REVIEW (30 <= Score < 60)
        # Setup user baseline
        u_rev = "rev_user@upi"
        b_time = datetime(2026, 11, 15, 12, 0)
        t_base = Transaction("TB", u_rev, "shop@upi", 200.0, b_time, "Mumbai", "DEV_1")
        self.engine.evaluate_transaction(t_base, commit=True)

        # New payee large amount (20) + new device (15) = 35 -> REVIEW
        t_rev = Transaction("T_REV", u_rev, "new_vendor@upi", 12345.0, b_time + timedelta(hours=1), "Mumbai", "DEV_NEW")
        res_rev = self.engine.evaluate_transaction(t_rev, commit=False)
        self.assertEqual(res_rev.decision, "REVIEW")
        self.assertGreaterEqual(res_rev.risk_score, 30.0)
        self.assertLess(res_rev.risk_score, 60.0)

        # 3. BLOCK (Score >= 60)
        # Account takeover combo: Amount anomaly (25) + New payee large (20) + Odd hours (10) + New device (15) = 70 -> BLOCK
        t_base2 = Transaction("TB2", u_rev, "shop@upi", 300.0, b_time + timedelta(minutes=10), "Mumbai", "DEV_1")
        self.engine.evaluate_transaction(t_base2, commit=True)

        t_block = Transaction(
            "T_BLOCK",
            u_rev,
            "crypto_drain@upi",
            50000.0,
            datetime(2026, 11, 16, 3, 0), # Odd hours
            "Mumbai",
            "DEV_HACKER"
        )
        res_block = self.engine.evaluate_transaction(t_block, commit=False)
        self.assertEqual(res_block.decision, "BLOCK")
        self.assertGreaterEqual(res_block.risk_score, 60.0)

    def test_json_persistence(self):
        """Test saving and reloading transactions to JSON file."""
        t1 = Transaction("T_PERSIST", "alice@upi", "bob@upi", 750.0, datetime(2026, 11, 15, 14, 0), "Mumbai", "DEV_A")
        self.engine.evaluate_transaction(t1, commit=True)

        new_engine = FraudShieldEngine(data_file=self.temp_file.name)
        loaded = new_engine.load_data()
        self.assertTrue(loaded)
        self.assertEqual(len(new_engine.transactions), 1)
        self.assertEqual(new_engine.transactions[0].transaction_id, "T_PERSIST")
        self.assertEqual(new_engine.transactions[0].amount, 750.0)

    def test_case_insensitive_upi_handling(self):
        """Test that UPI IDs are normalized and treated case-insensitively."""
        valid, normalized = Validator.validate_upi_id("Priya.Sharma@OkHdfcBank")
        self.assertTrue(valid)
        self.assertEqual(normalized, "priya.sharma@okhdfcbank")

        # History retrieval should find transactions regardless of case
        t1 = Transaction("T1", "priya@okhdfcbank", "merchant@upi", 300.0, datetime.now(), "Mumbai", "DEV_1")
        self.engine.evaluate_transaction(t1, commit=True)

        history_upper = self.engine.get_user_history("PRIYA@OKHDFCBANK")
        self.assertEqual(len(history_upper), 1)

    def test_false_alarm_marking(self):
        """Test marking a flagged transaction as a False Alarm (Stretch Feature)."""
        t = Transaction(
            "T_FA",
            "user@upi",
            "new_payee@upi",
            25000.0,
            datetime.now(),
            "Mumbai",
            "DEV_1"
        )
        evaluated = self.engine.evaluate_transaction(t, commit=True)
        self.assertIn(evaluated.decision, ("REVIEW", "BLOCK"))
        self.assertFalse(evaluated.is_false_alarm)

        # Analyst marks as false alarm
        evaluated.is_false_alarm = True
        evaluated.analyst_notes = "Customer confirmed transaction over phone"
        self.engine.save_data()

        # Reload and verify
        reloaded_engine = FraudShieldEngine(data_file=self.temp_file.name)
        reloaded_engine.load_data()
        loaded_txn = reloaded_engine.transactions[0]
        self.assertTrue(loaded_txn.is_false_alarm)
        self.assertEqual(loaded_txn.analyst_notes, "Customer confirmed transaction over phone")


if __name__ == "__main__":
    unittest.main()
