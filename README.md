# CP-004 FraudShield: Rule-Based UPI Transaction Risk Engine

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen.svg)]()
[![Standard Library](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-success.svg)]()
[![Domain](https://img.shields.io/badge/Domain-FinTech%20%7C%20Payment%20Security-orange.svg)]()

**FraudShield** is a rule-based UPI transaction risk engine built as a Python console application. It evaluates incoming UPI transactions against **nine independent, weighted fraud detection rules**, synthesizes them into an explainable **0–100 composite risk score**, and issues definitive payment decisions: **ALLOW**, **REVIEW**, or **BLOCK**.

Every decision includes a full audit breakdown of which rules triggered and why, providing explainability for compliance, security analysts, and fraud operations teams.

---

## Table of Contents
1. [Core Features](#core-features)
2. [The Nine Fraud Detection Rules](#the-nine-fraud-detection-rules)
3. [Composite Risk Scoring & Decision Model](#composite-risk-scoring--decision-model)
4. [Centralized Configuration (`CONFIG`)](#centralized-configuration-config)
5. [Input Validation & Supported Formats](#input-validation--supported-formats)
6. [Interactive Console Menu](#interactive-console-menu)
7. [Built-In Demo Scenario](#built-in-demo-scenario)
8. [JSON Data Persistence](#json-data-persistence)
9. [Running the Application](#running-the-application)
10. [Running the Unit Test Suite](#running-the-unit-test-suite)
11. [Project Structure](#project-structure)

---

## Core Features

- **Nine Explainable Rules:** Covers velocity bursts, amount anomalies, high-value new payees, odd hours, unrecognized devices, location jumps / impossible travel, repeated transfers (smurfing), daily limits, and large round amounts.
- **Traceable & Explainable Audit Trail:** Every transaction records exactly which rules fired, the weight contributed, and human-readable reasoning.
- **Dynamic 0–100 Risk Scoring:** Normalizes individual rule weights and classifies transactions into **ALLOW**, **REVIEW**, or **BLOCK**.
- **Interactive Console Application:** Add transactions manually, inspect logs, view user risk profiles, look up IDs, and analyze rule frequency distributions.
- **Single `CONFIG` Block:** Rule weights and thresholds are centralized in a single configuration block and can be adjusted interactively during runtime without modifying source code.
- **Zero External Dependencies:** Built entirely with Python's standard library (`json`, `datetime`, `re`, `math`, `sys`, `os`, `unittest`).
- **Resilient JSON Persistence:** Transactions and audit trails automatically persist across program restarts.
- **Analyst False-Alarm Workflow (CP-004 Stretch):** Analysts can mark flagged transactions as verified false alarms with notes, and the engine automatically computes per-rule and global false-alarm rates.
- **User Ledger Drilldown:** Inspect high-risk users and immediately review their complete historical transaction timeline.
- **Built-in FinTech Demo Scenario:** Pre-configured simulation demonstrating legitimate baselines, velocity bursts, impossible travel, and midnight account takeover attacks.

---

## The Nine Fraud Detection Rules

| # | Rule Name | Code | Default Weight | Condition & Threshold | Fraud Pattern Addressed |
|---|---|---|---|---|---|
| **1** | **Velocity Burst** | `R1_VELOCITY` | **30.0** | > 3 transactions within 120 seconds (2 mins) | Scripted bot spam, automated drainers, card testing |
| **2** | **Amount Anomaly** | `R2_AMOUNT_ANOMALY` | **30.0** | > 5.0× user's historical average amount (min 2 past txns) | Sudden unauthorized account drainage |
| **3** | **New Payee Large Amount** | `R3_NEW_PAYEE_LARGE` | **25.0** | First transfer to an unseen payee ≥ ₹10,000.00 | Social engineering scams, mule account transfers |
| **4** | **Odd Hours Activity** | `R4_ODD_HOURS` | **15.0** | Transaction initiated between 00:00 and 05:00 AM | Nocturnal account compromise / unauthorized access |
| **5** | **Unrecognized Device** | `R5_NEW_DEVICE` | **15.0** | Device ID not previously seen in user's history | Stolen credentials used on attacker's phone or emulator |
| **6** | **Location Jump** | `R6_LOCATION_JUMP` | **30.0** | Unfamiliar city OR impossible travel (< 2 hours between cities) | Stolen credentials, proxy/VPN abuse, impossible physical transit |
| **7** | **Repeated Transfers** | `R7_REPEAT_PAYEE` | **30.0** | > 2 transfers to the same payee within 300 seconds (5 mins) | Smurfing (splitting large funds to avoid single-transfer alarms) |
| **8** | **Daily Limit Exceeded** | `R8_DAILY_LIMIT` | **30.0** | Cumulative volume on same calendar day > ₹1,00,000.00 | Regulatory UPI daily limits (NPCI guidelines) |
| **9** | **Large Round Amount** | `R9_ROUND_AMOUNT` | **10.0** | Multiple of ₹1,000.00 and amount ≥ ₹10,000.00 | Criminals testing clean integer sums (₹25k, ₹50k, ₹75k) |

---

## Composite Risk Scoring & Decision Model

When a transaction is evaluated:
1. Each rule evaluates the incoming transaction and historical user activity.
2. If a rule triggers, its corresponding weight is added to the raw score:
   $$\text{Raw Score} = \sum_{\text{triggered rules}} \text{Weight}_i$$
3. The raw score is capped to a scale of **0.0 to 100.0**:
   $$\text{Risk Score} = \min(100.0, \max(0.0, \text{Raw Score}))$$
4. The system issues one of three decisions:
   - **`ALLOW`** ($\text{Risk Score} < 30.0$): Low risk. Transaction proceeds normally.
   - **`REVIEW`** ($30.0 \le \text{Risk Score} < 60.0$): Moderate risk. Transaction is flagged for manual compliance review / Step-up 2FA.
   - **`BLOCK`** ($\text{Risk Score} \ge 60.0$): Critical risk. Transaction is immediately declined.

---

## Centralized Configuration (`CONFIG`)

All thresholds, time windows, and weights are governed by a single `CONFIG` dictionary at the top of `fraudshield.py`:

```python
DEFAULT_CONFIG = {
    "THRESHOLD_REVIEW": 30.0,
    "THRESHOLD_BLOCK": 60.0,
    "RULE_VELOCITY_BURST_WEIGHT": 30.0,
    "VELOCITY_WINDOW_SECONDS": 120,
    "VELOCITY_MAX_TXNS": 3,
    "RULE_AMOUNT_ANOMALY_WEIGHT": 30.0,
    "AMOUNT_ANOMALY_MULTIPLIER": 5.0,
    "AMOUNT_ANOMALY_MIN_HISTORY": 2,
    "RULE_NEW_PAYEE_LARGE_WEIGHT": 25.0,
    "NEW_PAYEE_LARGE_THRESHOLD": 10000.0,
    "RULE_ODD_HOURS_WEIGHT": 15.0,
    "ODD_HOURS_START": 0,
    "ODD_HOURS_END": 5,
    "RULE_NEW_DEVICE_WEIGHT": 15.0,
    "RULE_LOCATION_JUMP_WEIGHT": 30.0,
    "IMPOSSIBLE_TRAVEL_WINDOW_HOURS": 2.0,
    "RULE_REPEAT_PAYEE_WEIGHT": 30.0,
    "REPEAT_PAYEE_WINDOW_SECONDS": 300,
    "REPEAT_PAYEE_MAX_TXNS": 2,
    "RULE_DAILY_LIMIT_WEIGHT": 30.0,
    "DAILY_LIMIT_THRESHOLD": 100000.0,
    "RULE_LARGE_ROUND_WEIGHT": 10.0,
    "LARGE_ROUND_MIN_AMOUNT": 10000.0,
    "LARGE_ROUND_STEP": 1000.0,
    "DATA_FILE": "fraudshield_data.json"
}
```

Administrators can inspect or update these values at runtime using **Option 8** in the interactive menu without restarting the program.

---

## Input Validation & Supported Formats

- **UPI IDs:** Checked against standard format `username@bank` (e.g., `priya@okhdfcbank`, `merchant@paytm`). Sender and receiver cannot be identical.
- **Monetary Amounts:** Must be finite positive numbers ($> 0.00$). Automatically rounded to 2 decimal places.
- **Timestamps:**
  - Full datetime: `YYYY-MM-DD HH:MM:SS` or `YYYY-MM-DD HH:MM` (e.g. `2026-11-15 14:30:00`)
  - Time-only: `HH:MM:SS` or `HH:MM` (automatically paired with today's date)
  - Blank input: automatically applies the current system timestamp.
- **Location & Device:** Non-empty descriptive strings (e.g., `Mumbai`, `Bengaluru`, `DEV_PIXEL_8`).

---

## Interactive Console Menu

When launched, FraudShield displays an interactive menu:

```text
╔══════════════════════════════════════════════════════════════════╗
║     FRAUDSHIELD: RULE-BASED UPI TRANSACTION RISK ENGINE          ║
║     Capstone CP-004 | Explainable Multi-Rule Fraud Detection     ║
╠══════════════════════════════════════════════════════════════════╣
║  [1] Evaluate / Add a Transaction                                ║
║  [2] Load & Run Built-in Demo Scenario (ATO, Velocity, Jump)     ║
║  [3] View All Recorded Transactions                              ║
║  [4] View Flagged Transactions & Flag Reasons (Audit Report)     ║
║  [5] Look Up Transaction by ID                                   ║
║  [6] View User History & Risk Profile (Risk Count per User)      ║
║  [7] View Engine Analytics & Rule Trigger Statistics             ║
║  [8] View / Adjust Thresholds & Rule Weights (CONFIG)            ║
║  [9] Data Management (Save / Reload / Reset Storage)             ║
║  [0] Exit Program                                                ║
╚══════════════════════════════════════════════════════════════════╝
```

---

## Built-In Demo Scenario

Select **Option 2** to load the comprehensive 15-event simulation. The scenario simulates:

1. **Legitimate User Baseline:**
   - User `priya@okhdfcbank` makes normal purchases in Mumbai on `DEV_PIXEL_8` (₹350 coffee, ₹850 grocery, ₹600 lunch). Average baseline: ₹600.
   - Outcome: **`ALLOW`** (Score: 0.0).

2. **Velocity Burst Attack:**
   - User `rahul.verma@ybl` sends 4 transactions within 75 seconds.
   - 4th transaction triggers `R1_VELOCITY` (> 3 txns within 120s).
   - Outcome: **`REVIEW`** (Score: 30.0).

3. **Geographic Anomaly / Impossible Travel:**
   - User `amit.kumar@sbi` transacts in Bengaluru at 16:00.
   - 20 minutes later, a ₹25,000 transaction is attempted from London on an unknown device (`DEV_UNKNOWN_LINUX`).
   - Triggers `R3_NEW_PAYEE_LARGE` (+25), `R5_NEW_DEVICE` (+15), `R6_LOCATION_JUMP` (+30).
   - Outcome: **`BLOCK`** (Score: 70.0).

4. **Account Takeover (ATO) Midnight Attack:**
   - Compromised credentials for `priya@okhdfcbank` used at 02:40 AM from a rooted emulator (`DEV_ROOTED_EMULATOR_99`) in Kolkata.
   - Transfers ₹75,000 (125× her average) to an unverified mule receiver.
   - Triggers: Amount Anomaly (+30), New Payee Large (+25), Odd Hours (+15), Unrecognized Device (+15), Unfamiliar City (+30), Large Round Amount (+10).
   - Outcome: **`BLOCK`** (Score: 100.0).

5. **Smurfing / Repeated Payee Spam:**
   - User `vikram.singh@axisbank` sends three rapid ₹9,000 payments to the same recipient in under 90 seconds.
   - Outcome: **`REVIEW`** (Score: 30.0).

6. **Daily UPI Limit Ceiling Breach:**
   - User `sneha.patel@icici` attempts two payments totaling ₹1,15,000 in one day.
   - Outcome: **`REVIEW`** (Score: 40.0).

---

## JSON Data Persistence

Transactions are serialized to `fraudshield_data.json` upon evaluation. Sample record:

```json
{
  "transaction_id": "TXN-1010",
  "sender_upi": "priya@okhdfcbank",
  "receiver_upi": "crypto_cashout@mulebank",
  "amount": 75000.0,
  "timestamp": "2026-11-16 02:40:00",
  "city": "Kolkata",
  "device_id": "DEV_ROOTED_EMULATOR_99",
  "risk_score": 100.0,
  "decision": "BLOCK",
  "triggered_rules": [
    {
      "rule_id": "R2_AMOUNT_ANOMALY",
      "name": "Amount Anomaly",
      "weight": 30.0,
      "triggered": true,
      "reason": "Unusually large amount: ₹75,000.00 is 125.0x the user's historical average of ₹600.00 (threshold: > 5.0x = ₹3,000.00)."
    },
    {
      "rule_id": "R3_NEW_PAYEE_LARGE",
      "name": "New Payee with Large Amount",
      "weight": 25.0,
      "triggered": true,
      "reason": "High-value first-time transfer: ₹75,000.00 sent to never-before-seen payee 'crypto_cashout@mulebank' (threshold: >= ₹10,000.00)."
    },
    {
      "rule_id": "R4_ODD_HOURS",
      "name": "Odd Hours Activity",
      "weight": 15.0,
      "triggered": true,
      "reason": "Odd hours transaction: Initiated at 02:40:00 inside high-risk nocturnal window (00:00 - 05:00)."
    },
    {
      "rule_id": "R5_NEW_DEVICE",
      "name": "Unrecognized Device",
      "weight": 15.0,
      "triggered": true,
      "reason": "Device anomaly: 'DEV_ROOTED_EMULATOR_99' has never been used by this user before (known device(s): 'DEV_PIXEL_8')."
    },
    {
      "rule_id": "R6_LOCATION_JUMP",
      "name": "Location Jump / Unfamiliar City",
      "weight": 30.0,
      "triggered": true,
      "reason": "Unfamiliar city: First transaction from 'Kolkata' for this user (previous transacted cities: Mumbai, Mumbai, Mumbai)."
    },
    {
      "rule_id": "R9_ROUND_AMOUNT",
      "name": "Large Round Amount",
      "weight": 10.0,
      "triggered": true,
      "reason": "Suspicious round figure: ₹75,000.00 is an exact multiple of ₹1,000 above ₹10,000.00 (common signature of account draining / cash-out)."
    }
  ]
}
```

---

## Running the Application

FraudShield provides **three interfaces** to fit any workflow:

### 1. Modern Web Application & Live Dashboard (Recommended)
Run the self-contained web application (powered by Python's standard library):
```bash
py app.py
```
*(Or `python app.py` / `python3 app.py`)*

This launches a local REST API and Web Console, and automatically opens your browser at `http://127.0.0.1:8000`.
- **Live Evaluator:** Interactive form with real-time risk score gauge and fired rule breakdown.
- **1-Click Demo Runner:** Stream the 15-event FinTech simulation live.
- **Filterable Audit Ledger:** Search by ID, user, or city, and filter by decision.
- **Analyst Resolution:** Mark or unmark False Alarms with custom justification notes.
- **Rule Config Sliders:** Adjust rule weights and thresholds live with immediate effect.

---

### 2. Native Windows Desktop GUI
For a native desktop window (built with Python `tkinter`):
```bash
py app_gui.py
```

---

### 3. Interactive Terminal Console
For terminal environments:
```bash
py fraudshield.py
```
Choose **Option 2** to run the step-by-step interactive demo scenario.

---

### 4. Non-Interactive CLI Mode
```bash
# Run automated demo and print full assessment cards
py fraudshield.py --demo

# View current engine statistics and rule frequency
py fraudshield.py --stats
```

---

## Running the Unit Test Suite

FraudShield includes 14 unit tests validating all 9 rules, validators, score bounds, and persistence:

```bash
python3 -m unittest test_fraudshield.py
```

Output:
```text
................
----------------------------------------------------------------------
Ran 16 tests in 0.034s

OK
```

---

## Project Structure

```text
cp-04 fraudshield/
├── app.py                 # Web application & REST API server (Executive Dashboard)
├── app_gui.py             # Native desktop GUI application (Tkinter)
├── fraudshield.py         # Main risk engine, 9 rules, validation, CLI & demo
├── test_fraudshield.py    # Complete automated unit test suite (16 test cases)
├── fraudshield_data.json  # Persistent JSON transaction database & audit trail
└── README.md              # Project documentation & reference specification
```

---

## Disclaimer
FraudShield is an educational FinTech capstone simulation developed under CP-004. The rule-based flags are for risk assessment and demonstration; they indicate statistical suspicion rather than definitive legal proof of fraud.
