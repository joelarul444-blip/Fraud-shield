# FraudShield: Rule-Based UPI Transaction Risk Engine

**Capstone Problem:** CP-004  
**Domain:** Banking and FinTech  
**Difficulty:** Intermediate  
**Application Type:** Menu-driven console application  
**Implementation Language:** [Python / Java / C — use your assigned track language]  
**Project Status:** In development

## 1. Project Overview

FraudShield is a rule-based transaction risk checking system. It records UPI-style transactions and checks them against predefined rules that may indicate suspicious activity. Whenever a transaction is flagged, the system should display the reason that triggered the rule.

The goal is to implement simple, explainable checks before considering more advanced fraud detection approaches. A flagged transaction is considered suspicious by the rules; it is not proof that fraud has occurred.

## 2. Problem Statement

A payments startup wants to apply simple, explainable fraud rules before investing in machine learning. Every flagged transaction must show which rule was triggered.

## 3. Core Features

All five features below are compulsory for CP-004:

1. **Record transactions** with a transaction ID, user, amount, time (`hh:mm`), and city.
2. **Flag unusually large transactions:** flag a transaction when its amount is above five times that user's average transaction amount.
3. **Flag rapid transactions:** flag a user making more than three transactions within two minutes.
4. **Flag unfamiliar-city transactions:** flag a transaction made in a city where that user has never transacted before.
5. **Generate a risk report:** list all flagged transactions with the reason for each flag and show a risk count for each user.

## 4. Fraud Rules

### Rule 1 — Unusually Large Amount

Compare a transaction amount with the user's average transaction amount. Flag the transaction when it is **greater than five times** that average.

### Rule 2 — Too Many Transactions in a Short Time

Check transaction times for each user. Flag activity when the user makes **more than three transactions within two minutes**.

### Rule 3 — Unfamiliar City

Compare the transaction's city with the cities previously associated with that user. Flag the transaction if the user has not transacted in that city before.

### Risk Reporting

For each flagged transaction, show the transaction details and the rule or rules that were triggered. Also calculate the number of flagged transactions for each user.

## 5. Transaction Fields

Each transaction should contain these fields:

| Field | Description |
|---|---|
| Transaction ID | A unique identifier for the transaction |
| User | The user who made the transaction |
| Amount | The transaction amount |
| Time | Transaction time in `hh:mm` format |
| City | The city associated with the transaction |

## 6. Suggested Program Workflow

1. Display a console menu.
2. Allow the user to enter transaction details.
3. Validate the transaction input.
4. Check the recorded transactions against each fraud rule.
5. Store the flag reasons for transactions that trigger rules.
6. Display flagged transactions and the risk count per user.
7. Allow the user to continue or exit.

## 7. Suggested Console Menu

The exact menu can be adjusted to match the implementation:

1. Add a transaction
2. View recorded transactions
3. Analyze transactions for risk
4. View flagged transactions and reasons
5. View risk count per user
6. Exit

## 8. Technology

- **Programming language:** [Python / Java / C — use your assigned track language]
- **Interface:** Console / terminal
- **Data handling:** In-memory records to start with

The capstone brief does not require a GUI, website, or database. Any additional persistence or other enhancements should be treated as optional and discussed with the trainer if needed.

## 9. Running the Project

Add the run command for your chosen language after your source file has been created.

Examples of the kind of command to document:

- **Python:** `python main.py`
- **Java:** compile the Java source file, then run its class with `java`
- **C:** compile the C source file, then run the resulting program

Replace these examples with the exact filename and command used in your project.

## 10. Test Scenarios

Test the program with cases such as:

- A transaction amount greater than five times the user's average amount.
- A user making four or more transactions within a two-minute period.
- A user making a transaction in a city not present in their previous transaction history.
- A normal transaction that does not trigger any rule.
- A transaction that triggers more than one rule, ensuring every applicable reason is shown.
- Invalid input, such as an empty user, invalid time format, or a non-positive amount.

## 11. Optional Stretch Features

The capstone brief suggests these optional extensions:

- Allow an administrator to change rule thresholds without editing the source code.
- Allow an analyst to mark a flag as a false alarm and report the false-alarm rate for each rule.

## 12. Learning Objectives

Through this project, the aim is to practise:

- Working with transaction records and user history.
- Applying conditional rules to data.
- Comparing amounts and checking time windows.
- Tracking users' previously observed cities.
- Explaining why a transaction was flagge
- Validating input and testing unusual cases.

## 13. Disclaimer

FraudShield is an educational capstone simulation. Its rule-based flags are for demonstration and learning; they do not prove that a transaction is fraudulent and should not be used as a real payment security system.
