#!/usr/bin/env python3
"""
================================================================================
FraudShield Desktop GUI Application
CP-004 Capstone Project
================================================================================
A native desktop GUI application built using Python's standard library (tkinter).
Provides a visual interface for evaluating UPI payments, running fraud simulations,
inspecting the audit ledger, and managing rule thresholds.

Usage:
    python app_gui.py
    (Or: py app_gui.py)
================================================================================
"""

import sys
import os
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from datetime import datetime

from fraudshield import (
    FraudShieldEngine,
    Transaction,
    Validator,
    CONFIG,
    DEFAULT_CONFIG,
    run_demo_scenario
)


class FraudShieldGUI:
    """Desktop GUI interface for FraudShield using Tkinter and TTK."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("FraudShield — UPI Transaction Risk Engine")
        self.root.geometry("1100x720")
        self.root.minsize(950, 600)

        self.engine = FraudShieldEngine()
        self.engine.load_data()

        # Modern Dark-mode palette
        self.colors = {
            "bg": "#0f172a",
            "card": "#1e293b",
            "border": "#334155",
            "text": "#f8fafc",
            "text_muted": "#94a3b8",
            "primary": "#3b82f6",
            "success": "#10b981",
            "warning": "#f59e0b",
            "danger": "#ef4444"
        }

        self.root.configure(bg=self.colors["bg"])
        self.setup_styles()
        self.create_layout()
        self.refresh_all_views()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 9))
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["card"], foreground=self.colors["text_muted"], padding=[12, 6], font=("Segoe UI", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.colors["primary"])], foreground=[("selected", "#ffffff")])

        style.configure("TFrame", background=self.colors["bg"])
        style.configure("Card.TFrame", background=self.colors["card"], relief="solid", borderwidth=1)
        style.configure("TLabel", background=self.colors["card"], foreground=self.colors["text"])
        style.configure("Muted.TLabel", background=self.colors["card"], foreground=self.colors["text_muted"])
        style.configure("Header.TLabel", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI", 12, "bold"))

        style.configure("TButton", background=self.colors["primary"], foreground="#ffffff", borderwidth=0, padding=[10, 5], font=("Segoe UI", 9, "bold"))
        style.map("TButton", background=[("active", "#2563eb")])

        style.configure("Success.TButton", background=self.colors["success"], foreground="#ffffff")
        style.map("Success.TButton", background=[("active", "#059669")])

        style.configure("Danger.TButton", background=self.colors["danger"], foreground="#ffffff")
        style.map("Danger.TButton", background=[("active", "#dc2626")])

        style.configure("Treeview", background="#0b1120", foreground=self.colors["text"], fieldbackground="#0b1120", rowheight=26, bordercolor=self.colors["border"])
        style.configure("Treeview.Heading", background=self.colors["card"], foreground=self.colors["text"], font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", self.colors["primary"])])

    def create_layout(self):
        # Header banner
        header = tk.Frame(self.root, bg=self.colors["card"], height=55, padx=20, pady=10)
        header.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(header, text="🛡️ FraudShield: Rule-Based UPI Risk Engine", font=("Segoe UI", 14, "bold"), fg=self.colors["text"], bg=self.colors["card"])
        title_lbl.pack(side=tk.LEFT)

        demo_btn = tk.Button(header, text="▶ Run Demo Scenario", bg=self.colors["primary"], fg="#fff", font=("Segoe UI", 9, "bold"), padx=12, pady=4, relief="flat", command=self.run_demo)
        demo_btn.pack(side=tk.RIGHT, padx=5)

        clear_btn = tk.Button(header, text="🗑️ Clear Data", bg="#7f1d1d", fg="#fca5a5", font=("Segoe UI", 9), padx=10, pady=4, relief="flat", command=self.clear_data)
        clear_btn.pack(side=tk.RIGHT, padx=5)

        # Tab Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # Tabs
        self.tab_eval = ttk.Frame(self.notebook)
        self.tab_ledger = ttk.Frame(self.notebook)
        self.tab_stats = ttk.Frame(self.notebook)
        self.tab_config = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_eval, text="⚡ Evaluate Payment")
        self.notebook.add(self.tab_ledger, text="📑 Audit Ledger")
        self.notebook.add(self.tab_stats, text="📊 Analytics & Risk Profiles")
        self.notebook.add(self.tab_config, text="⚙️ Rules Config")

        self.build_evaluate_tab()
        self.build_ledger_tab()
        self.build_stats_tab()
        self.build_config_tab()

    # --------------------------------------------------------------------------
    # TAB 1: EVALUATE PAYMENT
    # --------------------------------------------------------------------------
    def build_evaluate_tab(self):
        paned = tk.PanedWindow(self.tab_eval, orient=tk.HORIZONTAL, bg=self.colors["bg"], bd=0)
        paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left Form Frame
        left_card = tk.LabelFrame(paned, text=" Transaction Input Details ", bg=self.colors["card"], fg=self.colors["text"], font=("Segoe UI", 10, "bold"), padx=15, pady=15)
        paned.add(left_card, minsize=420)

        fields = [
            ("Transaction ID:", "ent_id", "Leave blank for auto-generation"),
            ("Sender UPI ID *:", "ent_sender", "e.g. rohit@okhdfcbank"),
            ("Receiver UPI ID *:", "ent_receiver", "e.g. merchant@paytm"),
            ("Amount (INR ₹) *:", "ent_amount", "e.g. 1500.00"),
            ("City *:", "ent_city", "Mumbai"),
            ("Device ID:", "ent_device", "DEV_PIXEL_8"),
            ("Timestamp:", "ent_time", "YYYY-MM-DD HH:MM:SS or blank for now")
        ]

        self.entries = {}
        row = 0
        for label_text, var_name, placeholder in fields:
            lbl = tk.Label(left_card, text=label_text, bg=self.colors["card"], fg=self.colors["text_muted"], font=("Segoe UI", 9, "bold"))
            lbl.grid(row=row, column=0, sticky="w", pady=(6, 2))

            ent = tk.Entry(left_card, bg="#0b1120", fg=self.colors["text"], insertbackground="#fff", relief="flat", font=("Consolas", 10))
            ent.grid(row=row + 1, column=0, sticky="ew", pady=(0, 6), ipady=4)
            if placeholder in ("Mumbai", "DEV_PIXEL_8"):
                ent.insert(0, placeholder)
            self.entries[var_name] = ent
            row += 2

        left_card.columnconfigure(0, weight=1)

        eval_btn = tk.Button(left_card, text="🛡️ Evaluate Transaction Risk", bg=self.colors["primary"], fg="#fff", font=("Segoe UI", 10, "bold"), pady=8, relief="flat", command=self.handle_evaluate_click)
        eval_btn.grid(row=row, column=0, sticky="ew", pady=(15, 0))

        # Right Result Frame
        right_card = tk.LabelFrame(paned, text=" Risk Assessment Outcome ", bg=self.colors["card"], fg=self.colors["text"], font=("Segoe UI", 10, "bold"), padx=15, pady=15)
        paned.add(right_card, minsize=480)

        self.res_badge = tk.Label(right_card, text="[ AWAITING TRANSACTION ]", font=("Segoe UI", 14, "bold"), fg=self.colors["text_muted"], bg=self.colors["card"])
        self.res_badge.pack(anchor="w", pady=(0, 10))

        self.res_summary = tk.Label(right_card, text="Enter payment details on the left and click 'Evaluate Transaction Risk'.", bg=self.colors["card"], fg=self.colors["text_muted"], justify=tk.LEFT, wraplength=450)
        self.res_summary.pack(anchor="w", pady=(0, 10))

        tk.Label(right_card, text="Triggered Fraud Rules Breakdown:", font=("Segoe UI", 9, "bold"), bg=self.colors["card"], fg=self.colors["text"]).pack(anchor="w", pady=(10, 4))

        self.rules_box = tk.Text(right_card, bg="#0b1120", fg=self.colors["text"], font=("Consolas", 9), relief="flat", padx=10, pady=10, height=14)
        self.rules_box.pack(fill=tk.BOTH, expand=True)

    def handle_evaluate_click(self):
        sender = self.entries["ent_sender"].get().strip()
        valid, sender_res = Validator.validate_upi_id(sender, "Sender UPI")
        if not valid:
            messagebox.showerror("Validation Error", sender_res)
            return

        receiver = self.entries["ent_receiver"].get().strip()
        valid, receiver_res = Validator.validate_upi_id(receiver, "Receiver UPI")
        if not valid:
            messagebox.showerror("Validation Error", receiver_res)
            return

        if sender_res.lower() == receiver_res.lower():
            messagebox.showerror("Validation Error", "Sender and Receiver cannot be identical UPI IDs.")
            return

        amt_str = self.entries["ent_amount"].get().strip()
        valid, amt, err = Validator.validate_amount(amt_str)
        if not valid:
            messagebox.showerror("Validation Error", err)
            return

        city = self.entries["ent_city"].get().strip().title() or "Mumbai"
        device = self.entries["ent_device"].get().strip() or "DEV_DEFAULT"
        time_str = self.entries["ent_time"].get().strip()
        valid, dt, err = Validator.validate_timestamp(time_str)
        if not valid or dt is None:
            messagebox.showerror("Validation Error", err)
            return

        txn_id = self.entries["ent_id"].get().strip().upper() or self.engine.generate_next_id()
        if any(t.transaction_id.upper() == txn_id for t in self.engine.transactions):
            messagebox.showerror("Validation Error", f"Transaction ID '{txn_id}' already exists.")
            return

        txn = Transaction(
            transaction_id=txn_id,
            sender_upi=sender_res,
            receiver_upi=receiver_res,
            amount=amt,
            timestamp=dt,
            city=city,
            device_id=device
        )

        evaluated = self.engine.evaluate_transaction(txn, commit=True)
        self.display_evaluation_result(evaluated)
        self.refresh_all_views()

    def display_evaluation_result(self, txn: Transaction):
        color = self.colors["success"] if txn.decision == "ALLOW" else (self.colors["warning"] if txn.decision == "REVIEW" else self.colors["danger"])
        self.res_badge.config(text=f"DECISION: {txn.decision}  (Score: {txn.risk_score:.1f}/100.0)", fg=color)

        summary_text = (
            f"Transaction ID : {txn.transaction_id}\n"
            f"Route          : {txn.sender_upi} ➔ {txn.receiver_upi}\n"
            f"Amount         : ₹{txn.amount:,.2f}  |  City: {txn.city}  |  Device: {txn.device_id}\n"
            f"Timestamp      : {txn.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        self.res_summary.config(text=summary_text)

        self.rules_box.delete("1.0", tk.END)
        if not txn.triggered_rules:
            self.rules_box.insert(tk.END, "✓ No fraud rules triggered.\nTransaction fits within legitimate behavioral baseline.")
        else:
            for idx, r in enumerate(txn.triggered_rules, 1):
                self.rules_box.insert(tk.END, f"[{idx}] {r.name} (+{r.weight:.0f} pts)\n")
                self.rules_box.insert(tk.END, f"    ↳ Reason: {r.reason}\n\n")

    # --------------------------------------------------------------------------
    # TAB 2: AUDIT LEDGER
    # --------------------------------------------------------------------------
    def build_ledger_tab(self):
        ctrl_frame = tk.Frame(self.tab_ledger, bg=self.colors["bg"])
        ctrl_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(ctrl_frame, text="Filter / Search:", bg=self.colors["bg"], fg=self.colors["text_muted"]).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.filter_ledger())
        ent_search = tk.Entry(ctrl_frame, textvariable=self.search_var, bg="#0b1120", fg=self.colors["text"], insertbackground="#fff", width=30)
        ent_search.pack(side=tk.LEFT, padx=5, ipady=3)

        btn_fa = tk.Button(ctrl_frame, text="🛡️ Mark as False Alarm (Stretch)", bg=self.colors["card"], fg=self.colors["text"], relief="flat", command=self.handle_mark_fa)
        btn_fa.pack(side=tk.RIGHT, padx=5)

        columns = ("id", "sender", "receiver", "amount", "time", "city", "device", "score", "decision", "status")
        self.tree = ttk.Treeview(self.tab_ledger, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("id", text="Txn ID")
        self.tree.heading("sender", text="Sender UPI")
        self.tree.heading("receiver", text="Receiver UPI")
        self.tree.heading("amount", text="Amount (₹)")
        self.tree.heading("time", text="Time")
        self.tree.heading("city", text="City")
        self.tree.heading("device", text="Device")
        self.tree.heading("score", text="Score")
        self.tree.heading("decision", text="Decision")
        self.tree.heading("status", text="Analyst Status")

        self.tree.column("id", width=90)
        self.tree.column("sender", width=160)
        self.tree.column("receiver", width=160)
        self.tree.column("amount", width=100, anchor="e")
        self.tree.column("time", width=125)
        self.tree.column("city", width=90)
        self.tree.column("device", width=120)
        self.tree.column("score", width=60, anchor="center")
        self.tree.column("decision", width=80, anchor="center")
        self.tree.column("status", width=110, anchor="center")

        scroll = ttk.Scrollbar(self.tab_ledger, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scroll.pack(fill=tk.Y, side=tk.RIGHT)

    def filter_ledger(self):
        query = self.search_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())

        for t in self.engine.transactions:
            match_str = f"{t.transaction_id} {t.sender_upi} {t.receiver_upi} {t.city} {t.decision}".lower()
            if query and query not in match_str:
                continue

            fa_status = "FALSE ALARM" if t.is_false_alarm else ("FLAGGED" if t.decision != "ALLOW" else "CLEARED")
            self.tree.insert("", tk.END, values=(
                t.transaction_id,
                t.sender_upi,
                t.receiver_upi,
                f"₹{t.amount:,.2f}",
                t.timestamp.strftime("%Y-%m-%d %H:%M"),
                t.city,
                t.device_id,
                f"{t.risk_score:.1f}",
                t.decision,
                fa_status
            ))

    def handle_mark_fa(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Transaction", "Please select a transaction in the table to mark as False Alarm.")
            return

        item = self.tree.item(selected[0])
        txn_id = item["values"][0]
        found = next((t for t in self.engine.transactions if t.transaction_id == txn_id), None)
        if not found:
            return

        if found.decision == "ALLOW":
            messagebox.showinfo("Not Applicable", "Transaction is already cleared as ALLOW.")
            return

        note = simpledialog.askstring("Analyst Audit Note", f"Enter justification to mark {txn_id} as a False Alarm:")
        if note is not None:
            found.is_false_alarm = True
            found.analyst_notes = note.strip() or "Verified genuine user transaction by analyst"
            self.engine.save_data()
            messagebox.showinfo("Resolved", f"Transaction {txn_id} marked as FALSE ALARM.")
            self.refresh_all_views()

    # --------------------------------------------------------------------------
    # TAB 3: ANALYTICS & STATS
    # --------------------------------------------------------------------------
    def build_stats_tab(self):
        paned = tk.PanedWindow(self.tab_stats, orient=tk.HORIZONTAL, bg=self.colors["bg"], bd=0)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left KPIs
        left_frame = tk.LabelFrame(paned, text=" Risk Analytics & False Alarm Metrics ", bg=self.colors["card"], fg=self.colors["text"], font=("Segoe UI", 10, "bold"), padx=15, pady=15)
        paned.add(left_frame, minsize=420)

        self.stats_text = tk.Text(left_frame, bg="#0b1120", fg=self.colors["text"], font=("Consolas", 10), relief="flat", padx=10, pady=10)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        # Right User Profiles
        right_frame = tk.LabelFrame(paned, text=" User Risk Profiles Matrix ", bg=self.colors["card"], fg=self.colors["text"], font=("Segoe UI", 10, "bold"), padx=15, pady=15)
        paned.add(right_frame, minsize=480)

        cols = ("user", "volume", "txns", "avg", "flagged", "risk")
        self.user_tree = ttk.Treeview(right_frame, columns=cols, show="headings")
        self.user_tree.heading("user", text="User UPI")
        self.user_tree.heading("volume", text="Total Vol")
        self.user_tree.heading("txns", text="Txns")
        self.user_tree.heading("avg", text="Avg Amt")
        self.user_tree.heading("flagged", text="Flagged")
        self.user_tree.heading("risk", text="Risk Tier")

        self.user_tree.column("user", width=150)
        self.user_tree.column("volume", width=90, anchor="e")
        self.user_tree.column("txns", width=50, anchor="center")
        self.user_tree.column("avg", width=80, anchor="e")
        self.user_tree.column("flagged", width=60, anchor="center")
        self.user_tree.column("risk", width=80, anchor="center")

        self.user_tree.pack(fill=tk.BOTH, expand=True)

    def refresh_stats_tab(self):
        txns = self.engine.transactions
        total = len(txns)
        allow_cnt = sum(1 for t in txns if t.decision == "ALLOW")
        review_cnt = sum(1 for t in txns if t.decision == "REVIEW")
        block_cnt = sum(1 for t in txns if t.decision == "BLOCK")
        total_vol = sum(t.amount for t in txns)
        blocked_vol = sum(t.amount for t in txns if t.decision == "BLOCK")

        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert(tk.END, "=== SYSTEM FRAUD METRICS ===\n")
        self.stats_text.insert(tk.END, f"Total Transactions : {total}\n")
        self.stats_text.insert(tk.END, f"Processed Volume   : ₹{total_vol:,.2f}\n")
        self.stats_text.insert(tk.END, f"Blocked Volume     : ₹{blocked_vol:,.2f}\n\n")

        self.stats_text.insert(tk.END, "=== DECISION BREAKDOWN ===\n")
        pct_allow = (allow_cnt / total * 100) if total else 0
        pct_review = (review_cnt / total * 100) if total else 0
        pct_block = (block_cnt / total * 100) if total else 0
        self.stats_text.insert(tk.END, f"ALLOW  : {allow_cnt:>3} ({pct_allow:.1f}%)\n")
        self.stats_text.insert(tk.END, f"REVIEW : {review_cnt:>3} ({pct_review:.1f}%)\n")
        self.stats_text.insert(tk.END, f"BLOCK  : {block_cnt:>3} ({pct_block:.1f}%)\n\n")

        # False alarm metrics
        flagged_cnt = review_cnt + block_cnt
        false_alarms = [t for t in txns if t.is_false_alarm]
        fa_rate = (len(false_alarms) / flagged_cnt * 100) if flagged_cnt else 0.0
        self.stats_text.insert(tk.END, "=== FALSE ALARM AUDIT (STRETCH) ===\n")
        self.stats_text.insert(tk.END, f"Flagged Incidents  : {flagged_cnt}\n")
        self.stats_text.insert(tk.END, f"Marked False Alarm : {len(false_alarms)} ({fa_rate:.1f}%)\n")

        # User profiles tree
        self.user_tree.delete(*self.user_tree.get_children())
        users = sorted(list({t.sender_upi for t in txns}))
        for u in users:
            u_txns = [t for t in txns if t.sender_upi == u]
            u_vol = sum(t.amount for t in u_txns)
            u_avg = u_vol / len(u_txns) if u_txns else 0.0
            u_flg = sum(1 for t in u_txns if t.decision in ("REVIEW", "BLOCK"))
            rate = (u_flg / len(u_txns) * 100) if u_txns else 0.0
            tier = "HIGH" if (rate >= 50 or u_flg >= 3) else ("MODERATE" if u_flg > 0 else "LOW")

            self.user_tree.insert("", tk.END, values=(
                u,
                f"₹{u_vol:,.0f}",
                len(u_txns),
                f"₹{u_avg:,.0f}",
                u_flg,
                tier
            ))

    # --------------------------------------------------------------------------
    # TAB 4: CONFIGURATION
    # --------------------------------------------------------------------------
    def build_config_tab(self):
        card = tk.LabelFrame(self.tab_config, text=" Single Centralized Configuration (CONFIG) ", bg=self.colors["card"], fg=self.colors["text"], font=("Segoe UI", 10, "bold"), padx=20, pady=20)
        card.pack(fill=tk.BOTH, expand=True, padx=40, pady=10)

        cfg_fields = [
            ("Review Score Cutoff (0-100):", "THRESHOLD_REVIEW"),
            ("Block Score Cutoff (0-100):", "THRESHOLD_BLOCK"),
            ("Velocity Burst Weight:", "RULE_VELOCITY_BURST_WEIGHT"),
            ("Amount Anomaly Multiplier (x):", "AMOUNT_ANOMALY_MULTIPLIER"),
            ("Amount Anomaly Weight:", "RULE_AMOUNT_ANOMALY_WEIGHT"),
            ("New Payee Large Weight:", "RULE_NEW_PAYEE_LARGE_WEIGHT"),
            ("Location Jump Weight:", "RULE_LOCATION_JUMP_WEIGHT"),
            ("Daily UPI Limit Ceiling (₹):", "DAILY_LIMIT_THRESHOLD")
        ]

        self.cfg_entries = {}
        for r, (label, key) in enumerate(cfg_fields):
            tk.Label(card, text=label, bg=self.colors["card"], fg=self.colors["text_muted"], font=("Segoe UI", 9, "bold")).grid(row=r, column=0, sticky="w", pady=4)
            ent = tk.Entry(card, bg="#0b1120", fg=self.colors["text"], insertbackground="#fff", width=25)
            ent.grid(row=r, column=1, sticky="w", padx=15, pady=4)
            ent.insert(0, str(CONFIG.get(key, "")))
            self.cfg_entries[key] = ent

        btn_box = tk.Frame(card, bg=self.colors["card"])
        btn_box.grid(row=len(cfg_fields), column=0, columnspan=2, pady=(20, 0))

        tk.Button(btn_box, text="💾 Save Changes", bg=self.colors["primary"], fg="#fff", font=("Segoe UI", 9, "bold"), padx=15, pady=5, relief="flat", command=self.save_config).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_box, text="↺ Factory Defaults", bg=self.colors["card"], fg=self.colors["text"], padx=10, pady=5, relief="flat", command=self.reset_config).pack(side=tk.LEFT, padx=5)

    def save_config(self):
        try:
            for k, ent in self.cfg_entries.items():
                val = ent.get().strip()
                CONFIG[k] = type(DEFAULT_CONFIG[k])(val)
            messagebox.showinfo("Saved", "Rule thresholds and weights updated live!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def reset_config(self):
        CONFIG.clear()
        CONFIG.update(DEFAULT_CONFIG)
        for k, ent in self.cfg_entries.items():
            ent.delete(0, tk.END)
            ent.insert(0, str(CONFIG[k]))
        messagebox.showinfo("Reset", "All configuration restored to factory defaults.")

    # --------------------------------------------------------------------------
    # TOP ACTIONS
    # --------------------------------------------------------------------------
    def run_demo(self):
        run_demo_scenario(self.engine, interactive=False, reset_first=True)
        messagebox.showinfo("Demo Complete", f"15-event FinTech simulation executed!\n{len(self.engine.transactions)} transactions evaluated.")
        self.refresh_all_views()
        self.notebook.select(self.tab_ledger)

    def clear_data(self):
        if messagebox.askyesno("Confirm Purge", "Are you sure you want to clear all transaction records?"):
            self.engine.clear_data()
            self.refresh_all_views()
            messagebox.showinfo("Purged", "Transaction database cleared.")

    def refresh_all_views(self):
        self.filter_ledger()
        self.refresh_stats_tab()


def main():
    root = tk.Tk()
    app = FraudShieldGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
