#!/usr/bin/env python3
"""
================================================================================
FraudShield Web Application & Live Risk Dashboard
CP-004 Capstone Project
================================================================================
A self-contained web application and REST API built using Python's standard
library (http.server). Delivers an executive FinTech risk operations console
with real-time transaction evaluation, interactive demo runner, rule analytics,
and analyst audit workflow.

Usage:
    python app.py
    (Or: py app.py)
Automatically opens http://127.0.0.1:8000 in your web browser.
================================================================================
"""

import sys
import os
import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Import core FraudShield engine and data structures
from fraudshield import (
    FraudShieldEngine,
    Transaction,
    Validator,
    CONFIG,
    DEFAULT_CONFIG,
    Colors
)

engine = FraudShieldEngine()
engine.load_data()

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FraudShield — UPI Transaction Risk Engine</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f2937;
      --card-hover: #1e293b;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --text-dim: #6b7280;
      --accent: #6366f1;
      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
    }

    /* Top Navigation Bar */
    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 0.75rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      text-decoration: none;
      color: var(--text);
    }

    .brand-icon {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.2rem;
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.5);
    }

    .brand-title {
      font-size: 1.15rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .brand-badge {
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      background: rgba(59, 130, 246, 0.15);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: #60a5fa;
      border-radius: 9999px;
      font-weight: 600;
      text-transform: uppercase;
    }

    .nav-tabs {
      display: flex;
      gap: 0.5rem;
      background: #0b1120;
      padding: 0.25rem;
      border-radius: 10px;
      border: 1px solid var(--card-border);
    }

    .tab-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 0.5rem 1rem;
      border-radius: 7px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.4rem;
    }

    .tab-btn:hover { color: var(--text); background: rgba(255, 255, 255, 0.05); }
    .tab-btn.active {
      color: #fff;
      background: var(--primary);
      box-shadow: 0 2px 8px rgba(59, 130, 246, 0.4);
    }

    .header-actions {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .btn {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text);
      padding: 0.45rem 0.9rem;
      border-radius: 7px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.2s;
    }

    .btn:hover { background: var(--card-hover); border-color: #374151; }
    .btn-primary { background: var(--primary); border-color: var(--primary); color: #fff; }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-success { background: #059669; border-color: #059669; color: #fff; }
    .btn-success:hover { background: #10b981; }
    .btn-danger { background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.3); color: #f87171; }
    .btn-danger:hover { background: rgba(239, 68, 68, 0.25); }

    /* Main Container */
    main {
      flex: 1;
      padding: 2rem;
      max-width: 1440px;
      margin: 0 auto;
      width: 100%;
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1.25rem;
      margin-bottom: 2rem;
    }

    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.25rem;
      position: relative;
      overflow: hidden;
    }

    .kpi-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: var(--card-border);
    }

    .kpi-card.blue::before { background: var(--primary); }
    .kpi-card.green::before { background: var(--success); }
    .kpi-card.yellow::before { background: var(--warning); }
    .kpi-card.red::before { background: var(--danger); }

    .kpi-label {
      font-size: 0.75rem;
      text-transform: uppercase;
      font-weight: 700;
      color: var(--text-muted);
      letter-spacing: 0.05em;
      margin-bottom: 0.5rem;
    }

    .kpi-value {
      font-size: 1.8rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      margin-bottom: 0.25rem;
    }

    .kpi-sub {
      font-size: 0.8rem;
      color: var(--text-dim);
    }

    /* Layout Split */
    .grid-2col {
      display: grid;
      grid-template-columns: 420px 1fr;
      gap: 1.5rem;
    }

    @media (max-width: 1024px) {
      .grid-2col { grid-template-columns: 1fr; }
    }

    /* Panel Card */
    .panel {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      overflow: hidden;
    }

    .panel-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .panel-title {
      font-size: 0.95rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .panel-body {
      padding: 1.25rem;
    }

    /* Form Inputs */
    .form-group {
      margin-bottom: 1rem;
    }

    .form-label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }

    .form-input {
      width: 100%;
      background: #0b1120;
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 0.6rem 0.85rem;
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 0.9rem;
      transition: all 0.2s;
    }

    .form-input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
    }

    /* Assessment Output Card */
    .result-box {
      border: 1px solid var(--card-border);
      background: #0b1120;
      border-radius: 10px;
      padding: 1.25rem;
      margin-top: 1.25rem;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.65rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }

    .badge-allow { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-review { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-block { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-fa { background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); }

    /* Meter / Gauge */
    .gauge-wrapper {
      margin: 1rem 0;
    }

    .gauge-bar-bg {
      height: 10px;
      background: #1f2937;
      border-radius: 5px;
      overflow: hidden;
      position: relative;
    }

    .gauge-fill {
      height: 100%;
      width: 0%;
      border-radius: 5px;
      transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .gauge-markers {
      display: flex;
      justify-content: space-between;
      font-size: 0.7rem;
      color: var(--text-dim);
      margin-top: 0.35rem;
      font-family: var(--font-mono);
    }

    /* Rule Items */
    .rule-item {
      background: rgba(239, 68, 68, 0.08);
      border-left: 3px solid var(--danger);
      padding: 0.6rem 0.85rem;
      border-radius: 0 6px 6px 0;
      margin-bottom: 0.5rem;
      font-size: 0.85rem;
    }

    .rule-item.review {
      background: rgba(245, 158, 11, 0.08);
      border-left-color: var(--warning);
    }

    .rule-title {
      font-weight: 700;
      display: flex;
      justify-content: space-between;
      margin-bottom: 0.2rem;
    }

    .rule-reason {
      color: var(--text-muted);
      font-size: 0.8rem;
    }

    /* Tables */
    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      text-align: left;
    }

    th {
      background: #0b1120;
      color: var(--text-muted);
      font-weight: 600;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--card-border);
      text-transform: uppercase;
      font-size: 0.7rem;
      letter-spacing: 0.05em;
    }

    td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--card-border);
      color: var(--text);
    }

    tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .font-mono { font-family: var(--font-mono); }

    /* Modal */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 100;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 1rem;
    }

    .modal-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      width: 100%;
      max-width: 600px;
      overflow: hidden;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    }

    /* Toast */
    #toast {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      background: #1e293b;
      border: 1px solid var(--card-border);
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      color: #fff;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.4);
      display: none;
      z-index: 200;
      animation: slideIn 0.3s ease;
    }

    @keyframes slideIn {
      from { transform: translateY(20px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }
  </style>
</head>
<body>

  <!-- Top Header -->
  <header>
    <a href="#" class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <div class="brand-title">FraudShield</div>
        <div style="font-size: 0.75rem; color: var(--text-dim);">CP-004 UPI Risk Engine</div>
      </div>
      <span class="brand-badge">Live Operations</span>
    </a>

    <!-- Navigation Tabs -->
    <nav class="nav-tabs">
      <button class="tab-btn active" onclick="switchTab('dashboard')">📊 Dashboard</button>
      <button class="tab-btn" onclick="switchTab('evaluate')">⚡ Evaluate Txn</button>
      <button class="tab-btn" onclick="switchTab('ledger')">📑 Audit Ledger</button>
      <button class="tab-btn" onclick="switchTab('users')">👥 User Profiles</button>
      <button class="tab-btn" onclick="switchTab('config')">⚙️ Rules Config</button>
    </nav>

    <div class="header-actions">
      <button class="btn btn-primary" onclick="runDemoScenario(false)">
        ▶ Run Demo Scenario
      </button>
      <button class="btn btn-danger" onclick="clearAllData()">
        🗑️ Clear Data
      </button>
    </div>
  </header>

  <!-- Main Area -->
  <main>

    <!-- KPI Metrics Strip -->
    <div class="kpi-grid">
      <div class="kpi-card blue">
        <div class="kpi-label">Total Evaluated</div>
        <div class="kpi-value font-mono" id="kpi-total">0</div>
        <div class="kpi-sub" id="kpi-volume">Processed: ₹0.00</div>
      </div>
      <div class="kpi-card green">
        <div class="kpi-label">Approved (Allow)</div>
        <div class="kpi-value font-mono" id="kpi-allow">0</div>
        <div class="kpi-sub" id="kpi-allow-pct">0.0% of total</div>
      </div>
      <div class="kpi-card yellow">
        <div class="kpi-label">Requires Review</div>
        <div class="kpi-value font-mono" id="kpi-review">0</div>
        <div class="kpi-sub" id="kpi-review-pct">0.0% of total</div>
      </div>
      <div class="kpi-card red">
        <div class="kpi-label">Blocked Attacks</div>
        <div class="kpi-value font-mono" id="kpi-block">0</div>
        <div class="kpi-sub" id="kpi-blocked-vol">Prevented: ₹0.00</div>
      </div>
    </div>

    <!-- TAB 1: DASHBOARD -->
    <div id="tab-dashboard" class="tab-content active">
      <div class="grid-2col">
        <!-- Left: Rule Trigger Frequency -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">🎯 Rule Trigger Distribution</div>
            <span style="font-size: 0.75rem; color: var(--text-dim);" id="stat-flagged-count">0 flagged</span>
          </div>
          <div class="panel-body" id="rules-chart-container">
            <p style="color: var(--text-dim); font-size: 0.85rem;">No rules fired yet.</p>
          </div>
        </div>

        <!-- Right: Recent Activity Stream -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">⚡ Recent Transaction Stream</div>
            <button class="btn" style="font-size: 0.75rem; padding: 0.25rem 0.6rem;" onclick="loadData()">↻ Refresh</button>
          </div>
          <div class="table-container">
            <table id="recent-table">
              <thead>
                <tr>
                  <th>Txn ID</th>
                  <th>Sender</th>
                  <th>Amount</th>
                  <th>City</th>
                  <th>Score</th>
                  <th>Decision</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="recent-tbody">
                <tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No transactions yet. Click 'Run Demo Scenario' above.</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 2: EVALUATE NEW TRANSACTION -->
    <div id="tab-evaluate" class="tab-content">
      <div class="grid-2col">
        <!-- Left Form -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">💳 Evaluate Single UPI Payment</div>
          </div>
          <div class="panel-body">
            <form id="eval-form" onsubmit="handleFormSubmit(event)">
              <div class="form-group">
                <label class="form-label">Transaction ID (Optional)</label>
                <input type="text" id="inp-id" class="form-input" placeholder="Leave empty for auto-generation">
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">Sender UPI ID *</label>
                  <input type="text" id="inp-sender" class="form-input" placeholder="e.g. rohit@okhdfcbank" required>
                </div>
                <div class="form-group">
                  <label class="form-label">Receiver UPI ID *</label>
                  <input type="text" id="inp-receiver" class="form-input" placeholder="e.g. merchant@paytm" required>
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">Amount (INR ₹) *</label>
                  <input type="number" step="0.01" min="1" id="inp-amount" class="form-input" placeholder="1500.00" required>
                </div>
                <div class="form-group">
                  <label class="form-label">City *</label>
                  <input type="text" id="inp-city" class="form-input" placeholder="Mumbai" value="Mumbai" required>
                </div>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label class="form-label">Device ID</label>
                  <input type="text" id="inp-device" class="form-input" placeholder="DEV_PIXEL_8" value="DEV_PIXEL_8">
                </div>
                <div class="form-group">
                  <label class="form-label">Timestamp</label>
                  <input type="text" id="inp-time" class="form-input" placeholder="YYYY-MM-DD HH:MM:SS (blank = now)">
                </div>
              </div>

              <button type="submit" class="btn btn-primary" style="width: 100%; justify-content: center; padding: 0.75rem; margin-top: 0.5rem;">
                🛡️ Run Multi-Rule Fraud Assessment
              </button>
            </form>
          </div>
        </div>

        <!-- Right Result Output -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title">📑 Assessment Outcome & Explanation</div>
            <span id="eval-decision-badge"></span>
          </div>
          <div class="panel-body">
            <div id="eval-empty-placeholder" style="text-align: center; padding: 3rem 1rem; color: var(--text-dim);">
              <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🎯</div>
              <p>Enter payment details and click <strong>Run Multi-Rule Fraud Assessment</strong> to view real-time score and triggered rules.</p>
            </div>

            <div id="eval-result-card" style="display: none;">
              <div style="display: flex; justify-content: space-between; align-items: baseline;">
                <div>
                  <h3 id="res-id" class="font-mono" style="font-size: 1.1rem; color: var(--primary);">TXN-1001</h3>
                  <div id="res-route" style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.2rem;"></div>
                </div>
                <div style="text-align: right;">
                  <div id="res-amount" class="font-mono" style="font-size: 1.4rem; font-weight: 800;">₹0.00</div>
                  <div id="res-meta" style="font-size: 0.75rem; color: var(--text-dim);"></div>
                </div>
              </div>

              <!-- Risk Score Meter -->
              <div class="gauge-wrapper">
                <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 0.4rem;">
                  <span style="font-weight: 600;">Composite Risk Score</span>
                  <span id="res-score-text" class="font-mono" style="font-weight: 700;">0.0 / 100.0</span>
                </div>
                <div class="gauge-bar-bg">
                  <div id="res-gauge-fill" class="gauge-fill"></div>
                </div>
                <div class="gauge-markers">
                  <span>0 (Safe)</span>
                  <span style="color: var(--warning);">30 (Review Cutoff)</span>
                  <span style="color: var(--danger);">60 (Block Cutoff)</span>
                  <span>100</span>
                </div>
              </div>

              <!-- Triggered Rules List -->
              <div style="margin-top: 1.25rem;">
                <div style="font-size: 0.85rem; font-weight: 700; margin-bottom: 0.6rem;" id="res-rules-heading">
                  Rules Triggered
                </div>
                <div id="res-rules-list"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- TAB 3: AUDIT LEDGER -->
    <div id="tab-ledger" class="tab-content">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">📑 Complete UPI Transaction Audit Ledger</div>
          <div style="display: flex; gap: 0.5rem;">
            <input type="text" id="ledger-search" class="form-input" style="width: 250px; font-size: 0.8rem; padding: 0.35rem 0.75rem;" placeholder="Filter by ID, User, City..." oninput="filterLedger()">
            <select id="ledger-filter-decision" class="form-input" style="width: 140px; font-size: 0.8rem; padding: 0.35rem 0.5rem;" onchange="filterLedger()">
              <option value="ALL">All Decisions</option>
              <option value="ALLOW">Allow Only</option>
              <option value="REVIEW">Review Only</option>
              <option value="BLOCK">Block Only</option>
              <option value="FA">False Alarms</option>
            </select>
          </div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Txn ID</th>
                <th>Sender UPI</th>
                <th>Receiver UPI</th>
                <th>Amount</th>
                <th>Timestamp</th>
                <th>Location</th>
                <th>Device</th>
                <th>Risk Score</th>
                <th>Decision</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="ledger-tbody">
              <tr><td colspan="10" style="text-align: center; color: var(--text-dim);">No transactions in ledger.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 4: USER PROFILES -->
    <div id="tab-users" class="tab-content">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">👥 User Risk Profiles & Flagged Counts</div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>User UPI Handle</th>
                <th>Total Volume</th>
                <th>Txn Count</th>
                <th>Avg Amount</th>
                <th>Flagged Txns</th>
                <th>Risk Classification</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody id="users-tbody">
              <tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No user profiles recorded yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 5: RULES CONFIG -->
    <div id="tab-config" class="tab-content">
      <div class="panel" style="max-width: 800px; margin: 0 auto;">
        <div class="panel-header">
          <div class="panel-title">⚙️ Single Centralized Configuration (CONFIG)</div>
          <button class="btn" onclick="resetConfigDefaults()">↺ Factory Defaults</button>
        </div>
        <div class="panel-body">
          <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1.5rem;">
            Adjust weights, cutoffs, and behavioral thresholds live. Changes are applied instantly to all subsequent transaction evaluations.
          </p>

          <form id="config-form" onsubmit="handleConfigSave(event)">
            <h4 style="font-size: 0.9rem; color: var(--primary); margin-bottom: 0.75rem;">1. Score Decision Thresholds</h4>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Review Cutoff (0-100)</label>
                <input type="number" id="cfg-thresh-review" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">Block Cutoff (0-100)</label>
                <input type="number" id="cfg-thresh-block" class="form-input" required>
              </div>
            </div>

            <h4 style="font-size: 0.9rem; color: var(--primary); margin: 1.25rem 0 0.75rem 0;">2. Core Rule Weights</h4>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Rule 1 (Velocity Burst Weight)</label>
                <input type="number" id="cfg-r1-weight" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">Rule 2 (Amount Anomaly Weight)</label>
                <input type="number" id="cfg-r2-weight" class="form-input" required>
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Rule 3 (New Payee Large Weight)</label>
                <input type="number" id="cfg-r3-weight" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">Rule 6 (Location Jump Weight)</label>
                <input type="number" id="cfg-r6-weight" class="form-input" required>
              </div>
            </div>

            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Rule 7 (Repeat Payee Weight)</label>
                <input type="number" id="cfg-r7-weight" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">Rule 8 (Daily Limit Weight)</label>
                <input type="number" id="cfg-r8-weight" class="form-input" required>
              </div>
            </div>

            <h4 style="font-size: 0.9rem; color: var(--primary); margin: 1.25rem 0 0.75rem 0;">3. Operational Thresholds</h4>
            <div class="form-row">
              <div class="form-group">
                <label class="form-label">Amount Anomaly Multiplier (x)</label>
                <input type="number" step="0.5" id="cfg-anomaly-mult" class="form-input" required>
              </div>
              <div class="form-group">
                <label class="form-label">Daily UPI Ceiling (₹)</label>
                <input type="number" id="cfg-daily-limit" class="form-input" required>
              </div>
            </div>

            <button type="submit" class="btn btn-primary" style="margin-top: 1rem; width: 100%; justify-content: center;">
              💾 Save Configuration Settings
            </button>
          </form>
        </div>
      </div>
    </div>

  </main>

  <!-- False Alarm Modal -->
  <div id="fa-modal" class="modal-overlay">
    <div class="modal-card">
      <div class="panel-header">
        <div class="panel-title">🛡️ Analyst Action: Mark False Alarm</div>
        <button class="btn" style="padding: 0.2rem 0.5rem;" onclick="closeModal()">✕</button>
      </div>
      <div class="panel-body">
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;">
          Transaction <strong id="modal-txn-id" class="font-mono text-primary"></strong> was flagged by automated rules.
          Provide an analyst justification to mark this as a confirmed false alarm.
        </p>
        <div class="form-group">
          <label class="form-label">Audit Notes / Verification Reason *</label>
          <textarea id="modal-notes" class="form-input" rows="3" placeholder="e.g. Verified customer identity via phone OTP; genuine medical emergency transfer."></textarea>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 0.75rem; margin-top: 1.25rem;">
          <button class="btn" onclick="closeModal()">Cancel</button>
          <button class="btn btn-success" onclick="submitFalseAlarm()">Confirm & Resolve Flag</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Toast Notification -->
  <div id="toast"></div>

  <!-- JavaScript Application Logic -->
  <script>
    let allTransactions = [];
    let currentModalTxnId = null;

    function showToast(msg, duration = 3000) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.style.display = 'block';
      setTimeout(() => { toast.style.display = 'none'; }, duration);
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      event?.currentTarget?.classList.add('active');
      const target = document.getElementById('tab-' + tabId);
      if (target) target.classList.add('active');

      if (tabId === 'dashboard' || tabId === 'ledger' || tabId === 'users') {
        loadData();
      } else if (tabId === 'config') {
        loadConfig();
      }
    }

    async function loadData() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();

        // Update KPIs
        document.getElementById('kpi-total').textContent = data.total_txns;
        document.getElementById('kpi-volume').textContent = 'Processed: ₹' + data.total_volume.toLocaleString();
        document.getElementById('kpi-allow').textContent = data.decisions.ALLOW;
        document.getElementById('kpi-allow-pct').textContent = (data.total_txns ? (data.decisions.ALLOW / data.total_txns * 100).toFixed(1) : '0') + '% of total';
        document.getElementById('kpi-review').textContent = data.decisions.REVIEW;
        document.getElementById('kpi-review-pct').textContent = (data.total_txns ? (data.decisions.REVIEW / data.total_txns * 100).toFixed(1) : '0') + '% of total';
        document.getElementById('kpi-block').textContent = data.decisions.BLOCK;
        document.getElementById('kpi-blocked-vol').textContent = 'Prevented: ₹' + data.blocked_volume.toLocaleString();

        document.getElementById('stat-flagged-count').textContent = (data.decisions.REVIEW + data.decisions.BLOCK) + ' flagged';

        // Render Rule triggers chart
        renderRuleFrequencies(data.rule_counts, data.total_txns);

        // Fetch transactions list
        const txRes = await fetch('/api/transactions');
        allTransactions = await txRes.json();

        renderRecentTable(allTransactions);
        renderLedgerTable(allTransactions);
        renderUserProfiles(data.user_profiles);
      } catch (err) {
        console.error('Failed to load data:', err);
      }
    }

    function renderRuleFrequencies(ruleCounts, total) {
      const container = document.getElementById('rules-chart-container');
      container.innerHTML = '';

      const entries = Object.entries(ruleCounts || {});
      if (entries.length === 0) {
        container.innerHTML = '<p style="color: var(--text-dim); font-size: 0.85rem;">No fraud rules triggered yet.</p>';
        return;
      }

      entries.sort((a, b) => b[1] - a[1]);
      entries.forEach(([name, count]) => {
        const pct = total ? (count / total * 100).toFixed(1) : 0;
        const row = document.createElement('div');
        row.style.marginBottom = '0.75rem';
        row.innerHTML = `
          <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.25rem;">
            <span>${name}</span>
            <span class="font-mono" style="color: var(--text-dim);">${count}x (${pct}%)</span>
          </div>
          <div style="background: #1f2937; height: 6px; border-radius: 3px; overflow: hidden;">
            <div style="width: ${Math.min(pct * 2.5, 100)}%; background: #3b82f6; height: 100%; border-radius: 3px;"></div>
          </div>
        `;
        container.appendChild(row);
      });
    }

    function renderRecentTable(transactions) {
      const tbody = document.getElementById('recent-tbody');
      tbody.innerHTML = '';

      if (!transactions || transactions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No transactions yet. Click Run Demo Scenario above.</td></tr>';
        return;
      }

      const recent = [...transactions].reverse().slice(0, 8);
      recent.forEach(t => {
        const tr = document.createElement('tr');
        const badgeClass = t.decision === 'ALLOW' ? 'badge-allow' : (t.decision === 'REVIEW' ? 'badge-review' : 'badge-block');
        const isFA = t.is_false_alarm;

        tr.innerHTML = `
          <td class="font-mono" style="font-weight: 600; color: var(--primary);">${t.transaction_id}</td>
          <td>${t.sender_upi}</td>
          <td class="font-mono">₹${t.amount.toLocaleString()}</td>
          <td>${t.city}</td>
          <td class="font-mono">${t.risk_score.toFixed(1)}</td>
          <td>
            <span class="badge ${badgeClass}">${t.decision}</span>
            ${isFA ? '<span class="badge badge-fa" style="margin-left: 0.25rem;">FA</span>' : ''}
          </td>
          <td>
            <button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="viewTxnDetails('${t.transaction_id}')">Inspect</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function renderLedgerTable(transactions) {
      const tbody = document.getElementById('ledger-tbody');
      tbody.innerHTML = '';

      if (!transactions || transactions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: var(--text-dim);">No transactions recorded.</td></tr>';
        return;
      }

      transactions.forEach(t => {
        const tr = document.createElement('tr');
        const badgeClass = t.decision === 'ALLOW' ? 'badge-allow' : (t.decision === 'REVIEW' ? 'badge-review' : 'badge-block');

        tr.innerHTML = `
          <td class="font-mono" style="font-weight: 600; color: var(--primary);">${t.transaction_id}</td>
          <td>${t.sender_upi}</td>
          <td>${t.receiver_upi}</td>
          <td class="font-mono">₹${t.amount.toLocaleString()}</td>
          <td class="font-mono" style="color: var(--text-dim); font-size: 0.8rem;">${t.timestamp}</td>
          <td>${t.city}</td>
          <td style="color: var(--text-dim); font-size: 0.8rem;">${t.device_id}</td>
          <td class="font-mono">${t.risk_score.toFixed(1)}</td>
          <td>
            <span class="badge ${badgeClass}">${t.decision}</span>
            ${t.is_false_alarm ? '<span class="badge badge-fa" title="' + (t.analyst_notes || '') + '">FA</span>' : ''}
          </td>
          <td>
            ${t.decision !== 'ALLOW' ?
              (t.is_false_alarm ?
                `<button class="btn btn-danger" style="padding: 0.2rem 0.45rem; font-size: 0.75rem;" onclick="toggleFalseAlarm('${t.transaction_id}', false)">Unmark</button>` :
                `<button class="btn btn-success" style="padding: 0.2rem 0.45rem; font-size: 0.75rem;" onclick="openFalseAlarmModal('${t.transaction_id}')">Mark FA</button>`
              ) :
              '<span style="color: var(--text-dim); font-size: 0.75rem;">—</span>'
            }
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterLedger() {
      const query = document.getElementById('ledger-search').value.toLowerCase();
      const dec = document.getElementById('ledger-filter-decision').value;

      const filtered = allTransactions.filter(t => {
        const matchText = (t.transaction_id + ' ' + t.sender_upi + ' ' + t.receiver_upi + ' ' + t.city).toLowerCase().includes(query);
        let matchDec = true;
        if (dec === 'FA') matchDec = t.is_false_alarm;
        else if (dec !== 'ALL') matchDec = (t.decision === dec);
        return matchText && matchDec;
      });

      renderLedgerTable(filtered);
    }

    function renderUserProfiles(profiles) {
      const tbody = document.getElementById('users-tbody');
      tbody.innerHTML = '';

      if (!profiles || profiles.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No user profiles.</td></tr>';
        return;
      }

      profiles.forEach(u => {
        const tr = document.createElement('tr');
        const badge = u.risk_level === 'HIGH' ?
          '<span class="badge badge-block">HIGH RISK</span>' :
          (u.risk_level === 'MODERATE' ? '<span class="badge badge-review">MODERATE</span>' : '<span class="badge badge-allow">LOW RISK</span>');

        tr.innerHTML = `
          <td style="font-weight: 600;">${u.upi_id}</td>
          <td class="font-mono">₹${u.total_volume.toLocaleString()}</td>
          <td class="font-mono">${u.tx_count}</td>
          <td class="font-mono">₹${u.avg_amount.toLocaleString()}</td>
          <td class="font-mono" style="font-weight: 700; color: ${u.flagged_count > 0 ? '#f87171' : 'inherit'};">${u.flagged_count}</td>
          <td>${badge}</td>
          <td>
            <button class="btn" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="filterUserLedger('${u.upi_id}')">Ledger</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function filterUserLedger(userUpi) {
      switchTab('ledger');
      document.getElementById('ledger-search').value = userUpi;
      filterLedger();
    }

    async function handleFormSubmit(e) {
      e.preventDefault();
      const payload = {
        transaction_id: document.getElementById('inp-id').value.trim(),
        sender_upi: document.getElementById('inp-sender').value.trim(),
        receiver_upi: document.getElementById('inp-receiver').value.trim(),
        amount: parseFloat(document.getElementById('inp-amount').value),
        city: document.getElementById('inp-city').value.trim(),
        device_id: document.getElementById('inp-device').value.trim(),
        timestamp: document.getElementById('inp-time').value.trim()
      };

      try {
        const res = await fetch('/api/evaluate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const txn = await res.json();
        if (txn.error) {
          showToast('Error: ' + txn.error);
          return;
        }

        displayEvaluationResult(txn);
        showToast(`Transaction ${txn.transaction_id} evaluated: ${txn.decision}`);
        loadData();
      } catch (err) {
        showToast('Evaluation failed: ' + err);
      }
    }

    function displayEvaluationResult(txn) {
      document.getElementById('eval-empty-placeholder').style.display = 'none';
      document.getElementById('eval-result-card').style.display = 'block';

      document.getElementById('res-id').textContent = txn.transaction_id;
      document.getElementById('res-route').textContent = `${txn.sender_upi} ➔ ${txn.receiver_upi}`;
      document.getElementById('res-amount').textContent = `₹${txn.amount.toLocaleString()}`;
      document.getElementById('res-meta').textContent = `${txn.city} • ${txn.device_id} • ${txn.timestamp}`;

      const badge = document.getElementById('eval-decision-badge');
      const badgeClass = txn.decision === 'ALLOW' ? 'badge-allow' : (txn.decision === 'REVIEW' ? 'badge-review' : 'badge-block');
      badge.className = `badge ${badgeClass}`;
      badge.textContent = txn.decision;

      // Risk score & gauge
      document.getElementById('res-score-text').textContent = `${txn.risk_score.toFixed(1)} / 100.0`;
      const fill = document.getElementById('res-gauge-fill');
      fill.style.width = Math.min(100, Math.max(0, txn.risk_score)) + '%';
      fill.style.background = txn.decision === 'ALLOW' ? '#10b981' : (txn.decision === 'REVIEW' ? '#f59e0b' : '#ef4444');

      // Rules list
      const rulesList = document.getElementById('res-rules-list');
      rulesList.innerHTML = '';
      if (!txn.triggered_rules || txn.triggered_rules.length === 0) {
        rulesList.innerHTML = '<div style="color: var(--success); font-size: 0.85rem; padding: 0.5rem 0;">✓ No fraud rules triggered. Behavioral baseline normal.</div>';
      } else {
        txn.triggered_rules.forEach(r => {
          const item = document.createElement('div');
          item.className = 'rule-item ' + (txn.decision === 'REVIEW' ? 'review' : '');
          item.innerHTML = `
            <div class="rule-title">
              <span>${r.name}</span>
              <span class="font-mono">+${r.weight} pts</span>
            </div>
            <div class="rule-reason">${r.reason}</div>
          `;
          rulesList.appendChild(item);
        });
      }
    }

    function viewTxnDetails(txnId) {
      const txn = allTransactions.find(t => t.transaction_id === txnId);
      if (!txn) return;
      switchTab('evaluate');
      displayEvaluationResult(txn);
    }

    async function runDemoScenario(interactive) {
      showToast('Running 15-Event Demo Scenario...', 4000);
      try {
        const res = await fetch('/api/demo', { method: 'POST' });
        const data = await res.json();
        showToast(`[✓] Demo finished: ${data.evaluated_count} transactions processed!`, 4000);
        loadData();
      } catch (err) {
        showToast('Demo execution failed: ' + err);
      }
    }

    async function clearAllData() {
      if (!confirm('Are you sure you want to clear all transaction records?')) return;
      try {
        await fetch('/api/clear', { method: 'POST' });
        showToast('[✓] All records purged.');
        loadData();
      } catch (err) {
        showToast('Purge failed: ' + err);
      }
    }

    // False Alarm Modal
    function openFalseAlarmModal(txnId) {
      currentModalTxnId = txnId;
      document.getElementById('modal-txn-id').textContent = txnId;
      document.getElementById('modal-notes').value = '';
      document.getElementById('fa-modal').style.display = 'flex';
    }

    function closeModal() {
      document.getElementById('fa-modal').style.display = 'none';
      currentModalTxnId = null;
    }

    async function submitFalseAlarm() {
      if (!currentModalTxnId) return;
      const note = document.getElementById('modal-notes').value.trim() || 'Verified genuine transaction by analyst';
      await toggleFalseAlarm(currentModalTxnId, true, note);
      closeModal();
    }

    async function toggleFalseAlarm(txnId, isFA, notes = '') {
      try {
        const res = await fetch('/api/false-alarm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ transaction_id: txnId, is_false_alarm: isFA, notes: notes })
        });
        const data = await res.json();
        showToast(isFA ? `Txn ${txnId} marked as False Alarm.` : `Txn ${txnId} unflagged.`);
        loadData();
      } catch (err) {
        showToast('Action failed: ' + err);
      }
    }

    // Config Tab
    async function loadConfig() {
      try {
        const res = await fetch('/api/config');
        const cfg = await res.json();

        document.getElementById('cfg-thresh-review').value = cfg.THRESHOLD_REVIEW;
        document.getElementById('cfg-thresh-block').value = cfg.THRESHOLD_BLOCK;
        document.getElementById('cfg-r1-weight').value = cfg.RULE_VELOCITY_BURST_WEIGHT;
        document.getElementById('cfg-r2-weight').value = cfg.RULE_AMOUNT_ANOMALY_WEIGHT;
        document.getElementById('cfg-r3-weight').value = cfg.RULE_NEW_PAYEE_LARGE_WEIGHT;
        document.getElementById('cfg-r6-weight').value = cfg.RULE_LOCATION_JUMP_WEIGHT;
        document.getElementById('cfg-r7-weight').value = cfg.RULE_REPEAT_PAYEE_WEIGHT;
        document.getElementById('cfg-r8-weight').value = cfg.RULE_DAILY_LIMIT_WEIGHT;
        document.getElementById('cfg-anomaly-mult').value = cfg.AMOUNT_ANOMALY_MULTIPLIER;
        document.getElementById('cfg-daily-limit').value = cfg.DAILY_LIMIT_THRESHOLD;
      } catch (err) {
        showToast('Failed to load config: ' + err);
      }
    }

    async function handleConfigSave(e) {
      e.preventDefault();
      const payload = {
        THRESHOLD_REVIEW: parseFloat(document.getElementById('cfg-thresh-review').value),
        THRESHOLD_BLOCK: parseFloat(document.getElementById('cfg-thresh-block').value),
        RULE_VELOCITY_BURST_WEIGHT: parseFloat(document.getElementById('cfg-r1-weight').value),
        RULE_AMOUNT_ANOMALY_WEIGHT: parseFloat(document.getElementById('cfg-r2-weight').value),
        RULE_NEW_PAYEE_LARGE_WEIGHT: parseFloat(document.getElementById('cfg-r3-weight').value),
        RULE_LOCATION_JUMP_WEIGHT: parseFloat(document.getElementById('cfg-r6-weight').value),
        RULE_REPEAT_PAYEE_WEIGHT: parseFloat(document.getElementById('cfg-r7-weight').value),
        RULE_DAILY_LIMIT_WEIGHT: parseFloat(document.getElementById('cfg-r8-weight').value),
        AMOUNT_ANOMALY_MULTIPLIER: parseFloat(document.getElementById('cfg-anomaly-mult').value),
        DAILY_LIMIT_THRESHOLD: parseFloat(document.getElementById('cfg-daily-limit').value),
      };

      try {
        await fetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        showToast('[✓] Configuration settings updated successfully!');
      } catch (err) {
        showToast('Config save failed: ' + err);
      }
    }

    async function resetConfigDefaults() {
      if (!confirm('Reset all rules and weights to factory defaults?')) return;
      try {
        await fetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reset: true })
        });
        showToast('[✓] Config reset to defaults.');
        loadConfig();
      } catch (err) {
        showToast('Reset failed: ' + err);
      }
    }

    // Auto-load upon opening
    window.addEventListener('DOMContentLoaded', loadData);
  </script>
</body>
</html>
"""


class FraudShieldHTTPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler providing REST API and serving the Single Page Dashboard."""

    def log_message(self, format, *args):
        # Quieter server logs
        return

    def send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html_text):
        body = html_text.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)

        if url.path == "/" or url.path == "/index.html":
            self.send_html(HTML_PAGE)

        elif url.path == "/api/transactions":
            txns = [t.to_dict() for t in engine.transactions]
            self.send_json(txns)

        elif url.path == "/api/stats":
            txns = engine.transactions
            total = len(txns)
            allow_cnt = sum(1 for t in txns if t.decision == "ALLOW")
            review_cnt = sum(1 for t in txns if t.decision == "REVIEW")
            block_cnt = sum(1 for t in txns if t.decision == "BLOCK")
            total_vol = sum(t.amount for t in txns)
            blocked_vol = sum(t.amount for t in txns if t.decision == "BLOCK")

            rule_counts = {}
            for t in txns:
                for r in t.triggered_rules:
                    rule_counts[r.name] = rule_counts.get(r.name, 0) + 1

            # User profiles
            user_profiles = []
            users = sorted(list({t.sender_upi for t in txns}))
            for u in users:
                u_txns = [t for t in txns if t.sender_upi == u]
                u_vol = sum(t.amount for t in u_txns)
                u_avg = u_vol / len(u_txns) if u_txns else 0.0
                u_flagged = sum(1 for t in u_txns if t.decision in ("REVIEW", "BLOCK"))
                rate = (u_flagged / len(u_txns) * 100) if u_txns else 0.0
                lvl = "HIGH" if (rate >= 50 or u_flagged >= 3) else ("MODERATE" if u_flagged > 0 else "LOW")
                user_profiles.append({
                    "upi_id": u,
                    "total_volume": round(u_vol, 2),
                    "tx_count": len(u_txns),
                    "avg_amount": round(u_avg, 2),
                    "flagged_count": u_flagged,
                    "risk_level": lvl
                })

            data = {
                "total_txns": total,
                "total_volume": round(total_vol, 2),
                "blocked_volume": round(blocked_vol, 2),
                "decisions": {
                    "ALLOW": allow_cnt,
                    "REVIEW": review_cnt,
                    "BLOCK": block_cnt
                },
                "rule_counts": rule_counts,
                "user_profiles": user_profiles
            }
            self.send_json(data)

        elif url.path == "/api/config":
            self.send_json(CONFIG)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8') if content_len > 0 else "{}"
        payload = json.loads(body) if body else {}

        if url.path == "/api/evaluate":
            # Validate input
            sender_raw = payload.get("sender_upi", "")
            valid, sender = Validator.validate_upi_id(sender_raw, "Sender UPI")
            if not valid:
                self.send_json({"error": sender}, status=400)
                return

            receiver_raw = payload.get("receiver_upi", "")
            valid, receiver = Validator.validate_upi_id(receiver_raw, "Receiver UPI")
            if not valid:
                self.send_json({"error": receiver}, status=400)
                return

            if sender.lower() == receiver.lower():
                self.send_json({"error": "Sender and Receiver cannot be identical UPI IDs."}, status=400)
                return

            valid, amt, err = Validator.validate_amount(payload.get("amount", 0))
            if not valid:
                self.send_json({"error": err}, status=400)
                return

            valid, dt, err = Validator.validate_timestamp(payload.get("timestamp", ""))
            if not valid or dt is None:
                self.send_json({"error": err}, status=400)
                return

            city = (payload.get("city") or "Mumbai").strip().title()
            device = (payload.get("device_id") or "DEV_DEFAULT").strip()

            txn_id = (payload.get("transaction_id") or "").strip().upper()
            if not txn_id:
                txn_id = engine.generate_next_id()
            elif any(t.transaction_id.upper() == txn_id for t in engine.transactions):
                self.send_json({"error": f"Transaction ID '{txn_id}' already exists."}, status=400)
                return

            txn = Transaction(
                transaction_id=txn_id,
                sender_upi=sender,
                receiver_upi=receiver,
                amount=amt,
                timestamp=dt,
                city=city,
                device_id=device
            )

            evaluated = engine.evaluate_transaction(txn, commit=True)
            self.send_json(evaluated.to_dict())

        elif url.path == "/api/demo":
            from fraudshield import run_demo_scenario
            # Run demo without interactive console pauses
            run_demo_scenario(engine, interactive=False, reset_first=True)
            self.send_json({
                "status": "success",
                "evaluated_count": len(engine.transactions)
            })

        elif url.path == "/api/false-alarm":
            txn_id = payload.get("transaction_id", "").strip().upper()
            is_fa = bool(payload.get("is_false_alarm", False))
            notes = payload.get("notes", "")

            found = next((t for t in engine.transactions if t.transaction_id.upper() == txn_id), None)
            if not found:
                self.send_json({"error": "Transaction not found"}, status=404)
                return

            found.is_false_alarm = is_fa
            found.analyst_notes = notes if is_fa else ""
            engine.save_data()
            self.send_json({"status": "success", "transaction": found.to_dict()})

        elif url.path == "/api/clear":
            engine.clear_data()
            self.send_json({"status": "success"})

        elif url.path == "/api/config":
            if payload.get("reset"):
                CONFIG.clear()
                CONFIG.update(DEFAULT_CONFIG)
            else:
                for k, v in payload.items():
                    if k in CONFIG:
                        CONFIG[k] = type(CONFIG[k])(v)
            self.send_json(CONFIG)

        else:
            self.send_response(404)
            self.end_headers()


def run_web_server(port: int = 8000, auto_open: bool = True):
    """Start local web server on port 8000 and open default browser."""
    host = "127.0.0.1"
    server_address = (host, port)

    # Try binding to port; if occupied, search for next available port
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = HTTPServer((host, p), FraudShieldHTTPHandler)
            port = p
            break
        except OSError:
            continue

    if not httpd:
        print(f"{Colors.RED}[!] Could not bind web server to ports {port}-{port+20}.{Colors.RESET}")
        sys.exit(1)

    url = f"http://{host}:{port}"
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║         FRAUDSHIELD WEB APPLICATION & LIVE RISK DASHBOARD        ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╠══════════════════════════════════════════════════════════════════╣{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.GREEN}✓ Server running at:{Colors.RESET} {Colors.BOLD}{url}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.DIM}• Live Transaction Evaluator & Risk Score Meter{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.DIM}• 1-Click Interactive Demo Simulation Runner{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.DIM}• Complete Audit Ledger & False Alarm Resolution{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.DIM}• Dynamic Rule Thresholds & Weights Configuration{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║{Colors.RESET}  {Colors.YELLOW}Press Ctrl+C in this terminal to stop the server.{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")

    if auto_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Stopping FraudShield Web Server.{Colors.RESET}")
        httpd.server_close()


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_web_server(port=port, auto_open=True)
