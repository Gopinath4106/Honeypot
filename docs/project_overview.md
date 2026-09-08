# Project Overview

## Project Title
**Honeypot-Based Attack Monitoring and Security Analysis System**

## Academic Classification
- **Level**: 3rd Year BCA Cyber Security Major Project
- **Focus Areas**: Honeypots, Log Analysis, Incident Monitoring, Rule-Based Threat Classification, Web Application Security.

## Problem Statement
Traditional intrusion detection systems often generate high volumes of noise or rely on opaque machine learning models that are difficult to explain, verify, or validate deterministically in academic evaluations and low-latency environments. Furthermore, analyzing real-time unauthorized probing requires an isolated deceptive mechanism (honeypot) that lures attackers away from critical production assets while systematically recording attack telemetry.

## Proposed Solution
This system provides an end-to-end telemetry pipeline that:
1. Simulates or captures real SSH/Telnet authentication attempts via Cowrie honeypot.
2. Ingests raw JSON logs and sanitizes fields (Source IP, Ports, Protocol, Credentials, Injected Commands).
3. Applies transparent, deterministic classification rules to assign attack categories and severity levels (LOW, MEDIUM, HIGH, CRITICAL).
4. Stores normalized records in an embedded SQLite database.
5. Serves an administrative dashboard with live telemetry indicators, filtering capabilities, and downloadable PDF/CSV audit reports.
