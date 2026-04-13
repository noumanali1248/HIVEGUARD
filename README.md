<!-- README.md for Hive Guard – Registry Persistence Monitor -->

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge" alt="Version 1.0.0">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Windows-Registry%20Monitoring-red?style=for-the-badge" alt="Windows Registry">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge" alt="Active">
</p>

<h1 align="center">🛡️ Hive Guard</h1>
<h3 align="center">Registry Persistence Monitor for Windows</h3>

<p align="center">
  <strong>Real-time registry monitoring · Persistence detection · Forensic analysis</strong><br>
  <em>Defensive monitoring system for Windows security research</em>
</p>

<p align="center">
  <a href="#-overview">Overview</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-screenshots">Screenshots</a>
</p>

---

## 📌 Overview

**Hive Guard** is a Windows-based security monitoring tool designed to detect and analyze persistence mechanisms used by malware and advanced persistent threats (APTs).

It continuously monitors critical Windows registry hives and startup locations to detect unauthorized modifications in real time.

---

## 🎯 Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Registry Monitoring** | Real-time monitoring of critical Windows registry hives |
| 🧠 **Persistence Detection** | Detects malware persistence techniques |
| 📂 **Startup Tracking** | Monitors startup folder modifications |
| 📊 **Risk Scoring** | Behavior-based risk evaluation system |
| 📝 **Structured Logging** | Forensic-ready logs for investigation |
| 🔔 **Alert System** | Real-time notifications for suspicious changes |
| ⚡ **Lightweight Service** | Runs in background with minimal overhead |

---

## 🏗️ Architecture

```mermaid
flowchart TD

A[Windows System<br/>Registry + Startup Folders] --> B[Monitoring Engine<br/>Python + Win32 APIs]
B --> C[Event Detection Layer<br/>Change Tracking & Correlation]
C --> D[Risk Scoring Engine<br/>MITRE ATT&CK Mapping]
D --> E[Alert System<br/>Logs + Notifications]
E --> F[Analysis Dashboard<br/>Forensics View]
```
## 📸 Screenshots
<img width="975" height="492" alt="image" src="https://github.com/user-attachments/assets/10c9ead9-0ce2-4f74-928d-3d3459e129e2" />

