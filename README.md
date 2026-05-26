---
title: Advanced Cyber Security Scanner
emoji: 🛡️
colorFrom: cyan
colorTo: slate
sdk: docker
app_port: 7860
pinned: false
license: mit
---

# 🛡️ Advanced Cyber Security Scanner Web Hub

This repository contains an asynchronous, multi-threaded automated security assessment engine designed to identify common network weaknesses, evaluate web application exposure metrics, and map discovered security flags directly back to the **OWASP Top 10** and the **CIA Triad** alignment frameworks.

## 🚀 Cloud Platforms Layout Strategy

This single repository workspace folder is built to deploy cleanly to both cloud environments concurrently:
1. **Hugging Face (Frontend Visual Interface):** Driven by custom containers parsing `app.py` via an automated internal Streamlit web architecture router.
2. **Vercel (Backend JSON API Service):** Driven by serverless function configurations mapping asynchronous Flask routes via `api/index.py`.

---

## 📂 Production Code Directory Matrix

Ensure your deployment folder tree looks exactly like this layout before committing changes:

```text
cyber_project/               
│
├── api/                     
│   └── index.py             <-- Vercel endpoint routine bridge script
│
├── vercel.json              <-- Vercel system configuration map
├── requirements.txt         <-- Shared cloud dependencies library checklist
├── Dockerfile               <-- Hugging Face container environment launcher
├── README.md                <-- THIS FILE (Hugging Face metadata card)
├── app.py                   <-- Main interactive Streamlit Web UI dashboard
├── port_scanner.py          <-- Original network scanning engine
├── vulnerability_scanner.py <-- Original HTTP header evaluation engine
├── pentest_module.py        <-- Original SQLi/XSS simulation logic module
├── framework_mapper.py      <-- Original CIA/OWASP data alignment matrix
└── report_generator.py      <-- Original text/JSON formatting architecture
