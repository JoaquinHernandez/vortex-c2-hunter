# vortex-c2-hunter

# 📡 Vortex-C2-Hunter: Threat Hunting & C2 Beaconing Radar

A lightweight network threat hunting engine that detects persistent **Command-and-Control (C2) Beaconing**, **DNS Tunneling Exfiltration**, and **Covert Network Channels** using inter-arrival jitter statistics and Shannon entropy analysis.

---

## ✨ Key Capabilities
- **Jitter & Periodic Interval Detection**: Calculates the Coefficient of Variation ($CV = \frac{\sigma}{\mu}$) across connection timestamps to identify automated malware communication loops (e.g., Cobalt Strike, Sliver).
- **DNS Tunneling Radar**: Analyzes subdomain query entropy to expose base64/hex data exfiltration.
- **MITRE ATT&CK Correlation**: Automatically tags identified flows with technique IDs (`T1071.001`, `T1071.004`, `T1571`).
- **Zero Third-Party Dependencies**: Pure Python implementation using built-in mathematical and statistical modules.

---

## 🚀 Quick Start
```bash
python3 vortex_hunter.py
