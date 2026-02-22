# 🔐 Advanced Password Analyzer with Breach Detection

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-Stable-success.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)]()

---

## 📖 Overview
The **Advanced Password Analyzer** is a high-performance, privacy-centric cybersecurity utility designed to audit credential strength. This tool provides a professional-grade evaluation of password security by integrating:
- **Heuristic Scoring**: A multi-faceted evaluation of password complexity.
- **Mathematical Entropy**: Shannon-based randomness estimation.
- **Local Breach Detection**: Instant lookup against the 14-million-record `rockyou.txt` dataset.
- **Secure Generation**: Cryptographically strong secret creation.
- **Asynchronous Processing**: High responsiveness during intensive dataset scans.

> [!IMPORTANT]
> This application is entirely localized; no data ever leaves your machine. Your privacy is protected by "Security by Design".

---

## ⚙️ Core Architecture
The application follow a **Layered Design Pattern**, strictly separating the graphical presentation from the core processing logic. This ensures high responsiveness even during intensive 133MB file scans.

### Execution Flow
1. **Initialize**: Load the environment and GUI frame.
2. **Listen**: Monitor real-time user input.
3. **Analyze**: 
   - Execute heuristic scoring (RegEx validation).
   - Calculate Shannon Entropy bits.
4. **Update**: Refresh the strength metrics and dashboard dynamically.
5. **Breach Check**: Spawn an asynchronous background worker for `rockyou.txt` matching.
6. **Persistence**: Optional JSON serialization for session history.

---

## 🚀 Key Features

### 1. Heuristic Strength Engine
Uses a deterministic approach to score passwords based on length, character set diversity, and common pattern blacklisting.

### 2. Multi-threaded Breach Detection
Scans massive wordlists in a background thread using memory-efficient streaming, keeping the GUI perfectly responsive.

### 3. Entropy Analysis
Calculates statistical randomness (bits of security) to provide a numeric benchmark for password quality.

---

## 🛠️ Technical Implementation

### Core Scoring Logic
The analyzer evaluates character sets using high-performance pattern matching.

```python
# Regex Presence Checks
if re.search(r'[A-Z]', password):
    score += 1 # Award points for uppercase letters
if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
    score += 1 # Award points for special characters
```

### Memory-Efficient Search
Using Python generators and context managers, the tool handles 14 million records with a near-zero memory footprint.

```python
# Thread-safe Breach Search
def check_thread():
    with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip() == password:
                is_breached = True; break
    root.after(0, lambda: update_ui(is_breached))
```

### 📑 API / Function Reference
| Function | Description |
| :--- | :--- |
| `check_password_strength()` | Core scoring engine using RegEx and entropy math. |
| `analyze_password()` | Handles live UI updates and result population. |
| `check_breached()` | Manages threaded lookups in the breach list. |
| `generate_password()` | Creates cryptographically strong secrets. |
| `export_results()` | Serializes session data into a JSON report. |

---

## 📥 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/katwalsaista-dot/programming.git
   cd password-analyzer
   ```

2. **Setup Dependencies**:
   This project uses standard Python libraries. Tkinter is required for the GUI.
   ```bash
   # Standard library only - no external pip installs required
   ```

3. **Breach Database**:
   Place `rockyou.txt` in the project root to enable full breach detection capabilities.

4. **Run the Application**:
   ```bash
   python strength_checker.py
   ```

---

## 📝 Conclusion
The Advanced Password Analyzer represents a transition from basic scripting to professional-grade cybersecurity tool development. By integrating sophisticated data structures, multithreading, and cryptographic principles, the application provides a robust and secure environment for credential auditing.

---
© 2026 | Saista Katwal | Open Source Security Tools
