# 🔐 Advanced Password Analyzer with Breach Detection
**ST4017CMD Introduction to Programming | Individual Coursework**

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/status-Final--Delivery-success.svg)]()
[![Affiliation](https://img.shields.io/badge/University-Coventry%20/%20Softwarica-orange.svg)]()

---

## 📖 Overview
The **Advanced Password Analyzer** is a high-performance, privacy-centric cybersecurity utility designed to audit credential strength. Developed as part of the ST4017CMD module, this tool moves beyond simple length checks to provide:
- **Heuristic Scoring**: A multi-faceted judge of password complexity.
- **Mathematical Entropy**: Shanon-based randomness estimation.
- **Local Breach Detection**: Instant lookup against the 14-million-record `rockyou.txt` dataset.
- **Secure Generation**: Cryptographically strong secret creation.
- **Graphic Overviews**: Visual security pillars and architectural mapping.

### 🛠️ Technologies Used
- **Python 3.x**: Core logic and multithreading.
- **Tkinter**: Graphical User Interface.
- **RegEx**: High-speed string pattern matching.
- **JSON**: Result serialization and reporting.
- **Hashlib**: SHA-1 hashing for breach verification.

![Project Security Pillars Overview](figures/figure0_intro_graphic.svg)
*Figure 0: High-level conceptual overview of the system's security foundations.*

> [!IMPORTANT]
> This application is entirely localized; no data ever leaves your machine. Your privacy is protected by "Security by Design".

---

## 🖼️ System Architecture
The application follows a **Layered Design Pattern**, strictly separating the Tkinter-based presentation from the core Python logic. This ensures high responsiveness even during intensive 133MB file scans.

### ⚙️ Core Algorithm
The application follows a reactive, event-driven logical flow:
1. **START**: Initialize Application and GUI Frame.
2. **LISTEN**: Wait for user keystrokes in the entry field.
3. **PROCESS (Real-time)**:
   - READ current password string.
   - EXECUTE heuristic scoring (RegEx validation).
   - CALCULATE Shannon Entropy bits.
4. **UPDATE**: Refresh the strength label and results dashboard dynamically.
5. **SPAWN (Async)**: On "Check Breach", run background worker thread for `rockyou.txt` search.
6. **EXPORT**: Serialize session history into JSON logs if requested.
7. **STOP**: Terminate process on window closure.

![Architecture Overview](figures/figure1_system_architecture.svg)
*Figure 1: Architectural layering and data flow within the application.*

---

## 🚀 Key Features

### 1. Heuristic Strength Engine
Uses a deterministic approach to score passwords from 0 to 6 based on length, character set diversity, and common pattern blacklisting.
![Algorithm Flow](figures/figure4_strength_algorithm.svg)

### 2. Multi-threaded Breach Detection
Scans the massive `rockyou.txt` wordlist in a background worker thread using O(N) linear search, keeping the GUI responsive.
![Thread Model](figures/figure8_multithreading.svg)

### 3. Entropy Analysis
Calculates the statistical randomness (bits of security) to provide a numeric benchmark for password quality.
![Entropy Logic](figures/figure5_entropy_logic.svg)

---

## 🛠️ Technical Implementation

### Core Scoring Logic
The analyzer evaluates character sets using the Python `re` module for high-performance pattern matching.

```python
# Regex Presence Checks
if re.search(r'[A-Z]', password):
    score += 1 # Award points for uppercase letters
if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
    score += 1 # Award points for special characters
```

### Memory-Efficient Search
Using Python generators and context managers, we handle 14 million records with a near-zero memory footprint.

```python
# Thread-safe Breach Search
def check_thread():
    with open('rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if line.strip() == password:
                is_breached = True; break
    root.after(0, lambda: update_ui(is_breached))
```

### 📑 Function Reference
| Function | Description |
| :--- | :--- |
| `check_password_strength()` | Core scoring engine using RegEx and entropy math. |
| `analyze_password()` | Handles live UI updates and result population. |
| `check_breached()` | Manages threaded lookups in the breach list. |
| `generate_password()` | Creates cryptographically strong secrets. |
| `export_results()` | Serializes session data into a JSON report. |

---

## 📊 Visual Documentation Gallery
The project is supported by a comprehensive suite of 13 professional diagrams:

| Concept | Visualization |
| :--- | :--- |
| **System Interaction** | ![User Flow](figures/figure13_user_flow.svg) |
| **GUI Layout** | ![GUI Structure](figures/figure12_gui_layout.svg) |
| **JSON Data Persistence** | ![JSON Export](figures/figure10_json_structure.svg) |
| **File Handling** | ![File Workflow](figures/figure11_file_handling.svg) |
| **Tech Stack** | ![Tech Stack](figures/figure15_tech_stack.svg) |

---

## 📥 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/[YourGitHub]/password-analyzer.git
   cd password-analyzer
   ```

2. **Setup Dependencies**:
   This project uses standard Python libraries (Tkinter is usually pre-installed).
   ```bash
   # No external pip installs required for core logic
   ```

3. **RockYou Database**:
   Place `rockyou.txt` in the project root to enable full breach detection.

4. **Run the Application**:
   ```bash
   python strength_checker.py
   ```

---

## 📝 Conclusion
This project demonstrates the transition from basic procedural programming to professional-grade cybersecurity tool development. By integrating sophisticated data structures, multithreading, and cryptographic principles, the application meets the highest standards for the ST4017CMD module at Softwarica College.

---
© 2026 | [Your Name] | **Softwarica College of IT & E-Commerce**
