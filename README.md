# Python Assignment – Secure Authentication Toolkit

This repository contains the complete implementation for the **Secure Authentication Toolkit** assignment. It features a dual interface: an interactive Python Command-Line Interface (CLI) and a glassmorphic Web Dashboard built with a Python Flask REST API.

---

## 1. Project Objective

The objective of this project is to develop a modular authentication system demonstrating Python fundamentals and cybersecurity defenses. It implements security policies (complexity auditing, hashing, brute-force rate-limiting, and CSPRNG password generation) and analyzes event logs to identify malicious network behaviors (IP brute-forcing and account password-guessing).

---

## 2. Folders and Files

```text
SecureAuthenticationToolkit/
│
├── main.py            # CLI implementation (run via terminal)
├── app.py             # Flask Web Application (REST API backend)
├── users.json         # JSON database storing user profiles (credentials & lock counters)
├── login_logs.txt     # Audit log tracking system logins and registrations
├── README.md          # Complete project manual & assignment report
│
├── templates/
│   └── index.html     # Web dashboard layout
│
└── static/
    ├── style.css      # Custom stylesheet (Glassmorphic dark design)
    └── app.js         # Frontend controllers and async fetch API handlers
```

---

## 3. Assignment Modules Overview

### Module 1: Password Strength Checker (20 Marks)
* **Objective**: Evaluate the strength of a user-entered password against complex security criteria.
* **Requirements**: Matches strings using regular expressions (`re`).
* **Complexity Rules**:
  * Minimum 8 characters.
  * At least one uppercase letter (A-Z).
  * At least one lowercase letter (a-z).
  * At least one numeric digit (0-9).
  * At least one special symbol.
* **Rating**: Weak (fails $\ge 3$ criteria), Medium (fails 1-2 criteria), or Strong (meets all criteria).

### Module 2: Login Lockout Simulator (20 Marks)
* **Objective**: Protect user accounts from credential-stuffing by implementing lockout controls.
* **Requirements**:
  * Allow a maximum of three consecutive failed login attempts.
  * Display remaining attempts upon failure.
  * Lock the account after the third unsuccessful attempt.
  * Block all subsequent auth checks once locked, recording the incident in the audit log.

### Module 3: Secure Password Generator (20 Marks)
* **Objective**: Generate random, secure passwords based on user-selected criteria.
* **Requirements**:
  * Allow customization of character sets: Uppercase letters, Lowercase letters, Numbers, and Special characters.
  * Ensure the output meets all selected guidelines.
  * Utilize cryptographically secure generators (CSPRNG via Python's standard `secrets` module).

### Module 4: Brute Force Attack Detection (20 Marks)
* **Objective**: Parse log streams to flag IP addresses executing brute-force attacks.
* **Detection Logic**:
  * Process log strings line-by-line using regular expressions to capture the client's IP.
  * Count the total failed attempts grouped by IP address.
  * Flag any IP address with 3 or more failed login attempts.
  * Generate a detailed alert detailing the threat vector.

### Module 5: Password Guessing Detection (20 Marks)
* **Objective**: Identify password-guessing attacks targeting specific accounts.
* **Detection Logic**:
  * Track authentication failures by username.
  * Count the number of distinct passwords attempted against each account.
  * Generate a warning when a user is targeted with multiple distinct passwords.

---

## 4. Installation and Execution

### Prerequisites
* Python 3.7 or higher.
* Flask library (required for Web Dashboard):
  ```bash
  pip install flask
  ```

### How to Run

#### Running the Web Dashboard (Recommended)
1. Run the Flask server:
   ```bash
   python3 app.py
   ```
2. Open your web browser and navigate to:
   ```text
   http://127.0.0.1:5000/
   ```

#### Running the Terminal CLI
1. Run the terminal-driven menu script:
   ```bash
   python3 main.py
   ```

---

## 5. Developer Report (Assignment Submission Requirements)

### Technical Analysis of Modules

| Function / Module | Inputs | Outputs | Time Complexity | Space Complexity | Cybersecurity Concept | Python Concept |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`check_password_strength`** (Module 1) | `password` (str) | `tuple(rating, reasons)` | $O(L)$ where $L$ is length | $O(1)$ | Password Complexity Policy | RegEx, String comparison |
| **`hash_password`** | `password` (str) | `str` (SHA-256 Hex) | $O(L)$ | $O(1)$ | One-way hashing (Zero Plaintext) | `hashlib` encoding |
| **`login_user` / `api_login`** (Module 2) | Credentials (user, pwd) | Status/Access state | $O(N)$ where $N$ is users count | $O(N)$ | Account Rate Limiting, Lockouts | JSON modification, Dictionaries |
| **`generate_secure_password`** (Module 3) | Options & `length` | `str` (Generated password) | $O(\text{length})$ | $O(\text{length})$ | CSPRNG, Entropy | `secrets` module, list shuffling |
| **`api_analyze_logs`** (Modules 4 & 5) | Raw log string | JSON Alert report | $O(M)$ where $M$ is log lines | $O(U + I)$ (users & IPs tracked) | Event Log Analysis, SIEM Logic | Dictionary grouping, RegEx |

---

### Detection Logic Implemented

1. **Brute Force by IP (Module 4)**: 
   $$\text{Attempts}_{\text{IP}} = \sum \text{failed attempts}$$
   When a log line matches an auth failure status, the system extracts the IP. If $\text{Attempts}_{\text{IP}} \ge 3$, the IP is marked as highly suspicious.
2. **Password Guessing by Account (Module 5)**:
   $$\text{Distinct Passwords}_{\text{User}} = \text{Count}(\text{Unique Failed Passwords})$$
   If $\text{Distinct Passwords}_{\text{User}} \ge 2$, it is flagged as an account-specific dictionary attack, showing that an attacker is trying multiple credentials to gain unauthorized access to a single account.

---

### Challenges Encountered and Solutions
* **Challenge 1: Safe Password Selection**: During custom password generation, if a user disabled all checkboxes (no uppercase, lowercase, numbers, or symbols), the generator would attempt to choose from an empty character pool, resulting in a crash.
  * *Solution*: Enforced a backend fallback that defaults to activating all character sets if no parameters are selected.
* **Challenge 2: Multi-Format Log Parsing**: Log files format can vary depending on whether they are generated from the CLI (`main.py`) or the Web UI (`app.py`), particularly with the introduction of IP addresses.
  * *Solution*: Created a regular expression parser in `/api/analyze-logs` that detects and processes both system log entries (with IP headers) and standard comma-separated log lines.

---

### Future Improvements
1. **Password Salting**: Incorporate unique, random cryptographic salts per user before hashing. This blocks attacks using precomputed hash tables (Rainbow Tables).
2. **Dynamic Lockout Decay**: Implement a timestamp-based cooldown (e.g. unlock automatically after 15 minutes) instead of permanent locking requiring database updates.
3. **Database Migration**: Migrate local JSON database to SQLCipher or SQLite database for relational queries.
