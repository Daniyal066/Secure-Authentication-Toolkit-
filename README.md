# Secure Authentication Toolkit Using Python

An educational, command-line utility designed to demonstrate secure user registration, password strength auditing, hashing, brute-force lockout, secure password generation, and event logging.

---

## 1. Project Objective

The primary objective of this project is to model a secure user authentication system that prevents common vulnerabilities like:
* Storing plaintext passwords.
* Allowing weak passwords.
* Susceptibility to brute-force credential stuffing.
* Lack of audit trails.

This application is designed as a learning resource for both Python programming fundamentals and basic security principles.

---

## 2. Features

* **User Registration**: Enforces complexity rules, prevents duplicate usernames, hashes passwords using SHA-256, and stores credentials securely.
* **User Login**: Validates hashed credentials against stored values.
* **Password Strength Checker**: Evaluates passwords based on length, letter casing, digits, and special characters. Rates them as Weak, Medium, or Strong.
* **Brute-Force Detection**: Tracks consecutive failed login attempts and locks accounts after 3 consecutive failures.
* **Secure Password Generator**: Leverages the cryptographically secure `secrets` library to create highly random, high-entropy passwords.
* **Audit Logging**: Appends all login, lockout, and registration events to `login_logs.txt` with timestamps.
* **Persistent Storage**: Utilizes structured JSON database (`users.json`) to persist account details, failed login counts, and lockout status.

---

## 3. Folder Structure

```text
SecureAuthenticationToolkit/
│
├── main.py            # Main CLI application source code
├── app.py             # Flask Web Application (REST API backend)
├── users.json         # JSON database storing registered users
├── login_logs.txt     # Audit log tracking login attempts
├── README.md          # Complete project documentation
│
├── templates/
│   └── index.html     # Web UI Layout Structure
│
└── static/
    ├── style.css      # Custom styling sheets (glassmorphism UI)
    └── app.js         # Client-side validation and API communication script
```

---

## 4. Modules Used

* **`hashlib`**: Provides hashing algorithms (like SHA-256) to convert plain-text passwords to secure, irreversible message digests.
* **`json`**: Enables encoding and decoding of user data structures to and from disk.
* **`os`**: Standard interface to verify filesystem paths (e.g., checking if `users.json` exists).
* **`re`**: Regular expression module used to pattern-match password characters.
* **`string`**: Contains pre-defined ASCII character constants (digits, letters, symbols) to construct characters for password generation.
* **`secrets`**: Cryptographically secure pseudo-random number generator (CSPRNG) suitable for managing secrets like passwords and keys.
* **`datetime`**: Generates human-readable timestamps for auditing and logs.
* **`flask`** *(New)*: Lightweight WSGI web application framework used to build our Web GUI and expose authentication APIs.

---

## 5. Installation and Execution

### Prerequisites
* Python 3.6 or higher must be installed on your system.
* Flask package must be installed:
  ```bash
  pip install flask
  ```

### How to Run

#### Option A: Running the Web Interface (Recommended)
1. Run the Flask development server:
   ```bash
   python3 app.py
   ```
2. Open your web browser and go to:
   ```text
   http://127.0.0.1:5000/
   ```

#### Option B: Running the Command-Line Interface
1. Run the CLI tool:
   ```bash
   python3 main.py
   ```


---

## 6. Sample Output

### User Registration
```text
Select an option (1-5): 1

--- User Registration ---
Enter a new username: testuser

Password Requirements:
- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character
Enter a password: WeakPass1!

Password Strength: Strong
 -> Password meets all complexity requirements! Excellent choice.

[+] User 'testuser' registered successfully!
```

### Brute Force Lockout
```text
Select an option (1-5): 2

--- User Login ---
Enter username: testuser
Enter password: WrongPassword1
[!] Invalid username or password.
[i] You have 2 attempts remaining before account lockout.

--- User Login ---
Enter username: testuser
Enter password: WrongPassword2
[!] Invalid username or password.
[i] You have 1 attempts remaining before account lockout.

--- User Login ---
Enter username: testuser
Enter password: WrongPassword3
[!] Invalid username or password.
[!] WARNING: Account 'testuser' is now LOCKED due to 3 failed attempts.
```

---

## 7. Learning Outcomes

By reading, implementing, and running this project, you will understand:
1. **Plaintext Storage Risks**: How hashing prevents attackers from obtaining password lists if a database is breached.
2. **Brute Force Defense**: Why rate-limiting and locking accounts are necessary to restrict automated trial-and-error tools.
3. **Audit Trails**: How log analysis helps incident responders discover intrusion activities.
4. **CSPRNG vs. PRNG**: Why the standard `random` library is unsafe for password generation (predictable seeds), and why `secrets` must be used instead.
5. **JSON Data Format**: How standard structured data helps transfer and persist dictionary states.

---

## 8. Developer Reference: Function Documentation & Code Explanations

Here is a comprehensive breakdown of every function in [main.py](file:///Users/daniyalqureshi/Desktop/cyber/main.py).

---

### Function 1: `load_users()`

* **Purpose**: Reads registered users, hashed passwords, and failed login counts from `users.json`.
* **Inputs**: None
* **Outputs**: `dict` (A mapping of usernames to their registration data).
* **Python Concepts**: File Handling, Exception Handling (`try-except`), and the `json` module.
* **Cybersecurity Concept**: Secure Database State Management. Failing to catch file operations errors could crash the login loop, creating a Denial of Service (DoS) vulnerability.

#### Code Explanation
```python
def load_users():
    try:
        if not os.path.exists(USERS_FILE):
            return {}
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        print("[!] Warning: users.json is corrupted. Starting with an empty user database.")
        return {}
    except Exception as e:
        print(f"[!] Error loading user database: {e}")
        return {}
```
* **Line-by-line**:
  1. `try:` sets up a safety boundary to catch run-time exceptions.
  2. `if not os.path.exists(USERS_FILE):` checks if the database file exists on disk.
  3. `return {}` returns an empty dictionary if the file is missing (e.g., first-time run).
  4. `with open(USERS_FILE, "r") as file:` opens the database in read-only mode using a context manager, which guarantees the file closes even if an error occurs.
  5. `return json.load(file)` parses the JSON string inside the file and converts it into a Python dictionary.
  6. `except json.JSONDecodeError:` catches situations where the file contains invalid JSON data.
  7. `except Exception as e:` catches all other errors (such as OS file system permissions).
* **Why this approach was chosen**: JSON is human-readable, lightweight, and converts natively into Python dictionaries. Using `try-except` blocks ensures the toolkit remains running even if data is corrupted.
* **Alternative Approaches**: Storing credentials in SQLite or a relational database (which is standard for production apps but introduces additional dependencies).
* **Time Complexity**: $O(N)$ where $N$ is the size of the database.
* **Space Complexity**: $O(N)$ to hold the user details in memory.

---

### Function 2: `save_users(users)`

* **Purpose**: Writes the memory-held dictionary representation of users back to `users.json`.
* **Inputs**: `users` (dict)
* **Outputs**: `bool` (Whether the write operation was successful).
* **Python Concepts**: File I/O (`w` write-mode), `json.dump()`, context managers.
* **Cybersecurity Concept**: Data Integrity. Ensures authentication states, such as locked statuses and increments, are stored immediately.

#### Code Explanation
```python
def save_users(users):
    try:
        with open(USERS_FILE, "w") as file:
            json.dump(users, file, indent=4)
        return True
    except Exception as e:
        print(f"[!] Error saving user database: {e}")
        return False
```
* **Line-by-line**:
  1. `try:` begins error handling.
  2. `with open(USERS_FILE, "w") as file:` opens `users.json` in write mode, overwriting any current contents.
  3. `json.dump(users, file, indent=4)` serializes the Python dictionary into a formatted JSON string with an indentation of 4 spaces.
  4. `return True` indicates success.
  5. `except Exception as e:` intercepts OS write/permission blocks.
  6. `return False` returns failure.
* **Why this approach was chosen**: The context manager (`with`) avoids memory leaks and file lock states. The indentation formatting is clean and easy to inspect.
* **Alternative Approaches**: Serialization with `pickle` (unsafe in python because it can run arbitrary code upon loading) or raw comma-separated values (CSV).
* **Time Complexity**: $O(N)$
* **Space Complexity**: $O(N)$

---

### Function 3: `hash_password(password)`

* **Purpose**: Converts a plain text password into an irreversible, fixed-length 64-character SHA-256 hex string.
* **Inputs**: `password` (str)
* **Outputs**: `str` (SHA-256 Hex Digest)
* **Python Concepts**: Encoding strings, usage of built-in `hashlib`.
* **Cybersecurity Concept**: Zero Plaintext Storage. Hashing uses a mathematical one-way function. If the database leaks, an attacker only gets hashes, which cannot be reversed to reveal the passwords.

#### Code Explanation
```python
def hash_password(password):
    password_bytes = password.encode('utf-8')
    hash_obj = hashlib.sha256(password_bytes)
    return hash_obj.hexdigest()
```
* **Line-by-line**:
  1. `password.encode('utf-8')` converts the Unicode string to raw bytes. Cryptographic functions require byte input.
  2. `hashlib.sha256(...)` passes the bytes to the SHA-256 hashing algorithm.
  3. `hash_obj.hexdigest()` converts the output byte digest into a readable hexadecimal format.
* **Why this approach was chosen**: SHA-256 is built into Python's `hashlib` standard library. It is widely supported and has no known hash collision vulnerabilities.
* **Alternative Approaches**:
  * MD5 / SHA-1: Weak, obsolete algorithms prone to collision attacks. Do not use.
  * bcrypt / Argon2: Industry standard because they implement automatic salt generation and are computationally slow, hindering brute force. Since these are external libraries, SHA-256 was used for the assignment scope.
* **Time Complexity**: $O(L)$ where $L$ is the password length (extremely fast).
* **Space Complexity**: $O(1)$ constant workspace.

---

### Function 4: `check_password_strength(password)`

* **Purpose**: Audits a password to see if it meets complex password guidelines.
* **Inputs**: `password` (str)
* **Outputs**: `tuple` (rating string, feedback list)
* **Python Concepts**: List manipulation, regular expression pattern searches.
* **Cybersecurity Concept**: Password Policies. Setting boundaries prevents users from using vulnerable passwords like `123456` or `password`, which are cracked instantly.

#### Code Explanation
```python
def check_password_strength(password):
    reasons = []
    if len(password) < 8:
        reasons.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        reasons.append("Password must contain at least one uppercase letter (A-Z).")
    if not re.search(r"[a-z]", password):
        reasons.append("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"\d", password):
        reasons.append("Password must contain at least one digit (0-9).")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        reasons.append("Password must contain at least one special character (e.g., !, @, #, $, etc.).")
    failed_checks = len(reasons)
    if failed_checks == 0:
        return "Strong", ["Password meets all complexity requirements! Excellent choice."]
    elif failed_checks <= 2:
        return "Medium", reasons
    else:
        return "Weak", reasons
```
* **Line-by-line**:
  1. `reasons = []` creates a list of unmet criteria.
  2. `if len(password) < 8:` checks length.
  3. `re.search(r"[A-Z]", password)` uses regular expression to see if at least one character is in the set A-Z.
  4. Subsequent `re.search` blocks check for lowercase, digits, and special characters.
  5. `failed_checks = len(reasons)` counts the number of failures.
  6. Return branches assign the Weak/Medium/Strong ratings.
* **Why this approach was chosen**: Regular expressions are fast and precise for pattern checking.
* **Alternative Approaches**: Iterating through characters manually and using methods like `.isupper()`, `.islower()`, and `.isdigit()`. Regular expressions are cleaner.
* **Time Complexity**: $O(L)$ where $L$ is the password length.
* **Space Complexity**: $O(1)$ (the reasons list holds a maximum of 5 strings).

---

### Function 5: `generate_secure_password(length)`

* **Purpose**: Generates high-entropy passwords satisfying registration complexity rules.
* **Inputs**: `length` (int)
* **Outputs**: `str` (Secure Password)
* **Python Concepts**: List concatenation, `string` character constants, using `secrets` module.
* **Cybersecurity Concept**: CSPRNG (Cryptographically Secure Pseudo-Random Number Generation). Standard random engines (like standard `random.random()`) are predictable. `secrets` queries OS-level system entropy, preventing password prediction.

#### Code Explanation
```python
def generate_secure_password(length):
    if length < 8:
        length = 8
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    all_characters = upper + lower + digits + special
    password_chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_characters))
    secure_random = secrets.SystemRandom()
    secure_random.shuffle(password_chars)
    return "".join(password_chars)
```
* **Line-by-line**:
  1. Enforces a minimum length of 8.
  2. Sets up distinct groups of characters (uppercase, lowercase, numbers, symbols).
  3. Pre-populates the list with at least one character from each set, guaranteeing the password meets the complexity checker rules.
  4. Fills the remaining characters randomly.
  5. Shuffles the list with a cryptographically secure random device to mask character insertion locations.
* **Why this approach was chosen**: Hardcoded seed values are eliminated. Guaranteed check compliance reduces generation retries.
* **Alternative Approaches**: `random.choice()`. However, `random` relies on the Mersenne Twister algorithm, which can be reverse-engineered once an attacker observes 624 outputs.
* **Time Complexity**: $O(\text{length})$
* **Space Complexity**: $O(\text{length})$

---

### Function 6: `log_attempt(username, status, message)`

* **Purpose**: Appends records of security actions to `login_logs.txt`.
* **Inputs**: `username` (str), `status` (str), `message` (str)
* **Outputs**: None
* **Python Concepts**: File appending (`a` mode), date-time formatting.
* **Cybersecurity Concept**: Auditing and Non-repudiation. Log files track brute force attempts, account creation patterns, and lockouts. This serves as historical evidence for security analysis.

#### Code Explanation
```python
def log_attempt(username, status, message):
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] User: {username} | Status: {status} | Info: {message}\n"
        with open(LOG_FILE, "a") as file:
            file.write(log_entry)
    except Exception as e:
        print(f"[!] Critical Error writing to log file: {e}")
```
* **Line-by-line**:
  1. `datetime.datetime.now().strftime(...)` formats the current date and time.
  2. `with open(LOG_FILE, "a") as file:` opens the log file in append mode. This adds content without overwriting existing data.
  3. `file.write(log_entry)` writes the log line.
* **Why this approach was chosen**: Appending ensures historical events remain safe from replacement.
* **Alternative Approaches**: Writing to system logging pipelines (syslog) or logging frameworks (Python's `logging` module). Standard file appending is clean for small tools.
* **Time Complexity**: $O(1)$ constant time write.
* **Space Complexity**: $O(1)$ constant space.

---

### Function 7: `register_user()`

* **Purpose**: Interactive function managing duplicate prevention, validation, hashing, and state persistence.
* **Inputs**: None
* **Outputs**: None
* **Python Concepts**: CLI interactions, input striping, dictionary manipulation.
* **Cybersecurity Concept**: User Account Integrity, input Sanitization.

#### Code Explanation
```python
def register_user():
    username = input("Enter a new username: ").strip()
    if not username:
        return
    users = load_users()
    if username in users:
        print("[!] Username already exists.")
        return
    # [Prompting password and checking strength...]
    # [If accepted...]
    hashed_pwd = hash_password(password)
    users[username] = {
        "password": hashed_pwd,
        "failed_attempts": 0,
        "locked": False
    }
    save_users(users)
```
* **Line-by-line**:
  1. Takes user registration inputs.
  2. Ensures the username isn't a duplicate.
  3. Audits password complexity.
  4. Stores credentials alongside lockout management metrics (attempts counter, locked status flag).
* **Why this approach was chosen**: Prompts users for information and guides them on requirements step-by-step.
* **Time Complexity**: $O(N)$ due to file loading/saving.
* **Space Complexity**: $O(N)$ for holding user profiles.

---

### Function 8: `login_user()`

* **Purpose**: Coordinates access checks and brute-force mitigations.
* **Inputs**: None
* **Outputs**: None
* **Python Concepts**: Value retrieval, variable increments, dictionary modification.
* **Cybersecurity Concept**: Account Lockout Mechanism. After 3 bad attempts, the account locked flag (`locked`) is set to `True`, stopping attackers.

#### Code Explanation
```python
def login_user():
    username = input("Enter username: ").strip()
    password = input("Enter password: ")
    users = load_users()
    # [... Checks and validations ...]
    if user_data.get("locked", False):
        print("[!] Access Denied: This account has been locked.")
        return
    input_hash = hash_password(password)
    if user_data["password"] == input_hash:
        user_data["failed_attempts"] = 0
        user_data["locked"] = False
        save_users(users)
        # [... Success log ...]
    else:
        failed_count = user_data.get("failed_attempts", 0) + 1
        user_data["failed_attempts"] = failed_count
        if failed_count >= MAX_FAILED_ATTEMPTS:
            user_data["locked"] = True
            # [... Lock log ...]
```
* **Line-by-line**:
  1. Input credentials.
  2. Reads database records.
  3. Aborts login attempts if `locked` is true.
  4. Matches inputs against stored values.
  5. Resets tracking parameters if successful.
  6. Increments attempts if incorrect, locking the account once it hits the threshold.
* **Why this approach was chosen**: Account lockout is the most straightforward defense against brute-force attacks.
* **Time/Space Complexity**: $O(N)$ where $N$ is the number of database records.

---

### Function 9: `check_external_password()`, Function 10: `generate_password_ui()`, & Function 11: `main()`

* **Purpose**: Command line menu system and input parser wrapper methods.
* **Python Concepts**: Try-catch execution loops, string choices.
* **Cybersecurity Concept**: Fail-safe defaults. Program handles exceptions and keeps running instead of crashing.

---

## Future Enhancements
1. **Salting**: Adding unique, random salts to passwords before hashing to protect against Rainbow Table attacks.
2. **Slow Hashing Algorithms**: Using `bcrypt` or `Argon2` to make offline brute-force attacks slow and expensive.
3. **Database Migration**: Moving files to an encrypted database like SQLite SQLCipher.
4. **Lockout Decay**: Unlocking accounts automatically after a specific timeframe (e.g., 15 minutes) using timestamp audits.
