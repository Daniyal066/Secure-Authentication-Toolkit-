import hashlib
import json
import os
import re
import string
import secrets  # We will use secrets for secure generation, and random for demo
import datetime

# Configuration file paths
USERS_FILE = "users.json"
LOG_FILE = "login_logs.txt"
MAX_FAILED_ATTEMPTS = 3

def load_users():
    """
    Loads users from the JSON database file.
    
    Inputs: None
    Outputs: dict - Dictionary of registered users and their details.
    Python Concepts: File Handling, JSON Module, Exception Handling, Dictionaries.
    Cybersecurity Concepts: Data Persistence, Secure Storage Configuration.
    """
    try:
        if not os.path.exists(USERS_FILE):
            # If the file does not exist, return an empty dictionary
            return {}
        with open(USERS_FILE, "r") as file:
            return json.load(file)
    except json.JSONDecodeError:
        # Handles corrupted JSON file structure
        print("[!] Warning: users.json is corrupted. Starting with an empty user database.")
        return {}
    except Exception as e:
        print(f"[!] Error loading user database: {e}")
        return {}

def save_users(users):
    """
    Saves the user dictionary to the JSON database file.
    
    Inputs: users (dict) - Dictionary containing user credentials and status.
    Outputs: bool - True if save succeeded, False otherwise.
    Python Concepts: File Handling, JSON Module, Exception Handling.
    Cybersecurity Concepts: Secure State Preservation.
    """
    try:
        with open(USERS_FILE, "w") as file:
            json.dump(users, file, indent=4)
        return True
    except Exception as e:
        print(f"[!] Error saving user database: {e}")
        return False

def hash_password(password):
    """
    Hashes a password using the SHA-256 cryptographic hashing algorithm.
    
    Inputs: password (str) - The plaintext password.
    Outputs: str - The hexadecimal string of the SHA-256 hash.
    Python Concepts: String Encoding, Module Usage (hashlib).
    Cybersecurity Concepts: One-Way Cryptographic Hashing, Protection against Plaintext Exposure.
    """
    # Convert password string to bytes using UTF-8 encoding
    password_bytes = password.encode('utf-8')
    # Generate the SHA-256 hash object
    hash_obj = hashlib.sha256(password_bytes)
    # Return the hex representation of the digest
    return hash_obj.hexdigest()

def check_password_strength(password):
    """
    Evaluates password strength based on standard complexity rules.
    
    Inputs: password (str) - The password to analyze.
    Outputs: tuple (str, list) - The strength rating ('Weak', 'Medium', 'Strong') and reasons.
    Python Concepts: Lists, Regular Expressions (re), Conditional Statements.
    Cybersecurity Concepts: Password Complexity Policies, Defense against Dictionary Attacks.
    """
    reasons = []
    
    # 1. Length constraint
    if len(password) < 8:
        reasons.append("Password must be at least 8 characters long.")
    
    # 2. Uppercase character check
    if not re.search(r"[A-Z]", password):
        reasons.append("Password must contain at least one uppercase letter (A-Z).")
        
    # 3. Lowercase character check
    if not re.search(r"[a-z]", password):
        reasons.append("Password must contain at least one lowercase letter (a-z).")
        
    # 4. Digit check
    if not re.search(r"\d", password):
        reasons.append("Password must contain at least one digit (0-9).")
        
    # 5. Special character check
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        reasons.append("Password must contain at least one special character (e.g., !, @, #, $, etc.).")
    
    # Assess strength based on number of unmet requirements
    failed_checks = len(reasons)
    
    if failed_checks == 0:
        return "Strong", ["Password meets all complexity requirements! Excellent choice."]
    elif failed_checks <= 2:
        return "Medium", reasons
    else:
        return "Weak", reasons

def generate_secure_password(length):
    """
    Generates a cryptographically secure random password of specified length.
    
    Inputs: length (int) - The desired character length of the password.
    Outputs: str - The generated secure random password.
    Python Concepts: Math / Secrets Module, String Constants, Loops.
    Cybersecurity Concepts: Cryptographically Secure Pseudo-Random Number Generation (CSPRNG), Entropy.
    """
    if length < 8:
        print("[!] System recommends a minimum length of 8 characters for basic security.")
        length = 8
        
    # Define character pools
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # To guarantee the password satisfies complexity rules, we start with one of each type
    all_characters = upper + lower + digits + special
    
    password_chars = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    # Fill the remaining length with random selections from the combined pool
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_characters))
        
    # Shuffle the list of characters securely using secrets/SystemRandom to prevent pattern detection
    secure_random = secrets.SystemRandom()
    secure_random.shuffle(password_chars)
    
    return "".join(password_chars)

def log_attempt(username, status, message):
    """
    Logs login attempts with timestamp, status, and descriptive message.
    
    Inputs: 
        username (str) - The username trying to authenticate.
        status (str) - The outcome ('Success', 'Failed', or 'Locked').
        message (str) - Contextual information or errors.
    Outputs: None
    Python Concepts: File Handling (Appending), Datetime formatting.
    Cybersecurity Concepts: Security Auditing, Intrusion Detection, Non-repudiation.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] User: {username} | Status: {status} | Info: {message}\n"
        with open(LOG_FILE, "a") as file:
            file.write(log_entry)
    except Exception as e:
        print(f"[!] Critical Error writing to log file: {e}")

def register_user():
    """
    Registers a new user inside the database after validation checks.
    
    Inputs: None (Interactive CLI inputs inside function)
    Outputs: None
    Python Concepts: Dictionaries, User input/output, Conditional blocks.
    Cybersecurity Concepts: Secure Registration, Zero Plaintext Storage, Input Validation.
    """
    print("\n--- User Registration ---")
    username = input("Enter a new username: ").strip()
    
    if not username:
        print("[!] Username cannot be empty.")
        return
        
    users = load_users()
    
    # Check for unique username
    if username in users:
        print("[!] Username already exists. Please choose a different one.")
        return
        
    print("\nPassword Requirements:")
    print("- Minimum 8 characters")
    print("- At least one uppercase letter (A-Z)")
    print("- At least one lowercase letter (a-z)")
    print("- At least one digit (0-9)")
    print("- At least one special character")
    
    password = input("Enter a password: ")
    
    strength, feedback = check_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    for reason in feedback:
        print(f" -> {reason}")
        
    if strength == "Weak":
        print("[!] Registration rejected: Password is too weak.")
        return
        
    if strength == "Medium":
        confirm = input("[?] Password is Medium strength. Proceed anyway? (yes/no): ").strip().lower()
        if confirm != 'yes' and confirm != 'y':
            print("Registration cancelled.")
            return

    # Hash the password using SHA-256 before storing
    hashed_pwd = hash_password(password)
    
    # Store registration info, including login failure tracking fields
    users[username] = {
        "password": hashed_pwd,
        "failed_attempts": 0,
        "locked": False
    }
    
    if save_users(users):
        print(f"[+] User '{username}' registered successfully!")
        log_attempt(username, "Registration", "User registered successfully.")
    else:
        print("[!] Registration failed due to storage error.")

def login_user():
    """
    Authenticates an existing user and manages lockout states if consecutive failures occur.
    
    Inputs: None (Interactive CLI inputs)
    Outputs: None
    Python Concepts: Flow control, Exception Handling, JSON Data Modification.
    Cybersecurity Concepts: Authentication, Brute-Force Protection, Account Lockout.
    """
    print("\n--- User Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ")
    
    users = load_users()
    
    if username not in users:
        print("[!] Invalid username or password.")
        # Log attempts on non-existent accounts to detect user enumeration attacks
        log_attempt(username, "Failed", "Attempt on non-existent account.")
        return
        
    user_data = users[username]
    
    # Check if the account is locked
    if user_data.get("locked", False):
        print("[!] Access Denied: This account has been locked due to multiple failed login attempts.")
        log_attempt(username, "Locked", "Login attempt blocked on locked account.")
        return
        
    # Hash the user input password and compare with stored hash
    input_hash = hash_password(password)
    
    if user_data["password"] == input_hash:
        # Success: reset failed attempt counter and remove lock
        user_data["failed_attempts"] = 0
        user_data["locked"] = False
        save_users(users)
        
        print(f"[+] Access Granted! Welcome back, {username}.")
        log_attempt(username, "Success", "Successful login.")
    else:
        # Failed login attempt: Increment counter
        failed_count = user_data.get("failed_attempts", 0) + 1
        user_data["failed_attempts"] = failed_count
        
        print("[!] Invalid username or password.")
        
        if failed_count >= MAX_FAILED_ATTEMPTS:
            user_data["locked"] = True
            save_users(users)
            print(f"[!] WARNING: Account '{username}' is now LOCKED due to {MAX_FAILED_ATTEMPTS} failed attempts.")
            log_attempt(username, "Locked", f"Account locked after {failed_count} consecutive failed login attempts.")
        else:
            save_users(users)
            attempts_left = MAX_FAILED_ATTEMPTS - failed_count
            print(f"[i] You have {attempts_left} attempts remaining before account lockout.")
            log_attempt(username, "Failed", f"Failed attempt {failed_count} of {MAX_FAILED_ATTEMPTS}.")

def check_external_password():
    """
    Utility menu option allowing users to test any password's strength without registering.
    
    Inputs: None
    Outputs: None
    Python Concepts: IO functions, checking condition.
    Cybersecurity Concepts: Password auditing.
    """
    print("\n--- Password Strength Check Utility ---")
    password = input("Enter a password to evaluate: ")
    strength, feedback = check_password_strength(password)
    print(f"\nResult: The password is rated as: **{strength}**")
    print("Explanations:")
    for reason in feedback:
        print(f" - {reason}")

def generate_password_ui():
    """
    Interactive UI component for generating secure passwords.
    
    Inputs: None
    Outputs: None
    Python Concepts: Input casting, try-except for input validation.
    Cybersecurity Concepts: Entropy, Secure password distribution.
    """
    print("\n--- Password Generator ---")
    try:
        length_input = input("Enter desired password length (minimum 8, default 12): ").strip()
        if not length_input:
            length = 12
        else:
            length = int(length_input)
            
        if length < 1:
            print("[!] Length must be positive. Defaulting to 12.")
            length = 12
            
        secure_pass = generate_secure_password(length)
        print(f"\n[+] Generated Secure Password: {secure_pass}")
        print("\nWhy is this password secure?")
        print("1. Entropy: It uses characters from four distinct sets (uppercase, lowercase, numbers, special symbols).")
        print("2. Unpredictability: It utilizes Python's 'secrets' module, which hooks directly into system-level entropy.")
        print("3. Randomness: Cryptographically secure random generators protect passwords from being guessed by pattern attacks.")
    except ValueError:
        print("[!] Invalid integer. Defaulting to length 12.")
        secure_pass = generate_secure_password(12)
        print(f"\n[+] Generated Secure Password: {secure_pass}")

def main():
    """
    Main program entry point running the menu loop.
    """
    print("==================================================")
    print("      SECURE AUTHENTICATION TOOLKIT (PYTHON)      ")
    print("==================================================")
    
    while True:
        print("\n--- Main Menu ---")
        print("1. Register User")
        print("2. Login User")
        print("3. Check Password Strength")
        print("4. Generate Secure Password")
        print("5. Exit")
        
        choice = input("\nSelect an option (1-5): ").strip()
        
        try:
            if choice == "1":
                register_user()
            elif choice == "2":
                login_user()
            elif choice == "3":
                check_external_password()
            elif choice == "4":
                generate_password_ui()
            elif choice == "5":
                print("\n[+] Exiting Secure Authentication Toolkit. Stay Safe!")
                break
            else:
                print("[!] Invalid selection. Please choose a number from 1 to 5.")
        except KeyboardInterrupt:
            # Handles Ctrl+C safely without displaying a trace error
            print("\n\n[!] Program interrupted. Exiting safely.")
            break
        except Exception as e:
            # Catch-all safety boundary for unexpected errors
            print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
