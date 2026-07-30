from flask import Flask, request, jsonify, render_template
import os
import re
import datetime
import string
import secrets

# Import core functionalities from main.py
from main import (
    load_users, 
    save_users, 
    hash_password, 
    check_password_strength, 
    USERS_FILE,
    LOG_FILE,
    MAX_FAILED_ATTEMPTS
)

app = Flask(__name__)

def log_attempt_with_ip(username, status, message, ip):
    """
    Logs login attempts with timestamp, IP address, status, and descriptive message.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] IP: {ip} | User: {username} | Status: {status} | Info: {message}\n"
        with open(LOG_FILE, "a") as file:
            file.write(log_entry)
    except Exception as e:
        print(f"[!] Error writing to log file: {e}")

@app.route('/')
def home():
    """
    Serves the primary web page interface.
    """
    return render_template("index.html")

@app.route('/api/register', methods=['POST'])
def api_register():
    """
    Registers a new user via API request.
    """
    try:
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        ip = request.remote_addr or "127.0.0.1"
        
        if not username:
            return jsonify({"success": False, "message": "Username cannot be empty."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password cannot be empty."}), 400
            
        users = load_users()
        
        if username in users:
            return jsonify({"success": False, "message": "Username already exists."}), 409
            
        strength, feedback = check_password_strength(password)
        if strength == "Weak":
            return jsonify({
                "success": False, 
                "message": "Password rejected: Too weak.",
                "feedback": feedback
            }), 400
            
        hashed_pwd = hash_password(password)
        users[username] = {
            "password": hashed_pwd,
            "failed_attempts": 0,
            "locked": False
        }
        
        if save_users(users):
            log_attempt_with_ip(username, "Registration", "User registered via Web UI.", ip)
            return jsonify({
                "success": True, 
                "message": f"User '{username}' registered successfully!",
                "strength": strength
            }), 201
        else:
            return jsonify({"success": False, "message": "Internal error writing to storage."}), 500
            
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Authenticates a user and manages lockouts with IP tracking.
    """
    try:
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        ip = request.remote_addr or "127.0.0.1"
        
        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required."}), 400
            
        users = load_users()
        
        if username not in users:
            log_attempt_with_ip(username, "Failed", "Web login attempt on non-existent account.", ip)
            return jsonify({"success": False, "message": "Invalid username or password."}), 401
            
        user_data = users[username]
        
        if user_data.get("locked", False):
            log_attempt_with_ip(username, "Locked", "Blocked Web login attempt on locked account.", ip)
            return jsonify({
                "success": False, 
                "message": "Access Denied: This account is locked due to multiple failed login attempts."
            }), 403
            
        input_hash = hash_password(password)
        if user_data["password"] == input_hash:
            user_data["failed_attempts"] = 0
            user_data["locked"] = False
            save_users(users)
            
            log_attempt_with_ip(username, "Success", "Successful Web login.", ip)
            return jsonify({"success": True, "message": f"Welcome back, {username}!"}), 200
        else:
            failed_count = user_data.get("failed_attempts", 0) + 1
            user_data["failed_attempts"] = failed_count
            
            if failed_count >= MAX_FAILED_ATTEMPTS:
                user_data["locked"] = True
                save_users(users)
                log_attempt_with_ip(username, "Locked", f"Web login: Account locked after {failed_count} failures.", ip)
                return jsonify({
                    "success": False, 
                    "message": "Account locked: Maximum failed login attempts exceeded."
                }), 403
            else:
                save_users(users)
                attempts_left = MAX_FAILED_ATTEMPTS - failed_count
                log_attempt_with_ip(username, "Failed", f"Web login: Failed attempt {failed_count} of {MAX_FAILED_ATTEMPTS}.", ip)
                return jsonify({
                    "success": False, 
                    "message": f"Invalid username or password. {attempts_left} attempts remaining."
                }), 401
                
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    """
    Evaluates password strength.
    """
    data = request.get_json() or {}
    password = data.get("password", "")
    strength, feedback = check_password_strength(password)
    return jsonify({
        "strength": strength,
        "feedback": feedback
    })

@app.route('/api/generate-password', methods=['POST'])
def api_generate_password():
    """
    Generates a secure password based on requested length and criteria (Module 3).
    """
    data = request.get_json() or {}
    try:
        length = int(data.get("length", 12))
    except (ValueError, TypeError):
        length = 12
        
    if length < 8:
        length = 8
        
    include_upper = data.get("uppercase", True)
    include_lower = data.get("lowercase", True)
    include_digits = data.get("digits", True)
    include_special = data.get("special", True)
    
    # If nothing is selected, default to all sets to prevent errors
    if not (include_upper or include_lower or include_digits or include_special):
        include_upper = include_lower = include_digits = include_special = True
        
    # Build character pools
    upper_pool = string.ascii_uppercase if include_upper else ""
    lower_pool = string.ascii_lowercase if include_lower else ""
    digits_pool = string.digits if include_digits else ""
    special_pool = "!@#$%^&*()-_=+[]{}|;:,.<>?" if include_special else ""
    
    combined_pool = upper_pool + lower_pool + digits_pool + special_pool
    
    password_chars = []
    
    # Ensure one character of each selected type is included first
    if include_upper:
        password_chars.append(secrets.choice(upper_pool))
    if include_lower:
        password_chars.append(secrets.choice(lower_pool))
    if include_digits:
        password_chars.append(secrets.choice(digits_pool))
    if include_special:
        password_chars.append(secrets.choice(special_pool))
        
    # Fill remaining characters
    remaining = length - len(password_chars)
    for _ in range(remaining):
        password_chars.append(secrets.choice(combined_pool))
        
    # Securely shuffle
    secure_random = secrets.SystemRandom()
    secure_random.shuffle(password_chars)
    password = "".join(password_chars)
    
    # Explain details
    explanation = []
    if include_upper:
        explanation.append("Includes uppercase letters (A-Z) to increase search space.")
    if include_lower:
        explanation.append("Includes lowercase letters (a-z) to disrupt single-case dictionary guessing.")
    if include_digits:
        explanation.append("Includes numerical digits (0-9) to defend against alphabetical-only attacks.")
    if include_special:
        explanation.append("Includes special characters to significantly expand complexity and entropy.")
        
    explanation.append("Generated using Python's cryptographically secure 'secrets' module.")
    
    return jsonify({
        "password": password,
        "explanation": explanation
    })

@app.route('/api/analyze-logs', methods=['POST'])
def api_analyze_logs():
    """
    Ingests and processes raw logs to detect:
    1. Brute force attacks grouped by IP (Module 4)
    2. Password guessing attacks grouped by Username (Module 5)
    """
    try:
        data = request.get_json() or {}
        raw_logs = data.get("logs", "")
        
        # Split log string into individual lines
        lines = [line.strip() for line in raw_logs.split("\n") if line.strip()]
        
        ip_failures = {}        # Tracks failed attempts per IP: { ip: count }
        user_failures = {}      # Tracks failed passwords per user: { username: set(passwords) }
        
        total_logs_processed = 0
        
        for line in lines:
            # Format option 1: standard CSV logs -> timestamp,ip,username,password,status
            # Format option 2: system log line -> [TIMESTAMP] IP: ip | User: username | Status: status | Info: msg
            
            ip = None
            username = None
            status = None
            password_used = "N/A"
            
            # Try to match the system log line format
            system_match = re.match(
                r"^\[.*?\]\s+IP:\s+(.*?)\s+\|\s+User:\s+(.*?)\s+\|\s+Status:\s+(.*?)\s+\|\s+Info:\s+(.*)$", 
                line
            )
            
            if system_match:
                ip = system_match.group(1).strip()
                username = system_match.group(2).strip()
                status = system_match.group(3).strip().lower()
                info = system_match.group(4).strip()
                # Check if password was written in the info message during logs simulation
                pwd_match = re.search(r"password attempted:\s*(.+)$", info, re.IGNORECASE)
                if pwd_match:
                    password_used = pwd_match.group(1)
            else:
                # Fallback to simple comma-separated entries: ip,username,password,status
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:
                    ip = parts[0]
                    username = parts[1]
                    password_used = parts[2]
                    status = parts[3].lower()
                    
            if ip and username and status:
                total_logs_processed += 1
                
                # Check for failed status (failed or locked)
                is_failed = "fail" in status or "lock" in status
                
                if is_failed:
                    # Module 4: Brute force by IP tracking
                    ip_failures[ip] = ip_failures.get(ip, 0) + 1
                    
                    # Module 5: Password guessing by Username tracking
                    if username not in user_failures:
                        user_failures[username] = set()
                    # Add password to calculate unique passwords tried
                    user_failures[username].add(password_used)

        # Detect Brute Force IPs (failures >= 3)
        brute_force_alerts = []
        for ip, count in ip_failures.items():
            if count >= 3:
                brute_force_alerts.append({
                    "ip": ip,
                    "failed_attempts": count,
                    "severity": "CRITICAL" if count >= 5 else "HIGH",
                    "explanation": f"IP address {ip} generated {count} consecutive authentication failures. This indicates an automated credential-stuffing script."
                })
                
        # Detect Password Guessing Usernames (multiple distinct passwords attempted)
        password_guessing_alerts = []
        for user, pwd_set in user_failures.items():
            count_distinct_pwd = len(pwd_set)
            if count_distinct_pwd >= 2:
                password_guessing_alerts.append({
                    "username": user,
                    "unique_passwords_attempted": count_distinct_pwd,
                    "passwords": list(pwd_set),
                    "severity": "HIGH",
                    "explanation": f"Account '{user}' was targeted with {count_distinct_pwd} different password attempts. This shows targeted dictionary password guessing."
                })

        return jsonify({
            "success": True,
            "total_processed": total_logs_processed,
            "brute_force_alerts": brute_force_alerts,
            "password_guessing_alerts": password_guessing_alerts
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Analysis failed: {str(e)}"}), 500

@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    """
    Reads and parses logs from file. Supports the updated IP structure.
    """
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as file:
                lines = file.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    system_match = re.match(
                        r"^\[(.*?)\]\s+IP:\s+(.*?)\s+\|\s+User:\s+(.*?)\s+\|\s+Status:\s+(.*?)\s+\|\s+Info:\s+(.*)$", 
                        line
                    )
                    if system_match:
                        logs.append({
                            "timestamp": system_match.group(1),
                            "ip": system_match.group(2),
                            "username": system_match.group(3),
                            "status": system_match.group(4),
                            "info": system_match.group(5)
                        })
                    else:
                        # Legacy fallback
                        legacy_match = re.match(r"^\[(.*?)\]\s+User:\s+(.*?)\s+\|\s+Status:\s+(.*?)\s+\|\s+Info:\s+(.*)$", line)
                        if legacy_match:
                            logs.append({
                                "timestamp": legacy_match.group(1),
                                "ip": "N/A",
                                "username": legacy_match.group(2),
                                "status": legacy_match.group(3),
                                "info": legacy_match.group(4)
                            })
                        else:
                            logs.append({
                                "timestamp": "N/A",
                                "ip": "N/A",
                                "username": "N/A",
                                "status": "System",
                                "info": line
                            })
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve logs: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
