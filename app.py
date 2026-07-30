from flask import Flask, request, jsonify, render_template
import os
import re
import datetime

# Import core functionalities from main.py to leverage existing modular code
from main import (
    load_users, 
    save_users, 
    hash_password, 
    check_password_strength, 
    generate_secure_password, 
    log_attempt,
    USERS_FILE,
    LOG_FILE,
    MAX_FAILED_ATTEMPTS
)

app = Flask(__name__)

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
    Expected JSON input: { "username": "name", "password": "pwd" }
    """
    try:
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        if not username:
            return jsonify({"success": False, "message": "Username cannot be empty."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password cannot be empty."}), 400
            
        users = load_users()
        
        # Check for unique username
        if username in users:
            return jsonify({"success": False, "message": "Username already exists."}), 409
            
        # Check password strength
        strength, feedback = check_password_strength(password)
        if strength == "Weak":
            return jsonify({
                "success": False, 
                "message": "Password rejected: Too weak.",
                "feedback": feedback
            }), 400
            
        # Hash and store user credentials
        hashed_pwd = hash_password(password)
        users[username] = {
            "password": hashed_pwd,
            "failed_attempts": 0,
            "locked": False
        }
        
        if save_users(users):
            log_attempt(username, "Registration", "User registered via Web UI.")
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
    Authenticates a user via API request and manages lockouts.
    Expected JSON input: { "username": "name", "password": "pwd" }
    """
    try:
        data = request.get_json() or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        if not username or not password:
            return jsonify({"success": False, "message": "Username and password are required."}), 400
            
        users = load_users()
        
        if username not in users:
            log_attempt(username, "Failed", "Web login attempt on non-existent account.")
            return jsonify({"success": False, "message": "Invalid username or password."}), 401
            
        user_data = users[username]
        
        # Check if the account is locked
        if user_data.get("locked", False):
            log_attempt(username, "Locked", "Blocked Web login attempt on locked account.")
            return jsonify({
                "success": False, 
                "message": "Access Denied: This account is locked due to multiple failed login attempts."
            }), 403
            
        # Match credentials
        input_hash = hash_password(password)
        if user_data["password"] == input_hash:
            # Clear lockout counter
            user_data["failed_attempts"] = 0
            user_data["locked"] = False
            save_users(users)
            
            log_attempt(username, "Success", "Successful Web login.")
            return jsonify({"success": True, "message": f"Welcome back, {username}!"}), 200
        else:
            # Increment failed attempts
            failed_count = user_data.get("failed_attempts", 0) + 1
            user_data["failed_attempts"] = failed_count
            
            if failed_count >= MAX_FAILED_ATTEMPTS:
                user_data["locked"] = True
                save_users(users)
                log_attempt(username, "Locked", f"Web login: Account locked after {failed_count} failures.")
                return jsonify({
                    "success": False, 
                    "message": "Account locked: Maximum failed login attempts exceeded."
                }), 403
            else:
                save_users(users)
                attempts_left = MAX_FAILED_ATTEMPTS - failed_count
                log_attempt(username, "Failed", f"Web login: Failed attempt {failed_count} of {MAX_FAILED_ATTEMPTS}.")
                return jsonify({
                    "success": False, 
                    "message": f"Invalid username or password. {attempts_left} attempts remaining."
                }), 401
                
    except Exception as e:
        return jsonify({"success": False, "message": f"Server error: {str(e)}"}), 500

@app.route('/api/check-password', methods=['POST'])
def api_check_password():
    """
    Evaluates password strength dynamically.
    Expected JSON input: { "password": "pwd" }
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
    Generates a secure password based on requested length.
    Expected JSON input: { "length": 12 }
    """
    data = request.get_json() or {}
    try:
        length = int(data.get("length", 12))
    except (ValueError, TypeError):
        length = 12
        
    password = generate_secure_password(length)
    return jsonify({
        "password": password,
        "explanation": [
            "Entropy: Leverages mixed character sets (uppercase, lowercase, numbers, and special symbols).",
            "CSPRNG: Leverages Python's cryptographically secure 'secrets' generator.",
            "Randomness: Bypasses standard pseudo-random seed pattern analysis to prevent prediction."
        ]
    })

@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    """
    Reads the login audit logs from text file and parses them into JSON objects.
    """
    try:
        logs = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as file:
                lines = file.readlines()
                # Parse in reverse order so newest logs appear first
                for line in reversed(lines):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Expected format: [TIMESTAMP] User: NAME | Status: STATUS | Info: MESSAGE
                    match = re.match(r"^\[(.*?)\]\s+User:\s+(.*?)\s+\|\s+Status:\s+(.*?)\s+\|\s+Info:\s+(.*)$", line)
                    if match:
                        logs.append({
                            "timestamp": match.group(1),
                            "username": match.group(2),
                            "status": match.group(3),
                            "info": match.group(4)
                        })
                    else:
                        # Fallback for unparsed logs
                        logs.append({
                            "timestamp": "N/A",
                            "username": "N/A",
                            "status": "System",
                            "info": line
                        })
        return jsonify({"success": True, "logs": logs})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve logs: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
