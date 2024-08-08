import re
import hashlib
import time

# Simulated database to store user credentials
user_database = {}

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def analyze_password_strength(password):
    # Define the criteria for a strong password
    length_criteria = len(password) >= 12
    complexity_criteria = bool(re.search(r'[A-Z]', password)) and \
                          bool(re.search(r'[a-z]', password)) and \
                          bool(re.search(r'[0-9]', password)) and \
                          bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    
    # Check for common patterns (e.g., "password123", "qwerty")
    common_patterns = ["password", "123456", "qwerty", "abc123", "letmein"]
    pattern_criteria = not any(pattern in password.lower() for pattern in common_patterns)
    
    # Determine overall strength
    strength = length_criteria and complexity_criteria and pattern_criteria
    return strength, length_criteria, complexity_criteria, pattern_criteria

def password_strength_report(password):
    strength, length, complexity, pattern = analyze_password_strength(password)
    report = {
        "Password": password,
        "Strength": "Strong" if strength else "Weak",
        "Length Criteria": length,
        "Complexity Criteria": complexity,
        "Pattern Criteria": pattern
    }
    return report

def dictionary_attack(password, common_passwords):
    return password in common_passwords

def brute_force_time(password):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*(),.?\":{}|<>"
    attempts = len(charset) ** len(password)
    attack_speed = 1e6  # 1 million attempts per second
    time_to_crack = attempts / attack_speed
    return time_to_crack

def vulnerability_report(password, common_passwords):
    is_in_dictionary = dictionary_attack(password, common_passwords)
    brute_force_estimate = brute_force_time(password)
    
    report = {
        "Password": password,
        "Dictionary Attack": "Vulnerable" if is_in_dictionary else "Not Vulnerable",
        "Estimated Time to Brute Force (seconds)": brute_force_estimate
    }
    return report

def generate_password_security_report(password, common_passwords):
    strength_report = password_strength_report(password)
    vulnerability_report_data = vulnerability_report(password, common_passwords)
    
    recommendations = []
    if not strength_report["Length Criteria"]:
        recommendations.append("Increase the length of your password to at least 12 characters.")
    if not strength_report["Complexity Criteria"]:
        recommendations.append("Include a mix of uppercase letters, lowercase letters, numbers, and special characters.")
    if not strength_report["Pattern Criteria"]:
        recommendations.append("Avoid using common patterns and easily guessable passwords.")
    if vulnerability_report_data["Dictionary Attack"] == "Vulnerable":
        recommendations.append("Choose a password that is not found in common password lists.")
    if vulnerability_report_data["Estimated Time to Brute Force (seconds)"] < 3600:
        recommendations.append("Your password can be cracked in less than an hour with brute force. Consider making it more complex.")

    report = {
        "Password": password,
        "Strength Report": strength_report,
        "Vulnerability Report": vulnerability_report_data,
        "Recommendations": recommendations if recommendations else ["Your password is strong and secure."]
    }
    return report

# Create a new account with username and password
def create_account(username, password, common_passwords):
    if username in user_database:
        return "Username already exists."
    
    password_report = generate_password_security_report(password, common_passwords)
    if password_report["Strength Report"]["Strength"] == "Weak":
        report = "Weak password. Please choose a stronger password.\n"
        report += "Password Strength Details:\n"
        for key, value in password_report["Strength Report"].items():
            if key != "Password":
                report += f"{key}: {'Met' if value else 'Not Met'}\n"
        report += "\nRecommendations:\n"
        for recommendation in password_report["Recommendations"]:
            report += f"- {recommendation}\n"
        return report
    
    hashed_password = hash_password(password)
    user_database[username] = hashed_password
    return "Account created successfully."

# Login with the provided username and password
def login(username, password):
    if username not in user_database:
        return "Invalid username."
    
    hashed_password = hash_password(password)
    if user_database[username] != hashed_password:
        return "Invalid password."
    
    return "Login successful."

# Logout function
def logout():
    return "You have been logged out."

# Main function to manage account creation, login, and logout
def main():
    common_passwords = ["password", "123456", "qwerty", "abc123", "letmein"]  # A small sample, use a larger list in practice

    while True:
        # Account creation phase
        username = input("Enter username to create an account: ")
        password = input("Enter password: ")
        result = create_account(username, password, common_passwords)
        print(result)
        
        if "Account created successfully." in result:
            break  # Exit loop if account creation is successful
    
    while True:
        # Login phase
        username = input("Enter username to login: ")
        password = input("Enter password: ")
        result = login(username, password)
        print(result)
        
        if "Login successful." in result:
            break  # Exit loop if login is successful

    while True:
        # After successful login, provide logout option
        action = input("Enter 'logout' to log out or 'exit' to quit the program: ").strip().lower()
        if action == "logout":
            print(logout())
            break  # Exit loop after logging out
        elif action == "exit":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please enter 'logout' or 'exit'.")

# Run the main function
if __name__ == "__main__":
    main()
