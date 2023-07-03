import re

def check_password_strength(password):
    # Check the length of the password
    if len(password) < 8:
        return "Password should be at least 8 characters long."

    # Check if the password contains uppercase letters
    if not re.search(r'[A-Z]', password):
        return "Password should contain at least one uppercase letter."

    # Check if the password contains lowercase letters
    if not re.search(r'[a-z]', password):
        return "Password should contain at least one lowercase letter."

    # Check if the password contains digits
    if not re.search(r'\d', password):
        return "Password should contain at least one digit."

    # Check if the password contains special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password should contain at least one special character."

    # If all checks pass, the password is considered strong
    return "Password is strong."

# Example usage
password = input("Enter a password to check its strength: ")
result = check_password_strength(password)
print(result)