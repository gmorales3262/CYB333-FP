# password_analyzer.py
# CYB333 Final Project - Password Strength Analyzer
# Author: Gerardo Morales

import re
import math

def analyze_length(password):
    """Evaluate password length."""
    length = len(password)
    if length < 8:
        return 1, "Password is too short (less than 8 characters)."
    elif length < 12:
        return 2, "Password length is acceptable but could be stronger."
    else:
        return 3, "Password length is strong."

def analyze_character_types(password):
    """Check for uppercase, lowercase, digits, and symbols."""
    score = 0
    messages = []

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        messages.append("Missing uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        messages.append("Missing lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        messages.append("Missing digit.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        messages.append("Missing special character.")

    return score, messages

def calculate_entropy(password):
    """Calculate Shannon entropy."""
    if not password:
        return 0

    # Count frequency of each character
    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0
    length = len(password)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)

def analyze_password(password):
    """Run all analysis modules and return a structured result."""
    length_score, length_msg = analyze_length(password)
    type_score, type_msgs = analyze_character_types(password)
    entropy = calculate_entropy(password)

    total_score = length_score + type_score

    return {
        "password": password,
        "length_score": length_score,
        "length_feedback": length_msg,
        "character_type_score": type_score,
        "character_type_feedback": type_msgs,
        "entropy": entropy,
        "total_score": total_score
    }

if __name__ == "__main__":
    test = input("Enter a password to analyze: ")
    result = analyze_password(test)
    print(result)
