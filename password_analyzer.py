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

def load_dictionary_words(filepath="data/common_words.txt"):
    """Load dictionary words from a file."""
    try:
        with open(filepath, "r") as f:
            words = [w.strip().lower() for w in f.readlines()]
        return words
    except FileNotFoundError:
        return []
    
def load_common_passwords(filepath="data/common_passwords.txt"):
    """Load a list of common passwords from a file."""
    try:
        with open(filepath, "r") as f:
            return [p.strip().lower() for p in f.readlines()]
    except FileNotFoundError:
        return []

def normalize_leetspeak(password):
    """Convert common leet-speak characters to their alphabetic equivalents."""
    leet_map = {
        '@': 'a',
        '4': 'a',
        '3': 'e',
        '1': 'l',
        '!': 'i',
        '0': 'o',
        '$': 's',
        '5': 's',
        '7': 't'
    }

    normalized = ""
    for char in password.lower():
        normalized += leet_map.get(char, char)

    return normalized
    
def dictionary_word_detection(password, dictionary_words):
    """Check if the password contains dictionary words or common patterns."""
    password_lower = password.lower()
    normalized = normalize_leetspeak(password_lower)

    found_words = []

    for word in dictionary_words:
        if word in password_lower or word in normalized:
            found_words.append(word)

    return found_words

def detect_sequences(password):
    """Detect common sequential patterns in the password."""
    sequences = []

    # Numeric sequences
    numeric_sequences = ["0123456789", "1234567890"]
    # Alphabet sequences
    alpha_sequences = ["abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba"]
    # Keyboard sequences
    keyboard_sequences = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]

    password_lower = password.lower()

    # Check numeric sequences
    for seq in numeric_sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password_lower:
                sequences.append(seq[i:i+3])

    # Check alphabet sequences
    for seq in alpha_sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password_lower:
                sequences.append(seq[i:i+3])

    # Check keyboard sequences
    for seq in keyboard_sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password_lower:
                sequences.append(seq[i:i+3])

    return list(set(sequences))

def detect_repeated_characters(password):
    """Detect repeated characters like 'aaa' or '111'."""
    repeats = []
    current = password[0]
    count = 1

    for char in password[1:]:
        if char == current:
            count += 1
        else:
            if count >= 3:
                repeats.append(current * count)
            current = char
            count = 1

    if count >= 3:
        repeats.append(current * count)

    return repeats

def common_password_detection(password, common_passwords):
    """Check if the password exactly matches a known common password."""
    return password.lower() in common_passwords

def analyze_password(password):
    """Run all analysis modules and return a structured result."""
    length_score, length_msg = analyze_length(password)
    type_score, type_msgs = analyze_character_types(password)
    entropy = calculate_entropy(password)

    dictionary_words = load_dictionary_words()
    found_words = dictionary_word_detection(password, dictionary_words)

    common_passwords = load_common_passwords()
    is_common = common_password_detection(password, common_passwords)

    sequences = detect_sequences(password)
    repeats = detect_repeated_characters(password)

    total_score = length_score + type_score

    return {
        "password": password,
        "length_score": length_score,
        "length_feedback": length_msg,
        "character_type_score": type_score,
        "character_type_feedback": type_msgs,
        "entropy": entropy,
        "dictionary_matches": found_words,
        "is_common_password": is_common,
        "sequences_detected": sequences,
        "repeated_characters": repeats,
        "total_score": total_score
    }

if __name__ == "__main__":
    test = input("Enter a password to analyze: ")
    result = analyze_password(test)
    print(result)
