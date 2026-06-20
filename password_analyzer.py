# password_analyzer.py
# CYB333 Final Project - Password Strength Analyzer
# Author: Gerardo Morales

import math
import csv
import argparse
import json

# -----------------------------
# LENGTH ANALYSIS
# -----------------------------
def analyze_length(password):
    length = len(password)
    if length < 8:
        return 1, "Password is too short (less than 8 characters)."
    elif length < 12:
        return 2, "Password length is acceptable but could be stronger."
    else:
        return 3, "Password length is strong."


# -----------------------------
# CHARACTER TYPE ANALYSIS
# -----------------------------
def analyze_character_types(password):
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    score = sum([has_upper, has_lower, has_digit, has_special])

    feedback = []
    if not has_upper:
        feedback.append("Missing uppercase letter.")
    if not has_lower:
        feedback.append("Missing lowercase letter.")
    if not has_digit:
        feedback.append("Missing digit.")
    if not has_special:
        feedback.append("Missing special character.")

    return score, feedback


# -----------------------------
# ENTROPY CALCULATION
# -----------------------------
def calculate_entropy(password):
    if not password:
        return 0.0

    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0
    length = len(password)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)


# -----------------------------
# DICTIONARY WORD DETECTION
# -----------------------------
def load_dictionary_words(filepath="data/common_words.txt"):
    try:
        with open(filepath, "r") as f:
            return [w.strip().lower() for w in f.readlines()]
    except FileNotFoundError:
        return []


LEET_MAP = {
    "4": "a", "@": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t"
}

def normalize_leetspeak(password):
    return "".join(LEET_MAP.get(c.lower(), c.lower()) for c in password)


def dictionary_word_detection(password):
    normalized = normalize_leetspeak(password)
    words = load_dictionary_words()
    found = [w for w in words if w in normalized]
    return found


# -----------------------------
# COMMON PASSWORD DETECTION
# -----------------------------
def load_common_passwords(filepath="data/common_passwords.txt"):
    try:
        with open(filepath, "r") as f:
            return [p.strip().lower() for p in f.readlines()]
    except FileNotFoundError:
        return []


def common_password_detection(password):
    common = load_common_passwords()
    return password.lower() in common


# -----------------------------
# PATTERN DETECTION
# -----------------------------
def detect_sequences(password):
    sequences = []
    for i in range(len(password) - 2):
        chunk = password[i:i+3]
        if chunk.isdigit() and chunk in "0123456789":
            sequences.append(chunk)
        if chunk.isalpha() and chunk.lower() in "abcdefghijklmnopqrstuvwxyz":
            sequences.append(chunk)
    return sequences


def detect_repeated_characters(password):
    if not password:
        return []

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


# -----------------------------
# RECOMMENDATIONS ENGINE
# -----------------------------
def generate_recommendations(results):
    recs = []

    if results["length_score"] == 1:
        recs.append("Increase password length to at least 12 characters.")
    elif results["length_score"] == 2:
        recs.append("Consider increasing password length for stronger security.")

    for msg in results["character_type_feedback"]:
        if "uppercase" in msg:
            recs.append("Add at least one uppercase letter.")
        if "lowercase" in msg:
            recs.append("Add at least one lowercase letter.")
        if "digit" in msg:
            recs.append("Include at least one number.")
        if "special" in msg:
            recs.append("Add at least one special character (e.g., !, @, #, $).")

    if results["dictionary_matches"]:
        recs.append("Avoid using dictionary words or common phrases.")

    if results["is_common_password"]:
        recs.append("This password is commonly used and easily guessed. Choose a more unique password.")

    if results["sequential_patterns"]:
        recs.append("Avoid sequential patterns like '123' or 'abc'.")

    if results["repeated_patterns"]:
        recs.append("Avoid repeated characters such as 'aaa' or '111'.")

    if results["entropy"] < 3.5:
        recs.append("Increase randomness to improve entropy.")

    if not recs:
        recs.append("Your password appears strong.")

    return recs


# -----------------------------
# STRENGTH SCORING MODEL (0–10)
# -----------------------------
def calculate_strength_score(results):
    score = 0

    # Length (0–2)
    if results["length_score"] == 2:
        score += 1
    elif results["length_score"] == 3:
        score += 2

    # Character diversity (0–3)
    diversity = results["character_type_score"]
    score += min(diversity, 3)

    # Entropy (0–2)
    if results["entropy"] >= 4.0:
        score += 2
    elif results["entropy"] >= 3.0:
        score += 1

    # Dictionary penalty
    if results["dictionary_matches"]:
        score -= 2

    # Common password penalty
    if results["is_common_password"]:
        score -= 3

    # Pattern penalties
    if results["sequential_patterns"]:
        score -= 1
    if results["repeated_patterns"]:
        score -= 1

    return max(0, min(10, score))


# -----------------------------
# MAIN ANALYSIS FUNCTION
# -----------------------------
def analyze_password(password):
    length_score, length_msg = analyze_length(password)
    type_score, type_msgs = analyze_character_types(password)
    entropy = calculate_entropy(password)
    found_words = dictionary_word_detection(password)
    is_common = common_password_detection(password)
    sequences = detect_sequences(password)
    repeats = detect_repeated_characters(password)

    recommendations = generate_recommendations({
        "length_score": length_score,
        "character_type_feedback": type_msgs,
        "dictionary_matches": found_words,
        "is_common_password": is_common,
        "sequential_patterns": sequences,
        "repeated_patterns": repeats,
        "entropy": entropy
    })

    strength_score = calculate_strength_score({
        "length_score": length_score,
        "character_type_score": type_score,
        "entropy": entropy,
        "dictionary_matches": found_words,
        "is_common_password": is_common,
        "sequential_patterns": sequences,
        "repeated_patterns": repeats
    })

    return {
        "password": password,
        "length_score": length_score,
        "length_feedback": length_msg,
        "character_type_score": type_score,
        "character_type_feedback": type_msgs,
        "entropy": entropy,
        "dictionary_matches": found_words,
        "is_common_password": is_common,
        "sequential_patterns": sequences,
        "repeated_patterns": repeats,
        "recommendations": recommendations,
        "strength_score": strength_score
    }


# -----------------------------
# BATCH MODE
# -----------------------------
def analyze_password_file(filepath):
    results = []
    try:
        with open(filepath, "r") as f:
            passwords = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"File not found: {filepath}")
        return []

    for pwd in passwords:
        if pwd:
            results.append(analyze_password(pwd))

    return results


# -----------------------------
# CSV EXPORT
# -----------------------------
def export_results_to_csv(results, output_path="analysis_results.csv"):
    if not results:
        print("No results to export.")
        return

    keys = results[0].keys()

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

    print(f"Results exported to {output_path}")


# -----------------------------
# CLI INTERFACE
# -----------------------------
def run_cli():
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer - analyze single passwords or files."
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--password", type=str, help="Analyze a single password.")
    group.add_argument("-f", "--file", type=str, help="Analyze a file of passwords.")

    parser.add_argument("-o", "--output", type=str, help="Optional: save results to JSON.")

    args = parser.parse_args()

    if args.password:
        result = analyze_password(args.password)
        print(json.dumps(result, indent=4))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=4)
            print(f"Results saved to {args.output}")

    elif args.file:
        results = analyze_password_file(args.file)
        print(json.dumps(results, indent=4))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            print(f"Results saved to {args.output}")


# -----------------------------
# MAIN ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    run_cli()
