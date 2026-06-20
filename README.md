# Password Strength Analyzer

A modular, extensible Python tool for evaluating password strength using entropy, dictionary detection, leet‑speak normalization, pattern analysis, common password lists, and a refined 0–10 scoring model.

---

## Overview

This project implements a comprehensive password analysis engine designed for security auditing and educational use. It evaluates passwords using multiple criteria:
• Length scoring
• Character type diversity
• Shannon entropy
• Dictionary word detection
• Leet‑speak normalization
• Common password list matching
• Sequential pattern detection
• Repeated character detection
• Human‑readable recommendations
• Batch mode for analyzing entire files

The analyzer outputs a structured dictionary for each password, including a final strength score (0–10).

---

## Features

### Length & Character Analysis
Evaluates password length and diversity of character types (uppercase, lowercase, digits, special characters).

### Entropy Calculation
Computes Shannon entropy to estimate randomness.

### Dictionary Word Detection
Identifies embedded dictionary words, even when obfuscated with leet‑speak (e.g., P@ssw0rd → password).

### Common Password Detection
Flags passwords found in known breach lists.

### Pattern Detection
Detects:
• Sequential numbers (123, 456)
• Sequential letters (abc, xyz)
• Keyboard patterns (qwe, asd)
• Repeated characters (aaa, 1111)

### Recommendations Engine
Generates clear, actionable guidance for improving password strength.

### Batch Mode
Analyze an entire file of passwords at once.

### Refined Scoring Model (0–10)
Weighted scoring based on:
• Length
• Character diversity
• Entropy
• Dictionary words
• Common passwords
• Patterns

---

## Project Structure

project/
│
├── password_analyzer.py      # Main analysis engine
├── analysis.ipynb            # Jupyter notebook for testing
├── data/
│   ├── common_words.txt      # Dictionary word list
│   ├── common_passwords.txt  # Breached password list
│   └── password_list.txt     # Sample batch input
└── README.md                 # Documentation

## Usage

### Analyze a single password:

```python
from password_analyzer import analyze_password

result = analyze_password("Password123")
print(result)
```

### Analyze a file of passwords:

```python
from password_analyzer import analyze_password_file

results = analyze_password_file("data/password_list.txt")
```

### Example Output:

    {
    "password": "Password123",
    "length_score": 2,
    "character_type_score": 3,
    "entropy": 3.28,
    "dictionary_matches": ["password"],
    "is_common_password": true,
    "sequential_patterns": ["123"],
    "repeated_patterns": [],
    "recommendations": [
        "Add at least one special character.",
        "Avoid dictionary words.",
        "Avoid sequential patterns like '123'."
    ],
    "strength_score": 3
    }

### Scoring Model:

Category	                Points
Length	                    0–2
Character Diversity	        0–3
Entropy	                    0–2
Dictionary Penalty	        –2
Common Password Penalty	    –3
Pattern Penalties	        –2 total
Final Score	                0–10

## Requirements:
• Python 3.8+
• No external libraries required (standard library only)

---

## Academic Context
This project was developed as part of CYB 333 – Secure Windows Administration, demonstrating secure password evaluation techniques, pattern recognition, and modular Python design.

---

## License:
This project is for educational use.