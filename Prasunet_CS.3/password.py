import tkinter as tk
from tkinter import messagebox
import re
import requests

# Function to check for common dictionary words
def check_dictionary_words(password):
    common_words = requests.get("https://raw.githubusercontent.com/dwyl/english-words/master/words.txt").text.split()
    password_lower = password.lower()
    for word in common_words:
        if word in password_lower and len(word) > 3:
            return True
    return False

# Function to calculate entropy of the password
def calculate_entropy(password):
    pool_size = 0
    if re.search(r'[a-z]', password):
        pool_size += 26
    if re.search(r'[A-Z]', password):
        pool_size += 26
    if re.search(r'[0-9]', password):
        pool_size += 10
    if re.search(r'[@$!%*?&#]', password):
        pool_size += len('@$!%*?&#')
    entropy = len(password) * (pool_size ** 0.5)
    return entropy

# Function to check if the password is a common password
def check_common_passwords(password):
    common_passwords = requests.get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt").text.split()
    return password in common_passwords

# Main function to assess password strength
def assess_password_strength(password):
    # Criteria checks
    length_criteria = len(password) >= 12
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[@$!%*?&#]', password))
    no_repeated_chars = len(password) == len(set(password))
    dictionary_word_criteria = not check_dictionary_words(password)
    common_password_criteria = not check_common_passwords(password)
    entropy_criteria = calculate_entropy(password) > 50  # Arbitrary threshold for entropy

    # Assess strength
    strength_score = sum([
        length_criteria,
        uppercase_criteria,
        lowercase_criteria,
        number_criteria,
        special_char_criteria,
        no_repeated_chars,
        dictionary_word_criteria,
        common_password_criteria,
        entropy_criteria
    ])

    # Feedback
    feedback = "Very Weak"
    if strength_score == 9:
        feedback = "Very Strong"
    elif strength_score >= 7:
        feedback = "Strong"
    elif strength_score >= 5:
        feedback = "Moderate"
    else:
        feedback = "Weak"

    # Suggestions for improvement
    suggestions = []
    if not length_criteria:
        suggestions.append("Increase the length to 12 or more characters.")
    if not uppercase_criteria:
        suggestions.append("Add uppercase letters (A-Z).")
    if not lowercase_criteria:
        suggestions.append("Add lowercase letters (a-z).")
    if not number_criteria:
        suggestions.append("Include numbers (0-9).")
    if not special_char_criteria:
        suggestions.append("Include special characters (@$!%*?&#).")
    if not no_repeated_chars:
        suggestions.append("Avoid repeated characters.")
    if not dictionary_word_criteria:
        suggestions.append("Avoid common dictionary words.")
    if not common_password_criteria:
        suggestions.append("Avoid common passwords.")
    if not entropy_criteria:
        suggestions.append("Increase the entropy by adding more diverse characters.")

    return feedback, {
        "Length criteria (12+ characters)": length_criteria,
        "Uppercase criteria": uppercase_criteria,
        "Lowercase criteria": lowercase_criteria,
        "Number criteria": number_criteria,
        "Special character criteria": special_char_criteria,
        "No repeated characters": no_repeated_chars,
        "No common dictionary words": dictionary_word_criteria,
        "Not a common password": common_password_criteria,
        "High entropy": entropy_criteria
    }, suggestions

# GUI Application
def show_results():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    strength, criteria_results, suggestions = assess_password_strength(password)

    results_text = f"Password Strength: {strength}\n\nCriteria Results:\n"
    for criteria, met in criteria_results.items():
        results_text += f"  - {criteria}: {'Met' if met else 'Not Met'}\n"

    if suggestions:
        results_text += "\nSuggestions for improvement:\n"
        for suggestion in suggestions:
            results_text += f"  - {suggestion}\n"

    results_label.config(text=results_text)

# Set up the main application window
root = tk.Tk()
root.title("Password Strength Assessor")

# Create and place widgets
tk.Label(root, text="Enter a password:").pack(pady=5)
entry = tk.Entry(root, show="*", width=40)
entry.pack(pady=5)

tk.Button(root, text="Assess Password", command=show_results).pack(pady=10)

results_label = tk.Label(root, text="", justify=tk.LEFT, wraplength=400)
results_label.pack(pady=10)

# Start the GUI event loop
root.mainloop()
