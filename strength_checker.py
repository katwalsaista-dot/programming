import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import re
import random
import string
import hashlib
import threading
import json
import os
from datetime import datetime

# Global variables for the GUI
root = None
password_entry = None
result_text = None
progress_bar = None
strength_label = None
history_listbox = None
history_data = []

# Password strength checker
def check_password_strength(password):
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long")
    
    # Upper case check
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("❌ Add uppercase letters")
    
    # Lower case check
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("❌ Add lowercase letters")
    
    # Numbers check
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("❌ Add numbers")
    
    # Special characters check
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
        score += 1
    else:
        feedback.append("❌ Add special characters")
    
    # Common patterns to avoid
    common_patterns = ['123', 'abc', 'qwerty', 'password', 'admin']
    for pattern in common_patterns:
        if pattern in password.lower():
            feedback.append(f"⚠️ Avoid common pattern: '{pattern}'")
            score -= 1
    
    # Determine strength level
    if score >= 5:
        strength = "Strong 🔒"
        color = "green"
    elif score >= 3:
        strength = "Medium ⚠️"
        color = "orange"
    else:
        strength = "Weak 🔴"
        color = "red"
    
    # Entropy calculation
    charset_size = 0
    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'[0-9]', password):
        charset_size += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset_size += 32
    
    if charset_size > 0:
        entropy = len(password) * (charset_size ** 0.5)
    else:
        entropy = 0
    
    return {
        'score': score,
        'strength': strength,
        'color': color,
        'feedback': feedback,
        'length': len(password),
        'entropy': round(entropy, 2)
    }

# Generate strong password
def generate_password():
    length = 16
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(random.choice(characters) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    analyze_password()

# Check for breached passwords using rockyou.txt
def check_breached():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password first")
        return
    
    # Show progress
    progress_bar.start()
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Checking against breached passwords database (rockyou.txt)...\n")
    
    # Check in a separate thread
    def check_thread():
        try:
            # First, check if rockyou.txt exists
            rockyou_path = 'rockyou.txt'
            sample_created = False
            
            # If rockyou.txt doesn't exist, create a sample with common passwords
            if not os.path.exists(rockyou_path):
                result_text.insert(tk.END, "rockyou.txt not found. Creating sample with common breached passwords...\n")
                with open(rockyou_path, 'w', encoding='utf-8') as f:
                    # Add some common breached passwords from actual breaches
                    common_passwords = [
                        '123456', 'password', '12345678', 'qwerty', 'abc123',
                        'password1', '12345', '123456789', 'letmein', 'welcome',
                        'monkey', 'dragon', 'baseball', 'football', 'hello',
                        'charlie', 'trustno1', 'starwars', 'master', 'sunshine',
                        'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
                        '654321', 'superman', '1qaz2wsx', '7777777', 'freedom',
                        '121212', '000000', 'qazwsx', 'mustang', 'jordan',
                        'harley', 'ranger', 'jennifer', 'hunter', 'buster',
                        'soccer', 'batman', 'test', 'killer', 'hockey'
                    ]
                    for pwd in common_passwords:
                        f.write(pwd + '\n')
                sample_created = True
            # Check if password is in the file
            is_breached = False
            try:
                with open(rockyou_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        if line.strip() == password:
                            is_breached = True
                            break
            except UnicodeDecodeError:
                # Try with different encoding for actual rockyou.txt
                with open(rockyou_path, 'r', encoding='latin-1') as f:
                    for line in f:
                        if line.strip() == password:
                            is_breached = True
                            break
            
            # Calculate hash
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            
            # Update GUI in main thread
            root.after(0, lambda isb=is_breached, sha1=sha1_hash, sample=sample_created: 
                      update_breach_result(isb, sha1, sample))
            
        except Exception as e:
            error_msg = str(e)
            root.after(0, lambda msg=error_msg: result_text.insert(tk.END, f"Error: {msg}\n"))
        finally:
            root.after(0, progress_bar.stop)
    
    # Run in separate thread
    threading.Thread(target=check_thread, daemon=True).start()

def update_breach_result(is_breached, sha1_hash, sample_created):
    if is_breached:
        result_text.insert(tk.END, "⚠️ WARNING: This password has been breached!\n", 'warning')
        result_text.insert(tk.END, f"Hash (SHA-1): {sha1_hash}\n")
        result_text.insert(tk.END, "This password was found in rockyou.txt (common breached passwords list)\n")
        result_text.insert(tk.END, "Recommendation: Change this password immediately!\n")
    else:
        if sample_created:
            result_text.insert(tk.END, "✅ Not found in common breached passwords\n")
            result_text.insert(tk.END, f"Hash (SHA-1): {sha1_hash}\n")
            result_text.insert(tk.END, "Note: Using sample rockyou.txt. For complete check, use the full rockyou.txt file.\n")
        else:
            result_text.insert(tk.END, "✅ Good! Not found in rockyou.txt\n")
            result_text.insert(tk.END, f"Hash (SHA-1): {sha1_hash}\n")
            result_text.insert(tk.END, "Note: This checks against the actual rockyou.txt file.\n")

# Analyze password
def analyze_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Please enter a password first")
        return
    
    result = check_password_strength(password)
    
    # Update strength label
    strength_label.config(text=f"Strength: {result['strength']}", fg=result['color'])
    
    # Display results
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Password Analysis Results:\n")
    result_text.insert(tk.END, "="*40 + "\n")
    result_text.insert(tk.END, f"Password: {'*' * len(password)}\n")
    result_text.insert(tk.END, f"Length: {result['length']} characters\n")
    result_text.insert(tk.END, f"Strength Score: {result['score']}/6\n")
    result_text.insert(tk.END, f"Entropy: {result['entropy']}\n")
    result_text.insert(tk.END, f"Strength Level: {result['strength']}\n\n")
    
    if result['feedback']:
        result_text.insert(tk.END, "Recommendations:\n")
        for item in result['feedback']:
            result_text.insert(tk.END, f"• {item}\n")
    else:
        result_text.insert(tk.END, "✅ Excellent password! No recommendations needed.\n")
    
    # Add to history
    add_to_history(password, result['strength'])

# Add password check to history
def add_to_history(password, strength):
    timestamp = datetime.now().strftime("%H:%M:%S")
    history_data.append({
        'time': timestamp,
        'password': '*' * len(password),
        'strength': strength,
        'full_password': password  # Stored but not displayed
    })
    
    # Update listbox (show only last 10 entries)
    history_listbox.delete(0, tk.END)
    for item in history_data[-10:]:
        display_text = f"{item['time']} - {item['password']} - {item['strength']}"
        history_listbox.insert(tk.END, display_text)

# Show password from history
def show_selected_password():
    selection = history_listbox.curselection()
    if selection:
        index = selection[0]
        if len(history_data) > index:
            actual_index = len(history_data) - 10 + index if len(history_data) > 10 else index
            password_entry.delete(0, tk.END)
            password_entry.insert(0, history_data[actual_index]['full_password'])
            analyze_password()

# Clear history
def clear_history():
    global history_data
    history_data = []
    history_listbox.delete(0, tk.END)
    messagebox.showinfo("Info", "History cleared")

# Export results
def export_results():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "No password to export")
        return
    
    result = check_password_strength(password)
    export_data = {
        "timestamp": datetime.now().isoformat(),
        "password_analyzed": "*" * len(password),
        "analysis_results": result,
        "history_count": len(history_data)
    }
    
    filename = f"password_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(export_data, f, indent=2)
    
    messagebox.showinfo("Export Successful", f"Results exported to {filename}")

# Toggle password visibility
def toggle_password():
    if password_entry.cget('show') == '':
        password_entry.config(show='*')
        toggle_btn.config(text="👁 Show")
    else:
        password_entry.config(show='')
        toggle_btn.config(text="👁 Hide")

# Download rockyou.txt helper function
def download_rockyou_help():
    help_text = """
    To use the full rockyou.txt file:
    
    1. Download rockyou.txt from:
       - Kali Linux: /usr/share/wordlists/rockyou.txt.gz
       - Or download from: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
       
    2. Extract it if needed (it's usually a .gz file)
    
    3. Place rockyou.txt in the same folder as this program
    
    4. The file contains 14 million+ breached passwords
    
    Note: The file is ~133 MB when extracted
    
    For now, the program uses a small sample of common passwords.
    """
    messagebox.showinfo("rockyou.txt Help", help_text)

# Create the GUI
def create_gui():
    global root, password_entry, result_text, progress_bar, strength_label, history_listbox, toggle_btn
    
    root = tk.Tk()
    root.title("Password Analyzer - Cybersecurity Tool")
    root.geometry("800x700")
    root.configure(bg='#f0f0f0')
    
    # Title
    title_label = tk.Label(root, text="🔐 Password Analyzer Tool", 
                          font=('Arial', 20, 'bold'), bg='#f0f0f0', fg='#2c3e50')
    title_label.pack(pady=10)
    
    # Subtitle
    subtitle_label = tk.Label(root, text="For Cybersecurity Students | Uses rockyou.txt for breach checking", 
                            font=('Arial', 10), bg='#f0f0f0', fg='#7f8c8d')
    subtitle_label.pack()
    
    # Main container
    main_frame = tk.Frame(root, bg='#f0f0f0')
    main_frame.pack(pady=10, padx=20, fill='both', expand=True)
    
    # Input section
    input_frame = tk.LabelFrame(main_frame, text="Password Input", 
                               font=('Arial', 12, 'bold'), bg='#f0f0f0')
    input_frame.pack(fill='x', pady=(0, 10))
    
    tk.Label(input_frame, text="Enter Password:", bg='#f0f0f0').grid(row=0, column=0, padx=5, pady=10)
    password_entry = tk.Entry(input_frame, width=40, show='*', font=('Arial', 12))
    password_entry.grid(row=0, column=1, padx=5, pady=10)
    password_entry.bind('<KeyRelease>', lambda e: analyze_password())
    
    # Toggle password visibility button
    toggle_btn = tk.Button(input_frame, text="👁 Show", command=toggle_password, width=8)
    toggle_btn.grid(row=0, column=2, padx=5)
    
    # Buttons frame
    btn_frame = tk.Frame(input_frame, bg='#f0f0f0')
    btn_frame.grid(row=1, column=0, columnspan=3, pady=10)
    
    analyze_btn = tk.Button(btn_frame, text="🔍 Analyze Password", command=analyze_password, 
                           bg='#3498db', fg='white', font=('Arial', 10, 'bold'), width=20)
    analyze_btn.pack(side='left', padx=5)
    
    generate_btn = tk.Button(btn_frame, text="🎲 Generate Strong", command=generate_password, 
                            bg='#2ecc71', fg='white', font=('Arial', 10, 'bold'), width=20)
    generate_btn.pack(side='left', padx=5)
    
    breach_btn = tk.Button(btn_frame, text="⚠️ Check Breach", command=check_breached, 
                          bg='#e74c3c', fg='white', font=('Arial', 10, 'bold'), width=20)
    breach_btn.pack(side='left', padx=5)
    
    # Strength indicator
    strength_frame = tk.Frame(main_frame, bg='#f0f0f0')
    strength_frame.pack(fill='x', pady=(0, 10))
    
    strength_label = tk.Label(strength_frame, text="Strength: Not Analyzed", 
                             font=('Arial', 14, 'bold'), fg='gray')
    strength_label.pack()
    
    # Progress bar
    progress_bar = ttk.Progressbar(strength_frame, mode='indeterminate', length=400)
    progress_bar.pack(pady=5)
    
    # Results section
    result_frame = tk.LabelFrame(main_frame, text="Analysis Results", 
                                font=('Arial', 12, 'bold'), bg='#f0f0f0')
    result_frame.pack(fill='both', expand=True, pady=(0, 10))
    
    result_text = scrolledtext.ScrolledText(result_frame, width=70, height=12, 
                                           font=('Courier', 10))
    result_text.pack(padx=10, pady=10, fill='both', expand=True)
    
    # Configure text tags
    result_text.tag_config('warning', foreground='red', font=('Courier', 10, 'bold'))
    
    # History section
    history_frame = tk.LabelFrame(main_frame, text="Check History (Last 10)", 
                                 font=('Arial', 12, 'bold'), bg='#f0f0f0')
    history_frame.pack(fill='x')
    
    history_listbox = tk.Listbox(history_frame, height=4, font=('Courier', 10))
    history_listbox.pack(side='left', fill='both', expand=True, padx=(10, 5), pady=10)
    
    history_btn_frame = tk.Frame(history_frame, bg='#f0f0f0')
    history_btn_frame.pack(side='right', padx=5)
    
    show_btn = tk.Button(history_btn_frame, text="Load Selected", command=show_selected_password, width=15)
    show_btn.pack(pady=5)
    
    clear_btn = tk.Button(history_btn_frame, text="Clear History", command=clear_history, width=15)
    clear_btn.pack(pady=5)
    
    export_btn = tk.Button(history_btn_frame, text="Export Results", command=export_results, width=15)
    export_btn.pack(pady=5)
    
    rockyou_help_btn = tk.Button(history_btn_frame, text="rockyou.txt Help", command=download_rockyou_help, width=15)
    rockyou_help_btn.pack(pady=5)
    
    # Footer
    footer_label = tk.Label(root, text="Cybersecurity Student Tool | Uses rockyou.txt for breach checking", 
                           font=('Arial', 8), bg='#f0f0f0', fg='#95a5a6')
    footer_label.pack(pady=10)
    
    return root

# Main function
def main():
    global root
    root = create_gui()
    root.mainloop()

if __name__ == "__main__":
    main()
