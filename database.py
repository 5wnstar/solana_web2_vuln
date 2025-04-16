import sqlite3
import os
import random
import string
from flask import g

DATABASE = 'vuln_bank.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db(app):
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create users table with seed phrase and admin flag
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            wallet_address TEXT UNIQUE NOT NULL,
            seed_phrase TEXT NOT NULL,
            balance REAL DEFAULT 100.0,
            profile_picture TEXT,
            is_admin BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            last_login DATETIME,
            failed_login_attempts INTEGER DEFAULT 0
        )
        ''')
        
        # Create transactions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'completed',
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (recipient_id) REFERENCES users (id)
        )
        ''')
        
        # Create comments table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            comment_text TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_approved BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Create access_logs table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Add initial users if they don't exist
        initial_users = [
            ('guvenkaya_sec', 'root@solana', '0x1234567890abcdef', False),
            ('timurguvenkaya', 'user@solana', '0xabcdef1234567890', False),
            ('superteam', 'superteam@solana', '0x7890abcdef123456', True)  # Admin user
        ]
        
        for username, password, wallet_address, is_admin in initial_users:
            try:
                cursor.execute('''
                INSERT OR IGNORE INTO users (username, password, wallet_address, seed_phrase, balance, is_admin)
                VALUES (?, ?, ?, ?, ?, ?)
                ''', (username, password, wallet_address, generate_seed_phrase(), 100.0, is_admin))
            except sqlite3.IntegrityError:
                pass
        
        db.commit()
        db.close()

def generate_seed_phrase():
    """Generate a 12-word seed phrase"""
    words = [
        'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
        'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
        # ... add more words for a complete BIP39 wordlist
    ]
    return ' '.join(random.choices(words, k=12))

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    get_db().commit()
    return (rv[0] if rv else None) if one else rv

def close_db(e=None):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Get user by username - VULNERABLE to SQL Injection
def get_user_by_username(username):
    # Vulnerable: No parameterization
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return query_db(query, one=True)

# Get user by id
def get_user_by_id(user_id):
    return query_db("SELECT * FROM users WHERE id = ?", [user_id], one=True)

# Register new user
def register_user(username, password, wallet_address):
    try:
        seed_phrase = generate_seed_phrase()
        query_db("INSERT INTO users (username, password, wallet_address, seed_phrase, balance) VALUES (?, ?, ?, ?, ?)",
                [username, password, wallet_address, seed_phrase, 100.0])
        return True
    except sqlite3.IntegrityError:
        return False

# Get user balance
def get_balance(user_id):
    user = get_user_by_id(user_id)
    if user:
        return user['balance']
    return 0

# Vulnerable transfer implementation (no proper validation, allowing negative transfers)
def transfer_tokens(sender_id, recipient_address, amount):
    # Get sender's current balance
    sender = get_user_by_id(sender_id)
    if not sender:
        return False, "Insufficient funds"
        
    # Get recipient by wallet address
    recipient = query_db("SELECT * FROM users WHERE wallet_address = ?", [recipient_address], one=True)
    if not recipient:
        return False, "Recipient not found"
    
    # Check if sender and recipient are the same
    if sender_id == recipient['id']:
        return False, "Cannot transfer to yourself"
    
    # Check balance only for positive transfers
    if amount > 0 and amount > sender['balance']:
        return False, "Insufficient funds"
    
    # Perform the transfer
    try:
        # For negative amounts, we need to add the absolute value to sender and subtract from recipient
        if amount < 0:
            query_db("UPDATE users SET balance = balance + ? WHERE id = ?", [abs(amount), sender_id])
            query_db("UPDATE users SET balance = balance - ? WHERE id = ?", [abs(amount), recipient['id']])
        else:
            # For positive amounts, normal transfer
            query_db("UPDATE users SET balance = balance - ? WHERE id = ?", [amount, sender_id])
            query_db("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, recipient['id']])
        
        # Record the transaction
        query_db(
            "INSERT INTO transactions (sender_id, recipient_id, amount, timestamp) VALUES (?, ?, ?, datetime('now'))",
            [sender_id, recipient['id'], amount]
        )
        
        return True, "Transfer completed successfully"
    except Exception as e:
        print(f"Transfer error: {str(e)}")  # Add error logging
        return False, "Insufficient funds"

# Get user's transaction history
def get_transaction_history(user_id):
    # Vulnerable: Returns all fields including potentially sensitive information
    return query_db("""
        SELECT t.*, 
               s.username as sender_username, s.wallet_address as sender_wallet,
               r.username as recipient_username, r.wallet_address as recipient_wallet
        FROM transactions t
        JOIN users s ON t.sender_id = s.id
        JOIN users r ON t.recipient_id = r.id
        WHERE t.sender_id = ? OR t.recipient_id = ?
        ORDER BY t.timestamp DESC
    """, [user_id, user_id])

# Get transaction by ID - Vulnerable to BOLA
def get_transaction_by_id(tx_id):
    # Vulnerable: No authorization check if the user has permission to view this transaction
    return query_db("SELECT * FROM transactions WHERE id = ?", [tx_id], one=True)

# Save profile picture - Vulnerable to unrestricted file upload
def save_profile_picture(user_id, filename):
    query_db("UPDATE users SET profile_picture = ? WHERE id = ?", [filename, user_id])
    return True

# Add comment - Vulnerable to XSS
def add_comment(user_id, comment_text):
    # Vulnerable: No sanitization of comment_text
    query_db("INSERT INTO comments (user_id, comment_text, timestamp) VALUES (?, ?, datetime('now'))",
             [user_id, comment_text])
    return True

# Get all comments - For XSS vulnerability
def get_comments():
    return query_db("SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id ORDER BY c.timestamp DESC")

def get_user_by_wallet_address(wallet_address):
    return query_db("SELECT * FROM users WHERE wallet_address = ?", [wallet_address], one=True)

def is_admin(user_id):
    user = get_user_by_id(user_id)
    return user and user['is_admin'] == 1

def get_all_users():
    return query_db("SELECT id, username, wallet_address, balance, is_admin, is_active FROM users")

def update_user_balance(user_id, new_balance):
    query_db("UPDATE users SET balance = ? WHERE id = ?", [new_balance, user_id])
    return True

def toggle_user_status(user_id):
    user = get_user_by_id(user_id)
    if user:
        new_status = 0 if user['is_active'] else 1
        query_db("UPDATE users SET is_active = ? WHERE id = ?", [new_status, user_id])
        return True
    return False

def log_access(user_id, action, ip_address):
    query_db("INSERT INTO access_logs (user_id, action, ip_address) VALUES (?, ?, ?)",
             [user_id, action, ip_address])
    return True

def get_access_logs():
    return query_db("""
        SELECT l.*, u.username 
        FROM access_logs l 
        LEFT JOIN users u ON l.user_id = u.id 
        ORDER BY l.timestamp DESC
    """)

def get_all_transactions():
    return query_db("""
        SELECT t.*, 
               s.username as sender_username, s.wallet_address as sender_wallet,
               r.username as recipient_username, r.wallet_address as recipient_wallet
        FROM transactions t
        JOIN users s ON t.sender_id = s.id
        JOIN users r ON t.recipient_id = r.id
        ORDER BY t.timestamp DESC
    """)

def reverse_transaction(tx_id):
    transaction = get_transaction_by_id(tx_id)
    if transaction:
        # Add the amount back to sender
        query_db("UPDATE users SET balance = balance + ? WHERE id = ?",
                [transaction['amount'], transaction['sender_id']])
        # Subtract from recipient
        query_db("UPDATE users SET balance = balance - ? WHERE id = ?",
                [transaction['amount'], transaction['recipient_id']])
        # Mark transaction as reversed
        query_db("UPDATE transactions SET status = 'reversed' WHERE id = ?", [tx_id])
        return True
    return False

def moderate_comment(comment_id, approve=True):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE comments SET is_approved = ? WHERE id = ?', (approve, comment_id))
    db.commit()
    return True

def delete_comment(comment_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM comments WHERE id = ?', (comment_id,))
    db.commit()
    return True