import sqlite3
import os
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
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

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
        query_db("INSERT INTO users (username, password, wallet_address, balance) VALUES (?, ?, ?, ?)",
                [username, password, wallet_address, 100.0])  # Start with 100 tokens
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
    # No amount validation or recipient validation!
    sender = get_user_by_id(sender_id)
    
    # Get recipient by wallet address - vulnerable to timing attacks
    recipient = query_db("SELECT * FROM users WHERE wallet_address = ?", [recipient_address], one=True)
    
    if not recipient:
        return False, "Recipient not found"
        
    # Vulnerable: No balance check or amount validation
    query_db("UPDATE users SET balance = balance - ? WHERE id = ?", [amount, sender_id])
    query_db("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, recipient['id']])
    
    # Record the transaction
    query_db(
        "INSERT INTO transactions (sender_id, recipient_id, amount, timestamp) VALUES (?, ?, ?, datetime('now'))",
        [sender_id, recipient['id'], amount]
    )
    
    return True, "Transfer completed"

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