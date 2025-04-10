from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
import jwt
import datetime
import hashlib
import os
import random
import string
from database import get_user_by_username, register_user, query_db

auth_bp = Blueprint('auth', __name__)

# Weak secret key
JWT_SECRET = "solana_vulnerable_app_secret"

# Weak token generation function
def generate_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        # Vulnerability: No token expiration
        # 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    # Vulnerability: Weak algorithm, no signature verification enforced
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

# Vulnerable login route - SQL Injection possible
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Vulnerability: SQL Injection in the get_user_by_username function
        user = get_user_by_username(username)
        
        if user and user['password'] == password:  # Vulnerability: Plain text password
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['wallet_address'] = user['wallet_address']
            
            # Generate JWT token with limited security
            token = generate_token(user['id'], user['username'])
            session['token'] = token
            
            # Return token in the response - will be stored in localStorage by frontend
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

# Register route - Insecure implementation
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')  # Vulnerability: No password hashing
        
        # Generate Solana-like wallet address (this is just for demonstration)
        letters = string.ascii_letters + string.digits
        wallet_address = ''.join(random.choice(letters) for i in range(44))
        
        if register_user(username, password, wallet_address):
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Username already taken', 'danger')
    
    return render_template('register.html')

# Logout route
@auth_bp.route('/logout')
def logout():
    # Vulnerability: No server-side token invalidation
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

# API endpoint to validate token - vulnerable implementation
@auth_bp.route('/api/validate-token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    
    try:
        # Vulnerability: No signature verification enforced
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({'valid': True, 'user_id': payload.get('user_id')})
    except:
        return jsonify({'valid': False})

# Gets user profile - Vulnerable to BOLA
@auth_bp.route('/api/user/<int:user_id>', methods=['GET'])
def get_user(user_id):
    # Vulnerability: No authorization check to see if the current user has permission to access this profile
    user = query_db("SELECT id, username, wallet_address, balance, profile_picture FROM users WHERE id = ?", 
                    [user_id], one=True)
    
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'wallet_address': user['wallet_address'],
            'balance': user['balance'],
            'profile_picture': user['profile_picture']
        })
    else:
        return jsonify({'error': 'User not found'}), 404