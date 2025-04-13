from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
import hashlib
import os
import random
import string
import requests
from database import get_user_by_username, register_user, query_db
from jwt_utils import generate_token, verify_token, token_required

auth_bp = Blueprint('auth', __name__)

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
            
            # Generate JWT token with multiple vulnerabilities
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
        payload = verify_token(token)
        return jsonify({'valid': True, 'user_id': payload.get('user_id')})
    except:
        return jsonify({'valid': False})

# Gets user profile - Vulnerable to BOLA
@auth_bp.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
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

# Vulnerable URL fetcher - SSRF vulnerability
@auth_bp.route('/api/fetch-url', methods=['POST'])
@token_required
def fetch_url(current_user):
    url = request.json.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    try:
        # Vulnerability: No URL validation or whitelist
        # Vulnerability: Follows redirects
        # Vulnerability: No timeout
        response = requests.get(
            url,
            allow_redirects=True,
            verify=False  # Vulnerability: Disabled SSL verification
        )
        
        # Vulnerability: Returns raw response content
        return jsonify({
            'status_code': response.status_code,
            'content': response.text,
            'headers': dict(response.headers)
        })
    except Exception as e:
        # Vulnerability: Detailed error messages
        return jsonify({
            'error': 'Failed to fetch URL',
            'details': str(e)
        }), 500