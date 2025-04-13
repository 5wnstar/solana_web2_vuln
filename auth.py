from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
import hashlib
import os
import random
import string
import requests
from database import get_user_by_username, register_user, query_db
from jwt_utils import generate_token, verify_token, token_required

auth_bp = Blueprint('auth', __name__)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user_by_username(username)
        
        if user and user['password'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['wallet_address'] = user['wallet_address']
            token = generate_token(user['id'], user['username'])
            session['token'] = token
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
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
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
@auth_bp.route('/api/validate-token', methods=['POST'])
def validate_token():
    token = request.json.get('token')
    
    try:
        payload = verify_token(token)
        return jsonify({'valid': True, 'user_id': payload.get('user_id')})
    except:
        return jsonify({'valid': False})
@auth_bp.route('/api/user/<int:user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
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
@auth_bp.route('/api/fetch-url', methods=['POST'])
@token_required
def fetch_url(current_user):
    url = request.json.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            verify=False  
        )
        return jsonify({
            'status_code': response.status_code,
            'content': response.text,
            'headers': dict(response.headers)
        })
    except Exception as e:
        return jsonify({
            'error': 'Failed to fetch URL',
            'details': str(e)
        }), 500