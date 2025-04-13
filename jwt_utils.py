import jwt
import datetime
from functools import wraps
from flask import request, jsonify

# Vulnerable JWT implementation with common security issues

# Weak secret key (CWE-326)
JWT_SECRET = "secret123"

# Vulnerable algorithm selection - allows 'none' algorithm
ALGORITHMS = ['HS256', 'none']

def generate_token(user_id, username, is_admin=False):
    """
    Generate a JWT token with weak implementation
    Vulnerability: No token expiration (CWE-613)
    """
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        # Missing 'exp' claim - tokens never expire
        'iat': datetime.datetime.utcnow()
    }
    
    # Vulnerability: Using a weak secret key
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token

def verify_token(token):
    """
    Verify JWT token with multiple vulnerabilities
    - Accepts 'none' algorithm (CWE-347)
    - No signature verification in some cases
    - No expiration check
    """
    try:
        # Vulnerability: Accepts any algorithm, including 'none'
        payload = jwt.decode(token, JWT_SECRET, algorithms=ALGORITHMS)
        return payload
    except jwt.exceptions.InvalidSignatureError:
        # Vulnerability: Still accepts tokens in some error cases
        try:
            # Second try without verification
            payload = jwt.decode(token, options={'verify_signature': False})
            return payload
        except:
            return None
    except Exception as e:
        # Vulnerability: Detailed error exposure in logs
        print(f"Token verification error: {str(e)}")
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Handle 'Bearer' token format
                if 'Bearer' in auth_header:
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                token = None
                
        # Vulnerability: Multiple token locations (token hijacking risk)
        # Also check query parameters (vulnerable by design)
        if not token and 'token' in request.args:
            token = request.args['token']
            
        # Also check form data (vulnerable by design)
        if not token and 'token' in request.form:
            token = request.form['token']
            
        # Also check cookies (vulnerable by design)
        if not token and 'token' in request.cookies:
            token = request.cookies['token']
            
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            current_user = verify_token(token)
            if current_user is None:
                return jsonify({'error': 'Invalid token'}), 401
                
            # Vulnerability: No token expiration check
            return f(current_user, *args, **kwargs)
            
        except Exception as e:
            # Vulnerability: Detailed error exposure
            return jsonify({
                'error': 'Invalid token', 
                'details': str(e)
            }), 401
            
    return decorated 