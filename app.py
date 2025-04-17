from flask import Flask, render_template, session, redirect, url_for, request, flash, jsonify, g
import os
from werkzeug.utils import secure_filename
from auth import auth_bp
from admin import admin_bp
from database import init_db, close_db, get_user_by_id, get_balance, is_admin
from database import transfer_tokens, get_transaction_history, get_transaction_by_id
from database import save_profile_picture, add_comment, get_comments
import json
import requests

app = Flask(__name__, 
            static_folder='static',  # Explicitly set static folder
            template_folder='templates')  # Explicitly set templates folder
app.config['SECRET_KEY'] = 'solana_vulnerable_app_secret'  # Weak secret key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(admin_bp, url_prefix='/admin')

# Close database connection on teardown
app.teardown_appcontext(close_db)

# Initialize database
with app.app_context():
    try:
        init_db(app)
    except Exception as e:
        print(f"Database initialization error: {e}")

# Simple middleware to check if user is logged in
def login_required(view):
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    wrapped_view.__name__ = view.__name__
    return wrapped_view

# Add admin check to template context
@app.context_processor
def inject_admin_status():
    return dict(is_admin=lambda: 'user_id' in session and is_admin(session['user_id']))

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Dashboard page - requires login
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    balance = get_balance(user_id)
    return render_template('dashboard.html', balance=balance)

# Profile page - Vulnerable to BOLA and unauthorized access
@app.route('/profile/<int:user_id>')
def profile(user_id):
    # Vulnerability: No authorization check - any user can view any profile
    user = get_user_by_id(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard'))
        
    return render_template('profile.html', user=user)

# Transfer tokens page - Vulnerable to unauthorized transfers
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        # Vulnerability: No CSRF protection
        sender_id = session.get('user_id')
        recipient_address = request.form.get('recipient')
        amount = float(request.form.get('amount', 0))
        
        # Vulnerability: No proper validation of sender's identity
        success, message = transfer_tokens(sender_id, recipient_address, amount)
        
        if success:
            flash(message, 'success')
            return jsonify({'success': True, 'message': message})
        else:
            flash(message, 'danger')
            return jsonify({'success': False, 'message': message})
            
    # Get the user's balance
    user_id = session.get('user_id')
    balance = get_balance(user_id)
        
    return render_template('transfer.html', balance=balance)

# Transaction history page
@app.route('/transactions')
@login_required
def transactions():
    user_id = session.get('user_id')
    history = get_transaction_history(user_id)
    return render_template('transactions.html', transactions=history)

# View single transaction - Vulnerable to BOLA
@app.route('/transaction/<int:tx_id>')
@login_required
def view_transaction(tx_id):
    # Vulnerability: No check if the current user is authorized to view this transaction
    transaction = get_transaction_by_id(tx_id)
    
    if not transaction:
        flash('Transaction not found', 'danger')
        return redirect(url_for('transactions'))
        
    return render_template('transaction_detail.html', transaction=transaction)

# Upload profile picture - Vulnerable to unrestricted file upload
@app.route('/upload-profile-pic', methods=['POST'])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        flash('No file part', 'warning')
        return redirect(url_for('dashboard'))
        
    file = request.files['profile_pic']
    
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect(url_for('dashboard'))
        
    # Basic extension check but no magic number validation
    allowed_extensions = {'png', 'jpg', 'jpeg'}
    file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
    
    if file_ext not in allowed_extensions:
        flash('Only PNG, JPG, and JPEG files are allowed', 'danger')
        return redirect(url_for('dashboard'))
        
    if file:
        # Vulnerability: Only checks extension, not file content/magic numbers
        # An attacker could modify a malicious file's header to match image magic numbers
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        user_id = session.get('user_id')
        save_profile_picture(user_id, filename)
        
        flash('Profile picture updated', 'success')
        
    return redirect(url_for('dashboard'))

# Comments section - Vulnerable to XSS
@app.route('/comments', methods=['GET', 'POST'])
@login_required
def comments():
    if request.method == 'POST':
        comment_text = request.form.get('comment')
        user_id = session.get('user_id')
        
        # Vulnerability: No sanitization of user input
        add_comment(user_id, comment_text)
        flash('Comment added', 'success')

    all_comments = get_comments()
    return render_template('comments.html', comments=all_comments)

@app.route('/api-docs')
def api_docs():
    # Vulnerability: Exposes API endpoints and methods without requiring authentication
    return render_template('api_docs.html')

# API endpoint to get user balance - Vulnerable to BOLA
@app.route('/api/balance/<int:user_id>', methods=['GET'])
def api_get_balance(user_id):
    # Vulnerability: No authorization check
    balance = get_balance(user_id)
    return jsonify({'user_id': user_id, 'balance': balance})

# For debugging purposes only
@app.route('/test-static')
def test_static():
    return """
    <html>
    <head>
        <title>Static Test</title>
    </head>
    <body>
        <h1>Testing Static Files</h1>
        <p>CSS file path: /static/style.css</p>
        <div style="border:1px solid red; padding:10px;">
            This should be visible regardless of CSS.
        </div>
    </body>
    </html>
    """

# URL fetcher page
@app.route('/url-fetcher')
@login_required
def url_fetcher():
    return render_template('url_fetcher.html')

@app.route('/auth/api/fetch-internal', methods=['GET', 'POST'])
def fetch_internal():
    # Get URL from query params for GET or form data for POST
    url = request.args.get('url') if request.method == 'GET' else request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # Get the session cookie from the current request
        session_cookie = request.cookies.get('session')
        
        # Prepare headers with the session cookie
        headers = {
            'Cookie': f'session={session_cookie}'
        }
        
        # Make the request with the session cookie
        response = requests.get(url, 
                              verify=False, 
                              timeout=5,
                              headers=headers,
                              cookies={'session': session_cookie})
        
        return jsonify({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text
        })
    except Exception as e:
        return jsonify({
            'error': 'Failed to fetch URL',
            'details': str(e)
        }), 500

# Run the app
if __name__ == '__main__':
    app.run(debug=True) 