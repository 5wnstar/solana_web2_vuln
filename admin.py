from flask import Blueprint, render_template, session, redirect, url_for, request, flash, jsonify
from database import (
    is_admin, get_all_users, get_user_by_id, update_user_balance, toggle_user_status,
    log_access, get_access_logs, get_all_transactions, reverse_transaction,
    moderate_comment, get_comments, delete_comment
)
from functools import wraps

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'warning')
            return redirect(url_for('auth.login'))
        if not is_admin(session['user_id']):
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@admin_required
def admin_dashboard():
    users = get_all_users()
    transactions = get_all_transactions()
    access_logs = get_access_logs()
    return render_template('admin/dashboard.html', 
                         users=users, 
                         transactions=transactions,
                         access_logs=access_logs)

@admin_bp.route('/users')
@admin_required
def user_management():
    users = get_all_users()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    if toggle_user_status(user_id):
        flash('User status updated successfully', 'success')
    else:
        flash('Failed to update user status', 'danger')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/user/<int:user_id>/balance', methods=['POST'])
@admin_required
def update_balance(user_id):
    new_balance = float(request.form.get('balance'))
    if update_user_balance(user_id, new_balance):
        flash('User balance updated successfully', 'success')
    else:
        flash('Failed to update user balance', 'danger')
    return redirect(url_for('admin.user_management'))

@admin_bp.route('/transactions')
@admin_required
def transaction_management():
    transactions = get_all_transactions()
    return render_template('admin/transactions.html', transactions=transactions)

@admin_bp.route('/transaction/<int:tx_id>/reverse', methods=['POST'])
@admin_required
def reverse_tx(tx_id):
    if reverse_transaction(tx_id):
        flash('Transaction reversed successfully', 'success')
    else:
        flash('Failed to reverse transaction', 'danger')
    return redirect(url_for('admin.transaction_management'))

@admin_bp.route('/comments')
@admin_required
def comment_moderation():
    comments = get_comments()
    return render_template('admin/comments.html', comments=comments)

@admin_bp.route('/comment/<int:comment_id>/moderate', methods=['POST'])
@admin_required
def moderate_comment_action(comment_id):
    action = request.form.get('action')
    if action == 'approve':
        moderate_comment(comment_id, True)
        flash('Comment approved', 'success')
    elif action == 'reject':
        moderate_comment(comment_id, False)
        flash('Comment rejected', 'success')
    return redirect(url_for('admin.comment_moderation'))

@admin_bp.route('/comment/<int:comment_id>/delete', methods=['POST'])
@admin_required
def delete_comment_route(comment_id):
    if delete_comment(comment_id):
        flash('Comment deleted successfully', 'success')
    else:
        flash('Failed to delete comment', 'danger')
    return redirect(url_for('admin.comment_moderation'))

@admin_bp.route('/logs')
@admin_required
def access_logs():
    logs = get_access_logs()
    return render_template('admin/logs.html', logs=logs)

@admin_bp.route('/api/users', methods=['GET'])
@admin_required
def api_users():
    users = get_all_users()
    return jsonify([dict(user) for user in users])

@admin_bp.route('/api/transactions', methods=['GET'])
@admin_required
def api_transactions():
    transactions = get_all_transactions()
    return jsonify([dict(tx) for tx in transactions]) 