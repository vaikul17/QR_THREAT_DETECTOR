from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from supabase import create_client, Client
import io
import csv
import datetime
from datetime import datetime, timedelta
from modules.qr_decoder import decode_qr, decode_qr_from_base64
from modules.url_analyzer import analyze_url
from modules.risk_engine import calculate_risk
from modules.qr_generator import generate_qr_code
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "qr_threat_detector_secret_key_2024"

# Configuration
BASE_DIR = "."
UPLOAD_FOLDER = "static/uploads"
REPORT_FOLDER = "static/reports"

# Supabase SDK Configuration
SUPABASE_URL = "https://eeloeocxzuaagnhmklmf.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVlbG9lb2N4enVhYWduaG1rbG1mIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM0MDkyNDIsImV4cCI6MjA4ODk4NTI0Mn0.RYd9MHMF7JXu3hdLrAGxFcWX9_ywgJNkuvAl1m2jR-Q"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Bulletproof check for Vercel/Read-Only filesystem
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)
except (PermissionError, OSError):
    # If we get a permission error (e.g. on Vercel serverless), switch EVERYTHING to /tmp
    BASE_DIR = "/tmp"
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static/uploads")
    REPORT_FOLDER = os.path.join(BASE_DIR, "static/reports")
    
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(REPORT_FOLDER, exist_ok=True)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, password_hash, role='user', created_at=None):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.created_at = created_at

@login_manager.user_loader
def load_user(user_id):
    try:
        response = supabase.table('users').select('*').eq('id', user_id).execute()
        if response.data:
            user = response.data[0]
            return User(user['id'], user['username'], user['email'], user['password_hash'], user['role'], user['created_at'])
    except Exception as e:
        print(f"Error loading user {user_id}: {e}")
    return None

# Helper functions
def log_scan(user_id, url, risk, category='general', analysis=None):
    try:
        data = {
            "user_id": user_id,
            "url": url,
            "score": risk['score'],
            "verdict": risk['verdict'],
            "category": category,
            "analysis": analysis,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        response = supabase.table('scans').insert(data).execute()
        if response.data:
            return response.data[0]['id']
    except Exception as e:
        print(f"Error logging scan: {e}")
    return None

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template("index.html", page='home')

@app.route("/home")
def home():
    return render_template("index.html", page='home')

# Authentication routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        remember = request.form.get("remember", False)
        
        try:
            response = supabase.table('users').select('*').eq('username', username).execute()
            if response.data:
                user = response.data[0]
                if check_password_hash(user['password_hash'], password):
                    user_obj = User(user['id'], user['username'], user['email'], 
                                  user['password_hash'], user['role'], user['created_at'])
                    login_user(user_obj, remember=remember)
                    
                    # Update theme preference
                    session['theme'] = user.get('theme', 'dark')
                    
                    flash(f'Welcome back, {username}!', 'success')
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('dashboard'))
            
            flash('Invalid username or password', 'error')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template("login.html", page='login')

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template("register.html")
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template("register.html")
        
        try:
            # Check if user exists
            response = supabase.table('users').select('*').or_(f'username.eq.{username},email.eq.{email}').execute()
            if response.data:
                flash('Username or email already exists', 'error')
                return render_template("register.html")
            
            # Create new user
            password_hash = generate_password_hash(password)
            user_data = {
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "role": "user"
            }
            supabase.table('users').insert(user_data).execute()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template("register.html", page='register')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Main scan route
@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    result = None
    if request.method == "POST":
        # Handle file upload
        if 'qr' in request.files and request.files['qr'].filename:
            file = request.files['qr']
            filename = f"scan_{int(datetime.now().timestamp())}_{secure_filename(file.filename)}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            uploaded_url = url_for('static', filename=f'uploads/{filename}')

            url = decode_qr(filepath)
            analysis = analyze_url(url)
            risk = calculate_risk(analysis)
            
            scan_id = log_scan(current_user.id, url, risk, analysis=analysis)
            result = {
                "url": url,
                "risk": risk,
                "analysis": analysis,
                "scan_id": scan_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "uploaded_file": uploaded_url
            }
        
        # Handle URL input
        elif 'url_input' in request.form and request.form['url_input']:
            url = request.form['url_input']
            analysis = analyze_url(url)
            risk = calculate_risk(analysis)
            
            scan_id = log_scan(current_user.id, url, risk, analysis=analysis)
            result = {
                "url": url,
                "risk": risk,
                "analysis": analysis,
                "scan_id": scan_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    
    return render_template("index.html", page='scan', result=result)

# Bulk scan route
@app.route("/bulk_scan", methods=["GET", "POST"])
@login_required
def bulk_scan():
    results = []
    if request.method == "POST":
        if 'qr_files' in request.files:
            files = request.files.getlist('qr_files')
            for file in files:
                if file.filename:
                    filename = f"bulk_{int(datetime.now().timestamp())}_{secure_filename(file.filename)}"
                    filepath = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(filepath)
                    
                    try:
                        url = decode_qr(filepath)
                        analysis = analyze_url(url)
                        risk = calculate_risk(analysis)
                        scan_id = log_scan(current_user.id, url, risk, category='bulk', analysis=analysis)
                        results.append({
                            "url": url,
                            "risk": risk,
                            "scan_id": scan_id,
                            "status": "success",
                            "uploaded_file": url_for('static', filename=f'uploads/{filename}')
                        })
                    except Exception as e:
                        results.append({
                            "filename": file.filename,
                            "status": "error",
                            "error": str(e)
                        })
    
    return render_template("bulk_scan.html", page='bulk_scan', results=results)

# Dashboard route
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        # Get statistics: verdict counts
        scans_res = supabase.table('scans').select('verdict').eq('user_id', current_user.id).execute()
        stats = {}
        for row in scans_res.data:
            v = row['verdict']
            stats[v] = stats.get(v, 0) + 1
        
        # Get recent scans
        recent_res = supabase.table('scans').select('*').eq('user_id', current_user.id).order('timestamp', desc=True).limit(10).execute()
        recent_scans = recent_res.data
        
        # Get category stats
        category_stats = {}
        for row in scans_res.data:
            # We already have all scans in scans_res.data, but wait, scans_res only selected verdict.
            # Let's just fetch all needed columns in one go or do multiple queries if needed.
            # Actually, for counts, multiple queries or one plus processing is fine.
            pass
        
        # Re-fetch for category stats if needed or select more columns initially
        full_scans_res = supabase.table('scans').select('verdict, category, favorite').eq('user_id', current_user.id).execute()
        category_stats = {}
        favorite_count = 0
        for row in full_scans_res.data:
            c = row['category']
            category_stats[c] = category_stats.get(c, 0) + 1
            if row['favorite']:
                favorite_count += 1
        
        total_scans = len(full_scans_res.data)
        
        return render_template("dashboard.html", page='dashboard', 
                             stats=stats, 
                             recent_scans=recent_scans,
                             category_stats=category_stats,
                             total_scans=total_scans,
                             favorite_count=favorite_count)
    except Exception as e:
        print(f"Error in dashboard: {e}")
        return render_template("dashboard.html", page='dashboard', 
                             stats={}, 
                             recent_scans=[],
                             category_stats={},
                             total_scans=0,
                             favorite_count=0)

# History route with filters
@app.route("/history")
@login_required
def history():
    search = request.args.get('search', '')
    verdict_filter = request.args.get('verdict', '')
    category_filter = request.args.get('category', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    try:
        query = supabase.table('scans').select('*', count='exact').eq('user_id', current_user.id)
        
        if search:
            query = query.ilike('url', f'%{search}%')
        if verdict_filter:
            query = query.eq('verdict', verdict_filter)
        if category_filter:
            query = query.eq('category', category_filter)
        if date_from:
            query = query.gte('timestamp', date_from)
        if date_to:
            query = query.lte('timestamp', date_to)
            
        start = (page - 1) * per_page
        end = start + per_page - 1
        
        response = query.order('timestamp', desc=True).range(start, end).execute()
        rows = response.data
        total = response.count
        total_pages = (total + per_page - 1) // per_page if total else 0
        
        return render_template("history.html", 
                             page='history',
                             rows=rows, 
                             search=search,
                             verdict_filter=verdict_filter,
                             category_filter=category_filter,
                             date_from=date_from,
                             date_to=date_to,
                             current_page=page,
                             total_pages=total_pages)
    except Exception as e:
        print(f"Error in history: {e}")
        return render_template("history.html", page='history', rows=[], total_pages=0)

# Toggle favorite
@app.route("/toggle_favorite/<int:scan_id>")
@login_required
def toggle_favorite(scan_id):
    try:
        response = supabase.table('scans').select('favorite').eq('id', scan_id).eq('user_id', current_user.id).execute()
        if response.data:
            current_fav = response.data[0]['favorite']
            new_fav = 0 if current_fav else 1
            supabase.table('scans').update({"favorite": new_fav}).eq('id', scan_id).execute()
    except Exception as e:
        print(f"Error toggling favorite: {e}")
    return redirect(request.referrer or url_for('history'))

# Delete scan
@app.route("/delete_scan/<int:scan_id>")
@login_required
def delete_scan(scan_id):
    try:
        supabase.table('scans').delete().eq('id', scan_id).eq('user_id', current_user.id).execute()
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting scan: {str(e)}', 'error')
    return redirect(request.referrer or url_for('history'))

# Scan Details route
@app.route("/scan/<int:scan_id>")
@login_required
def scan_details(scan_id):
    try:
        response = supabase.table('scans').select('*').eq('id', scan_id).eq('user_id', current_user.id).execute()
        if response.data:
            scan = response.data[0]
            return render_template("scan_details.html", scan=scan)
        else:
            flash('Scan not found', 'error')
            return redirect(url_for('history'))
    except Exception as e:
        flash(f'Error fetching scan details: {str(e)}', 'error')
        return redirect(url_for('history'))

# Profile route
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        
        try:
            # Verify current password
            response = supabase.table('users').select('password_hash').eq('id', current_user.id).execute()
            if not response.data or not check_password_hash(response.data[0]['password_hash'], current_password):
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
            
            update_data = {}
            # Update username/email
            if username != current_user.username:
                check_res = supabase.table('users').select('id').eq('username', username).neq('id', current_user.id).execute()
                if check_res.data:
                    flash('Username already exists', 'error')
                    return redirect(url_for('profile'))
                update_data['username'] = username
            
            if email != current_user.email:
                check_res = supabase.table('users').select('id').eq('email', email).neq('id', current_user.id).execute()
                if check_res.data:
                    flash('Email already exists', 'error')
                    return redirect(url_for('profile'))
                update_data['email'] = email
            
            # Update password if provided
            if new_password:
                update_data['password_hash'] = generate_password_hash(new_password)
            
            if update_data:
                supabase.table('users').update(update_data).eq('id', current_user.id).execute()
                flash('Profile updated successfully', 'success')
            
            return redirect(url_for('profile'))
        except Exception as e:
            flash(f'Error updating profile: {str(e)}', 'error')
    
    return render_template("profile.html", page='profile')

# Settings route
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        theme = request.form.get("theme")
        try:
            supabase.table('users').update({"theme": theme}).eq('id', current_user.id).execute()
            session['theme'] = theme
            flash('Settings saved successfully', 'success')
        except Exception as e:
            flash(f'Error saving settings: {str(e)}', 'error')
        return redirect(url_for('settings'))
    
    return render_template("settings.html", page='settings')

# Generate QR route
@app.route("/generate_qr", methods=["GET", "POST"])
@login_required
def generate_qr():
    qr_image = None
    if request.method == "POST":
        url = request.form.get("url")
        if url:
            qr_image = generate_qr_code(url)
    
    return render_template("generate_qr.html", page='generate_qr', qr_image=qr_image)

# Export routes

@app.route("/export_pdf")
@login_required
def export_pdf():
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    
    try:
        # Fetch scans
        rows_res = supabase.table('scans').select('*').eq('user_id', current_user.id).order('timestamp', desc=True).limit(100).execute()
        rows = rows_res.data
        
        # Calculate stats from rows
        stats_dict = {}
        for row in rows:
            v = row['verdict']
            stats_dict[v] = stats_dict.get(v, 0) + 1
        
        # Use a physical file in /tmp (BASE_DIR)
        pdf_path = os.path.join(BASE_DIR, f"scan_report_{current_user.id}.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=30)
        elements.append(Paragraph("QR Threat Detector - Scan Report", title_style))
        elements.append(Spacer(1, 20))
        
        # Summary
        summary_text = "<br/>".join([f"{v}: {count}" for v, count in stats_dict.items()])
        elements.append(Paragraph(f"<b>Summary:</b><br/>{summary_text}", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Table
        data = [['URL', 'Score', 'Verdict', 'Category', 'Timestamp']]
        for row in rows:
            data.append([row['url'][:50] + '...' if len(row['url']) > 50 else row['url'],
                        str(row['score']), row['verdict'], row['category'], row['timestamp']])
        
        table = Table(data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)
        
        doc.build(elements)
        
        with open(pdf_path, 'rb') as f:
            pdf_bytes = f.read()
            
        from flask import Response
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename=scan_report_{datetime.now().strftime("%Y%m%d")}.pdf'
            }
        )
    except Exception as e:
        flash(f"Error generating PDF: {str(e)}", "error")
        return redirect(url_for('history'))

# API Routes
@app.route("/api/scan", methods=["POST"])
def api_scan():
    """API endpoint for scanning QR codes"""
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url']
    analysis = analyze_url(url)
    risk = calculate_risk(analysis)
    
    return jsonify({
        'url': url,
        'analysis': analysis,
        'risk': risk,
        'timestamp': datetime.now().isoformat()
    })

@app.route("/api/scan_batch", methods=["POST"])
def api_scan_batch():
    """API endpoint for batch scanning"""
    data = request.get_json()
    
    if not data or 'urls' not in data:
        return jsonify({'error': 'URLs array is required'}), 400
    
    urls = data['urls']
    results = []
    
    for url in urls:
        analysis = analyze_url(url)
        risk = calculate_risk(analysis)
        results.append({
            'url': url,
            'analysis': analysis,
            'risk': risk
        })
    
    return jsonify({'results': results})

# Admin routes
@app.route("/admin")
@login_required
@admin_required
def admin():
    try:
        # Get all users
        users_res = supabase.table('users').select('*').order('created_at', desc=True).execute()
        users = users_res.data
        
        # Get total scans
        scans_count_res = supabase.table('scans').select('*', count='exact').execute()
        total_scans = scans_count_res.count
        
        # Get scans today
        today = datetime.now().strftime("%Y-%m-%d")
        today_scans_res = supabase.table('scans').select('*', count='exact').gte('timestamp', today).execute()
        today_scans = today_scans_res.count
        
        # Get all scans (recent) and flatten the username
        recent_res = supabase.table('scans').select('*, users(username)').order('timestamp', desc=True).limit(50).execute()
        recent_all_scans = []
        for scan in recent_res.data:
            # Flatten users(username) into the scan dictionary
            if 'users' in scan and scan['users']:
                scan['username'] = scan['users'].get('username', 'Unknown')
            else:
                scan['username'] = 'Unknown'
            recent_all_scans.append(scan)
        
        return render_template("admin.html", page='admin',
                             users=users,
                             total_scans=total_scans,
                             today_scans=today_scans,
                             recent_all_scans=recent_all_scans)
    except Exception as e:
        flash(f"Error in admin dashboard: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route("/admin/user/<int:user_id>/delete")
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin'))
    
    try:
        supabase.table('scans').delete().eq('user_id', user_id).execute()
        supabase.table('users').delete().eq('id', user_id).execute()
        flash('User deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting user: {str(e)}', 'error')
        
    return redirect(url_for('admin'))

@app.route("/admin/scan/<int:scan_id>/delete")
@login_required
@admin_required
def admin_delete_scan(scan_id):
    try:
        supabase.table('scans').delete().eq('id', scan_id).execute()
        flash('Scan deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting scan: {str(e)}', 'error')
    return redirect(url_for('admin'))

@app.route("/admin/user/<int:user_id>/promote")
@login_required
@admin_required
def promote_user(user_id):
    try:
        supabase.table('users').update({"role": "admin"}).eq('id', user_id).execute()
        flash('User promoted to admin', 'success')
    except Exception as e:
        flash(f'Error promoting user: {str(e)}', 'error')
    return redirect(url_for('admin'))

# API Key management removed

# API Key management removed

# Theme toggle
@app.route("/toggle_theme")
def toggle_theme():
    current_theme = session.get('theme', 'dark')
    new_theme = 'light' if current_theme == 'dark' else 'dark'
    session['theme'] = new_theme
    
    if current_user.is_authenticated:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET theme = ? WHERE id = ?", (new_theme, current_user.id))
        conn.commit()
        conn.close()
    
    return redirect(request.referrer or url_for('dashboard'))

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", error="Internal server error"), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
