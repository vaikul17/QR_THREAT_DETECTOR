from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import psycopg2
from psycopg2.extras import RealDictCursor
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

# Supabase PostgreSQL Connection String
# WARNING: Vercel does not support Supabase's new IPv6 direct connections (Port 5432).
# We MUST use the IPv4 connection pooler on Port 6543 for Vercel Serverless.
# URL-encoded to handle special characters in the password (@ -> %40, # -> %23)
DB_URL = "postgresql://postgres:9S%40%23V8jP2cKL5mX%40@aws-0-ap-south-1.pooler.supabase.com:6543/postgres?pgbouncer=true"

# For SQLAlchemy/Vercel compat, sometimes "postgres://" needs to be "postgresql://"
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
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

# Helper functions
def get_db_connection():
    # Connect directly to the external Supabase Postgres database
    conn = psycopg2.connect(DB_URL)
    return conn

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['password_hash'], user['role'], user['created_at'])
    return None

# Database initialization
def init_db():
    conn = psycopg2.connect(DB_URL)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id SERIAL PRIMARY KEY, username TEXT UNIQUE, email TEXT UNIQUE, 
                  password_hash TEXT, role TEXT DEFAULT 'user', theme TEXT DEFAULT 'dark',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Scans table
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id SERIAL PRIMARY KEY, user_id INTEGER, url TEXT, 
                  score INTEGER, verdict TEXT, category TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  favorite INTEGER DEFAULT 0, notes TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Settings table
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (id SERIAL PRIMARY KEY, user_id INTEGER, key TEXT, value TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Create default admin user if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_hash = generate_password_hash("admin123")
        c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (%s, %s, %s, %s)",
                  ("admin", "admin@qrthreat.com", admin_hash, "admin"))
    
    conn.commit()
    conn.close()

# We deliberately DO NOT call init_db() globally here anymore.
# Vercel's serverless cold-boots will crash or hang trying to run DDL creation queries.
# Tables MUST be created by pasting init_supabase.sql directly into the Supabase SQL editor.

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_scan(user_id, url, risk, category='general'):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO scans (user_id, url, score, verdict, category, timestamp) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
              (user_id, url, risk['score'], risk['verdict'], category, timestamp))
    scan_id = c.fetchone()[0]
    conn.commit()
    conn.close()
    return scan_id

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
        
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            user_obj = User(user['id'], user['username'], user['email'], 
                          user['password_hash'], user['role'], user['created_at'])
            login_user(user_obj, remember=remember)
            
            # Update theme preference
            session['theme'] = user['theme'] if 'theme' in user.keys() and user['theme'] else 'dark'
            
            flash(f'Welcome back, {username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
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
        
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if user exists
        c.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        if c.fetchone():
            flash('Username or email already exists', 'error')
            conn.close()
            return render_template("register.html")
        
        # Create new user
        password_hash = generate_password_hash(password)
        try:
            c.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                      (username, email, password_hash))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
        finally:
            conn.close()
    
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
            
            scan_id = log_scan(current_user.id, url, risk)
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
            
            scan_id = log_scan(current_user.id, url, risk)
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
                        scan_id = log_scan(current_user.id, url, risk, 'bulk')
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
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    
    # Get statistics
    c.execute("SELECT verdict, COUNT(*) as count FROM scans WHERE user_id = %s GROUP BY verdict", (current_user.id,))
    stats = {row['verdict']: row['count'] for row in c.fetchall()}
    
    # Get recent scans
    c.execute("SELECT * FROM scans WHERE user_id = %s ORDER BY timestamp DESC LIMIT 10", (current_user.id,))
    recent_scans = c.fetchall()
    
    # Get category stats
    c.execute("SELECT category, COUNT(*) as count FROM scans WHERE user_id = %s GROUP BY category", (current_user.id,))
    category_stats = {row['category']: row['count'] for row in c.fetchall()}
    
    # Get total scans
    c.execute("SELECT COUNT(*) as total FROM scans WHERE user_id = %s", (current_user.id,))
    total_result = c.fetchone()
    total_scans = total_result['total'] if total_result else 0
    
    # Get favorite scans
    c.execute("SELECT COUNT(*) as fav FROM scans WHERE user_id = %s AND favorite = 1", (current_user.id,))
    fav_result = c.fetchone()
    favorite_count = fav_result['fav'] if fav_result else 0
    
    conn.close()
    
    return render_template("dashboard.html", page='dashboard', 
                         stats=stats, 
                         recent_scans=recent_scans,
                         category_stats=category_stats,
                         total_scans=total_scans,
                         favorite_count=favorite_count)

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
    
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    
    query = "SELECT * FROM scans WHERE user_id = %s"
    params = [current_user.id]
    
    if search:
        query += " AND url LIKE %s"
        params.append(f'%{search}%')
    if verdict_filter:
        query += " AND verdict = %s"
        params.append(verdict_filter)
    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)
    if date_from:
        query += " AND timestamp >= %s"
        params.append(date_from)
    if date_to:
        query += " AND timestamp <= %s"
        params.append(date_to)
    
    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([per_page, (page - 1) * per_page])
    
    c.execute(query, params)
    rows = c.fetchall()
    
    # Get total count for pagination
    count_query = "SELECT COUNT(*) as total FROM scans WHERE user_id = %s"
    count_params = [current_user.id]
    if search:
        count_query += " AND url LIKE %s"
        count_params.append(f'%{search}%')
    if verdict_filter:
        count_query += " AND verdict = %s"
        count_params.append(verdict_filter)
    if category_filter:
        count_query += " AND category = %s"
        count_params.append(category_filter)
    if date_from:
        count_query += " AND timestamp >= %s"
        count_params.append(date_from)
    if date_to:
        count_query += " AND timestamp <= %s"
        count_params.append(date_to)
    
    c.execute(count_query, count_params)
    result = c.fetchone()
    total = result['total'] if result else 0
    total_pages = (total + per_page - 1) // per_page
    
    conn.close()
    
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

# Toggle favorite
@app.route("/toggle_favorite/<int:scan_id>")
@login_required
def toggle_favorite(scan_id):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM scans WHERE id = %s AND user_id = %s", (scan_id, current_user.id))
    scan = c.fetchone()
    
    if scan:
        new_favorite = 0 if scan['favorite'] else 1
        c.execute("UPDATE scans SET favorite = %s WHERE id = %s", (new_favorite, scan_id))
        conn.commit()
    
    conn.close()
    return redirect(url_for('history'))

# Delete scan
@app.route("/delete_scan/<int:scan_id>")
@login_required
def delete_scan(scan_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id = %s AND user_id = %s", (scan_id, current_user.id))
    conn.commit()
    conn.close()
    flash('Scan deleted successfully', 'success')
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
        
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        
        # Verify current password
        c.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
        user = c.fetchone()
        
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect', 'error')
            conn.close()
            return redirect(url_for('profile'))
        
        # Update username/email
        if username != current_user.username:
            c.execute("SELECT * FROM users WHERE username = %s AND id != %s", (username, current_user.id))
            if c.fetchone():
                flash('Username already exists', 'error')
                conn.close()
                return redirect(url_for('profile'))
            c.execute("UPDATE users SET username = %s WHERE id = %s", (username, current_user.id))
        
        if email != current_user.email:
            c.execute("SELECT * FROM users WHERE email = %s AND id != %s", (email, current_user.id))
            if c.fetchone():
                flash('Email already exists', 'error')
                conn.close()
                return redirect(url_for('profile'))
            c.execute("UPDATE users SET email = %s WHERE id = %s", (email, current_user.id))
        
        # Update password if provided
        if new_password:
            password_hash = generate_password_hash(new_password)
            c.execute("UPDATE users SET password_hash = %s WHERE id = %s", (password_hash, current_user.id))
        
        conn.commit()
        conn.close()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template("profile.html", page='profile')

# Settings route
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        theme = request.form.get("theme")
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, current_user.id))
        conn.commit()
        conn.close()
        
        session['theme'] = theme
        flash('Settings saved successfully', 'success')
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
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT 100", (current_user.id,))
    rows = c.fetchall()
    # Query summary stats while connection still open
    c.execute("SELECT verdict, COUNT(*) as count FROM scans WHERE user_id = ? GROUP BY verdict", (current_user.id,))
    stats = c.fetchall()
    conn.close()

    # Use a physical file in /tmp (BASE_DIR) instead of memory buffer for Vercel stability
    pdf_path = os.path.join(BASE_DIR, f"scan_report_{current_user.id}.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=30)
    elements.append(Paragraph("QR Threat Detector - Scan Report", title_style))
    elements.append(Spacer(1, 20))
    
    # Summary
    summary = "<br/>".join([f"{row['verdict']}: {row['count']}" for row in stats])
    elements.append(Paragraph(f"<b>Summary:</b><br/>{summary}", styles['Normal']))
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
    
    # Read the file back into memory to stream safely on Vercel
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
    conn = get_db_connection()
    c = conn.cursor()
    
    # Get all users
    c.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    
    # Get total scans
    c.execute("SELECT COUNT(*) as total FROM scans")
    total_scans = c.fetchone()['total']
    
    # Get scans today
    c.execute("SELECT COUNT(*) as today FROM scans WHERE DATE(timestamp) = DATE('now')")
    today_scans = c.fetchone()['today']
    
    # Get all scans (recent)
    c.execute("SELECT scans.*, users.username FROM scans LEFT JOIN users ON scans.user_id = users.id ORDER BY scans.timestamp DESC LIMIT 50")
    recent_all_scans = c.fetchall()
    
    conn.close()
    
    return render_template("admin.html", page='admin',
                         users=users,
                         total_scans=total_scans,
                         today_scans=today_scans,
                         recent_all_scans=recent_all_scans)

@app.route("/admin/user/<int:user_id>/delete")
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin'))
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE user_id = %s", (user_id,))
    c.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route("/admin/scan/<int:scan_id>/delete")
@login_required
@admin_required
def admin_delete_scan(scan_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM scans WHERE id = %s", (scan_id,))
    conn.commit()
    conn.close()
    flash('Scan deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route("/admin/user/<int:user_id>/promote")
@login_required
@admin_required
def promote_user(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET role = 'admin' WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    flash('User promoted to admin', 'success')
    return redirect(url_for('admin'))

# Backup database
@app.route("/backup_db")
@login_required
@admin_required
def backup_db():
    from flask import Response
    
    # PostgreSQL cannot be copied as a file like SQLite.
    # To backup a Postgres DB natively on a Vercel runtime (no pg_dump),
    # we export key tables to a CSV as a lightweight backup.
    
    conn = get_db_connection()
    c = conn.cursor()
    
    # Create an in-memory string buffer for CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Backup Users
    writer.writerow(['--- USERS ---'])
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    if users:
        writer.writerow([i[0] for i in c.description]) # headers
        writer.writerows(users)
    
    # Backup Scans
    writer.writerow(['\n--- SCANS ---'])
    c.execute("SELECT * FROM scans")
    scans = c.fetchall()
    if scans:
        writer.writerow([i[0] for i in c.description]) # headers
        writer.writerows(scans)
    
    conn.close()
    
    # Get bytes
    backup_data = output.getvalue().encode('utf-8')
    
    return Response(
        backup_data,
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=postgres_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        }
    )

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
        c.execute("UPDATE users SET theme = %s WHERE id = %s", (new_theme, current_user.id))
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
