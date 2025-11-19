import os
import io
import uuid
import webbrowser
import secrets
import hashlib
from datetime import datetime, timedelta
import dns.resolver
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from cryptography.fernet import Fernet

# -------------------- Setup --------------------
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or secrets.token_hex(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///lab_results.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    raise RuntimeError("Missing FERNET_KEY in .env — generate one with Fernet.generate_key()")
fernet = Fernet(FERNET_KEY.encode())

# -------------------- Models --------------------
class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(30))
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # patient, staff, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Result(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    patient_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    uploaded_by = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(300), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(20), default='pending')
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    viewed_at = db.Column(db.DateTime, nullable=True)

class Log(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    device_info = db.Column(db.String(300))
    details = db.Column(db.Text)

class OTP(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'))
    code = db.Column(db.String(10))
    expires_at = db.Column(db.DateTime)
    used = db.Column(db.Boolean, default=False)

# -------------------- Helpers --------------------
def is_valid_email_domain(email: str) -> bool:
    try:
        if "@" not in email:
            return False
        domain = email.split("@", 1)[1].lower()
        DISPOSABLE_DOMAINS = {
            "tempmail.com", "mailinator.com", "guerrillamail.com",
            "10minutemail.com", "trashmail.com"
        }
        if domain in DISPOSABLE_DOMAINS:
            return False
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception:
        return False

def compute_hash(bytes_data):
    return hashlib.sha256(bytes_data).hexdigest()

def encrypt_and_save_file(file_bytes, result_id):
    enc = fernet.encrypt(file_bytes)
    path = os.path.join(app.config['UPLOAD_FOLDER'], f"{result_id}.enc")
    with open(path, "wb") as f:
        f.write(enc)
    return path

def decrypt_file(path):
    with open(path, "rb") as f:
        enc = f.read()
    return fernet.decrypt(enc)

def log_action(user_id, action, details=""):
    ip = None
    ua = None
    try:
        ip = request.remote_addr
        ua = request.headers.get('User-Agent')
    except Exception:
        pass
    l = Log(user_id=user_id, action=action, ip_address=ip, device_info=ua, details=details)
    db.session.add(l)
    db.session.commit()

def send_notification_simulation(patient_email, message):
    print(f"[NOTIFICATION -> {patient_email}] {message}")

def generate_otp_for_user(user):
    code = str(secrets.randbelow(900000) + 100000)
    expires = datetime.utcnow() + timedelta(minutes=5)
    otp = OTP(user_id=user.id, code=code, expires_at=expires)
    db.session.add(otp)
    db.session.commit()
    print(f"[OTP for {user.email}] Code: {code} (expires {expires.isoformat()} UTC)")
    return otp

def verify_otp(user_id, code):
    otp = OTP.query.filter_by(user_id=user_id, code=code, used=False).order_by(OTP.expires_at.desc()).first()
    if not otp or datetime.utcnow() > otp.expires_at:
        return False
    otp.used = True
    db.session.commit()
    return True

# -------------------- Routes --------------------
@app.route('/')
def index():
    if User.query.first() is None:
        return redirect(url_for('register'))
    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('forensic_dashboard'))
        elif role in ['staff', 'receptionist', 'patient']:
            return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --- LOGIN ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            log_action(user.id, 'login_success')
            if user.role == 'admin':
                return redirect(url_for('forensic_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            if user:
                log_action(user.id, 'login_failed', details='bad password or other')
            flash("Invalid credentials", "danger")
    return render_template('login.html')

# --- REGISTER ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    no_users_exist = User.query.first() is None
    if not no_users_exist:
        if 'user_id' not in session:
            flash("Only staff/admin can register users. Please log in.", "warning")
            return redirect(url_for('login'))
        creator = User.query.get(session['user_id'])
        if not creator or creator.role not in ('staff', 'admin'):
            flash("Access denied. Only staff or admin can register users.", "danger")
            return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        requested_role = request.form.get('role', 'patient').lower()
        if not name or not email or not password:
            flash("Name, email and password are required.", "warning")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "warning")
            return redirect(url_for('register'))
        if no_users_exist:
            role_to_set = requested_role if requested_role in ('admin', 'staff') else 'admin'
        else:
            role_to_set = requested_role if creator.role == 'admin' and requested_role in ('admin', 'staff', 'patient') else 'patient'
        hashed_pw = bcrypt.generate_password_hash(password).decode()
        new_user = User(name=name, email=email, password=hashed_pw, role=role_to_set)
        db.session.add(new_user)
        db.session.commit()
        flash("User registered successfully!", "success")
        if no_users_exist:
            session['user_id'] = new_user.id
            session['role'] = new_user.role
            if new_user.role == 'admin':
                return redirect(url_for('forensic_dashboard'))
            return redirect(url_for('dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('register.html')

# --- LOGOUT ---
@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    session.clear()
    if user_id:
        log_action(user_id, 'logout')
    return redirect(url_for('login'))

# --- DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    if user.role in ['staff', 'receptionist']:
        patients = User.query.filter_by(role='patient').order_by(User.created_at.desc()).all()
        return render_template('staff_dashboard.html', user=user, patients=patients)
    elif user.role == 'admin':
        return redirect(url_for('forensic_dashboard'))
    else:
        results = Result.query.filter_by(patient_id=user.id).order_by(Result.uploaded_at.desc()).all()
        return render_template('patient_dashboard.html', user=user, results=results)

# --- FORENSIC (ADMIN) ---
@app.route('/forensic')
def forensic_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Admin access only", "danger")
        return redirect(url_for('login'))
    users = User.query.order_by(User.created_at.desc()).all()
    results = Result.query.order_by(Result.uploaded_at.desc()).all()
    total_patients = User.query.filter_by(role='patient').count()
    total_staff = User.query.filter_by(role='staff').count()
    total_admins = User.query.filter_by(role='admin').count()
    total_uploads = Result.query.count()
    logs = Log.query.order_by(Log.timestamp.desc()).limit(50).all()
    return render_template(
        'forensic_dashboard.html',
        users=users, results=results, logs=logs,
        total_patients=total_patients, total_staff=total_staff,
        total_admins=total_admins, total_uploads=total_uploads
    )

# --- STAFF: register patient ---
@app.route('/register_patient', methods=['GET', 'POST'])
def register_patient():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'staff':
        flash("Only staff members can register patients.", "danger")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        if not name or not email:
            flash("Name and email are required.", "warning")
            return redirect(url_for('register_patient'))
        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "warning")
            return redirect(url_for('register_patient'))
        if not is_valid_email_domain(email):
            flash("Invalid or non-existent email domain. Please use a real email.", "danger")
            return redirect(url_for('register_patient'))
        if User.query.filter_by(email=email).first():
            flash("This email is already registered.", "warning")
            return redirect(url_for('register_patient'))
        hashed = bcrypt.generate_password_hash("patient123").decode()
        new_patient = User(name=name, email=email, password=hashed, role='patient')
        db.session.add(new_patient)
        db.session.commit()
        log_action(session['user_id'], 'register_patient', details=f"patient_id={new_patient.id}, email={email}")
        flash(f"Patient '{name}' registered successfully!", "success")
        return redirect(url_for('dashboard'))
    return render_template('register_patient.html')

# --- UPLOAD RESULTS ---
@app.route('/upload_result/<patient_id>', methods=['GET', 'POST'])
def upload_result_for_patient(patient_id):
    try:
        if 'user_id' not in session or session.get('role') not in ['staff', 'receptionist']:
            flash("Access denied", "danger")
            return redirect(url_for('login'))
        patient = User.query.get(patient_id)
        if not patient or patient.role != 'patient':
            flash("Invalid patient.", "warning")
            return redirect(url_for('dashboard'))
        if request.method == 'POST':
            file = request.files.get('file')
            if not file or file.filename.strip() == '':
                flash("Please select a file to upload.", "warning")
                return redirect(request.url)
            file_bytes = file.read()
            file_hash = compute_hash(file_bytes)
            result_id = str(uuid.uuid4())
            encrypted_path = encrypt_and_save_file(file_bytes, result_id)
            result = Result(
                id=result_id,
                patient_id=patient.id,
                uploaded_by=session['user_id'],
                file_path=encrypted_path,
                file_hash=file_hash,
                status='uploaded'
            )
            db.session.add(result)
            db.session.commit()
            log_action(session['user_id'], 'upload_result', details=f"result_id={result.id}, patient_id={patient.id}")
            send_notification_simulation(patient.email, f"Your lab result (ID: {result.id}) has been uploaded. Log in to view it.")
            flash(f"Result uploaded successfully and notification sent to {patient.email}", "success")
            return redirect(url_for('dashboard'))
        return render_template('upload.html', patient=patient)
    except Exception as e:
        print(f"[UPLOAD ERROR] {e}")
        flash("An unexpected error occurred while uploading the result.", "danger")
        return redirect(url_for('dashboard'))

# --- OTP / View / Download ---
@app.route('/request_view/<result_id>', methods=['GET'])
def request_view(result_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    res = Result.query.get(result_id)
    if not res or res.patient_id != session['user_id']:
        flash("Result not found or access denied.", "warning")
        return redirect(url_for('dashboard'))
    user = User.query.get(session['user_id'])
    generate_otp_for_user(user)
    log_action(user.id, 'otp_requested', details=f"result_id={result_id}")
    flash("OTP sent (simulated). Check server console for the code.", "info")
    return redirect(url_for('enter_otp', result_id=result_id))

@app.route('/enter_otp/<result_id>', methods=['GET', 'POST'])
def enter_otp(result_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form.get('otp', '').strip()
        if verify_otp(session['user_id'], code):
            res = Result.query.get(result_id)
            res.status = 'viewed'
            res.viewed_at = datetime.utcnow()
            db.session.commit()
            log_action(session['user_id'], 'view_result', details=f"result_id={result_id}")
            return redirect(url_for('view_result', result_id=result_id))
        else:
            flash("Invalid or expired OTP", "warning")
    return render_template('enter_otp.html', result_id=result_id)

@app.route('/view_result/<result_id>')
def view_result(result_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    res = Result.query.get(result_id)
    if not res or res.patient_id != session['user_id']:
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))
    return render_template('result_view.html', result=res)

@app.route('/download_result/<result_id>')
def download_result(result_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    res = Result.query.get(result_id)
    if not res or res.patient_id != session['user_id']:
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))
    plaintext = decrypt_file(res.file_path)
    return send_file(io.BytesIO(plaintext), download_name=f"result_{result_id}.pdf", as_attachment=True)

# --- Admin uploads view ---
from sqlalchemy.orm import aliased

@app.route('/admin/uploads')
def admin_uploads():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('login'))
    patient = aliased(User)
    uploader = aliased(User)
    uploads = (
        db.session.query(
            Result,
            patient.name.label('patient_name'),
            patient.email.label('patient_email'),
            patient.role.label('patient_role'),
            uploader.name.label('uploaded_by_name'),
        )
        .join(patient, Result.patient_id == patient.id)
        .join(uploader, Result.uploaded_by == uploader.id)
        .order_by(Result.uploaded_at.desc())
        .all()
    )
    return render_template('admin_upload.html', uploads=uploads)

# --- Delete upload ---
@app.route('/upload/delete/<upload_id>', methods=['POST'])
def upload_delete(upload_id):
    # Ensure only admins can delete
    if session.get('user_role') != 'admin':
        flash("Only admin users can delete uploads.")
        return redirect(request.referrer or url_for('forensic_dashboard'))

    deleted_by = session.get('user_id', 'admin')
    conn = _get_db_conn()
    if not conn:
        flash('Database not available')
        return redirect(request.referrer or url_for('forensic_dashboard'))

    conn.execute(
        'UPDATE uploads SET status = ?, deleted_by = ?, deleted_at = CURRENT_TIMESTAMP WHERE id = ?',
        ('deleted', deleted_by, upload_id)
    )
    conn.execute(
        'INSERT INTO logs (user_id, action, details) VALUES (?, ?, ?)',
        (deleted_by, 'delete_upload', f'upload_id={upload_id}')
    )
    conn.commit()
    conn.close()

    flash(f'Upload {upload_id} successfully deleted by admin.')
    return redirect(request.referrer or url_for('forensic_dashboard'))
# -------------------- Run --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("\n[DEBUG] Flask registered endpoints:")
        for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
            print(f"{rule.endpoint} -> {rule.rule}")
        try:
            webbrowser.open_new("http://127.0.0.1:5000")
        except Exception:
            pass
    app.run(host='127.0.0.1', port=5000, debug=True)
