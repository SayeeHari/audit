import os, secrets, datetime, json, io
from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_file, abort, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')

DB_USER = os.getenv('DB_USER', 'audit_user')
DB_PASS = os.getenv('DB_PASS', 'Hari@2003')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_NAME = os.getenv('DB_NAME', 'secure_sdlc_audit')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}?charset=utf8mb4"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
UPLOAD_ROOT = os.path.join(BASE_DIR, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_ROOT

ALLOWED_EXCEL = {'xls', 'xlsx'}
ALLOWED_IMAGES = {'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# -------- Ensure Upload Directories -------- #
def ensure_dirs():
    os.makedirs(os.path.join(UPLOAD_ROOT, 'assets'), exist_ok=True)
    os.makedirs(os.path.join(UPLOAD_ROOT, 'checklists'), exist_ok=True)
    os.makedirs(os.path.join(UPLOAD_ROOT, 'evidence'), exist_ok=True)


# -------- Models -------- #
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    org_name = db.Column(db.String(150))
    audit_date = db.Column(db.String(50))
    mobile = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='auditee')
    org_type = db.Column(db.String(50))
    registered_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)


class Token(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(200), unique=True, nullable=False)
    purpose = db.Column(db.String(50))
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    used = db.Column(db.Boolean, default=False)


class DataSubmission(db.Model):
    __tablename__ = 'data_submission'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assets_filename = db.Column(db.String(300))
    checklist_filename = db.Column(db.String(300))
    auditees_count = db.Column(db.Integer)
    auditee_names_json = db.Column(db.Text)
    submitted_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class ControlEvidence(db.Model):
    __tablename__ = 'control_evidence'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    submission_id = db.Column(db.Integer, db.ForeignKey('data_submission.id'), nullable=True)
    control_number = db.Column(db.Integer)
    status = db.Column(db.String(50))
    image_filename = db.Column(db.String(300), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    submitted_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# -------- Flask 3 compatible hook -------- #
def setup():
    ensure_dirs()
    # db.create_all()  # Uncomment if you want to create tables automatically


# -------- Utility -------- #
def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        org_name = request.form.get('org_name')
        audit_date = request.form.get('audit_date')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        password = request.form.get('password')
        org_type = request.form.get('org_type')
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger'); return redirect(url_for('register'))
        user = User(name=name, org_name=org_name, audit_date=audit_date,
                    mobile=mobile, email=email, org_type=org_type, role='auditee')
        user.set_password(password)
        db.session.add(user); db.session.commit()
        flash('Registration successful. Please log in.', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email'); password = request.form.get('password'); role = request.form.get('role','auditee')
        print(f"Login attempt - email: {email}, role: {role}")
        user = User.query.filter_by(email=email, role=role).first()
        print(f"User found: {user}")
        if user and user.check_password(password):
            login_user(user); flash('Logged in', 'success')
            if user.role == 'auditor': return redirect(url_for('auditor_dashboard'))
            if user.role == 'tester': return redirect(url_for('tester_dashboard'))
            return redirect(url_for('index'))
        flash('Invalid credentials or role', 'danger'); return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('Logged out', 'info'); return redirect(url_for('index'))

@app.route('/auditor/create_token', methods=['GET','POST'])
@login_required
def create_token():
    if current_user.role != 'auditor': abort(403)
    if request.method == 'POST':
        purpose = request.form.get('purpose')
        code = secrets.token_urlsafe(12)
        token = Token(code=code, purpose=purpose, created_by=current_user.id)
        db.session.add(token); db.session.commit()
        flash(f'Token created: {code} (purpose: {purpose})', 'success'); return redirect(url_for('create_token'))
    tokens = Token.query.order_by(Token.created_on.desc()).limit(30).all()
    return render_template('auditor_dashboard.html', tokens=tokens)

@app.route('/data-token', methods=['GET','POST'])
@login_required
def data_token():
    if current_user.role != 'auditee': abort(403)
    if request.method == 'POST':
        code = request.form.get('code')
        token = Token.query.filter_by(code=code, purpose='data', used=False).first()
        if not token: flash('Invalid or used token','danger'); return redirect(url_for('data_token'))
        session['data_token'] = code; flash('Token accepted','success'); return redirect(url_for('data_submit'))
    return render_template('data-submit-login.html')

@app.route('/data-submit', methods=['GET','POST'])
@login_required
def data_submit():
    if current_user.role != 'auditee': abort(403)
    if 'data_token' not in session: flash('Enter data token first','warning'); return redirect(url_for('data_token'))
    if request.method == 'POST':
        assets = request.files.get('assets'); checklist = request.files.get('checklist')
        aud_count = int(request.form.get('auditees_count', 0))
        auditee_names = [request.form.get(f'auditee_name_{i}') for i in range(1, aud_count+1)]
        if not assets or not allowed_file(assets.filename, ALLOWED_EXCEL): flash('Upload Excel assets','danger'); return redirect(url_for('data_submit'))
        if not checklist or not allowed_file(checklist.filename, ALLOWED_EXCEL): flash('Upload Excel checklist','danger'); return redirect(url_for('data_submit'))
        assets_fname = secure_filename(f"{current_user.id}_assets_{int(datetime.datetime.utcnow().timestamp())}_{assets.filename}")
        checklist_fname = secure_filename(f"{current_user.id}_checklist_{int(datetime.datetime.utcnow().timestamp())}_{checklist.filename}")
        assets.save(os.path.join(app.config['UPLOAD_FOLDER'],'assets',assets_fname))
        checklist.save(os.path.join(app.config['UPLOAD_FOLDER'],'checklists',checklist_fname))
        subm = DataSubmission(user_id=current_user.id, assets_filename=assets_fname,
                              checklist_filename=checklist_fname, auditees_count=aud_count,
                              auditee_names_json=json.dumps(auditee_names))
        db.session.add(subm)
        tok = Token.query.filter_by(code=session.get('data_token')).first()
        if tok: tok.used = True
        db.session.commit(); session.pop('data_token', None)
        flash('Documents submitted','success'); return redirect(url_for('index'))
    return render_template('data-submit.html')

@app.route('/evidence-token', methods=['GET','POST'])
@login_required
def evidence_token():
    if current_user.role != 'auditee': abort(403)
    if request.method == 'POST':
        code = request.form.get('code')
        token = Token.query.filter_by(code=code, purpose='evidence', used=False).first()
        if not token: flash('Invalid or used token','danger'); return redirect(url_for('evidence_token'))
        session['evidence_token'] = code; flash('Token accepted','success'); return redirect(url_for('control_and_evidence'))
    return render_template('control-login.html')

@app.route('/control-and-evidence', methods=['GET','POST'])
@login_required
def control_and_evidence():
    if current_user.role != 'auditee': abort(403)
    if 'evidence_token' not in session: flash('Enter evidence token first','warning'); return redirect(url_for('evidence_token'))
    if request.method == 'POST':
        last_submission = DataSubmission.query.filter_by(user_id=current_user.id).order_by(DataSubmission.submitted_on.desc()).first()
        for i in range(1, 11):
            status = request.form.get(f'control_status_{i}')
            notes = request.form.get(f'control_notes_{i}', '')
            image = request.files.get(f'control_image_{i}')
            img_fname = None
            if status == 'Compliant':
                if not image or not allowed_file(image.filename, ALLOWED_IMAGES):
                    flash(f'Control {i} marked Compliant but image missing','danger'); return redirect(url_for('control_and_evidence'))
                img_fname = secure_filename(f"{current_user.id}_ctl{i}_{int(datetime.datetime.utcnow().timestamp())}_{image.filename}")
                image.save(os.path.join(app.config['UPLOAD_FOLDER'],'evidence', img_fname))
            ev = ControlEvidence(user_id=current_user.id, submission_id=last_submission.id if last_submission else None,
                                 control_number=i, status=status, image_filename=img_fname, notes=notes)
            db.session.add(ev)
        tok = Token.query.filter_by(code=session.get('evidence_token')).first()
        if tok: tok.used = True
        db.session.commit(); session.pop('evidence_token', None)
        flash('Evidence submitted. Logging out for security.','success'); logout_user(); return redirect(url_for('index'))
    return render_template('control_and_evidence.html', controls=range(1,11))

@app.route('/auditor/dashboard')
@login_required
def auditor_dashboard():
    if current_user.role != 'auditor': abort(403)
    total_auditees = User.query.filter_by(role='auditee').count()
    submissions_count = DataSubmission.query.count()
    evidence_count = ControlEvidence.query.count()
    compliant_count = ControlEvidence.query.filter_by(status='Compliant').count()
    non_compliant_count = ControlEvidence.query.filter_by(status='Non-Compliant').count()
    recent_submissions = DataSubmission.query.order_by(DataSubmission.submitted_on.desc()).limit(20).all()
    return render_template('auditor_dashboard.html',
                           total_auditees=total_auditees,
                           submissions_count=submissions_count,
                           evidence_count=evidence_count,
                           compliant_count=compliant_count,
                           non_compliant_count=non_compliant_count,
                           recent_submissions=recent_submissions)

@app.route('/tester/dashboard')
@login_required
def tester_dashboard():
    if current_user.role != 'tester': abort(403)
    submissions = DataSubmission.query.order_by(DataSubmission.submitted_on.desc()).all()
    return render_template('tester_dashboard.html', submissions=submissions)

@app.route('/uploads/<subdir>/<filename>')
@login_required
def uploaded_file(subdir, filename):
    allowed = {'assets','checklists','evidence'}
    if subdir not in allowed: abort(404)
    folder = os.path.join(app.config['UPLOAD_FOLDER'], subdir)
    path = os.path.join(folder, filename)
    if not os.path.exists(path): abort(404)
    return send_from_directory(folder, filename, as_attachment=True)

@app.route('/auditor/generate_pdf/<int:submission_id>')
@login_required
def generate_pdf(submission_id):
    if current_user.role != 'auditor': abort(403)
    submission = DataSubmission.query.get_or_404(submission_id)
    user = User.query.get(submission.user_id)
    evidences = ControlEvidence.query.filter_by(submission_id=submission.id).order_by(ControlEvidence.control_number).all()
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    margin = 40; y = height - margin
    c.setFont("Helvetica-Bold", 16); c.drawString(margin, y, f"Secure SDLC Evidence Report - {user.name} / {user.org_name}")
    y -= 30; c.setFont("Helvetica", 10); c.drawString(margin, y, f"Submitted on: {submission.submitted_on.strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 20
    for ev in evidences:
        if y < 180: c.showPage(); y = height - margin
        c.setFont("Helvetica-Bold", 12); c.drawString(margin, y, f"Control #{ev.control_number} - {ev.status}")
        y -= 18
        if ev.notes: c.setFont("Helvetica", 9); c.drawString(margin, y, f"Notes: {ev.notes}"); y -= 14
        if ev.image_filename:
            path = os.path.join(app.config['UPLOAD_FOLDER'], 'evidence', ev.image_filename)
            try:
                img = ImageReader(path); iw, ih = img.getSize()
                max_w = width - 2*margin; max_h = 300
                scale = min(max_w/iw, max_h/ih, 1)
                iw_s, ih_s = iw*scale, ih*scale
                c.drawImage(img, margin, y - ih_s, width=iw_s, height=ih_s); y -= ih_s + 12
            except Exception:
                c.setFont("Helvetica",9); c.drawString(margin,y, f"[Could not embed image: {ev.image_filename}]"); y -= 14
    c.save(); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"evidence_report_{submission.id}.pdf", mimetype='application/pdf')

if __name__ == '__main__':
    setup()
    app.run(host='0.0.0.0', port=5000, debug=True)
