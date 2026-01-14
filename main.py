import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
from sqlalchemy import desc

# --- 1. Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "tracker.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev-secret-key-123' # Change this in production

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Where to redirect if user is not logged in

# --- 2. Database Models ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Relationships to data
    habits = db.relationship('DailyHabit', backref='user', lazy=True)
    logs = db.relationship('DailyLog', backref='user', lazy=True)
    reflections = db.relationship('Reflection', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class DailyHabit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # LINK TO USER
    date = db.Column(db.Date, default=date.today, nullable=False)
    fajr = db.Column(db.Boolean, default=False)
    zuhr = db.Column(db.Boolean, default=False)
    asr = db.Column(db.Boolean, default=False)
    maghrib = db.Column(db.Boolean, default=False)
    isha = db.Column(db.Boolean, default=False)
    quran = db.Column(db.Boolean, default=False)
    nofap = db.Column(db.Boolean, default=False)
    coding_hours = db.Column(db.Float, default=0.0)

class DailyLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # LINK TO USER
    date = db.Column(db.Date, default=date.today, nullable=False)
    mood = db.Column(db.String(10), default='Neutral')
    urge_level = db.Column(db.Integer, default=1)
    productivity = db.Column(db.Integer, default=3)

class Reflection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # LINK TO USER
    date = db.Column(db.Date, default=date.today, nullable=False)
    reference = db.Column(db.String(100))
    note = db.Column(db.Text, nullable=False)

# --- 3. Auth Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 4. App Routes (Now Protected) ---

@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    today = date.today()
    # Find habit for current user only
    habit = DailyHabit.query.filter_by(date=today, user_id=current_user.id).first()
    if not habit:
        habit = DailyHabit(date=today, user_id=current_user.id)
        db.session.add(habit)
        db.session.commit()

    if request.method == 'POST':
        habit.fajr = 'fajr' in request.form
        habit.zuhr = 'zuhr' in request.form
        habit.asr = 'asr' in request.form
        habit.maghrib = 'maghrib' in request.form
        habit.isha = 'isha' in request.form
        habit.quran = 'quran' in request.form
        habit.nofap = 'nofap' in request.form
        habit.coding_hours = float(request.form.get('coding_hours', 0))
        db.session.commit()
        flash('Updated successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', habit=habit, today=today)

@app.route('/logs', methods=['GET', 'POST'])
@login_required
def logs():
    today = date.today()
    log = DailyLog.query.filter_by(date=today, user_id=current_user.id).first()
    if not log:
        log = DailyLog(date=today, user_id=current_user.id)
        db.session.add(log)
        db.session.commit()

    if request.method == 'POST':
        log.mood = request.form['mood']
        log.urge_level = int(request.form['urge_level'])
        log.productivity = int(request.form['productivity'])
        db.session.commit()
        flash('Log saved!', 'success')
        return redirect(url_for('logs'))

    past_logs = DailyLog.query.filter_by(user_id=current_user.id).order_by(desc(DailyLog.date)).limit(14).all()
    return render_template('logs.html', log=log, past_logs=past_logs, today=today)

@app.route('/reflection', methods=['GET', 'POST'])
@login_required
def reflections():
    if request.method == 'POST':
        new_ref = Reflection(
            user_id=current_user.id,
            reference=request.form.get('reference'),
            note=request.form.get('note')
        )
        db.session.add(new_ref)
        db.session.commit()
        return redirect(url_for('reflections'))
    
    refls = Reflection.query.filter_by(user_id=current_user.id).order_by(desc(Reflection.date)).all()
    return render_template('reflection.html', reflections=refls)

@app.route('/progress')
@login_required
def progress():
    # 1. Get the last 21 days
    days_to_show = 21
    start_date = date.today() - timedelta(days=days_to_show)
    
    # 2. Fetch data for CURRENT USER only
    h_data = DailyHabit.query.filter(DailyHabit.date >= start_date, DailyHabit.user_id == current_user.id).all()
    l_data = DailyLog.query.filter(DailyLog.date >= start_date, DailyLog.user_id == current_user.id).all()

    # 3. Create "Maps" so we can find data by date easily
    habit_map = {h.date: h for h in h_data}
    log_map = {l.date: l for l in l_data}

    # 4. Build synchronized lists for the last 21 days
    labels = []
    urge_levels = []
    coding_hours = []
    nofap_days = []
    prayer_percents = []
    quran_status = []

    for i in range(days_to_show + 1):
        d = start_date + timedelta(days=i)
        labels.append(d.strftime('%b %d'))
        
        # Get habit data or default to 0
        h = habit_map.get(d)
        if h:
            coding_hours.append(h.coding_hours)
            nofap_days.append(1 if h.nofap else 0)
            quran_status.append(1 if h.quran else 0)
            p_done = sum([h.fajr, h.zuhr, h.asr, h.maghrib, h.isha])
            prayer_percents.append((p_done / 5) * 100)
        else:
            coding_hours.append(0); nofap_days.append(0); quran_status.append(0); prayer_percents.append(0)

        # Get log data or default to 1 (low urge)
        l = log_map.get(d)
        urge_levels.append(l.urge_level if l else 0)

    chart_data = {
        'labels': labels,
        'urge_levels': urge_levels,
        'coding_hours': coding_hours,
        'nofap_days': nofap_days,
        'prayer_percents': prayer_percents,
        'quran_status': quran_status
    }
    return render_template('progress.html', chart_data=chart_data)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)