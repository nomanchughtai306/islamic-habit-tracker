import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
from datetime import datetime, timedelta
from sqlalchemy import desc
import secrets
from flask import current_app
from PIL import Image
from functools import wraps
from flask import abort
import requests
from functools import wraps
from flask import abort
import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from google import genai
from google.genai import types  # <--- Add this import

load_dotenv()
app = Flask(__name__)
chat_histories = {}
# --- 1. Configuration ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "tracker.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "connect_args": {
        "timeout": 15,
        "check_same_thread": False # Recommended for Flask + SQLite
    }
}

# Use the exact same config that worked in test.py
client = genai.Client(
    api_key=os.getenv("GOOGLE_API_KEY"),
    http_options={'api_version': 'v1'}
)


# The Gatekeeper Function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user isn't logged in OR isn't an admin
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("🚫 Access Denied: Admins only.", "danger")
            return redirect(url_for('dashboard')) # Kick them out
        return f(*args, **kwargs)
    return decorated_function


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Where to redirect if user is not logged in




def calculate_current_streak(habit_logs):
    if not habit_logs:
        return 0

    today = date.today()
    yesterday = today - timedelta(days=1)
    
    # Get the very latest log
    latest_log = habit_logs[0]
    
    # If the user hasn't logged today or yesterday, streak is 0
    if latest_log.date < yesterday:
        return 0

    streak = 0
    current_date_to_check = latest_log.date

    for log in habit_logs:
        # Check if the user did at least one thing on this day
        has_activity = any([log.fajr, log.zuhr, log.asr, log.maghrib, 
                            log.isha, log.quran, log.nofap, log.coding_hours > 0])

        if log.date == current_date_to_check and has_activity:
            streak += 1
            current_date_to_check -= timedelta(days=1)
        elif log.date < current_date_to_check:
            # We found a gap day where nothing was done
            break
            
    return streak

def get_daily_ayah():
    # Get the day of the year (e.g., 22 for Jan 22nd)
    day_of_year = datetime.now().timetuple().tm_yday
    
    # We fetch both Arabic and English Sahih International translation
    url = f"https://api.alquran.cloud/v1/ayah/{day_of_year}/editions/quran-uthmani,en.sahih"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'arabic': data[0]['text'],
                'english': data[1]['text'],
                'surah': data[0]['surah']['englishName'],
                'number': data[0]['numberInSurah']
            }
    except Exception as e:
        print(f"Error fetching Ayah: {e}")
    return None


def get_prayer_times(city="Mirpur", country="Pakistan"):
    try:
        # Method 1 is University of Islamic Sciences, Karachi
        url = f"http://api.aladhan.com/v1/timingsByCity?city={city}&country={country}&method=1"
        response = requests.get(url, timeout=5)
        data = response.json()
        return data['data']['timings']
    except Exception as e:
        print(f"Error fetching prayer times: {e}")
        return None

def save_picture(form_picture):
    # 1. Create a random name to prevent name conflicts
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)

    # 2. PRO LOGIC: Resize the image
    output_size = (150, 150)
    i = Image.open(form_picture)
    
    # This maintains the aspect ratio and crops/resizes cleanly
    i.thumbnail(output_size) 
    
    # 3. Save the compressed/resized version
    i.save(picture_path)

    return picture_fn

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    is_admin = db.Column(db.Boolean, default=False) 
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=False, default='default.png')
    
    # UPDATE THESE RELATIONSHIPS HERE:
    habits = db.relationship('DailyHabit', backref='user', lazy=True, cascade='all, delete-orphan')
    logs = db.relationship('DailyLog', backref='user', lazy=True, cascade='all, delete-orphan')
    reflections = db.relationship('Reflection', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_habits = DailyHabit.query.count()
    all_users = User.query.all()
    
    return render_template('admin.html', 
                           total_users=total_users, 
                           total_habits=total_habits,
                           users=all_users)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

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
        email = request.form.get('email') # New
        password = request.form.get('password')
        
        # Check if Username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
            
        # Check if Email exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('register'))
        
        # Create new user with all 3 fields
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # identity can be the username OR the email from the form
        identity = request.form.get('login_identity')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        # Look for a user where username matches OR email matches
        user = User.query.filter((User.username == identity) | (User.email == identity)).first()
        
        if user and user.check_password(password):
            # Uses the 'remember' variable from the checkbox
            login_user(user, remember=remember)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
            
        flash('Invalid username/email or password.', 'danger')
        
    return render_template('login.html')
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file.filename != '':
            old_pic = current_user.profile_pic
            # Save new pic
            new_pic = save_picture(file)
            current_user.profile_pic = new_pic
            
            # Optional: Delete old pic from folder if it's not default.png
            if old_pic != 'default.png':
                try:
                    os.remove(os.path.join(current_app.root_path, 'static/profile_pics', old_pic))
                except:
                    pass
                    
            db.session.commit()
            flash('Profile picture updated!', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = User.query.get(current_user.id)
    logout_user() # Log them out first
    db.session.delete(user)
    db.session.commit()
    flash('Your account has been deleted.', 'info')
    return redirect(url_for('register'))


# The name here MUST be delete_user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    
    if user_to_delete.id == current_user.id:
        flash('You cannot delete yourself!', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Delete their habits first (to avoid database errors)
    DailyHabit.query.filter_by(user_id=user_to_delete.id).delete()
    
    db.session.delete(user_to_delete)
    db.session.commit()
    
    flash(f'User {user_to_delete.email} has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- 4. App Routes (Now Protected) ---




@app.route('/', methods=['GET', 'POST'])
def dashboard():
    today = date.today()
    habit = None
    week_data = []
    total_streak = 0

    # --- 1. LOGGED-IN USER LOGIC ---
    if current_user.is_authenticated:
        # Handle Database loading/saving only for logged-in users
        habit = DailyHabit.query.filter_by(date=today, user_id=current_user.id).first()
        
        # Initialize habit if it doesn't exist for today
        if not habit:
            habit = DailyHabit(date=today, user_id=current_user.id)
            db.session.add(habit)
            db.session.commit() # Save the skeleton record

        # Handle Form Submission
        if request.method == 'POST':
            habit.fajr = 'fajr' in request.form
            habit.zuhr = 'zuhr' in request.form
            habit.asr = 'asr' in request.form
            habit.maghrib = 'maghrib' in request.form
            habit.isha = 'isha' in request.form
            habit.quran = 'quran' in request.form
            habit.nofap = 'nofap' in request.form
            habit.coding_hours = float(request.form.get('coding_hours', 0) or 0)
            db.session.commit()
            flash('Progress saved!', 'success')
            return redirect(url_for('dashboard'))

        # 7-Day Visual Data
        for i in range(6, -1, -1):
            check_date = today - timedelta(days=i)
            log = DailyHabit.query.filter_by(user_id=current_user.id, date=check_date).first()
            status = 'none'
            if log:
                is_full = all([log.fajr, log.zuhr, log.asr, log.maghrib, log.isha, log.quran, log.nofap])
                status = 'success' if is_full else 'partial'
            week_data.append({'day_name': check_date.strftime('%a'), 'status': status})

        # Calculate Streak
        curr_check = today
        while True:
            log = DailyHabit.query.filter_by(user_id=current_user.id, date=curr_check).first()
            is_full = log and all([log.fajr, log.zuhr, log.asr, log.maghrib, log.isha, log.quran, log.nofap])
            if is_full:
                total_streak += 1
                curr_check -= timedelta(days=1)
            else:
                if curr_check == today:
                    curr_check -= timedelta(days=1)
                    continue
                break
    
    # --- 2. GUEST LOGIC ---
    else:
        # For guests, we show empty placeholders or redirect them if they try to POST
        if request.method == 'POST':
            flash('Please login to save your progress!', 'info')
            return redirect(url_for('login'))
        
        # Fill week_data with 'none' status so the UI doesn't break
        for i in range(6, -1, -1):
            check_date = today - timedelta(days=i)
            week_data.append({'day_name': check_date.strftime('%a'), 'status': 'none'})

    # --- 3. PUBLIC DATA (Fetched for everyone) ---
    prayer_times = get_prayer_times() 
    ayah = get_daily_ayah()
    
    return render_template('dashboard.html', 
                           habit=habit, 
                           week_data=week_data, 
                           total_streak=total_streak, 
                           today=today,
                           ayah=ayah,
                           prayer_times=prayer_times)

@app.route('/api/chat', methods=['POST'])
def chat_with_ai():
    data = request.get_json()
    user_message = data.get('message', '')
    user_id = current_user.id 

    # We use a global chat session dictionary to keep the 'Chat' object alive
    # This is more reliable than manually managing the history list
    if user_id not in chat_histories:
        chat_histories[user_id] = client.chats.create(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                # We put the instruction in the prompt if config is still buggy
                temperature=0.7
            )
        )

    try:
        # Wrap the message with the persona to ensure it sticks
        contextual_message = f"(Mentor Instruction: Be concise and use Islamic wisdom) {user_message}"
        
        # Send message through the persistent chat object
        chat_session = chat_histories[user_id]
        response = chat_session.send_message(contextual_message)
        
        return jsonify({'response': response.text})

    except Exception as e:
        print(f"❌ AI ERROR: {str(e)}")
        # If the session expired or failed, reset it and try one more time
        chat_histories[user_id] = client.chats.create(model="gemini-2.5-flash")
        return jsonify({'response': "I'm resetting our connection. Please send that once more."}), 500

@app.route('/api/chat/clear', methods=['POST'])
def clear_chat():
    user_id = current_user.id# Use current_user.id
    chat_histories[user_id] = []
    return jsonify({'status': 'cleared'})
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
# --- Edit Reflection ---
@app.route('/reflection/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_reflection(id):
    # Ensure the reflection belongs to the current user
    reflection = Reflection.query.get_or_404(id)
    if reflection.user_id != current_user.id:
        flash("You do not have permission to edit this.", "danger")
        return redirect(url_for('reflections'))

    if request.method == 'POST':
        reflection.reference = request.form.get('reference')
        reflection.note = request.form.get('note')
        db.session.commit()
        flash("Reflection updated!", "success")
        return redirect(url_for('reflections'))
    
    return render_template('edit_reflection.html', reflection=reflection)

# --- Delete Reflection ---
@app.route('/reflection/delete/<int:id>', methods=['POST'])
@login_required
def delete_reflection(id):
    reflection = Reflection.query.get_or_404(id)
    if reflection.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for('reflections'))
    
    db.session.delete(reflection)
    db.session.commit()
    flash("Reflection deleted.", "info")
    return redirect(url_for('reflections'))

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
    app.run(host='0.0.0.0', port=5000, debug=False)
    