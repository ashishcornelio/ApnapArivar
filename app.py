import os
import json
import random
import string
import time
from flask import Flask, render_template, request, redirect, url_for, session, abort, send_from_directory
from flask_bcrypt import Bcrypt

# --- 1. CONFIGURATION ---

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_this'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

bcrypt = Bcrypt(app)
DB_FILE = 'db.json'

# --- 2. HELPER FUNCTIONS ---

def read_db():
    """Reads the entire JSON database."""
    if not os.path.exists(DB_FILE):
        write_db({"users": {}, "images": {}, "share_codes": {}})
    
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        # If file is empty or corrupt, reset it
        write_db({"users": {}, "images": {}, "share_codes": {}})
        with open(DB_FILE, 'r') as f:
            return json.load(f)


def write_db(data):
    """Writes the given data to the JSON database."""
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# --- 3. BASIC PAGES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/pending_approval')
def pending_approval():
    """Show this page to users who are waiting for authorization."""
    if not session.get('logged_in') or session.get('role') != 'pending':
        return redirect(url_for('login'))
    return render_template('pending_approval.html')

# --- 4. AUTHENTICATION ---

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        db = read_db()
        
        if not username or not email:
            return "Username and Email are required.", 400
        if username in db['users']:
            return "A user with this username already exists.", 400
        
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        db['users'][username] = {
            'username': username,
            'email': email,
            'hash': password_hash,
            'role': 'pending'
        }
        write_db(db)
        
        session['logged_in'] = True
        session['username'] = username
        session['role'] = 'pending'
        return redirect(url_for('pending_approval'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password_attempt = request.form['password']
        
        # Super Admin Check
        if username == 'admin123' and password_attempt == 'admin123':
            session['logged_in'] = True
            session['username'] = 'SuperAdmin'
            session['role'] = 'super_admin'
            return redirect(url_for('super_admin_panel'))
            
        db = read_db()
        user = db['users'].get(username)
        
        if user:
            if user['role'] == 'banned':
                return "This account has been banned.", 401
            
            if bcrypt.check_password_hash(user['hash'], password_attempt):
                session['logged_in'] = True
                session['username'] = user['username']
                session['role'] = user['role']
                
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'pending':
                    return redirect(url_for('pending_approval'))
            
        return "Invalid username or password", 401
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- 5. ADMIN DASHBOARD ---

@app.route('/admin')
def admin_dashboard():
    """Regular Admin's dashboard."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    role = session.get('role')
    if role == 'pending':
        return redirect(url_for('pending_approval'))
    if role != 'admin':
        return "Not authorized.", 403
        
    username = session['username']
    db = read_db()
    
    my_images = db['images'].get(username, [])
    
    # --- Calculate Storage Usage ---
    total_bytes = 0
    for img_name in my_images:
        try:
            path = os.path.join(app.config['UPLOAD_FOLDER'], img_name)
            if os.path.exists(path):
                total_bytes += os.path.getsize(path)
        except OSError:
            pass
    
    storage_mb = round(total_bytes / (1024 * 1024), 2)
    
    active_code = "None"
    expiry_timestamp = 0
    
    for code, info in db['share_codes'].items():
        if info.get('owner') == username:
            active_code = code
            expiry_timestamp = info.get('expiry', 0)
            
            if isinstance(expiry_timestamp, (int, float)):
                if time.time() > expiry_timestamp:
                    active_code = "Expired"
                    expiry_timestamp = 0
            break
            
    return render_template(
        'admin_dashboard.html', 
        images=my_images, 
        active_code=active_code,
        expiry_timestamp=expiry_timestamp,
        storage_mb=storage_mb,
        image_count=len(my_images)
    )

@app.route('/upload', methods=['POST'])
def upload_image():
    """Handles multiple image uploads for the logged-in admin."""
    if not session.get('logged_in') or session.get('role') != 'admin':
        abort(403)
        
    files = request.files.getlist('image')
    if not files or files[0].filename == '':
        return "No selected file(s)", 400
        
    db = read_db()
    username = session['username']
    
    if username not in db['images']:
        db['images'][username] = []
        
    for file in files:
        if file and file.filename:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            if filename not in db['images'][username]:
                 db['images'][username].append(filename)
    
    write_db(db)
    return redirect(url_for('admin_dashboard'))

@app.route('/uploads/<filename>')
def get_uploaded_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/generate_code', methods=['POST'])
def generate_code():
    """Generates a share code linked to the current user."""
    if not session.get('logged_in') or session.get('role') != 'admin':
        abort(403)
        
    try:
        hours = int(request.form.get('hours', 0) or 0)
        minutes = int(request.form.get('minutes', 0) or 0)
        seconds = int(request.form.get('seconds', 0) or 0)
    except ValueError:
        return "Invalid time format.", 400

    total_seconds = (hours * 3600) + (minutes * 60) + seconds
    if total_seconds <= 0:
        total_seconds = 3600
        
    expiry_timestamp = time.time() + total_seconds
    code = ''.join(random.choices(string.digits, k=6))
    username = session['username']
    
    db = read_db()
    
    for c, info in list(db['share_codes'].items()):
        if info.get('owner') == username:
            del db['share_codes'][c]
            
    db['share_codes'][code] = {
        "expiry": expiry_timestamp,
        "owner": username
    }
    write_db(db)
    
    return redirect(url_for('admin_dashboard'))

@app.route('/deactivate_code', methods=['POST'])
def deactivate_code():
    """Deactivates codes for the current user."""
    if not session.get('logged_in') or session.get('role') != 'admin':
        abort(403)
        
    db = read_db()
    username = session['username']
    
    for c, info in list(db['share_codes'].items()):
        if info.get('owner') == username:
            del db['share_codes'][c]
            
    write_db(db)
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_image/<filename>', methods=['POST'])
def delete_image(filename):
    """Deletes an image owned by the current user."""
    if not session.get('logged_in') or session.get('role') != 'admin':
        abort(403)
        
    db = read_db()
    username = session['username']
    
    if username in db['images'] and filename in db['images'][username]:
        db['images'][username].remove(filename)
        write_db(db)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            
    return redirect(url_for('admin_dashboard'))

# --- 6. SUPER ADMIN PANEL ---

@app.route('/super_admin')
def super_admin_panel():
    """Shows all users and all images/stats."""
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        return redirect(url_for('login'))
        
    db = read_db()
    all_users = db['users']
    all_images = db['images']
    
    user_stats = []
    
    # Calculate stats for every single user
    for username, user_data in all_users.items():
        images = all_images.get(username, [])
        total_bytes = 0
        
        for img_name in images:
            try:
                path = os.path.join(app.config['UPLOAD_FOLDER'], img_name)
                if os.path.exists(path):
                    total_bytes += os.path.getsize(path)
            except OSError:
                pass
        
        # Attach statistics and images to the user data structure
        user_data['image_count'] = len(images)
        user_data['storage_mb'] = round(total_bytes / (1024 * 1024), 2)
        user_data['user_images'] = images # Images are needed for the dropdown
        user_stats.append(user_data)
        
    return render_template('super_admin.html', user_stats=user_stats) # Pass the list of user stats

@app.route('/authorize_user/<username>', methods=['POST'])
def authorize_user(username):
    """Super Admin authorizes a 'pending' user."""
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        abort(403)
        
    db = read_db()
    if username in db['users'] and db['users'][username]['role'] == 'pending':
        db['users'][username]['role'] = 'admin'
        write_db(db)
        
    return redirect(url_for('super_admin_panel'))

@app.route('/ban_user/<username>', methods=['POST'])
def ban_user(username):
    """Super Admin bans a 'pending' or 'admin' user."""
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        abort(403)
        
    db = read_db()
    if username in db['users']:
        db['users'][username]['role'] = 'banned'
        write_db(db)
        
    return redirect(url_for('super_admin_panel'))

@app.route('/unban_user/<username>', methods=['POST'])
def unban_user(username):
    """Super Admin unbans a 'banned' user, setting them to 'pending'."""
    if not session.get('logged_in') or session.get('role') != 'super_admin':
        abort(403)
        
    db = read_db()
    if username in db['users'] and db['users'][username]['role'] == 'banned':
        db['users'][username]['role'] = 'pending'
        write_db(db)
        
    return redirect(url_for('super_admin_panel'))


# --- 7. GUEST VIEWING ---

@app.route('/share')
def share_page():
    """The page a guest sees. Asks for the code."""
    return render_template('guest_view.html', show_code_form=True)

@app.route('/share/view', methods=['POST'])
def view_by_code():
    """Checks code, expiry, and finds the correct user's images."""
    
    code_attempt = request.form['code'].strip()
    db = read_db()
    
    code_info = db['share_codes'].get(code_attempt)
    
    if code_info:
        expiry_timestamp = code_info.get('expiry', 0)
        
        if time.time() < expiry_timestamp:
            owner = code_info.get('owner')
            if owner:
                images = db['images'].get(owner, [])
                image_count = len(images)
                return render_template(
                    'guest_view.html', 
                    show_code_form=False, 
                    images=images,
                    image_count=image_count
                )
            else:
                return "Invalid code (no owner).", 401
        else:
            return "This code has expired.", 401
    else:
        return "Invalid code.", 401

# --- 8. RUN THE APP ---
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)