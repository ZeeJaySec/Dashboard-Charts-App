from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import sqlite3, os, json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Database path setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

# Ensure database file exists
def init_db():
    os.makedirs(BASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    
    # Existing users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # Table for chart datasets with tabular data support
    c.execute('''CREATE TABLE IF NOT EXISTS chart_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    chart_name TEXT NOT NULL,
                    data_type TEXT NOT NULL,
                    columns TEXT,
                    rows TEXT,
                    data_values TEXT,
                    chart_title TEXT DEFAULT '',
                    x_axis_label TEXT DEFAULT '',
                    y_axis_label TEXT DEFAULT '',
                    custom_colors TEXT,
                    is_public BOOLEAN DEFAULT 0,
                    shared_with TEXT, -- JSON array of user IDs
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # Dashboards table
    c.execute('''CREATE TABLE IF NOT EXISTS dashboards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_public BOOLEAN DEFAULT 0,
                    layout_config TEXT, -- JSON for dashboard layout
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )''')
    
    # Dashboard charts (many-to-many relationship)
    c.execute('''CREATE TABLE IF NOT EXISTS dashboard_charts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dashboard_id INTEGER,
                    chart_id INTEGER,
                    position_x INTEGER DEFAULT 0,
                    position_y INTEGER DEFAULT 0,
                    width INTEGER DEFAULT 6,
                    height INTEGER DEFAULT 4,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (dashboard_id) REFERENCES dashboards (id),
                    FOREIGN KEY (chart_id) REFERENCES chart_data (id)
                )''')
    
    # Shared dashboards
    c.execute('''CREATE TABLE IF NOT EXISTS dashboard_shares (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dashboard_id INTEGER,
                    shared_with_user_id INTEGER,
                    can_edit BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (dashboard_id) REFERENCES dashboards (id),
                    FOREIGN KEY (shared_with_user_id) REFERENCES users (id)
                )''')
    
    # Check if we need to migrate old schema for users table
    try:
        c.execute("SELECT created_at FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # Old schema exists, need to migrate users table
        print("Migrating users table schema...")
        c.execute('''ALTER TABLE users ADD COLUMN created_at TIMESTAMP''')
        # Update existing records with current timestamp
        c.execute('''UPDATE users SET created_at = datetime('now') WHERE created_at IS NULL''')
        print("Users table migration completed!")
    
    # Check if we need to migrate old schema for chart_data table
    try:
        c.execute("SELECT chart_title FROM chart_data LIMIT 1")
    except sqlite3.OperationalError:
        # Old schema exists, need to migrate
        print("Migrating chart_data table schema...")
        c.execute('''ALTER TABLE chart_data ADD COLUMN chart_title TEXT DEFAULT ''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN x_axis_label TEXT DEFAULT ''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN y_axis_label TEXT DEFAULT ''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN custom_colors TEXT''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN is_public BOOLEAN DEFAULT 0''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN shared_with TEXT''')
        c.execute('''ALTER TABLE chart_data ADD COLUMN created_at TIMESTAMP''')
        # Update existing records with current timestamp
        c.execute('''UPDATE chart_data SET created_at = datetime('now') WHERE created_at IS NULL''')
        print("Chart_data table migration completed!")
    
    conn.commit()
    
    # Ensure there is always at least one admin
    c.execute("SELECT id FROM users WHERE role='admin'")
    admin_exists = c.fetchone()
    if not admin_exists:
        # Use a known hashed password for 'admin123'
        known_hash = generate_password_hash("admin123")
        c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", 
                 ("admin", known_hash, "admin"))
        print("Admin user created with username: 'admin' and password: 'admin123'")
    
    conn.commit()
    conn.close()

# Helper function for database connection
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Home route → redirect to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Remove the public register route and replace with admin-only user creation
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only allow access if user is admin
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')
        try:
            conn = get_db_connection()
            hashed_password = generate_password_hash(password)
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                        (username, hashed_password, role))
            conn.commit()
            conn.close()
            flash("✅ User created successfully!", "success")
            return redirect(url_for('manage_users'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="⚠️ Username already exists! Try another.")
    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute("SELECT id, username, password, role FROM users WHERE username=?", 
                           (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role'] if user['role'] else 'user'
            session['user_id'] = user['id']
            flash(f"👋 Welcome back, {user['username']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="❌ Invalid username or password!")
    return render_template('login.html')

# Route for users to change their own password
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Validate passwords
        if new_password != confirm_password:
            flash("❌ New password and confirmation do not match!", "error")
            return render_template('change_password.html')
        
        if len(new_password) < 6:
            flash("❌ Password must be at least 6 characters long!", "error")
            return render_template('change_password.html')
        
        conn = get_db_connection()
        
        # Verify current password
        user = conn.execute(
            "SELECT password FROM users WHERE id = ?", 
            (session['user_id'],)
        ).fetchone()
        
        if not user or not check_password_hash(user['password'], current_password):
            conn.close()
            flash("❌ Current password is incorrect!", "error")
            return render_template('change_password.html')
        
        # Update password
        hashed_new_password = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed_new_password, session['user_id'])
        )
        conn.commit()
        conn.close()
        
        flash("✅ Password changed successfully!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# Route for admin to reset user passwords
@app.route('/reset-user-password/<int:user_id>', methods=['POST'])
def reset_user_password(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('dashboard'))
    
    # Prevent admin from resetting their own password here (they should use change-password)
    if user_id == session['user_id']:
        flash("❌ Please use 'Change Password' to change your own password!", "error")
        return redirect(url_for('manage_users'))
    
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Validate passwords
    if new_password != confirm_password:
        flash("❌ Passwords do not match!", "error")
        return redirect(url_for('manage_users'))
    
    if len(new_password) < 6:
        flash("❌ Password must be at least 6 characters long!", "error")
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    
    # Verify user exists
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("❌ User not found!", "error")
        return redirect(url_for('manage_users'))
    
    # Reset password
    hashed_password = generate_password_hash(new_password)
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hashed_password, user_id)
    )
    conn.commit()
    conn.close()
    
    flash(f"✅ Password for user '{user['username']}' has been reset successfully!", "success")
    return redirect(url_for('manage_users'))

# Change user role (admin only)
@app.route('/change-user-role/<int:user_id>', methods=['POST'])
def change_user_role(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('dashboard'))
    
    new_role = request.form['new_role']
    
    # Validate role
    valid_roles = ['user', 'PT', 'VA', 'admin']
    if new_role not in valid_roles:
        flash("❌ Invalid role specified!", "error")
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    
    # Verify user exists
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        conn.close()
        flash("❌ User not found!", "error")
        return redirect(url_for('manage_users'))
    
    # Update role
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    
    flash(f"✅ Role for user '{user['username']}' changed to {new_role}!", "success")
    return redirect(url_for('manage_users'))

# Manage users (admin only)
@app.route('/manage-users')
def manage_users():
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    users = conn.execute('''SELECT id, username, role, created_at 
                          FROM users ORDER BY created_at DESC''').fetchall()
    conn.close()
    
    return render_template('manage_users.html', users=users)

# Delete user (admin only)
@app.route('/delete-user/<int:user_id>')
def delete_user(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('dashboard'))
    
    # Prevent admin from deleting themselves
    if user_id == session['user_id']:
        flash("❌ You cannot delete your own account!", "error")
        return redirect(url_for('manage_users'))
    
    conn = get_db_connection()
    
    # Delete user's charts first
    conn.execute('DELETE FROM chart_data WHERE user_id = ?', (user_id,))
    
    # Delete user's dashboards and related data
    conn.execute('DELETE FROM dashboard_charts WHERE dashboard_id IN (SELECT id FROM dashboards WHERE user_id = ?)', (user_id,))
    conn.execute('DELETE FROM dashboard_shares WHERE dashboard_id IN (SELECT id FROM dashboards WHERE user_id = ?)', (user_id,))
    conn.execute('DELETE FROM dashboards WHERE user_id = ?', (user_id,))
    
    # Delete the user
    result = conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    if result.rowcount > 0:
        flash("✅ User deleted successfully!", "success")
    else:
        flash("❌ User not found!", "error")
    
    return redirect(url_for('manage_users'))

# Route to add new chart data
@app.route('/add-data', methods=['GET', 'POST'])
def add_data():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        chart_name = request.form['chart_name']
        data_type = request.form['data_type']
        is_public = 1 if request.form.get('is_public') else 0
        
        # Extract column names
        columns = []
        col_index = 0
        while f'col_{col_index}' in request.form:
            columns.append(request.form[f'col_{col_index}'])
            col_index += 1
        
        # Extract row names and values
        rows = []
        data_values = []
        row_index = 0
        while f'row_{row_index}' in request.form:
            rows.append(request.form[f'row_{row_index}'])
            row_values = []
            for col_index in range(len(columns)):
                cell_value = request.form.get(f'cell_{row_index}_{col_index}', '0')
                row_values.append(float(cell_value))
            data_values.append(row_values)
            row_index += 1
        
        # Store in database as JSON
        conn = get_db_connection()
        conn.execute('''INSERT INTO chart_data (user_id, chart_name, data_type, columns, rows, data_values, is_public) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (session['user_id'], chart_name, data_type, 
                     json.dumps(columns), json.dumps(rows), json.dumps(data_values), is_public))
        conn.commit()
        conn.close()
        
        flash("✅ Chart data added successfully!", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('add_data.html')

# Edit chart data
@app.route('/edit-data/<int:chart_id>', methods=['GET', 'POST'])
def edit_data(chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        chart_name = request.form['chart_name']
        data_type = request.form['data_type']
        is_public = 1 if request.form.get('is_public') else 0
        
        # Extract column names
        columns = []
        col_index = 0
        while f'col_{col_index}' in request.form:
            columns.append(request.form[f'col_{col_index}'])
            col_index += 1
        
        # Extract row names and values
        rows = []
        data_values = []
        row_index = 0
        while f'row_{row_index}' in request.form:
            rows.append(request.form[f'row_{row_index}'])
            row_values = []
            for col_index in range(len(columns)):
                cell_value = request.form.get(f'cell_{row_index}_{col_index}', '0')
                row_values.append(float(cell_value))
            data_values.append(row_values)
            row_index += 1
        
        # Update in database
        conn.execute('''UPDATE chart_data 
                       SET chart_name = ?, data_type = ?, columns = ?, rows = ?, data_values = ?, is_public = ?
                       WHERE id = ? AND user_id = ?''',
                    (chart_name, data_type, json.dumps(columns), json.dumps(rows), 
                     json.dumps(data_values), is_public, chart_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash("✅ Chart updated successfully!", "success")
        return redirect(url_for('my_data'))
    
    # GET request - load existing data
    chart = conn.execute('''SELECT chart_name, data_type, columns, rows, data_values, is_public
                          FROM chart_data WHERE id = ? AND user_id = ?''', 
                       (chart_id, session['user_id'])).fetchone()
    conn.close()
    
    if not chart:
        flash("❌ Chart not found!", "error")
        return redirect(url_for('my_data'))
    
    # Parse existing data - use 'data_values' instead of 'values' to avoid conflict
    existing_data = {
        'chart_name': chart['chart_name'],
        'data_type': chart['data_type'],
        'columns': json.loads(chart['columns']),
        'rows': json.loads(chart['rows']),
        'data_values': json.loads(chart['data_values']),
        'is_public': chart['is_public']
    }
    
    return render_template('edit_data.html', chart_id=chart_id, data=existing_data)

# Share chart with specific users
@app.route('/share-chart/<int:chart_id>', methods=['GET', 'POST'])
def share_chart(chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        # Get selected user IDs from form
        shared_user_ids = request.form.getlist('shared_users')
        
        # Update shared_with field
        conn.execute('''UPDATE chart_data 
                       SET shared_with = ?
                       WHERE id = ? AND user_id = ?''',
                    (json.dumps(shared_user_ids), chart_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash("✅ Chart sharing settings updated!", "success")
        return redirect(url_for('my_data'))
    
    # GET request - load existing data and users
    chart = conn.execute('''SELECT chart_name, shared_with 
                          FROM chart_data WHERE id = ? AND user_id = ?''', 
                       (chart_id, session['user_id'])).fetchone()
    
    # Get all users except current user
    users = conn.execute('''SELECT id, username FROM users WHERE id != ?''', 
                        (session['user_id'],)).fetchall()
    
    conn.close()
    
    if not chart:
        flash("❌ Chart not found!", "error")
        return redirect(url_for('my_data'))
    
    # Parse existing shared users
    shared_with = json.loads(chart['shared_with']) if chart['shared_with'] else []
    
    return render_template('share_chart.html', 
                         chart_id=chart_id, 
                         chart_name=chart['chart_name'],
                         users=users,
                         shared_with=shared_with)

# Customize chart styles
@app.route('/customize-chart/<int:chart_id>', methods=['GET', 'POST'])
def customize_chart(chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        chart_title = request.form.get('chart_title', '')
        x_axis_label = request.form.get('x_axis_label', '')
        y_axis_label = request.form.get('y_axis_label', '')
        
        # Extract custom colors
        custom_colors = []
        row_index = 0
        while f'color_{row_index}' in request.form:
            custom_colors.append(request.form[f'color_{row_index}'])
            row_index += 1
        
        # Update chart customization in database
        conn.execute('''UPDATE chart_data 
                       SET chart_title = ?, x_axis_label = ?, y_axis_label = ?, custom_colors = ?
                       WHERE id = ? AND user_id = ?''',
                    (chart_title, x_axis_label, y_axis_label, 
                     json.dumps(custom_colors), chart_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash("✅ Chart styles updated successfully!", "success")
        return redirect(url_for('dashboard'))
    
    # GET request - load existing chart data
    chart = conn.execute('''SELECT chart_name, data_type, columns, rows, data_values, 
                                  chart_title, x_axis_label, y_axis_label, custom_colors
                          FROM chart_data WHERE id = ? AND user_id = ?''', 
                       (chart_id, session['user_id'])).fetchone()
    conn.close()
    
    if not chart:
        flash("❌ Chart not found!", "error")
        return redirect(url_for('dashboard'))
    
    # Parse existing data
    existing_data = {
        'chart_name': chart['chart_name'],
        'data_type': chart['data_type'],
        'columns': json.loads(chart['columns']),
        'rows': json.loads(chart['rows']),
        'data_values': json.loads(chart['data_values']),
        'chart_title': chart['chart_title'] or '',
        'x_axis_label': chart['x_axis_label'] or '',
        'y_axis_label': chart['y_axis_label'] or '',
        'custom_colors': json.loads(chart['custom_colors']) if chart['custom_colors'] else []
    }
    
    return render_template('customize_chart.html', chart_id=chart_id, data=existing_data)

# Duplicate chart
@app.route('/duplicate-chart/<int:chart_id>')
def duplicate_chart(chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get original chart data
    chart = conn.execute('''SELECT chart_name, data_type, columns, rows, data_values 
                          FROM chart_data WHERE id = ? AND user_id = ?''', 
                       (chart_id, session['user_id'])).fetchone()
    
    if chart:
        # Insert duplicate with "Copy of" prefix
        new_name = f"Copy of {chart['chart_name']}"
        conn.execute('''INSERT INTO chart_data (user_id, chart_name, data_type, columns, rows, data_values) 
                       VALUES (?, ?, ?, ?, ?, ?)''',
                    (session['user_id'], new_name, chart['data_type'], 
                     chart['columns'], chart['rows'], chart['data_values']))
        conn.commit()
        flash("✅ Chart duplicated successfully!", "success")
    else:
        flash("❌ Chart not found!", "error")
    
    conn.close()
    return redirect(url_for('my_data'))

# Delete chart
@app.route('/delete-chart/<int:chart_id>')
def delete_chart(chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Delete the chart
    result = conn.execute('DELETE FROM chart_data WHERE id = ? AND user_id = ?', 
                         (chart_id, session['user_id']))
    conn.commit()
    conn.close()
    
    if result.rowcount > 0:
        flash("✅ Chart deleted successfully!", "success")
    else:
        flash("❌ Chart not found!", "error")
    
    return redirect(url_for('my_data'))

# Dashboard management
@app.route('/my-dashboards')
def my_dashboards():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get user's own dashboards
    user_dashboards = conn.execute('''
        SELECT id, name, description, is_public, created_at, updated_at 
        FROM dashboards WHERE user_id = ? ORDER BY updated_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get dashboards shared with user
    shared_dashboards = conn.execute('''
        SELECT d.id, d.name, d.description, d.is_public, d.created_at, d.updated_at,
               u.username as owner_username, ds.can_edit
        FROM dashboards d
        JOIN dashboard_shares ds ON d.id = ds.dashboard_id
        JOIN users u ON d.user_id = u.id
        WHERE ds.shared_with_user_id = ?
        ORDER BY d.updated_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('my_dashboards.html', 
                         user_dashboards=user_dashboards,
                         shared_dashboards=shared_dashboards)

# Create new dashboard
@app.route('/create-dashboard', methods=['GET', 'POST'])
def create_dashboard():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        is_public = 1 if request.form.get('is_public') else 0
        shared_user_ids = request.form.getlist('shared_users')
        
        conn = get_db_connection()
        
        # Create the dashboard
        cursor = conn.execute('''
            INSERT INTO dashboards (user_id, name, description, is_public) 
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], name, description, is_public))
        
        dashboard_id = cursor.lastrowid
        
        # Share with selected users
        for user_id in shared_user_ids:
            if user_id:  # Skip empty values
                conn.execute('''
                    INSERT INTO dashboard_shares (dashboard_id, shared_with_user_id, can_edit)
                    VALUES (?, ?, ?)
                ''', (dashboard_id, int(user_id), 0))  # can_edit = 0 for view-only initially
        
        conn.commit()
        conn.close()
        
        flash("✅ Dashboard created successfully!", "success")
        return redirect(url_for('my_dashboards'))
    
    return render_template('create_dashboard.html')

# Edit existing dashboard
@app.route('/edit-dashboard/<int:dashboard_id>', methods=['GET', 'POST'])
def edit_dashboard(dashboard_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user owns this dashboard
    dashboard = conn.execute('''
        SELECT id, name, description, is_public, user_id 
        FROM dashboards WHERE id = ? AND user_id = ?
    ''', (dashboard_id, session['user_id'])).fetchone()
    
    if not dashboard:
        conn.close()
        flash("❌ Dashboard not found or access denied!", "error")
        return redirect(url_for('my_dashboards'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description', '')
        is_public = 1 if request.form.get('is_public') else 0
        shared_user_ids = request.form.getlist('shared_users')
        
        # Update dashboard
        conn.execute('''
            UPDATE dashboards 
            SET name = ?, description = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (name, description, is_public, dashboard_id))
        
        # Remove existing shares
        conn.execute('DELETE FROM dashboard_shares WHERE dashboard_id = ?', (dashboard_id,))
        
        # Add new shares
        for user_id in shared_user_ids:
            if user_id:  # Skip empty values
                conn.execute('''
                    INSERT INTO dashboard_shares (dashboard_id, shared_with_user_id, can_edit)
                    VALUES (?, ?, ?)
                ''', (dashboard_id, int(user_id), 0))
        
        conn.commit()
        conn.close()
        
        flash("✅ Dashboard updated successfully!", "success")
        return redirect(url_for('my_dashboards'))
    
    # GET request - load existing data
    # Get current shared users
    shared_users = conn.execute('''
        SELECT u.id, u.username, u.role 
        FROM dashboard_shares ds
        JOIN users u ON ds.shared_with_user_id = u.id
        WHERE ds.dashboard_id = ?
    ''', (dashboard_id,)).fetchall()
    
    shared_user_ids = [str(user['id']) for user in shared_users]
    
    conn.close()
    
    return render_template('edit_dashboard.html', 
                         dashboard=dashboard,
                         shared_user_ids=shared_user_ids)

# Delete dashboard
@app.route('/delete-dashboard/<int:dashboard_id>')
def delete_dashboard(dashboard_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user owns this dashboard
    dashboard = conn.execute('''
        SELECT id, name FROM dashboards WHERE id = ? AND user_id = ?
    ''', (dashboard_id, session['user_id'])).fetchone()
    
    if not dashboard:
        conn.close()
        flash("❌ Dashboard not found or access denied!", "error")
        return redirect(url_for('my_dashboards'))
    
    # Delete dashboard charts and shares first (to maintain referential integrity)
    conn.execute('DELETE FROM dashboard_charts WHERE dashboard_id = ?', (dashboard_id,))
    conn.execute('DELETE FROM dashboard_shares WHERE dashboard_id = ?', (dashboard_id,))
    
    # Delete the dashboard
    result = conn.execute('DELETE FROM dashboards WHERE id = ?', (dashboard_id,))
    conn.commit()
    conn.close()
    
    if result.rowcount > 0:
        flash(f"✅ Dashboard '{dashboard['name']}' deleted successfully!", "success")
    else:
        flash("❌ Dashboard not found!", "error")
    
    return redirect(url_for('my_dashboards'))

# Duplicate dashboard
@app.route('/duplicate-dashboard/<int:dashboard_id>')
def duplicate_dashboard(dashboard_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get the original dashboard
    dashboard = conn.execute('''
        SELECT name, description, is_public 
        FROM dashboards WHERE id = ? AND user_id = ?
    ''', (dashboard_id, session['user_id'])).fetchone()
    
    if not dashboard:
        conn.close()
        flash("❌ Dashboard not found or access denied!", "error")
        return redirect(url_for('my_dashboards'))
    
    # Create duplicate dashboard with "Copy of" prefix
    new_name = f"Copy of {dashboard['name']}"
    cursor = conn.execute('''
        INSERT INTO dashboards (user_id, name, description, is_public) 
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], new_name, dashboard['description'], dashboard['is_public']))
    
    new_dashboard_id = cursor.lastrowid
    
    # Duplicate all charts from the original dashboard
    original_charts = conn.execute('''
        SELECT chart_id, position_x, position_y, width, height 
        FROM dashboard_charts WHERE dashboard_id = ?
    ''', (dashboard_id,)).fetchall()
    
    for chart in original_charts:
        conn.execute('''
            INSERT INTO dashboard_charts (dashboard_id, chart_id, position_x, position_y, width, height)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (new_dashboard_id, chart['chart_id'], chart['position_x'], 
              chart['position_y'], chart['width'], chart['height']))
    
    conn.commit()
    conn.close()
    
    flash(f"✅ Dashboard duplicated as '{new_name}'!", "success")
    return redirect(url_for('my_dashboards'))

    # Remove chart from dashboard
@app.route('/remove-chart-from-dashboard/<int:dashboard_id>/<int:chart_id>')
def remove_chart_from_dashboard(dashboard_id, chart_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user has permission to modify this dashboard
    # User can remove charts if:
    # 1. They own the dashboard, OR
    # 2. They are the username "admin" (not role-based), OR  
    # 3. They have edit permissions on a shared dashboard
    dashboard = conn.execute('''
        SELECT d.user_id, d.name, u.username as owner_username,
               ds.can_edit as shared_edit_permission
        FROM dashboards d
        JOIN users u ON d.user_id = u.id
        LEFT JOIN dashboard_shares ds ON d.id = ds.dashboard_id AND ds.shared_with_user_id = ?
        WHERE d.id = ?
    ''', (session['user_id'], dashboard_id)).fetchone()
    
    if not dashboard:
        conn.close()
        flash("❌ Dashboard not found!", "error")
        return redirect(url_for('my_dashboards'))
    
    # Check permissions
    can_edit = (
        dashboard['user_id'] == session['user_id'] or  # Owner
        session['username'] == 'admin' or              # Username "admin"
        dashboard['shared_edit_permission'] == 1       # Has edit permission on shared dashboard
    )
    
    if not can_edit:
        conn.close()
        flash("❌ You don't have permission to modify this dashboard!", "error")
        return redirect(url_for('dashboard_view', dashboard_id=dashboard_id))
    
    # Remove the chart from dashboard (but not delete the actual chart)
    result = conn.execute('''
        DELETE FROM dashboard_charts 
        WHERE dashboard_id = ? AND chart_id = ?
    ''', (dashboard_id, chart_id))
    
    conn.commit()
    conn.close()
    
    if result.rowcount > 0:
        flash("✅ Chart removed from dashboard!", "success")
    else:
        flash("❌ Chart not found in dashboard!", "error")
    
    return redirect(url_for('dashboard_view', dashboard_id=dashboard_id))

# Browse available dashboards (shared and public)
@app.route('/browse-dashboards')
def browse_dashboards():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Get public dashboards (excluding user's own)
    public_dashboards = conn.execute('''
        SELECT d.id, d.name, d.description, d.is_public, d.created_at, d.updated_at,
               u.username as owner_username,
               (SELECT COUNT(*) FROM dashboard_charts WHERE dashboard_id = d.id) as chart_count
        FROM dashboards d
        JOIN users u ON d.user_id = u.id
        WHERE d.is_public = 1 AND d.user_id != ?
        ORDER BY d.updated_at DESC
    ''', (session['user_id'],)).fetchall()
    
    # Get dashboards shared with this user
    shared_dashboards = conn.execute('''
        SELECT d.id, d.name, d.description, d.is_public, d.created_at, d.updated_at,
               u.username as owner_username, ds.can_edit,
               (SELECT COUNT(*) FROM dashboard_charts WHERE dashboard_id = d.id) as chart_count
        FROM dashboards d
        JOIN dashboard_shares ds ON d.id = ds.dashboard_id
        JOIN users u ON d.user_id = u.id
        WHERE ds.shared_with_user_id = ?
        ORDER BY d.updated_at DESC
    ''', (session['user_id'],)).fetchall()
    
    conn.close()
    
    return render_template('browse_dashboards.html',
                         public_dashboards=public_dashboards,
                         shared_dashboards=shared_dashboards)

# View and edit dashboard
# View and edit dashboard
@app.route('/dashboard-view/<int:dashboard_id>')
def dashboard_view(dashboard_id):
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Check if user has access to this dashboard
    dashboard = conn.execute('''
        SELECT d.*, u.username as owner_username,
               (d.user_id = ? OR ds.shared_with_user_id = ? OR d.is_public = 1) as has_access,
               ds.can_edit as shared_edit_permission
        FROM dashboards d
        LEFT JOIN dashboard_shares ds ON d.id = ds.dashboard_id AND ds.shared_with_user_id = ?
        JOIN users u ON d.user_id = u.id
        WHERE d.id = ?
    ''', (session['user_id'], session['user_id'], session['user_id'], dashboard_id)).fetchone()
    
    if not dashboard or not dashboard['has_access']:
        conn.close()
        flash("❌ Dashboard not found or access denied!", "error")
        return redirect(url_for('my_dashboards'))
    
    # Get charts in this dashboard
    dashboard_charts = conn.execute('''
        SELECT dc.*, cd.chart_name, cd.data_type, cd.columns, cd.rows, cd.data_values,
               cd.chart_title, cd.x_axis_label, cd.y_axis_label, cd.custom_colors,
               u.username as chart_owner
        FROM dashboard_charts dc
        JOIN chart_data cd ON dc.chart_id = cd.id
        JOIN users u ON cd.user_id = u.id
        WHERE dc.dashboard_id = ?
        ORDER BY dc.position_y, dc.position_x
    ''', (dashboard_id,)).fetchall()
    
    # Get available charts for this user (own charts + shared charts + public charts)
    available_charts = conn.execute('''
        SELECT cd.id, cd.chart_name, cd.data_type, u.username as owner_username,
               (cd.user_id = ?) as is_owner
        FROM chart_data cd
        JOIN users u ON cd.user_id = u.id
        WHERE cd.user_id = ? OR cd.is_public = 1 OR cd.shared_with LIKE ?
        ORDER BY cd.chart_name
    ''', (session['user_id'], session['user_id'], f'%"{session["user_id"]}"%')).fetchall()
    
    conn.close()
    
    # Parse chart data
    parsed_charts = []
    for chart in dashboard_charts:
        try:
            parsed_charts.append({
                'id': chart['id'],
                'chart_id': chart['chart_id'],
                'chart_name': chart['chart_name'],
                'data_type': chart['data_type'],
                'columns': json.loads(chart['columns']) if chart['columns'] else [],
                'rows': json.loads(chart['rows']) if chart['rows'] else [],
                'values': json.loads(chart['data_values']) if chart['data_values'] else [],
                'chart_title': chart['chart_title'] or '',
                'x_axis_label': chart['x_axis_label'] or '',
                'y_axis_label': chart['y_axis_label'] or '',
                'custom_colors': json.loads(chart['custom_colors']) if chart['custom_colors'] else [],
                'chart_owner': chart['chart_owner'],
                'position_x': chart['position_x'],
                'position_y': chart['position_y'],
                'width': chart['width'],
                'height': chart['height']
            })
        except Exception as e:
            print(f"Error parsing chart {chart['chart_name']}: {e}")
            continue
    
    return render_template('dashboard_view.html',
                         dashboard=dashboard,
                         dashboard_charts=parsed_charts,
                         available_charts=available_charts)
    
    # Get available charts for this user (own charts + shared charts + public charts)
    available_charts = conn.execute('''
        SELECT cd.id, cd.chart_name, cd.data_type, u.username as owner_username,
               (cd.user_id = ?) as is_owner
        FROM chart_data cd
        JOIN users u ON cd.user_id = u.id
        WHERE cd.user_id = ? OR cd.is_public = 1 OR cd.shared_with LIKE ?
        ORDER BY cd.chart_name
    ''', (session['user_id'], session['user_id'], f'%"{session["user_id"]}"%')).fetchall()
    
    conn.close()
    
    # Parse chart data
    parsed_charts = []
    for chart in dashboard_charts:
        try:
            parsed_charts.append({
                'id': chart['id'],
                'chart_id': chart['chart_id'],
                'chart_name': chart['chart_name'],
                'data_type': chart['data_type'],
                'columns': json.loads(chart['columns']) if chart['columns'] else [],
                'rows': json.loads(chart['rows']) if chart['rows'] else [],
                'values': json.loads(chart['data_values']) if chart['data_values'] else [],
                'chart_title': chart['chart_title'] or '',
                'x_axis_label': chart['x_axis_label'] or '',
                'y_axis_label': chart['y_axis_label'] or '',
                'custom_colors': json.loads(chart['custom_colors']) if chart['custom_colors'] else [],
                'chart_owner': chart['chart_owner'],
                'position_x': chart['position_x'],
                'position_y': chart['position_y'],
                'width': chart['width'],
                'height': chart['height']
            })
        except Exception as e:
            print(f"Error parsing chart {chart['chart_name']}: {e}")
            continue
    
    return render_template('dashboard_view.html',
                         dashboard=dashboard,
                         dashboard_charts=parsed_charts,
                         available_charts=available_charts)

# API to add chart to dashboard
@app.route('/api/add-chart-to-dashboard', methods=['POST'])
def api_add_chart_to_dashboard():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authorized'}), 401
    
    data = request.get_json()
    dashboard_id = data.get('dashboard_id')
    chart_id = data.get('chart_id')
    
    conn = get_db_connection()
    
    # Verify user has access to both dashboard and chart
    dashboard_access = conn.execute('''
        SELECT id FROM dashboards 
        WHERE id = ? AND (user_id = ? OR is_public = 1 OR id IN (
            SELECT dashboard_id FROM dashboard_shares WHERE shared_with_user_id = ?
        ))
    ''', (dashboard_id, session['user_id'], session['user_id'])).fetchone()
    
    chart_access = conn.execute('''
        SELECT id FROM chart_data 
        WHERE id = ? AND (user_id = ? OR is_public = 1 OR shared_with LIKE ?)
    ''', (chart_id, session['user_id'], f'%"{session["user_id"]}"%')).fetchone()
    
    if not dashboard_access or not chart_access:
        conn.close()
        return jsonify({'success': False, 'error': 'Access denied'})
    
    # Add chart to dashboard
    conn.execute('''
        INSERT INTO dashboard_charts (dashboard_id, chart_id, position_x, position_y, width, height)
        VALUES (?, ?, 0, 0, 6, 4)
    ''', (dashboard_id, chart_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Chart added to dashboard'})

# Admin view - all dashboards
@app.route('/admin/dashboards')
def admin_all_dashboards():
    if 'username' not in session or session.get('role') != 'admin':
        flash("❌ Admin access required!", "error")
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    all_dashboards = conn.execute('''
        SELECT d.*, u.username as owner_username,
               (SELECT COUNT(*) FROM dashboard_charts WHERE dashboard_id = d.id) as chart_count
        FROM dashboards d
        JOIN users u ON d.user_id = u.id
        ORDER BY d.updated_at DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin_dashboards.html', dashboards=all_dashboards)

# API endpoint to get chart data (includes shared charts)
@app.route('/api/my-chart-data')
def my_chart_data():
    if 'username' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    try:
        conn = get_db_connection()
        
        # Get user's own charts AND charts shared with them
        charts = conn.execute('''SELECT c.id, c.chart_name, c.data_type, c.columns, c.rows, c.data_values, 
                                       c.chart_title, c.x_axis_label, c.y_axis_label, c.custom_colors,
                                       c.user_id, u.username as owner_username, c.is_public
                                FROM chart_data c
                                JOIN users u ON c.user_id = u.id
                                WHERE c.user_id = ? OR c.is_public = 1 OR c.shared_with LIKE ?
                                ORDER BY c.created_at DESC''', 
                             (session['user_id'], f'%"{session["user_id"]}"%')).fetchall()
        conn.close()
        
        chart_data = []
        for chart in charts:
            try:
                # Parse JSON data with error handling
                columns = json.loads(chart['columns']) if chart['columns'] else []
                rows = json.loads(chart['rows']) if chart['rows'] else []
                values = json.loads(chart['data_values']) if chart['data_values'] else []
                
                # Safely get customization fields (they might be None)
                chart_title = chart['chart_title'] or ''
                x_axis_label = chart['x_axis_label'] or ''
                y_axis_label = chart['y_axis_label'] or ''
                custom_colors = json.loads(chart['custom_colors']) if chart['custom_colors'] else []
                
                chart_data.append({
                    'id': chart['id'],
                    'chart_name': chart['chart_name'],
                    'type': chart['data_type'],
                    'columns': columns,
                    'rows': rows,
                    'values': values,
                    'chart_title': chart_title,
                    'x_axis_label': x_axis_label,
                    'y_axis_label': y_axis_label,
                    'custom_colors': custom_colors,
                    'owner_username': chart['owner_username'],
                    'is_shared': chart['user_id'] != session['user_id'],
                    'is_public': bool(chart['is_public'])
                })
            except json.JSONDecodeError as e:
                print(f"JSON parsing error for chart {chart['id']}: {e}")
                continue
            except Exception as e:
                print(f"Error processing chart {chart['id']}: {e}")
                continue
        
        return jsonify(chart_data)
    
    except Exception as e:
        print(f"Database error in my_chart_data: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# API to get all users (for sharing)
@app.route('/api/all-users')
def api_all_users():
    if 'username' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    conn = get_db_connection()
    users = conn.execute('''
        SELECT id, username, role FROM users WHERE id != ? ORDER BY username
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    users_list = [dict(user) for user in users]
    return jsonify(users_list)

# API to get users count (for admin)
@app.route('/api/users-count')
def api_users_count():
    if 'username' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    
    conn = get_db_connection()
    count = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()
    conn.close()
    
    return jsonify({'count': count['count']})

# API to get current chart sharing settings
@app.route('/api/chart-sharing/<int:chart_id>')
def api_chart_sharing(chart_id):
    if 'username' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    conn = get_db_connection()
    chart = conn.execute('''
        SELECT is_public, shared_with FROM chart_data 
        WHERE id = ? AND user_id = ?
    ''', (chart_id, session['user_id'])).fetchone()
    conn.close()
    
    if not chart:
        return jsonify({'error': 'Chart not found'}), 404
    
    shared_with = json.loads(chart['shared_with']) if chart['shared_with'] else []
    
    return jsonify({
        'is_public': bool(chart['is_public']),
        'shared_with': shared_with
    })

# API to update chart sharing
@app.route('/api/update-chart-sharing', methods=['POST'])
def api_update_chart_sharing():
    if 'username' not in session:
        return jsonify({'error': 'Not authorized'}), 401
    
    data = request.get_json()
    chart_id = data.get('chart_id')
    shared_users = data.get('shared_users', [])
    is_public = data.get('is_public', False)
    
    conn = get_db_connection()
    
    # Verify chart ownership
    chart = conn.execute('''
        SELECT id FROM chart_data WHERE id = ? AND user_id = ?
    ''', (chart_id, session['user_id'])).fetchone()
    
    if not chart:
        conn.close()
        return jsonify({'success': False, 'error': 'Chart not found or access denied'})
    
    # Update sharing settings
    conn.execute('''
        UPDATE chart_data 
        SET is_public = ?, shared_with = ?
        WHERE id = ?
    ''', (is_public, json.dumps(shared_users), chart_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Sharing settings updated'})

# Route to view and manage existing data
@app.route('/my-data')
def my_data():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    data_sets = conn.execute('''SELECT id, chart_name, data_type, columns, rows, data_values, 
                                       is_public, shared_with, created_at 
                               FROM chart_data WHERE user_id = ? ORDER BY created_at DESC''', 
                            (session['user_id'],)).fetchall()
    conn.close()
    
    # Parse JSON data for template
    parsed_data_sets = []
    for data_set in data_sets:
        try:
            columns = json.loads(data_set['columns'])
            rows = json.loads(data_set['rows'])
            values = json.loads(data_set['data_values'])
            shared_with = json.loads(data_set['shared_with']) if data_set['shared_with'] else []
            
            parsed_data = {
                'id': data_set['id'],
                'chart_name': data_set['chart_name'],
                'data_type': data_set['data_type'],
                'columns': columns,
                'rows': rows,
                'chart_values': values,
                'is_public': data_set['is_public'],
                'shared_with': shared_with,
                'created_at': data_set['created_at']
            }
            parsed_data_sets.append(parsed_data)
            
        except Exception as e:
            print(f"ERROR parsing data for chart {data_set['chart_name']}: {e}")
            parsed_data_sets.append({
                'id': data_set['id'],
                'chart_name': data_set['chart_name'],
                'data_type': data_set['data_type'],
                'columns': [],
                'rows': [],
                'chart_values': [],
                'is_public': data_set['is_public'],
                'shared_with': [],
                'created_at': data_set['created_at'],
                'error': str(e)
            })
    
    return render_template('my_data.html', data_sets=parsed_data_sets)

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("⚠️ Please log in first!", "warning")
        return redirect(url_for('login'))
    
    role = session.get('role', 'user')
    username = session.get('username')
    
    # Charts will fetch data dynamically via JavaScript from /api/my-chart-data
    if role == 'admin':
        return render_template('dashboard_admin.html', username=username)
    else:
        return render_template('dashboard_user.html', username=username)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
