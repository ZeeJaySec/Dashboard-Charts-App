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
    
    # Check if we need to migrate old schema for users table
    try:
        c.execute("SELECT created_at FROM users LIMIT 1")
    except sqlite3.OperationalError:
        # Old schema exists, need to migrate users table
        print("Migrating users table schema...")
        c.execute('''ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP''')
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
        c.execute('''ALTER TABLE chart_data ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP''')
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
                                       c.user_id, u.username as owner_username
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
                    'is_shared': chart['user_id'] != session['user_id']
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

# Debug route to check database
@app.route('/debug-charts')
def debug_charts():
    if 'username' not in session:
        return "Not logged in"
    
    conn = get_db_connection()
    charts = conn.execute('SELECT * FROM chart_data WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    
    result = []
    for chart in charts:
        chart_dict = {
            'id': chart['id'],
            'chart_name': chart['chart_name'],
            'data_type': chart['data_type'],
            'columns': chart['columns'],
            'rows': chart['rows'],
            'data_values': chart['data_values'],
        }
        
        # Safely get the new columns (they might not exist yet)
        try:
            chart_dict['chart_title'] = chart['chart_title']
        except:
            chart_dict['chart_title'] = ''
        
        try:
            chart_dict['x_axis_label'] = chart['x_axis_label']
        except:
            chart_dict['x_axis_label'] = ''
        
        try:
            chart_dict['y_axis_label'] = chart['y_axis_label']
        except:
            chart_dict['y_axis_label'] = ''
        
        try:
            chart_dict['custom_colors'] = chart['custom_colors']
        except:
            chart_dict['custom_colors'] = ''
        
        try:
            chart_dict['is_public'] = chart['is_public']
        except:
            chart_dict['is_public'] = 0
        
        try:
            chart_dict['shared_with'] = chart['shared_with']
        except:
            chart_dict['shared_with'] = ''
        
        result.append(chart_dict)
    
    return jsonify(result)

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