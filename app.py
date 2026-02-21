from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATABASE = "database.db"

# ------------------ DATABASE CONNECTION ------------------

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# ------------------ LOGIN MANAGER ------------------

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    conn.close()

    if user:
        return User(user["id"], user["username"])
    return None

# ------------------ DATABASE INIT ------------------

def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            company TEXT,
            role TEXT,
            status TEXT,
            applied_date TEXT,
            deadline TEXT,
            notes TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ------------------ AUTH ROUTES ------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?,?)",
                (username, password)
            )
            conn.commit()
            flash("Registered successfully! Please login.")
            return redirect(url_for('login'))
        except:
            flash("Username already exists.")
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            login_user(User(user["id"], user["username"]))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------ DASHBOARD ------------------

@app.route('/')
@login_required
def dashboard():
    conn = get_db_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=?",
        (current_user.id,)
    ).fetchone()[0]

    offers = conn.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=? AND status='Offer'",
        (current_user.id,)
    ).fetchone()[0]

    rejected = conn.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=? AND status='Rejected'",
        (current_user.id,)
    ).fetchone()[0]

    conn.close()

    return render_template(
        'dashboard.html',
        total=total,
        offers=offers,
        rejected=rejected
    )

# ------------------ APPLICATION ROUTES ------------------

@app.route('/applications')
@login_required
def applications():
    conn = get_db_connection()

    apps = conn.execute(
        "SELECT * FROM applications WHERE user_id=? ORDER BY deadline",
        (current_user.id,)
    ).fetchall()

    conn.close()
    return render_template('applications.html', apps=apps)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_application():
    if request.method == 'POST':
        conn = get_db_connection()

        conn.execute("""
            INSERT INTO applications
            (user_id, company, role, status, applied_date, deadline, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user.id,
            request.form['company'],
            request.form['role'],
            request.form['status'],
            request.form['applied_date'],
            request.form['deadline'],
            request.form['notes']
        ))

        conn.commit()
        conn.close()

        return redirect(url_for('applications'))

    return render_template('add_application.html')


# ✅ NEW: STATUS UPDATE DROPDOWN ROUTE
@app.route('/update_status/<int:id>', methods=['POST'])
@login_required
def update_status(id):
    new_status = request.form['status']

    conn = get_db_connection()
    conn.execute("""
        UPDATE applications
        SET status=?
        WHERE id=? AND user_id=?
    """, (new_status, id, current_user.id))

    conn.commit()
    conn.close()

    return redirect(url_for('applications'))


@app.route('/delete/<int:id>')
@login_required
def delete_application(id):
    conn = get_db_connection()

    conn.execute(
        "DELETE FROM applications WHERE id=? AND user_id=?",
        (id, current_user.id)
    )

    conn.commit()
    conn.close()

    return redirect(url_for('applications'))


if __name__ == '__main__':
    app.run(debug=True)