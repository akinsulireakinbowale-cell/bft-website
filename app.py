import os
import secrets
from functools import wraps

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    session,
    render_template_string,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash


# ==========================================
# APP CONFIGURATION
# ==========================================

app = Flask(name)

app.config.update(
SECRET_KEY=os.environ.get("SECRET_KEY"),
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SAMESITE="Lax",
SESSION_COOKIE_SECURE=True,
PERMANENT_SESSION_LIFETIME=1800,
)

if not app.config["SECRET_KEY"]:
raise RuntimeError("Please set the SECRET_KEY environment variable.")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Please set the SECRET_KEY environment variable.")

database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///bft.db",
)

if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1,
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ==========================================
# DATABASE MODELS
# ==========================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(
        db.String(100),
        nullable=False,
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False,
    )

    phone = db.Column(
        db.String(30),
        nullable=False,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    referral_code = db.Column(
        db.String(20),
        unique=True,
        nullable=False,
    )

    referred_by = db.Column(
        db.String(20),
        nullable=True,
    )


class UserStatus(db.Model):
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        primary_key=True,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )


# Create missing tables without intentionally deleting existing data.
with app.app_context():
    db.create_all()


# ==========================================
# ACCOUNT STATUS HELPERS
# ==========================================

def user_is_active(user):
    if user is None:
        return False

    status = db.session.get(UserStatus, user.id)

    # Existing users without a status record remain active.
    return status is None or status.is_active


def set_user_active(user, active):
    status = db.session.get(UserStatus, user.id)

    if status is None:
        status = UserStatus(
            user_id=user.id,
            is_active=active,
        )
        db.session.add(status)
    else:
        status.is_active = active

    db.session.commit()


def generate_unique_referral_code():
    while True:
        code = secrets.token_hex(4).upper()

        existing = User.query.filter_by(
            referral_code=code
        ).first()

        if existing is None:
            return code


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return None

    if not user_is_active(user):
        session.clear()
        return None

    return user


def get_admin_email():
    return os.environ.get(
        "ADMIN_EMAIL",
        "",
    ).strip().lower()


def is_admin_user(user):
    admin_email = get_admin_email()

    return (
        user is not None
        and bool(admin_email)
        and user.email.lower() == admin_email
    )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        if not is_admin_user(user):
            return page("""
                <h1>Access Denied</h1>

                <p class="error">
                    You are not authorised to access this page.
                </p>

                <a class="btn" href="{{ url_for('dashboard') }}">
                    Return to Dashboard
                </a>
            """), 403

        return view(*args, **kwargs)

    return wrapped


# ==========================================
# PAGE DESIGN
# ==========================================

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>BFT Website</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background: #f2f5f9;
            margin: 0;
            padding: 20px 12px;
            color: #222;
        }

        .card {
            background: white;
            max-width: 1100px;
            margin: 20px auto;
            padding: 24px;
            border-radius: 14px;
            box-shadow: 0 4px 15px #ddd;
            overflow-wrap: anywhere;
        }

        h1 {
            color: #174ea6;
            text-align: center;
        }

        h2 {
            color: #174ea6;
        }

        p {
            color: #555;
            line-height: 1.6;
        }

        input {
            display: block;
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border-radius: 7px;
            border: 1px solid #ccc;
            font-size: 16px;
        }

        button,
        .btn {
            display: inline-block;
            background: #174ea6;
            color: white;
            padding: 12px 16px;
            margin: 6px 0;
            border: 0;
            border-radius: 7px;
            text-align: center;
            text-decoration: none;
            font-size: 15px;
            cursor: pointer;
        }

        button {
            width: 100%;
        }

        .danger {
            background: #b00020;
        }

        .success-button {
            background: #137333;
        }

        .error {
            color: #b00020;
        }

        .success {
            color: #137333;
        }

        .table-wrap {
            overflow-x: auto;
            width: 100%;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 16px;
        }

        th,
        td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #174ea6;
            color: white;
        }

        tr:nth-child(even) {
            background: #f5f7fa;
        }

        td a {
            color: #174ea6;
            font-weight: bold;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(
                auto-fit,
                minmax(140px, 1fr)
            );
            gap: 12px;
        }

        .stat {
            background: #eef3fc;
            padding: 16px;
            border-radius: 10px;
            text-align: center;
        }

        .stat strong {
            display: block;
            font-size: 25px;
            color: #174ea6;
        }

        .profile-item {
            padding: 12px;
            margin: 8px 0;
            background: #f5f7fa;
            border-radius: 7px;
        }

        .profile-item strong {
            color: #174ea6;
        }

        label {
            display: block;
            margin-top: 12px;
            font-weight: bold;
        }

        .action-form {
            margin: 0;
        }

        .action-form button {
            min-width: 110px;
        }

        .status-active {
            color: #137333;
            font-weight: bold;
        }

        .status-inactive {
            color: #b00020;
            font-weight: bold;
        }

        .navigation {
            margin-bottom: 15px;
        }

        .navigation a {
            margin-right: 8px;
        }

        @media (max-width: 600px) {
            .card {
                padding: 16px;
            }

            h1 {
                font-size: 25px;
            }

            th,
            td {
                padding: 8px;
                font-size: 13px;
            }
        }
    </style>
</head>

<body>
    <div class="card">
        {{ content|safe }}
    </div>
</body>
</html>
"""


def page(template, **context):
    content = render_template_string(
        template,
        **context,
    )

    return render_template_string(
        PAGE,
        content=content,
    )


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    user = current_user()

    if user:
        return redirect(url_for("dashboard"))

    return page("""
        <h1>Welcome to BFT</h1>

        <p>
            Your journey starts here.
            Create an account to get started.
        </p>

        <a class="btn" href="{{ url_for('register') }}">
            Create an Account
        </a>

        <a class="btn" href="{{ url_for('login') }}">
            Log In
        </a>
    """)


# ==========================================
# REGISTRATION
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    referral_from_url = request.args.get(
        "ref",
        "",
    ).strip().upper()

    if request.method == "POST":
        name = request.form.get(
            "full_name",
            "",
        ).strip()

        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        password = request.form.get(
            "password",
            "",
        )

        referral = request.form.get(
            "referral_code",
            "",
        ).strip().upper() or None

        if not name or not email or not phone or not password:
            message = "Please complete all required fields."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        elif User.query.filter_by(email=email).first():
            message = "This email is already registered."

        elif referral and not User.query.filter_by(
            referral_code=referral
        ).first():
            message = "That referral code is not valid."

        else:
            user = User(
                full_name=name,
                email=email,
                phone=phone,
                password_hash=generate_password_hash(password),
                referral_code=generate_unique_referral_code(),
                referred_by=referral,
            )

            try:
                db.session.add(user)
                db.session.commit()

                return redirect(
                    url_for("login", registered="1")
                )

            except Exception:
                db.session.rollback()

                app.logger.exception(
                    "Registration failed."
                )

                message = (
                    "Registration could not be completed. "
                    "Please try again."
                )

    return page("""
        <h1>Create Account</h1>

        <p class="error">{{ message }}</p>

        <form method="post">
            <label>Full Name</label>
            <input
                name="full_name"
                required
                maxlength="100"
                placeholder="Full name"
            >

            <label>Email Address</label>
            <input
                name="email"
                type="email"
                required
                maxlength="150"
                placeholder="Email address"
            >

            <label>Phone Number</label>
            <input
                name="phone"
                type="tel"
                required
                maxlength="30"
                placeholder="Phone number"
            >

            <label>Password</label>
            <input
                name="password"
                type="password"
                required
                minlength="8"
                placeholder="At least 8 characters"
            >

            <label>Referral Code (Optional)</label>
            <input
                name="referral_code"
                placeholder="Enter referral code"
                value="{{ referral }}"
            >

            <button type="submit">Register</button>
        </form>

        <p>
            Already have an account?
            <a href="{{ url_for('login') }}">Log in</a>
        </p>

        <a href="{{ url_for('home') }}">Home</a>
    """, message=message, referral=referral_from_url)


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""

    if request.args.get("registered"):
        message = "Account created. You can now log in."

    if request.method == "POST":
        email = request.form.get(
            "email",
            "",
        ).strip().lower()

        password = request.form.get(
            "password",
            "",
        )

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(
            user.password_hash,
            password,
        ):
            if not user_is_active(user):
                return page("""
                    <h1>Account Inactive</h1>

                    <p class="error">
                        Your account is inactive.
                        Please contact the administrator.
                    </p>

                    <a class="btn" href="{{ url_for('login') }}">
                        Back to Login
                    </a>
                """), 403

            session.clear()
            session["user_id"] = user.id

            return redirect(url_for("dashboard"))

        message = "Incorrect email or password."

    return page("""
        <h1>Log In</h1>

        <p class="success">{{ message }}</p>

        <form method="post">
            <label>Email Address</label>
            <input
                name="email"
                type="email"
                required
                placeholder="Email address"
            >

            <label>Password</label>
            <input
                name="password"
                type="password"
                required
                placeholder="Password"
            >

            <button type="submit">Log In</button>
        </form>

        <p>
            Don't have an account?
            <a href="{{ url_for('register') }}">
                Register here
            </a>
        </p>

        <a href="{{ url_for('home') }}">Home</a>
    """, message=message)


# ==========================================
# USER DASHBOARD
# ==========================================

@app.route("/dashboard")
def dashboard():
    user = current_user()

    if user is None:
        return redirect(url_for("login"))

    if not user.referral_code:
        user.referral_code = generate_unique_referral_code()
        db.session.commit()

    referral_link = url_for(
        "register",
        ref=user.referral_code,
        _external=True,
    )

    referral_count = User.query.filter_by(
        referred_by=user.referral_code
    ).count()

    return page("""
        <h1>Welcome, {{ user.full_name }}</h1>

        <p>Your BFT dashboard</p>

        <div class="profile-item">
            <strong>Email:</strong> {{ user.email }}
        </div>

        <div class="profile-item">
            <strong>Phone:</strong> {{ user.phone }}
        </div>

        <div class="profile-item">
            <strong>Your Referral Code:</strong>
            {{ user.referral_code }}
        </div>

        <div class="profile-item">
            <strong>People Referred:</strong>
            {{ referral_count }}
        </div>

        <h2>Your Referral Link</h2>

        <p>Share this link with people you invite to BFT.</p>

        <input
            value="{{ referral_link }}"
            readonly
            onclick="this.select()"
        >

        <div class="navigation">
            <a class="btn" href="{{ url_for('edit_profile') }}">
                Edit My Profile
            </a>

            {% if is_admin_user(user) %}
                <a class="btn" href="{{ url_for('admin_dashboard') }}">
                    Admin Dashboard
                </a>
            {% endif %}

            <a class="btn" href="{{ url_for('logout') }}">
                Log Out
            </a>
        </div>
    """,
        user=user,
        referral_count=referral_count,
        referral_link=referral_link,
        is_admin_user=is_admin_user,
    )


# ==========================================
# EDIT OWN PROFILE
# ==========================================

@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    user = current_user()

    if user is None:
        return redirect(url_for("login"))

    message = ""

    if request.method == "POST":
        name = request.form.get(
            "full_name",
            "",
        ).strip()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        if not name or not phone:
            message = "Name and phone number are required."

        elif len(name) > 100 or len(phone) > 30:
            message = "The name or phone number is too long."

        else:
            user.full_name = name
            user.phone = phone

            try:
                db.session.commit()
                return redirect(url_for("dashboard"))

            except Exception:
                db.session.rollback()

                app.logger.exception(
                    "Profile update failed."
                )

                message = "Unable to update your profile."

    return page("""
        <h1>Edit My Profile</h1>

        <p class="error">{{ message }}</p>

        <form method="post">
            <label>Full Name</label>
            <input
                name="full_name"
                value="{{ user.full_name }}"
                maxlength="100"
                required
            >

            <label>Email Address</label>
            <input value="{{ user.email }}" readonly>

            <p>Your email address cannot be changed here.</p>

            <label>Phone Number</label>
            <input
                name="phone"
                value="{{ user.phone }}"
                maxlength="30"
                required
            >

            <button type="submit">Save Changes</button>
        </form>

        <a class="btn" href="{{ url_for('dashboard') }}">
            Back to Dashboard
        </a>
    """, user=user, message=message)


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    search = request.args.get(
        "search",
        "",
    ).strip()

    query = User.query

    if search:
        term = f"%{search}%"

        query = query.filter(
            or_(
                User.full_name.ilike(term),
                User.email.ilike(term),
                User.phone.ilike(term),
                User.referral_code.ilike(term),
            )
        )

    users = query.order_by(User.id.desc()).all()
    all_users = User.query.all()

    total_users = len(all_users)

    active_users = sum(
        1 for user in all_users
        if user_is_active(user)
    )

    inactive_users = total_users - active_users

    return page("""
        <h1>Admin Dashboard</h1>

        <p>Manage BFT registered users.</p>

        <div class="stats">
            <div class="stat">
                <strong>{{ total_users }}</strong>
                Total Users
          
            </div>

            <div class="stat">
                <strong>{{ active_users }}</strong>
                Active Users
            </div>

            <div class="stat">
                <strong>{{ inactive_users }}</strong>
                Inactive Users
            </div>
        </div>

        <h2>Search Users</h2>

        <form method="get" action="{{ url_for('admin_dashboard') }}">
            <input
                type="text"
                name="search"
                value="{{ search }}"
                placeholder="Search by name, email, phone or referral code"
            >
            <button type="submit">Search</button>
        </form>

        <p>Total matching users: {{ users|length }}</p>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Phone</th>
                        <th>Referral Code</th>
                        <th>Referred By</th>
                        <th>Status</th>
                        <th>Action</th>
                    </tr>
                </thead>

                <tbody>
                    {% for person in users %}
                    <tr>
                        <td>{{ person.id }}</td>
                        <td>{{ person.full_name }}</td>
                        <td>{{ person.email }}</td>
                        <td>{{ person.phone }}</td>
                        <td>{{ person.referral_code }}</td>
                        <td>{{ person.referred_by or "None" }}</td>

                        <td>
                            {% if user_is_active(person) %}
                                <span class="status-active">Active</span>
                            {% else %}
                                <span class="status-inactive">Inactive</span>
                            {% endif %}
                        </td>

                        <td>
                            {% if user_is_active(person) %}
                                <form
                                    class="action-form"
                                    method="post"
                                    action="{{ url_for('deactivate_user', user_id=person.id) }}"
                                    onsubmit="return confirm('Deactivate this account?');"
                                >
                                    <button class="danger" type="submit">
                                        Deactivate
                                    </button>
                                </form>
                            {% else %}
                                <form
                                    class="action-form"
                                    method="post"
                                    action="{{ url_for('activate_user', user_id=person.id) }}"
                                    onsubmit="return confirm('Activate this account?');"
                                >
                                    <button class="success-button" type="submit">
                                        Activate
                                    </button>
                                </form>
                            {% endif %}
                        </td>
                    </tr>
                    {% else %}
                    <tr>
                        <td colspan="8">No users found.</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <p>
            <a class="btn" href="{{ url_for('dashboard') }}">
                Back to Dashboard
            </a>

            <a class="btn" href="{{ url_for('logout') }}">
                Log Out
            </a>
        </p>
    """,
        search=search,
        users=users,
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        user_is_active=user_is_active,
    )


# ==========================================
# ACTIVATE USER
# ==========================================

@app.route("/admin/activate/<int:user_id>", methods=["POST"])
@admin_required
def activate_user(user_id):
    user = db.session.get(User, user_id)

    if user is None:
        return "User not found", 404

    set_user_active(user, True)

    return redirect(url_for("admin_dashboard"))


# ==========================================
# DEACTIVATE USER
# ==========================================

@app.route("/admin/deactivate/<int:user_id>", methods=["POST"])
@admin_required
def deactivate_user(user_id):
    admin = current_user()
    user = db.session.get(User, user_id)

    if user is None:
        return "User not found", 404

    # Prevent the administrator from deactivating their own account.
    if user.id == admin.id:
        return "You cannot deactivate your own account.", 400

    set_user_active(user, False)

    return redirect(url_for("admin_dashboard"))


# ==========================================
# LOG OUT
# ==========================================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    app.run(debug=False)
