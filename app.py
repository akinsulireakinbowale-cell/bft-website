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
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Please set the SECRET_KEY environment variable.")

database_url = os.environ.get("DATABASE_URL", "sqlite:///bft.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    referral_code = db.Column(db.String(20), unique=True, nullable=False)
    referred_by = db.Column(db.String(20), nullable=True)


with app.app_context():
    db.create_all()


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>BFT</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f5f9;
            margin: 0;
            padding: 20px 12px;
            color: #222;
        }

        .card {
            background: white;
            max-width: 850px;
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
        }

        input, button {
            box-sizing: border-box;
            width: 100%;
            padding: 12px;
            margin: 8px 0;
            border-radius: 7px;
            border: 1px solid #ccc;
            font-size: 16px;
        }

        button, .btn {
            display: inline-block;
            box-sizing: border-box;
            background: #174ea6;
            color: white;
            padding: 12px;
            margin: 6px 0;
            border: 0;
            border-radius: 7px;
            text-align: center;
            text-decoration: none;
            font-size: 16px;
            cursor: pointer;
        }

        .error {
            color: #b00020;
        }

        .success {
            color: #137333;
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin-top: 16px;
        }

        th, td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
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
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
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
            padding: 10px;
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
    content = render_template_string(template, **context)
    return render_template_string(PAGE, content=content)


def current_user():
    user_id = session.get("user_id")

    if user_id is None:
        return None

    return db.session.get(User, user_id)


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()

        if not user:
            session.clear()
            return redirect(url_for("login"))

        admin_email = os.environ.get(
            "ADMIN_EMAIL", ""
        ).strip().lower()

        if not admin_email or user.email.lower() != admin_email:
            return page("""
                <h1>Access Denied</h1>
                <p>You are not authorised to access this page.</p>
                <a class="btn" href="{{ url_for('dashboard') }}">
                    Return to Dashboard
                </a>
            """), 403

        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def home():
    return page("""
        <h1>Welcome to BFT</h1>
        <p>Your journey starts here.</p>

        <a class="btn" href="{{ url_for('register') }}">
            Create an Account
        </a>

        <a class="btn" href="{{ url_for('login') }}">
            Log In
        </a>
    """)


@app.route("/register", methods=["GET", "POST"])
def register():
    message = ""

    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        referral = (
            request.form.get("referral_code", "").strip().upper()
            or None
        )

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
                referral_code=secrets.token_hex(4).upper(),
                referred_by=referral,
            )

            db.session.add(user)
            db.session.commit()

            return redirect(url_for("login", registered="1"))

    return page("""
        <h1>Create Account</h1>
        <p class="error">{{ message }}</p>

        <form method="post">
            <input name="full_name"
                   placeholder="Full name"
                   required maxlength="100">

            <input name="email"
                   type="email"
                   placeholder="Email address"
                   required maxlength="150">

            <input name="phone"
                   type="tel"
                   placeholder="Phone number"
                   required maxlength="30">

            <input name="password"
                   type="password"
                   placeholder="Password (at least 8 characters)"
                   required minlength="8">

            <input name="referral_code"
                   placeholder="Referral code (optional)">

            <button type="submit">Register</button>
        </form>

        <a href="{{ url_for('home') }}">Home</a>
    """, message=message)


@app.route("/login", methods=["GET", "POST"])
def login():
    message = (
        "Account created. You can now log in."
        if request.args.get("registered")
        else ""
    )

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id

            return redirect(url_for("dashboard"))

        message = "Incorrect email or password."

    return page("""
        <h1>Log In</h1>
        <p class="success">{{ message }}</p>

        <form method="post">
            <input name="email"
                   type="email"
                   placeholder="Email address"
                   required>

            <input name="password"
                   type="password"
                   placeholder="Password"
                   required>

            <button type="submit">Log In</button>
        </form>

        <a href="{{ url_for('register') }}">Create an account</a><br>
        <a href="{{ url_for('home') }}">Home</a>
    """, message=message)


@app.route("/dashboard")
def dashboard():
    user = current_user()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    if not user.referral_code:
        user.referral_code = secrets.token_hex(4).upper()
        db.session.commit()
