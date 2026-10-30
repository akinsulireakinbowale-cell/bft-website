import os
import secrets
import string
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    flash,
    session,
    render_template_string,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)


# ==========================================
# APP CONFIGURATION
# ==========================================

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "Please set the SECRET_KEY environment variable."
    )

app.config.update(
    SECRET_KEY=secret_key,

    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "true").lower()
        == "true"
    ),

    PERMANENT_SESSION_LIFETIME=1800,
)

app.config.update(
    SECRET_KEY=secret_key,

    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    SESSION_COOKIE_SECURE=(
        os.environ.get("COOKIE_SECURE", "true").lower()
        == "true"
    ),

    PERMANENT_SESSION_LIFETIME=1800,
)

database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///bft.db",
)

# Support Render PostgreSQL connection URLs.
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql://",
        1,
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get(
        "RATELIMIT_STORAGE_URI",
        "memory://",
    ),
)

# ==========================================
# DATABASE MODELS
# ==========================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(
        db.String(120),
        nullable=False,
    )

    email = db.Column(
        db.String(150),
        unique=True,
        nullable=False,
        index=True,
    )

    phone = db.Column(
        db.String(40),
        nullable=False,
        default="",
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    referral_code = db.Column(
        db.String(30),
        unique=True,
        nullable=False,
        index=True,
    )

    referred_by = db.Column(
        db.String(30),
        nullable=True,
    )

# ==========================================
# WALLET MODEL
# ==========================================

class Wallet(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False,
        index=True,
    )

    balance = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=0,
    )

    currency = db.Column(
        db.String(3),
        nullable=False,
        default="NGN",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


# ==========================================
# WALLET TRANSACTION MODEL
# ==========================================

class WalletTransaction(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    wallet_id = db.Column(
        db.Integer,
        db.ForeignKey("wallet.id"),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    transaction_type = db.Column(
        db.String(20),
        nullable=False,
    )

    amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
    )

    reference = db.Column(
        db.String(100),
        unique=True,
        nullable=True,
    )

    description = db.Column(
        db.String(255),
        nullable=False,
        default="",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
)
class UserStatus(db.Model):
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        primary_key=True,
        nullable=False,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )


# ==========================================
# USER AND REFERRAL FUNCTIONS
# ==========================================

def user_is_active(user):
    if user is None:
        return False

    status = UserStatus.query.filter_by(
        user_id=user.id
    ).first()

    return True if status is None else bool(status.is_active)


def set_user_active(user, active):
    status = UserStatus.query.filter_by(
        user_id=user.id
    ).first()

    if status is None:
        db.session.add(
            UserStatus(
                user_id=user.id,
                is_active=bool(active),
            )
        )
    else:
        status.is_active = bool(active)

    db.session.commit()


def make_referral_code(length=8):
    alphabet = string.ascii_uppercase + string.digits

    for _ in range(30):
        code = "".join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        if not User.query.filter_by(
            referral_code=code
        ).first():
            return code

    return secrets.token_hex(5).upper()


def is_admin(user):
    configured_email = os.environ.get(
        "ADMIN_EMAIL",
        "",
    ).strip().lower()

    return bool(
        user
        and configured_email
        and user.email.lower() == configured_email
    )


def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    user = db.session.get(User, user_id)

    if user is None or not user_is_active(user):
        session.clear()
        return None

    return user


# ==========================================
# LOGIN AND ADMIN PROTECTION
# ==========================================

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            flash(
                "Please log in to continue.",
                "error",
            )
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = get_current_user()

        if user is None:
            flash(
                "Please log in to continue.",
                "error",
            )
            return redirect(url_for("login"))

        if not is_admin(user):
            abort(403)

        return view(*args, **kwargs)

    return wrapped


# ==========================================
# WEBSITE DESIGN
# ==========================================

STYLE = """
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    background: #f4f7fb;
    color: #182230;
    font-family: Arial, sans-serif;
}

header {
    background: #102b4e;
    color: white;
    padding: 16px 5%;
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
}

header a {
    color: white;
    text-decoration: none;
    margin-left: 12px;
}

main {
    max-width: 1100px;
    margin: 28px auto;
    padding: 0 16px;
}

.card {
    background: white;
    padding: 22px;
    border-radius: 12px;
    box-shadow: 0 3px 14px #0000000d;
    margin-bottom: 18px;
}

label {
    display: block;
    margin: 12px 0 5px;
    font-weight: bold;
}

input {
    width: 100%;
    padding: 11px;
    border: 1px solid #cbd5e1;
    border-radius: 7px;
    font-size: 16px;
}

button,
.button {
    display: inline-block;
    background: #1769aa;
    color: white;
    border: 0;
    border-radius: 7px;
    padding: 10px 14px;
    text-decoration: none;
    cursor: pointer;
    font-size: 14px;
}

.danger {
    background: #b42318;
}

.success {
    background: #16803c;
}

.muted {
    color: #64748b;
}

.notice {
    padding: 11px;
    border-radius: 7px;
    background: #eaf2ff;
    margin: 10px 0;
}

.notice.error {
    background: #ffe8e6;
    color: #8c1d18;
}

.notice.success {
    background: #e6f7ed;
    color: #17643a;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 10px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
}

.table-wrap {
    overflow-x: auto;
}

.inline {
    display: inline-block;
    margin: 3px;
}

.actions {
    min-width: 220px;
}

@media (max-width: 600px) {
    header a {
        margin-left: 0;
        margin-right: 10px;
    }

    th,
    td {
        padding: 8px;
        font-size: 13px;
    }
}
"""


def page(title, body, **context):
    template = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >
    <title>{{ title }} | BFT</title>
    <style>
    """ + STYLE + """
    </style>
</head>

<body>
<header>
    <strong>BFT</strong>

    <nav>
        {% if current_user %}
            <a href="{{ url_for('dashboard') }}">
                Dashboard
            </a>

                        {% if current_user_is_admin %}
                <a href="{{ url_for('admin_dashboard') }}">Admin Dashboard</a>
            {% endif %}

            <a href="{{ url_for('logout') }}">
                Log out
            </a>
        {% else %}
            <a href="{{ url_for('login') }}">
                Log in
            </a>

            <a href="{{ url_for('register') }}">
                Register
            </a>
        {% endif %}
    </nav>
</header>

<main>
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, message in messages %}
            <div class="notice {{ category }}">
                {{ message }}
            </div>
        {% endfor %}
    {% endwith %}

    """ + body + """
</main>
</body>
</html>
"""

    current = get_current_user()

    values = {
        "title": title,
        "current_user": current,
        "current_user_is_admin": is_admin(current),
    }

    values.update(context)

    return render_template_string(template, **values)


# ==========================================
# REGISTRATION FORM
# ==========================================

REGISTER_FORM = """
<section class="card">
    <h1>Create your BFT account</h1>

    <form method="post">
        <label for="full_name">Full name</label>
        <input
            id="full_name"
            name="full_name"
            maxlength="120"
            required
            value="{{ request.form.get('full_name', '') }}"
        >

        <label for="email">Email address</label>
        <input
            id="email"
            name="email"
            type="email"
            maxlength="150"
            required
            value="{{ request.form.get('email', '') }}"
        >

        <label for="phone">Phone number</label>
        <input
            id="phone"
            name="phone"
            maxlength="40"
            required
            value="{{ request.form.get('phone', '') }}"
        >

        <label for="password">
            Password (at least 8 characters)
        </label>
        <input
            id="password"
            name="password"
            type="password"
            minlength="8"
            required
        >

        <label for="confirm_password">
            Confirm password
        </label>
        <input
            id="confirm_password"
            name="confirm_password"
            type="password"
            minlength="8"
            required
        >

        <label for="referral_code">
            Referral code (optional)
        </label>
        <input
            id="referral_code"
            name="referral_code"
            maxlength="30"
            value="{{ request.form.get('referral_code', '') }}"
        >

        <p>
            <button type="submit">Register</button>
        </p>
    </form>

    <p>
        Already registered?
        <a href="{{ url_for('login') }}">Log in</a>.
    </p>
</section>
"""


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    if get_current_user():
        return redirect(url_for("dashboard"))

    return page(
        "Home",
        """
        <section class="card">
            <h1>Welcome to BFT</h1>

            <p>
                Create an account or log in to access
                your dashboard.
            </p>

            <a class="button" href="{{ url_for('register') }}">
                Create account
            </a>

            <a class="button" href="{{ url_for('login') }}">
                Log in
            </a>
        </section>
        """,
    )


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get(
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

        confirm_password = request.form.get(
            "confirm_password",
            "",
        )

        referral_input = request.form.get(
            "referral_code",
            "",
        ).strip().upper()

        referrer = None

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        referral_input = request.form.get(
            "referral_code", ""
        ).strip().upper()

        referrer = None

        if not all([full_name, email, phone, password]):
            flash("Please complete all required fields.", "error")

        elif len(password) < 8:
            flash(
                "Your password must be at least 8 characters long.",
                "error",
            )

        elif password != confirm_password:
            flash("The passwords do not match.", "error")

        elif User.query.filter_by(email=email).first():
            flash(
                "An account with that email already exists. Please log in.",
                "error",
            )

        else:
            if referral_input:
                referrer = User.query.filter_by(
                    referral_code=referral_input
                ).first()

                if not referrer:
                    flash(
                        "That referral code was not found. Check it and try again.",
                        "error",
                    )
                    return page("Register", body)

            user = User(
                full_name=full_name,
                email=email,
                phone=phone,
                password_hash=generate_password_hash(password),
                referral_code=make_referral_code(),
                referred_by=(
                    referrer.referral_code if referrer else None
                ),
            )

            try:
                db.session.add(user)
                db.session.flush()

                db.session.add(
                    UserStatus(
                        user_id=user.id,
                        is_active=True,
                    )
                )

                db.session.commit()

                session.clear()
                session.permanent = True
                session["user_id"] = user.id

                flash(
                    "Your account has been created successfully.",
                    "success",
                )

                return redirect(url_for("dashboard"))

            except Exception:
                db.session.rollback()
                app.logger.exception("Registration failed.")
                flash(
                    "We could not create your account. Please try again.",
                    "error",
                )

    return page("Register", body)


# REGISTRATION HTML
body = """
<section class="card">
    <h1>Create Your BFT Account</h1>

    <form method="POST" action="{{ url_for('register') }}">

        <input
            type="hidden"
            name="csrf_token"
            value="{{ csrf_token() }}"
        >

        <label for="full_name">Full Name</label>
        <input
            type="text"
            id="full_name"
            name="full_name"
            maxlength="120"
            required
        >

        <label for="email">Email Address</label>
        <input
            type="email"
            id="email"
            name="email"
            maxlength="150"
            required
        >

        <label for="phone">Phone Number</label>
        <input
            type="text"
            id="phone"
            name="phone"
            maxlength="40"
            required
        >

        <label for="password">Password</label>
        <input
            type="password"
            id="password"
            name="password"
            minlength="8"
            required
        >

        <label for="confirm_password">Confirm Password</label>
        <input
            type="password"
            id="confirm_password"
            name="confirm_password"
            required
        >

        <label for="referral_code">Referral Code (Optional)</label>
        <input
            type="text"
            id="referral_code"
            name="referral_code"
        >

        <button type="submit">Create Account</button>

    </form>

        <p>
        Already registered?
        <a href="{{ url_for('login') }}">Log in</a>
    </p>
</section>
"""


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
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
                flash(
                    "Your account is deactivated. Please contact the administrator.",
                    "error",
                )
            else:
                session.clear()
                session.permanent = True
                session["user_id"] = user.id

                flash("Welcome back.", "success")

                return redirect(url_for("dashboard"))

        else:
            flash(
                "The email or password is incorrect.",
                "error",
            )

    body = """
    <section class="card">
        <h1>Log in</h1>

        <form method="post">

    <input
        type="hidden"
        name="csrf_token"
        value="{{ csrf_token() }}"
    >

    <label for="email">Email address</label>
    <input
        id="email"
        name="email"
        type="email"
        required
        value="{{ request.form.get('email', '') }}"
    >

    <label for="email">Email address</label>

            <label for="password">Password</label>
            <input
                id="password"
                name="password"
                type="password"
                required
            >

            <p>
                <button type="submit">Log in</button>
            </p>
        </form>

        <p>
            New here?
            <a href="{{ url_for('register') }}">
                Create an account
            </a>.
        </p>
    </section>
    """

    return page("Log in", body)


# ==========================================
# USER DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()

    referral_count = User.query.filter_by(
        referred_by=user.referral_code
    ).count()

    referral_link = url_for(
        "register",
        _external=True,
    ) + "?ref=" + user.referral_code

    body = """
    <section class="card">
        <h1>Hello, {{ user.full_name }}!</h1>

        <p>Welcome to your BFT dashboard.</p>

        <h3>Your Referral Information</h3>

        <p>
            <strong>Referral Code:</strong>
            {{ user.referral_code }}
        </p>

        <p>
            <strong>Total Referrals:</strong>
            {{ referral_count }}
        </p>

        <div>
            <label for="referral_link">Your Referral Link</label>

            <input
                id="referral_link"
                value="{{ referral_link }}"
                readonly
                onclick="this.select()"
            >

            <p class="muted">
                Share this link with people you invite to BFT.
            </p>
        </div>

        <p>
            <a class="button" href="{{ url_for('edit_profile') }}">
                Edit My Profile
            </a>
        </p>

        <p>
            <a class="button" href="{{ url_for('my_wallet') }}">
                My Wallet
            </a>
        </p>
    </section>
    """ 
    
    return page(
        "Dashboard",
        body,
        user=user,
        referral_count=referral_count,
        referral_link=referral_link,
    )

# ==========================================
# MY WALLET
# ==========================================

@app.route("/wallet")
@login_required
def my_wallet():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    wallet = Wallet.query.filter_by(
        user_id=user.id
    ).first()

    if wallet is None:
        wallet = Wallet(
            user_id=user.id,
            balance=0,
            currency="NGN",
        )

        db.session.add(wallet)
        db.session.commit()

    transactions = WalletTransaction.query.filter_by(
        wallet_id=wallet.id
    ).order_by(
        WalletTransaction.created_at.desc()
    ).limit(50).all()

    body = """
    <section class="card">
        <h1>My Wallet</h1>

        <p>Your available wallet balance:</p>

        <h2>
            {{ wallet.currency }}
            {{ "%.2f"|format(wallet.balance) }}
        </h2>

<p>
    <a class="button" href="{{ url_for('deposit_funds') }}">
        Deposit Funds
    </a>
</p>

<p>
    <a class="button" href="{{ url_for('request_withdrawal') }}">
        Withdraw Funds
    </a>
</p>

        <p class="muted">
            Your wallet balance is displayed in Nigerian naira.
        </p>
    </section>

    <section class="card">
        <h2>Transaction History</h2>

        {% if transactions %}
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Description</th>
                        </tr>
                    </thead>

                    <tbody>
                        {% for transaction in transactions %}
                            <tr>
                                <td>
                                    {{ transaction.created_at.strftime("%d %b %Y") }}
                                </td>

                                <td>
                                    {{ transaction.transaction_type|title }}
                                </td>

                                <td>
                                    {{ wallet.currency }}
                                    {{ "%.2f"|format(transaction.amount) }}
                                </td>

                                <td>
                                    {{ transaction.status|title }}
                                </td>

                                <td>
                                    {{ transaction.description }}
                                </td>
                            </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <p>You have no transactions yet.</p>
        {% endif %}
    </section>
    """

    return page(
        "My Wallet",
        body,
        user=user,
        wallet=wallet,
        transactions=transactions,
    )

# ==========================================
# DEPOSIT FUNDS
# ==========================================

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit_funds():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        sender_name = request.form.get(
            "sender_name", ""
        ).strip()

        payment_reference = request.form.get(
            "payment_reference", ""
        ).strip()

        amount_text = request.form.get(
            "amount", ""
        ).strip()

        if not sender_name or not payment_reference or not amount_text:
            flash("Please complete all deposit fields.")
            return redirect(url_for("deposit_funds"))

        try:
            amount = Decimal(amount_text)
        except InvalidOperation:
            flash("Please enter a valid deposit amount.")
            return redirect(url_for("deposit_funds"))

        if not amount.is_finite() or amount <= 0:
            flash("The deposit amount must be greater than zero.")
            return redirect(url_for("deposit_funds"))

        if amount.as_tuple().exponent < -2:
            flash("Please enter no more than two decimal places.")
            return redirect(url_for("deposit_funds"))

        existing_request = DepositRequest.query.filter_by(
            payment_reference=payment_reference
        ).first()

        if existing_request:
            flash("This payment reference has already been submitted.")
            return redirect(url_for("deposit_funds"))

        deposit = DepositRequest(
            user_id=user.id,
            amount=amount,
            sender_name=sender_name,
            payment_reference=payment_reference,
            status="pending",
        )

        db.session.add(deposit)
        db.session.commit()

        flash(
            "Your deposit request has been submitted. "
            "It will remain pending until your payment is verified."
        )

        return redirect(url_for("my_wallet"))

    body = """
    <section class="card">
        <h1>Deposit Funds</h1>

        <p>
            Transfer money to the BFT bank account provided
            by the administrator.
        </p>

        <p>
            <strong>Bank details:</strong>
        </p>

        <p>
            Contact the BFT administrator for the verified
            bank name, account name, and account number.
        </p>

        <p class="muted">
            Do not transfer money until you have confirmed
            the official account details.
        </p>
    </section>

    <section class="card">
        <h2>Submit Your Transfer</h2>

        <form method="POST" action="{{ url_for('deposit_funds') }}">

            <label for="amount">Amount (NGN)</label>
            <input
                type="number"
                id="amount"
                name="amount"
                min="0.01"
                step="0.01"
                required
            >

            <label for="sender_name">Account Name Used for Transfer</label>
            <input
                type="text"
                id="sender_name"
                name="sender_name"
                maxlength="120"
                required
            >

            <label for="payment_reference">Transfer Reference</label>
            <input
                type="text"
                id="payment_reference"
                name="payment_reference"
                maxlength="100"
                required
            >

            <button type="submit">
                Submit Deposit Request
            </button>

        </form>
    </section>
    """

    return page("Deposit Funds", body, user=user)

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def request_withdrawal():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    wallet = Wallet.query.filter_by(user_id=user.id).first()

    if wallet is None:
        flash("Your wallet is not available yet.")
        return redirect(url_for("my_wallet"))

    if request.method == "POST":
        amount_text = request.form.get("amount", "").strip()
        bank_name = request.form.get("bank_name", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_number = request.form.get("account_number", "").strip()

        if not all([
            amount_text,
            bank_name,
            account_name,
            account_number,
        ]):
            flash("Please complete all withdrawal fields.")
            return redirect(url_for("request_withdrawal"))

        try:
            amount = Decimal(amount_text)
        except InvalidOperation:
            flash("Please enter a valid withdrawal amount.")
            return redirect(url_for("request_withdrawal"))

        if not amount.is_finite() or amount <= 0:
            flash("The withdrawal amount must be greater than zero.")
            return redirect(url_for("request_withdrawal"))

        if amount.as_tuple().exponent < -2:
            flash("Use no more than two decimal places.")
            return redirect(url_for("request_withdrawal"))

        if len(bank_name) > 120 or len(account_name) > 120:
            flash("One of the bank details is too long.")
            return redirect(url_for("request_withdrawal"))

        if len(account_number) > 30:
            flash("Please check the account number.")
            return redirect(url_for("request_withdrawal"))

        if not account_number.isdigit():
            flash("The account number must contain digits only.")
            return redirect(url_for("request_withdrawal"))

        pending_total = db.session.query(
            db.func.coalesce(
                db.func.sum(WithdrawalRequest.amount),
                0,
            )
        ).filter_by(
            user_id=user.id,
            status="pending",
        ).scalar()

        available_balance = (
            Decimal(str(wallet.balance))
            - Decimal(str(pending_total))
        )

        if amount > available_balance:
            flash(
                "Your request exceeds the available balance "
                "after pending withdrawals."
            )
            return redirect(url_for("request_withdrawal"))

        withdrawal = WithdrawalRequest(
            user_id=user.id,
            amount=amount,
            bank_name=bank_name,
            account_name=account_name,
            account_number=account_number,
            status="pending",
        )

        db.session.add(withdrawal)
        db.session.commit()

        flash(
            "Your withdrawal request has been submitted "
            "and is awaiting administrator review."
        )
        return redirect(url_for("my_wallet"))

    body = """
    <section class="card">
        <h1>Request Withdrawal</h1>

        <p>
            <strong>Wallet balance:</strong>
            NGN {{ "%.2f"|format(wallet.balance) }}
        </p>

        <p>
            Pending withdrawals are deducted from the amount
            available for new requests. Your wallet will only
            be debited when an approved withdrawal is processed.
        </p>

        <form method="post">
            <label for="amount">Withdrawal Amount (NGN)</label>
            <input
                type="number"
                id="amount"
                name="amount"
                min="0.01"
                step="0.01"
                required
            >

            <label for="bank_name">Bank Name</label>
            <input
                type="text"
                id="bank_name"
                name="bank_name"
                maxlength="120"
                required
            >

            <label for="account_name">Account Name</label>
            <input
                type="text"
                id="account_name"
                name="account_name"
                maxlength="120"
                required
            >

            <label for="account_number">Account Number</label>
            <input
                type="text"
                id="account_number"
                name="account_number"
                inputmode="numeric"
                maxlength="30"
                required
            >

            <button type="submit">Submit Withdrawal Request</button>
        </form>

        <p>
            <a class="button" href="{{ url_for('my_wallet') }}">
                Back to My Wallet
            </a>
        </p>
    </section>
    """

    return page(
        "Request Withdrawal",
        body,
        user=user,
        wallet=wallet,
    )

# ==========================================
# DEPOSIT REQUEST MODEL
# ==========================================

class DepositRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
    )

    sender_name = db.Column(
        db.String(120),
        nullable=False,
    )

    payment_reference = db.Column(
        db.String(100),
        nullable=False,
        unique=True,
    )

    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    admin_note = db.Column(
        db.String(255),
        nullable=False,
        default="",
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    reviewed_at = db.Column(
        db.DateTime,
        nullable=True,
                  )

class WithdrawalRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )

    amount = db.Column(db.Numeric(12, 2), nullable=False)

    bank_name = db.Column(db.String(120), nullable=False)
    account_name = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(30), nullable=False)

    status = db.Column(
        db.String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    admin_note = db.Column(db.String(255), nullable=False, default="")

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    reviewed_at = db.Column(db.DateTime, nullable=True)

# ==========================================
# EDIT YOUR OWN PROFILE
# ==========================================

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    if request.method == "POST":
        full_name = request.form.get(
            "full_name",
            "",
        ).strip()

        phone = request.form.get(
            "phone",
            "",
        ).strip()

        if not full_name or not phone:
            flash(
                "Name and phone number are required.",
                "error",
            )

        elif len(full_name) > 120 or len(phone) > 40:
            flash(
                "The name or phone number is too long.",
                "error",
            )

        else:
            user.full_name = full_name
            user.phone = phone

            try:
                db.session.commit()

                flash(
                    "Your profile has been updated.",
                    "success",
                )

                return redirect(url_for("dashboard"))

            except Exception:
                db.session.rollback()
                app.logger.exception("Profile update failed.")

                flash(
                    "Unable to update your profile. Please try again.",
                    "error",
                )

    body = """
    <section class="card">
        <h1>Edit my profile</h1>

        <form method="post">
            <label for="full_name">Full name</label>
            <input
                id="full_name"
                name="full_name"
                maxlength="120"
                required
                value="{{ request.form.get('full_name', user.full_name) }}"
            >

            <label for="email">Email address</label>
            <input
                id="email"
                value="{{ user.email }}"
                readonly
            >

            <p class="muted">
                Your email address cannot be changed here.
            </p>

            <label for="phone">Phone number</label>
            <input
                id="phone"
                name="phone"
                maxlength="40"
                value="{{ request.form.get('phone', user.phone or '') }}"
            >

            <button type="submit">Save changes</button>
            <a href="{{ url_for('dashboard') }}">Cancel</a>
        </form>
    </section>
    """

    return page("Edit Profile", body, user=user)

# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    search = request.args.get("search", "").strip()

    query = User.query

    if search:
        query = query.filter(
            db.or_(
                User.full_name.ilike(f"%{search}%"),
                User.email.ilike(f"%{search}%"),
            )
        )

    users = query.order_by(User.id.desc()).all()

    total_users = User.query.count()

    all_users = User.query.all()
    active_users = sum(
        1 for member in all_users
        if user_is_active(member)
    )
    inactive_users = total_users - active_users

    body = """
    <section class="card">
        <h1>Administrator Dashboard</h1>
        <p>Welcome to BFT user management.</p>

        <div class="card">
            <h2>User Statistics</h2>
            <p>Total users: <strong>{{ total_users }}</strong></p>
            <p>Active users: <strong>{{ active_users }}</strong></p>
            <p>Deactivated users: <strong>{{ inactive_users }}</strong></p>
        </div>

        <form method="get">
            <label for="search">Search by name or email</label>
            <input
                id="search"
                name="search"
                value="{{ search }}"
                placeholder="Enter name or email"
            >
            <button type="submit">Search</button>
            <a href="{{ url_for('admin_dashboard') }}">Clear</a>
        </form>

<h2>Deposit Management</h2>

<p>
    <a class="button" href="{{ url_for('admin_deposits') }}">
        View Deposit Requests
    </a>
</p>

<h2>Withdrawal Management</h2>
<p>
    <a class="button" href="{{ url_for('admin_withdrawals') }}">
        View Withdrawal Requests
    </a>
</p>

        <h2>Registered Users</h2>

        {% for member in users %}
            <div class="card">
                <h3>{{ member.full_name }}</h3>
                <p><strong>ID:</strong> {{ member.id }}</p>
                <p><strong>Email:</strong> {{ member.email }}</p>
                <p><strong>Phone:</strong> {{ member.phone }}</p>
                <p><strong>Referral code:</strong> {{ member.referral_code }}</p>
                <p><strong>Referred by:</strong> {{ member.referred_by or "None" }}</p>

                {% if user_is_active(member) %}
                    <p><strong>Status:</strong> Active</p>
                {% else %}
                    <p><strong>Status:</strong> Deactivated</p>
                {% endif %}

                <p>
                    <a class="button"
                       href="{{ url_for('admin_edit_user', user_id=member.id) }}">
                       Edit User
                    </a>
                </p>

                {% if user_is_active(member) %}
                    <form method="post"
                          action="{{ url_for('admin_deactivate_user', user_id=member.id) }}"
                          onsubmit="return confirm('Deactivate this user?');">
                        <button type="submit">Deactivate</button>
                    </form>
                {% else %}
                    <form method="post"
                          action="{{ url_for('admin_activate_user', user_id=member.id) }}">
                        <button type="submit">Activate</button>
                    </form>
                {% endif %}
            </div>
        {% else %}
            <p>No users found.</p>
        {% endfor %}
    </section>
    """

    return page(
        "Administrator Dashboard",
        body,
        users=users,
        search=search,
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        user_is_active=user_is_active,
    )

# ==========================================
# ADMIN DEPOSIT MANAGEMENT
# ==========================================

@app.route("/admin/deposits")
@admin_required
def admin_deposits():
    deposits = DepositRequest.query.order_by(
        DepositRequest.created_at.desc()
    ).all()

    body = """
    <section class="card">
        <h1>Deposit Management</h1>

        {% if deposits %}
            {% for deposit in deposits %}
                <div class="card">
                    <h3>Deposit #{{ deposit.id }}</h3>

                    <p><strong>User ID:</strong> {{ deposit.user_id }}</p>
                    <p><strong>Amount:</strong> NGN {{ "%.2f"|format(deposit.amount) }}</p>
                    <p><strong>Sender:</strong> {{ deposit.sender_name }}</p>
                    <p><strong>Reference:</strong> {{ deposit.payment_reference }}</p>
                    <p><strong>Status:</strong> {{ deposit.status|title }}</p>

                    {% if deposit.status == "pending" %}
                        <form method="post"
                              action="{{ url_for('admin_review_deposit', deposit_id=deposit.id) }}">
                            <button type="submit" name="decision" value="approve">
                                Approve Verified Deposit
                            </button>

                            <button type="submit" name="decision" value="reject">
                                Reject Deposit
                            </button>
                        </form>
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}
            <p>No deposit requests yet.</p>
        {% endif %}

        <p>
            <a class="button" href="{{ url_for('admin_dashboard') }}">
                Back to Admin Dashboard
            </a>
        </p>
    </section>
    """

    return page(
        "Deposit Management",
        body,
        deposits=deposits,
    )


@app.route(
    "/admin/deposits/<int:deposit_id>/review",
    methods=["POST"],
)
@admin_required
def admin_review_deposit(deposit_id):
    decision = request.form.get("decision", "").strip()

    if decision not in ("approve", "reject"):
        flash("Invalid deposit decision.")
        return redirect(url_for("admin_deposits"))

    try:
        # Lock the deposit row to help prevent duplicate processing.
        deposit = (
            DepositRequest.query
            .filter_by(id=deposit_id)
            .with_for_update()
            .first()
        )

        if deposit is None:
            flash("Deposit request not found.")
            return redirect(url_for("admin_deposits"))

        # Only pending deposits can be reviewed.
        if deposit.status != "pending":
            flash("This deposit has already been reviewed.")
            return redirect(url_for("admin_deposits"))

        if decision == "reject":
            deposit.status = "rejected"
            deposit.reviewed_at = datetime.utcnow()
            deposit.admin_note = "Rejected by administrator."

            db.session.commit()

            flash("Deposit request rejected. No money was added.")
            return redirect(url_for("admin_deposits"))

        # APPROVAL:
        # Confirm that the real bank transfer has been received
        # before approving this request.
        wallet = Wallet.query.filter_by(
            user_id=deposit.user_id
        ).with_for_update().first()

        if wallet is None:
            wallet = Wallet(
                user_id=deposit.user_id,
                balance=Decimal("0.00"),
                currency="NGN",
            )
            db.session.add(wallet)
            db.session.flush()

        # Use a unique reference for this wallet transaction.
        transaction_reference = f"deposit-{deposit.id}"

        existing_transaction = WalletTransaction.query.filter_by(
            reference=transaction_reference
        ).first()

        if existing_transaction is not None:
            raise ValueError(
                "A transaction already exists for this deposit."
            )

        # Credit the wallet and record the transaction together.
        wallet.balance = (
            Decimal(str(wallet.balance)) + Decimal(str(deposit.amount))
        )
        wallet.updated_at = datetime.utcnow()

        wallet_transaction = WalletTransaction(
            wallet_id=wallet.id,
            user_id=deposit.user_id,
            transaction_type="deposit",
            amount=deposit.amount,
            status="completed",
            reference=transaction_reference,
            description=f"Approved deposit #{deposit.id}",
        )

        db.session.add(wallet_transaction)

        deposit.status = "approved"
        deposit.reviewed_at = datetime.utcnow()
        deposit.admin_note = "Payment verified and approved."

        # Save everything in one database transaction.
        db.session.commit()

        flash(
            "Deposit approved, wallet credited, "
            "and transaction recorded."
        )

    except Exception:
        db.session.rollback()
        app.logger.exception("Deposit review failed.")
        flash(
            "The deposit could not be processed. "
            "Check the application logs."
        )

    return redirect(url_for("admin_deposits"))

# ==========================================
# ADMIN WITHDRAWAL MANAGEMENT
# ==========================================

@app.route("/admin/withdrawals")
@admin_required
def admin_withdrawals():
    withdrawals = WithdrawalRequest.query.order_by(
        WithdrawalRequest.created_at.desc()
    ).all()

    body = """
    <section class="card">
        <h1>Withdrawal Management</h1>

        {% if withdrawals %}
            {% for withdrawal in withdrawals %}
                <div class="card">
                    <h3>Withdrawal #{{ withdrawal.id }}</h3>

                    <p>
                        <strong>User ID:</strong>
                        {{ withdrawal.user_id }}
                    </p>

                    <p>
                        <strong>Amount:</strong>
                        NGN {{ "%.2f"|format(withdrawal.amount) }}
                    </p>

                    <p>
                        <strong>Bank:</strong>
                        {{ withdrawal.bank_name }}
                    </p>

                    <p>
                        <strong>Account Name:</strong>
                        {{ withdrawal.account_name }}
                    </p>

                    <p>
                        <strong>Account Number:</strong>
                        {{ withdrawal.account_number }}
                    </p>

                    <p>
                        <strong>Status:</strong>
                        {{ withdrawal.status|title }}
                    </p>

                    <p>
                        <strong>Requested:</strong>
                        {{ withdrawal.created_at }}
                    </p>

                    {% if withdrawal.status == "pending" %}
                        <form
                            method="post"
                            action="{{ url_for(
                                'admin_review_withdrawal',
                                withdrawal_id=withdrawal.id
                            ) }}"
                            onsubmit="return confirm(
                                'Confirm that you have verified this request. ' +
                                'Approving will deduct the amount from the wallet.'
                            );"
                        >
                            <button
                                type="submit"
                                name="decision"
                                value="approve"
                            >
                                Approve &amp; Mark Paid
                            </button>

                            <button
                                type="submit"
                                name="decision"
                                value="reject"
                            >
                                Reject Withdrawal
                            </button>
                        </form>
                    {% endif %}
                </div>
            {% endfor %}
        {% else %}
            <p>No withdrawal requests have been submitted yet.</p>
        {% endif %}

        <p>
            <a class="button"
               href="{{ url_for('admin_dashboard') }}">
                Back to Admin Dashboard
            </a>
        </p>
    </section>
    """

    return page(
        "Withdrawal Management",
        body,
        withdrawals=withdrawals,
    )

@app.route(
    "/admin/withdrawals/<int:withdrawal_id>/review",
    methods=["POST"],
)
@admin_required
def admin_review_withdrawal(withdrawal_id):
    decision = request.form.get("decision", "").strip()

    if decision not in ("approve", "reject"):
        flash("Invalid withdrawal decision.")
        return redirect(url_for("admin_withdrawals"))

    try:
        # Lock the withdrawal row to prevent simultaneous processing.
        withdrawal = (
            WithdrawalRequest.query
            .filter_by(id=withdrawal_id)
            .with_for_update()
            .first()
        )

        if withdrawal is None:
            flash("Withdrawal request not found.")
            return redirect(url_for("admin_withdrawals"))

        # A completed or rejected request cannot be processed again.
        if withdrawal.status != "pending":
            flash("This withdrawal has already been reviewed.")
            return redirect(url_for("admin_withdrawals"))

        if decision == "reject":
            withdrawal.status = "rejected"
            withdrawal.reviewed_at = datetime.utcnow()
            withdrawal.admin_note = "Rejected by administrator."

            db.session.commit()

            flash("Withdrawal rejected. The wallet was not debited.")
            return redirect(url_for("admin_withdrawals"))

        # Lock the user's wallet before checking and changing the balance.
        wallet = (
            Wallet.query
            .filter_by(user_id=withdrawal.user_id)
            .with_for_update()
            .first()
        )

        if wallet is None:
            db.session.rollback()
            flash("This user does not have a wallet.")
            return redirect(url_for("admin_withdrawals"))

        amount = Decimal(str(withdrawal.amount))
        balance = Decimal(str(wallet.balance))

        if amount <= 0:
            db.session.rollback()
            flash("Invalid withdrawal amount.")
            return redirect(url_for("admin_withdrawals"))

        # Check for an existing transaction to prevent duplicate deductions.
        transaction_reference = f"withdrawal-{withdrawal.id}"

        existing_transaction = WalletTransaction.query.filter_by(
            reference=transaction_reference
        ).first()

        if existing_transaction is not None:
            db.session.rollback()
            flash(
                "A transaction already exists for this withdrawal. "
                "Please check the transaction history."
            )
            return redirect(url_for("admin_withdrawals"))

        # Recheck the current wallet balance before deducting.
        if balance < amount:
            db.session.rollback()
            flash(
                "Insufficient wallet balance. "
                "The withdrawal was not processed."
            )
            return redirect(url_for("admin_withdrawals"))

        # Deduct the amount and record the transaction together.
        wallet.balance = balance - amount
        wallet.updated_at = datetime.utcnow()

        transaction = WalletTransaction(
            wallet_id=wallet.id,
            user_id=withdrawal.user_id,
            transaction_type="withdrawal",
            amount=amount,
            status="completed",
            reference=transaction_reference,
            description=f"Withdrawal #{withdrawal.id} paid",
        )

        db.session.add(transaction)

        withdrawal.status = "approved"
        withdrawal.reviewed_at = datetime.utcnow()
        withdrawal.admin_note = (
            "Payment verified by administrator; "
            "wallet deduction recorded."
        )

        # Commit the wallet deduction, transaction and status together.
        db.session.commit()

        flash(
            "Withdrawal marked paid. "
            "Wallet deducted and transaction recorded."
        )

    except Exception:
        db.session.rollback()
        app.logger.exception("Withdrawal processing failed.")
        flash(
            "Withdrawal processing failed. "
            "Check the application logs before retrying."
        )

    return redirect(url_for("admin_withdrawals"))

# ==========================================
# ADMIN: DEACTIVATE USER
# ==========================================

@app.route(
    "/admin/users/<int:user_id>/deactivate",
    methods=["POST"],
)
@admin_required
def admin_deactivate_user(user_id):
    target = db.session.get(User, user_id)

    if target is None:
        flash("User not found.", "error")
    else:
        if is_admin(target):
            flash("You cannot deactivate the administrator account.", "error")
        else:
            set_user_active(target, False)
            flash("User deactivated successfully.", "success")

    return redirect(url_for("admin_dashboard"))

@app.route(
    "/admin/users/<int:user_id>/edit",
    methods=["GET", "POST"],
)
@admin_required
def admin_edit_user(user_id):
    target = db.session.get(User, user_id)

    if target is None:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        if not full_name or not email:
            flash("Name and email are required.", "error")
            return redirect(
                url_for("admin_edit_user", user_id=user_id)
            )

        existing_email = User.query.filter(
            db.func.lower(User.email) == email,
            User.id != user_id,
        ).first()

        if existing_email:
            flash("That email address is already in use.", "error")
            return redirect(
                url_for("admin_edit_user", user_id=user_id)
            )

        target.full_name = full_name
        target.email = email
        target.phone = phone

        try:
            db.session.commit()
            flash("User details updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to update user details.")
            flash("Could not update user details.", "error")
            return redirect(
                url_for("admin_edit_user", user_id=user_id)
            )

    body = """
    <section class="card">
        <h1>Edit User</h1>

        <form method="post">
            <label for="full_name">Full Name</label>
            <input
                id="full_name"
                name="full_name"
                value="{{ target.full_name }}"
                maxlength="120"
                required
            >

            <label for="email">Email</label>
            <input
                id="email"
                name="email"
                type="email"
                value="{{ target.email }}"
                maxlength="150"
                required
            >

            <label for="phone">Phone</label>
            <input
                id="phone"
                name="phone"
                value="{{ target.phone }}"
                maxlength="40"
            >

            <button type="submit">Save Changes</button>
        </form>

        <p>
            <a class="button"
               href="{{ url_for('admin_dashboard') }}">
                Back to Admin Dashboard
            </a>
        </p>
    </section>
    """

    return page(
        "Edit User",
        body,
        target=target,
)


# ==========================================
# ADMIN: ACTIVATE USER
# ==========================================

@app.route(
    "/admin/users/<int:user_id>/activate",
    methods=["POST"],
)
@admin_required
def admin_activate_user(user_id):
    target = db.session.get(User, user_id)

    if target is None:
        flash("User not found.", "error")
    else:
        set_user_active(target, True)
        flash("User activated successfully.", "success")

    return redirect(url_for("admin_dashboard"))

# ==========================================
# USER LOGOUT
# ==========================================

@app.route("/logout")
def logout():
    session.clear()

    flash(
        "You have been logged out successfully.",
        "success",
    )

    return redirect(url_for("home"))
    
# ==========================================
# DATABASE INITIALIZATION
# ==========================================

with app.app_context():
    db.create_all()
