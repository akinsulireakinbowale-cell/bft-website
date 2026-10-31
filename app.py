import os
import secrets
import string
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo
from flask_login import login_required
from decimal import Decimal

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
        "postgresql+psycopg2://",
        1,
    )
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://",
        "postgresql+psycopg2://",
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

class ReferralCodeStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
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


class GiftCode(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    code = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    amount = db.Column(
        db.Numeric(12, 2),
        nullable=False,
        default=100,
    )

    max_redemptions = db.Column(
        db.Integer,
        nullable=False,
        default=20,
    )

    redeemed_count = db.Column(
        db.Integer,
        nullable=False,
        default=0,
    )

    expires_at = db.Column(
        db.DateTime,
        nullable=False,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
    )

    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )


class GiftCodeRedemption(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    gift_code_id = db.Column(
        db.Integer,
        db.ForeignKey("gift_code.id"),
        nullable=False,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
    )

    redeemed_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
    )

    __table_args__ = (
        db.UniqueConstraint(
            "gift_code_id",
            "user_id",
            name="unique_gift_code_user",
        ),
    )

@app.route("/card-bank", methods=["GET", "POST"])
def card_bank():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    details = BankDetails.query.filter_by(user_id=user.id).first()

    if request.method == "POST":
        bank_name = request.form.get("bank_name", "").strip()
        account_name = request.form.get("account_name", "").strip()
        account_number = request.form.get("account_number", "").strip()

        if not all([bank_name, account_name, account_number]):
            flash("Please complete all bank details.")
            return redirect(url_for("card_bank"))

        if len(bank_name) > 120 or len(account_name) > 120:
            flash("Bank details are too long.")
            return redirect(url_for("card_bank"))

        if len(account_number) > 30 or not account_number.isdigit():
            flash("Please enter a valid account number.")
            return redirect(url_for("card_bank"))

        if details is None:
            details = BankDetails(user_id=user.id)
            db.session.add(details)

        details.bank_name = bank_name
        details.account_name = account_name
        details.account_number = account_number

        db.session.commit()

        flash("Your bank details have been saved.")
        return redirect(url_for("card_bank"))

    body = """
    <section class="card">
        <h1>My Card Bank</h1>
        <p>Save your bank details for future withdrawals.</p>

        <form method="POST">
            <input type="hidden" name="csrf_token"
                   value="{{ csrf_token() }}">

            <label>Bank Name</label>
            <input name="bank_name"
                   maxlength="120"
                   value="{{ details.bank_name if details else '' }}"
                   required>

            <label>Account Name</label>
            <input name="account_name"
                   maxlength="120"
                   value="{{ details.account_name if details else '' }}"
                   required>

            <label>Account Number</label>
            <input name="account_number"
                   inputmode="numeric"
                   maxlength="30"
                   value="{{ details.account_number if details else '' }}"
                   required>

            <button type="submit">Save Bank Details</button>
        </form>

        <a class="button" href="{{ url_for('dashboard') }}">
            Back to My Page
        </a>
    </section>
    """

    return page("Card Bank", body, details=details)

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
    padding-bottom: 90px;
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

/* BOTTOM NAVIGATION */

.bottom-nav {
    position: fixed;
    bottom: 0;
    left: 0;
    width: 100%;
    background: white;
    display: flex;
    justify-content: space-around;
    align-items: center;
    padding: 10px 4px;
    box-shadow: 0 -3px 12px #00000012;
    border-top: 1px solid #e2e8f0;
    z-index: 9999;
}

.bottom-nav a {
    flex: 1;
    text-align: center;
    text-decoration: none;
    color: #9299a3;
    font-size: 12px;
    font-weight: bold;
    padding: 5px 2px;
}

.bottom-nav a.active {
    color: #e02020;
}

.bottom-nav .nav-icon {
    display: block;
    font-size: 21px;
    margin-bottom: 4px;
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

    .bottom-nav a {
        font-size: 11px;
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
            <a href="{{ url_for('dashboard') }}"
   class="{% if request.endpoint == 'dashboard' %}active{% endif %}">

            {% if current_user_is_admin %}
                <a href="{{ url_for('admin_dashboard') }}">
                    Admin Dashboard
                </a>
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

<nav class="bottom-nav">

    <a href="{{ url_for('home') }}"
       class="{% if request.endpoint == 'home' %}active{% endif %}">
        <span class="nav-icon">⌂</span>
        Home
    </a>

    <a href="{{ url_for('market') }}"
       class="{% if request.endpoint == 'market' %}active{% endif %}">
        <span class="nav-icon">▣</span>
        Market
    </a>

    <a href="{{ url_for('order') }}"
       class="{% if request.endpoint == 'order' %}active{% endif %}">
        <span class="nav-icon">▤</span>
        Order
    </a>

    <a href="{{ url_for('team') }}"
       class="{% if request.endpoint == 'team' %}active{% endif %}">
        <span class="nav-icon">♧</span>
        Team
    </a>

    <a href="{{ url_for('dashboard') }}"
       class="{% if request.endpoint == 'dashboard' %}active{% endif %}">
        <span class="nav-icon">♙</span>
        My
    </a>

</nav>

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
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return page(
        "Home",
        """
        <style>
            .bft-home {
                max-width: 850px;
                margin: auto;
            }

            .bft-hero {
                background: linear-gradient(135deg, #b71c1c, #ef6c00);
                color: white;
                padding: 25px 18px;
                border-radius: 18px;
                text-align: center;
                margin-bottom: 18px;
            }

            .bft-hero h1 {
                margin: 0 0 8px;
                font-size: 29px;
            }

            .bft-hero p {
                margin: 0;
            }

            .bft-slider {
                position: relative;
                overflow: hidden;
                border-radius: 16px;
                margin-bottom: 20px;
                background: #eee;
            }

            .bft-slide {
                display: none;
                width: 100%;
                height: 190px;
                object-fit: cover;
            }

            .bft-slide.active {
                display: block;
            }

            .bft-shortcuts {
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                margin-bottom: 20px;
            }

            .bft-shortcut {
                background: white;
                border-radius: 14px;
                padding: 17px 8px;
                text-align: center;
                text-decoration: none;
                color: #333;
                box-shadow: 0 3px 12px rgba(0,0,0,.07);
                font-weight: bold;
                font-size: 13px;
            }

            .bft-shortcut span {
                display: block;
                font-size: 25px;
                margin-bottom: 7px;
            }

            .bft-section {
                background: white;
                padding: 20px;
                border-radius: 16px;
                margin-bottom: 18px;
                box-shadow: 0 3px 12px rgba(0,0,0,.06);
            }

            .bft-section h2 {
                color: #b71c1c;
                margin-top: 0;
            }

            .bft-overview-button {
                display: inline-block;
                background: linear-gradient(135deg, #b71c1c, #ef6c00);
                color: white;
                padding: 12px 20px;
                border-radius: 9px;
                text-decoration: none;
                font-weight: bold;
            }

            .bft-updates {
                border-left: 4px solid #ef6c00;
                padding: 10px 14px;
                background: #fff7f0;
                border-radius: 8px;
            }

            @media(max-width: 400px) {
                .bft-slide {
                    height: 150px;
                }
            }
        </style>

        <div class="bft-home">

            <section class="bft-hero">
                <h1>WELCOME TO BFT</h1>
                <p>Building a Better Digital Experience</p>
            </section>

            <div class="bft-slider">
                <img class="bft-slide active"
                     src="https://placehold.co/850x350/b71c1c/ffffff?text=Welcome+to+BFT"
                     alt="Welcome to BFT">

                <img class="bft-slide"
                     src="https://placehold.co/850x350/ef6c00/ffffff?text=Innovation+and+Growth"
                     alt="Innovation and Growth">

                <img class="bft-slide"
                     src="https://placehold.co/850x350/333333/ffffff?text=Your+BFT+Experience"
                     alt="Your BFT Experience">
            </div>

            <div class="bft-shortcuts">

                <a class="bft-shortcut"
                   href="{{ url_for('team') }}">
                    <span>👥</span>My Team
                </a>

                <a class="bft-shortcut"
                   href="{{ url_for('deposit') }}">
                    <span>📥</span>Recharge
                </a>

                <a class="bft-shortcut"
                   href="{{ url_for('withdraw') }}">
                    <span>📤</span>Withdraw
                </a>

                <a class="bft-shortcut"
                   href="{{ url_for('team') }}">
                    <span>🔗</span>Invite
                </a>

                <a class="bft-shortcut"
                   href="{{ url_for('dashboard') }}">
                    <span>📱</span>My Account
                </a>

                <a class="bft-shortcut"
                   href="mailto:support@bft.com">
                    <span>🎧</span>Online Service
                </a>

            </div>

            <section class="bft-section">
                <h2>📢 BFT Updates</h2>

                <div class="bft-updates">
                    <strong>Stay Connected!</strong>
                    <p>
                        Welcome to BFT. Check this section regularly
                        for important announcements, platform news
                        and service updates.
                    </p>
                </div>
            </section>

            <section class="bft-section">
                <h2>🏢 Company Overview</h2>

                <p>
                    Discover BFT, our vision, mission, core values
                    and commitment to providing a better digital
                    experience.
                </p>

                <a class="bft-overview-button"
                   href="{{ url_for('company_overview') }}">
                    View Company Overview
                </a>
            </section>

            <section class="bft-section">
                <h2>Welcome to BFT</h2>

                <p>
                    Explore our platform and discover the services
                    available to registered users.
                </p>

                {% if not current_user %}
                    <a class="bft-overview-button"
                       href="{{ url_for('register') }}">
                        Create Account
                    </a>

                    <a class="bft-overview-button"
                       href="{{ url_for('login') }}">
                        Log In
                    </a>
                {% else %}
                    <a class="bft-overview-button"
                       href="{{ url_for('market') }}">
                        Explore Market
                    </a>
                {% endif %}
            </section>

        </div>

        <script>
            let bftSlideIndex = 0;
            const bftSlides = document.querySelectorAll(".bft-slide");

            setInterval(function() {
                bftSlides[bftSlideIndex].classList.remove("active");

                bftSlideIndex =
                    (bftSlideIndex + 1) % bftSlides.length;

                bftSlides[bftSlideIndex].classList.add("active");
            }, 3500);
        </script>
        """,
    )
    
@app.route("/company-overview")
def company_overview():
    body = """
    <style>
        .company-profile {
            max-width: 850px;
            margin: auto;
        }

        .company-header {
            background: linear-gradient(135deg, #b71c1c, #ef6c00);
            color: white;
            padding: 30px 20px;
            border-radius: 18px;
            text-align: center;
            margin-bottom: 20px;
        }

        .company-header h1 {
            font-size: 30px;
            margin: 0 0 10px;
        }

        .company-card {
            background: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 16px;
            box-shadow: 0 3px 12px rgba(0,0,0,.06);
        }

        .company-card h2 {
            color: #b71c1c;
            margin-top: 0;
        }

        .company-card li {
            margin-bottom: 10px;
        }

        .company-status {
            background: #fff3e0;
            border-left: 4px solid #ef6c00;
            padding: 14px;
            border-radius: 8px;
        }
    </style>

    <div class="company-profile">

        <section class="company-header">
            <h1>BFT</h1>
            <h3>Building a Better Digital Experience</h3>
            <p>Our Business Profile</p>
        </section>

        <section class="company-card">
            <h2>About BFT</h2>
            <p>
                BFT is an independent digital platform focused on
                providing users with an organised, accessible and
                user-friendly online experience.
            </p>
            <p>
                Our platform provides account management,
                digital services, referral features and
                communication tools.
            </p>
        </section>

        <section class="company-card">
            <h2>Our Vision</h2>
            <p>
                To become a recognised digital platform known
                for accessibility, innovation, transparency
                and excellent user experience.
            </p>
        </section>

        <section class="company-card">
            <h2>Our Mission</h2>
            <p>
                To provide a simple and organised digital
                environment where users can access available
                services, manage their accounts and stay
                informed about platform updates.
            </p>
        </section>

        <section class="company-card">
            <h2>Our Core Values</h2>
            <ul>
                <li><strong>Transparency:</strong>
                Communicating clearly and honestly.</li>

                <li><strong>Trust:</strong>
                Building confidence through responsible operations.</li>

                <li><strong>Innovation:</strong>
                Improving our platform and services.</li>

                <li><strong>Accountability:</strong>
                Taking responsibility for our operations.</li>

                <li><strong>User Experience:</strong>
                Making our platform simple and convenient.</li>
            </ul>
        </section>

        <section class="company-card">
            <h2>Our Platform Features</h2>
            <ul>
                <li>Personal user accounts and dashboards.</li>
                <li>Wallet and transaction records.</li>
                <li>Deposit and withdrawal request facilities.</li>
                <li>Referral and team management.</li>
                <li>Gift-code redemption.</li>
                <li>Bank details management.</li>
                <li>Platform announcements and updates.</li>
            </ul>
        </section>

        <section class="company-card">
            <h2>Our Commitment to Users</h2>
            <p>
                We aim to provide clear information about our
                services, account activities, applicable charges
                and platform policies.
            </p>
            <p>
                We encourage users to understand the terms,
                conditions and risks associated with any
                financial features.
            </p>
        </section>

        <section class="company-card">
            <h2>Business Registration</h2>
            <div class="company-status">
                <strong>Registration Status: Not Yet Registered</strong>
                <p>
                    BFT is currently an independent project and
                    has not yet been registered with the
                    Corporate Affairs Commission (CAC).
                </p>
            </div>
        </section>

        <section class="company-card">
            <h2>Our Promise</h2>
            <p>
                At BFT, our goal is to keep improving,
                communicate responsibly and create a better
                digital experience for every user.
            </p>
            <h3 style="color:#b71c1c;">
                BFT — Transparency, Innovation and Better
                Digital Experiences.
            </h3>
        </section>

        <a class="button" href="{{ url_for('home') }}">
            Back to Home
        </a>

    </div>
    """

    return page("Company Overview", body)


# ==========================================
# REGISTER
# ==========================================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        referral_input = (
            request.form.get("referral_code")
            or request.args.get("ref")
            or ""
        ).strip().upper()

        referrer = None

        if not all([full_name, email, phone, password]):
            flash("Please complete all required fields.", "error")

        elif len(password) < 8:
            flash("Your password must be at least 8 characters long.", "error")

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

                referral_status = ReferralCodeStatus.query.filter_by(
                    user_id=referrer.id
                ).first()

                if referral_status and not referral_status.is_active:
                    flash(
                        "This referral code has been disabled.",
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

                # Create or retrieve the new user's wallet.
                wallet = Wallet.query.filter_by(
                    user_id=user.id
                ).first()

                if wallet is None:
                    wallet = Wallet(
                        user_id=user.id,
                        balance=Decimal("0.00"),
                        currency="NGN",
                    )
                    db.session.add(wallet)
                    db.session.flush()

                # Credit the ₦500 welcome bonus.
                welcome_amount = Decimal("500.00")
                wallet.balance = (
                    Decimal(str(wallet.balance or "0.00"))
                    + welcome_amount
                )

                # Record the welcome bonus.
                db.session.add(
                    WalletTransaction(
                        wallet_id=wallet.id,
                        user_id=user.id,
                        transaction_type="welcome_bonus",
                        amount=welcome_amount,
                        status="completed",
                        reference=f"WELCOME-{user.id}",
                        description="New user ₦500 welcome bonus",
                    )
                )

                db.session.commit()

                session.clear()
                session.permanent = True
                session["user_id"] = user.id

                flash(
                    "Your account has been created successfully. "
                    "₦500 welcome bonus has been credited to your wallet.",
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

    gift_rewards = db.session.query(
        db.func.coalesce(db.func.sum(GiftCode.amount), 0)
    ).join(
        GiftCodeRedemption,
        GiftCodeRedemption.gift_code_id == GiftCode.id
    ).filter(
        GiftCodeRedemption.user_id == user.id
    ).scalar()

    body = """
    <style>
        .my-profile {
            background: linear-gradient(110deg, #ef4858, #ff982f);
            color: white;
            padding: 25px 20px 45px;
            border-radius: 20px 20px 35px 35px;
            margin: -10px -5px 0;
        }

        .my-profile h2 {
            margin: 0;
            font-size: 21px;
        }

        .my-profile p {
            margin: 6px 0;
            font-size: 12px;
        }

        .my-balance {
            background: white;
            color: #222;
            padding: 20px;
            border-radius: 20px;
            margin: -28px 0 15px;
            position: relative;
            box-shadow: 0 5px 18px rgba(0,0,0,.07);
        }

        .my-balance h1 {
            font-size: 30px;
            margin: 8px 0;
            color: #171717;
        }

        .my-actions {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            background: white;
            padding: 17px 8px;
            border-radius: 20px;
            margin-bottom: 22px;
        }

        .my-action {
            text-align: center;
            text-decoration: none;
            color: #333;
            font-size: 11px;
            font-weight: bold;
        }

        .my-icon {
            width: 43px;
            height: 43px;
            margin: 0 auto 8px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 19px;
            background: linear-gradient(135deg, #ef4858, #ff982f);
        }

        .my-heading {
            font-size: 16px;
            margin: 18px 5px 10px;
            color: #555;
        }

        .my-menu {
            display: flex;
            align-items: center;
            gap: 12px;
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 17px;
            text-decoration: none;
            color: #292929;
            box-shadow: 0 3px 12px rgba(0,0,0,.035);
        }

        .my-menu-icon {
            width: 38px;
            height: 38px;
            border-radius: 50%;
            background: #fff1ed;
            color: #e95a63;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 17px;
        }

        .my-menu-text {
            flex: 1;
        }

        .my-menu-text strong {
            display: block;
            font-size: 14px;
        }

        .my-menu-text small {
            color: #888;
            font-size: 11px;
        }

        .my-arrow {
            color: #bbb;
        }
    </style>

    <div class="my-profile">
        <h2>{{ user.full_name }}</h2>
        <p>Account ID: {{ user.id }}</p>
    </div>

    <section class="my-balance">
        <small style="color:#888;">TOTAL BALANCE</small>

        <h1>
            ₦{{ "%.2f"|format(wallet.balance) }}
        </h1>

        <p style="color:#888; font-size:12px;">
            Your BFT wallet balance
        </p>
    </section>

    <section class="my-actions">
        <a class="my-action"
           href="{{ url_for('deposit_funds') }}">
            <div class="my-icon">▣</div>
            Recharge
        </a>

        <a class="my-action"
           href="{{ url_for('request_withdrawal') }}">
            <div class="my-icon">₦</div>
            Withdraw
        </a>

        <a class="my-action"
           href="{{ url_for('order') }}">
            <div class="my-icon">▤</div>
            My Order
        </a>

        <a class="my-action"
           href="{{ url_for('card_bank') }}">
            <div class="my-icon">▣</div>
            Card Bank
        </a>
    </section>

    <h3 class="my-heading">My Business</h3>

    <a class="my-menu" href="{{ url_for('team') }}">
        <div class="my-menu-icon">👥</div>
        <div class="my-menu-text">
            <strong>Team</strong>
            <small>Invite friends and view your team</small>
        </div>
        <span class="my-arrow">›</span>
    </a>

    <div class="my-menu">
        <div class="my-menu-icon">🎁</div>
        <div class="my-menu-text">
            <strong>Rewards</strong>
            <small>
                Total earned: ₦{{ "%.2f"|format(gift_rewards) }}
            </small>
        </div>
        <span class="my-arrow">›</span>
    </div>

    <a class="my-menu" href="{{ url_for('gift_code_page') }}">
        <div class="my-menu-icon">🎀</div>
        <div class="my-menu-text">
            <strong>Gift Code</strong>
            <small>Redeem your gift code</small>
        </div>
        <span class="my-arrow">›</span>
    </a>

    <div class="my-menu">
        <div class="my-menu-icon">⬇</div>
        <div class="my-menu-text">
            <strong>Download App</strong>
            <small>Coming Soon</small>
        </div>
        <span class="my-arrow">›</span>
    </div>
    """

    return page(
        "My Account",
        body,
        user=user,
        wallet=wallet,
        gift_rewards=gift_rewards,
        )

@app.route("/transaction-history")
@login_required
def transaction_history():
    user = get_current_user()
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    transactions = []

    if wallet:
        transactions = WalletTransaction.query.filter_by(
            wallet_id=wallet.id
        ).order_by(WalletTransaction.created_at.desc()).all()

    body = """
    <section class="card">
        <h1>Transaction History</h1>
        {% if transactions %}
            <table>
                <tr><th>Date</th><th>Type</th><th>Amount</th><th>Status</th></tr>
                {% for item in transactions %}
                <tr>
                    <td>{{ item.created_at }}</td>
                    <td>{{ item.transaction_type }}</td>
                    <td>₦{{ item.amount }}</td>
                    <td>{{ item.status }}</td>
                </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>No transactions found.</p>
        {% endif %}
        <a class="button" href="{{ url_for('dashboard') }}">Back to My Account</a>
    </section>
    """
    return page("Transaction History", body, transactions=transactions)


@app.route("/deposit-history")
@login_required
def deposit_history():
    user = get_current_user()
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    transactions = []

    if wallet:
        transactions = WalletTransaction.query.filter_by(
            wallet_id=wallet.id,
            transaction_type="deposit"
        ).order_by(WalletTransaction.created_at.desc()).all()

    body = """
    <section class="card">
        <h1>Deposit History</h1>
        {% if transactions %}
            {% for item in transactions %}
                <p>₦{{ item.amount }} — {{ item.status }} — {{ item.created_at }}</p>
            {% endfor %}
        {% else %}
            <p>No deposit history found.</p>
        {% endif %}
        <a class="button" href="{{ url_for('dashboard') }}">Back to My Account</a>
    </section>
    """
    return page("Deposit History", body, transactions=transactions)


@app.route("/withdrawal-history")
@login_required
def withdrawal_history():
    user = get_current_user()
    wallet = Wallet.query.filter_by(user_id=user.id).first()
    transactions = []

    if wallet:
        transactions = WalletTransaction.query.filter_by(
            wallet_id=wallet.id,
            transaction_type="withdrawal"
        ).order_by(WalletTransaction.created_at.desc()).all()

    body = """
    <section class="card">
        <h1>Withdrawal History</h1>
        {% if transactions %}
            {% for item in transactions %}
                <p>₦{{ item.amount }} — {{ item.status }} — {{ item.created_at }}</p>
            {% endfor %}
        {% else %}
            <p>No withdrawal history found.</p>
        {% endif %}
        <a class="button" href="{{ url_for('dashboard') }}">Back to My Account</a>
    </section>
    """
    return page("Withdrawal History", body, transactions=transactions)


@app.route("/gift-code")
@login_required
def gift_code_page():
    body = """
    <section class="card">
        <h1>Gift Code</h1>
        <form method="POST" action="{{ url_for('redeem_gift_code') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Enter Gift Code</label>
            <input type="text" name="code" required>
            <button type="submit">Redeem Code</button>
        </form>
        <a class="button" href="{{ url_for('dashboard') }}">Back to My Account</a>
    </section>
    """
    return page("Gift Code", body)

# ==========================================
# MARKET PAGE
# ==========================================

@app.route("/market")
@login_required
def market():
    body = """
    <section class="card">
        <h1>Market</h1>
        <p>Welcome to the BFT Market.</p>
        <p>Available products will appear here.</p>
    </section>
    """
    return page("Market", body)


# ==========================================
# ORDER PAGE
# ==========================================

@app.route("/order")
@login_required
def order():
    body = """
    <style>
        .order-header {
            background: linear-gradient(135deg, #d62828, #f77f00);
            color: white;
            padding: 24px;
            border-radius: 18px;
            margin-bottom: 18px;
        }

        .order-box {
            background: white;
            border-radius: 16px;
            padding: 22px;
            margin-bottom: 16px;
            box-shadow: 0 4px 14px rgba(0,0,0,0.07);
            text-align: center;
        }

        .order-icon {
            font-size: 42px;
            margin-bottom: 10px;
        }

        .order-title {
            color: #d62828;
            font-size: 20px;
            font-weight: bold;
        }

        .order-text {
            color: #777;
            line-height: 1.6;
        }

        .order-status {
            display: inline-block;
            background: #fff0e5;
            color: #f07700;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
        }

        .order-button {
            display: inline-block;
            background: linear-gradient(135deg, #d62828, #f77f00);
            color: white !important;
            padding: 12px 22px;
            border-radius: 10px;
            text-decoration: none;
            margin-top: 12px;
        }
    </style>

    <section class="card">

        <div class="order-header">
            <h1>My Orders</h1>
            <p>Manage and keep track of your orders.</p>
        </div>

        <div class="order-box">

            <div class="order-icon">🛍️</div>

            <div class="order-title">
                Your Orders
            </div>

            <p class="order-text">
                Your orders will appear here once
                products and ordering are available.
            </p>

            <span class="order-status">
                COMING SOON
            </span>

            <br>

            <a
                class="order-button"
                href="{{ url_for('dashboard') }}"
            >
                Back to My Page
            </a>

        </div>

    </section>
    """

    return page("My Orders", body)


# ==========================================
# TEAM PAGE
# ==========================================

@app.route("/team")
@login_required
def team():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    # Level 1: users directly referred by this user
    level1 = User.query.filter_by(
        referred_by=user.referral_code
    ).all()

    # Level 2: users referred by Level 1 members
    level1_codes = [member.referral_code for member in level1]

    level2 = []
    if level1_codes:
        level2 = User.query.filter(
            User.referred_by.in_(level1_codes)
        ).all()

    # Level 3: users referred by Level 2 members
    level2_codes = [member.referral_code for member in level2]

    level3 = []
    if level2_codes:
        level3 = User.query.filter(
            User.referred_by.in_(level2_codes)
        ).all()

    referral_status = ReferralCodeStatus.query.filter_by(
        user_id=user.id
    ).first()

    referral_active = (
        referral_status.is_active
        if referral_status
        else True
    )

    referral_link = url_for(
        "register",
        _external=True,
    ) + "?ref=" + user.referral_code

    body = """
    <style>
        .team-header {
            background: linear-gradient(135deg, #d62828, #f77f00);
            color: white;
            padding: 24px;
            border-radius: 18px;
            margin-bottom: 18px;
        }

        .team-card {
            background: white;
            border-radius: 16px;
            padding: 18px;
            margin-bottom: 15px;
            box-shadow: 0 4px 14px rgba(0,0,0,0.07);
        }

        .team-number {
            font-size: 25px;
            font-weight: bold;
            color: #d62828;
        }

        .team-muted {
            color: #777;
            font-size: 13px;
        }

        .team-copy {
            background: #d62828;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 9px;
            margin-top: 8px;
            cursor: pointer;
        }

        .team-input {
            width: 100%;
            box-sizing: border-box;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 9px;
            background: #f7f7f7;
        }

        .team-level {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .team-rate {
            color: #f77f00;
            font-size: 22px;
            font-weight: bold;
        }
    </style>

    <section class="card">

        <div class="team-header">
            <h1>My Team</h1>
            <p>Grow your network and track your team.</p>
        </div>

        <div class="team-card">
            <h3>Referral Code</h3>

            <input
                class="team-input"
                id="referralCode"
                value="{{ user.referral_code }}"
                readonly
            >

            <button
                class="team-copy"
                onclick="copyTeamText('referralCode')"
            >
                Copy Code
            </button>

            <p class="team-muted">
                Referral status:
                {% if referral_active %}
                    <strong style="color:green;">Active</strong>
                {% else %}
                    <strong style="color:red;">Disabled</strong>
                {% endif %}
            </p>
        </div>

        <div class="team-card">
            <h3>Referral Link</h3>

            <input
                class="team-input"
                id="referralLink"
                value="{{ referral_link }}"
                readonly
            >

            <button
                class="team-copy"
                onclick="copyTeamText('referralLink')"
            >
                Copy Link
            </button>
        </div>

        <div class="team-card">
            <h3>Team Overview</h3>

            <p>Total Team Members</p>
            <div class="team-number">
                {{ level1|length + level2|length + level3|length }}
            </div>
        </div>

        <div class="team-card">
            <div class="team-level">
                <div>
                    <h3>Level 1</h3>
                    <p class="team-muted">Direct referrals</p>
                </div>
                <div class="team-rate">10%</div>
            </div>
            <div class="team-number">{{ level1|length }}</div>
            <p class="team-muted">Members</p>
        </div>

        <div class="team-card">
            <div class="team-level">
                <div>
                    <h3>Level 2</h3>
                    <p class="team-muted">Second level</p>
                </div>
                <div class="team-rate">3%</div>
            </div>
            <div class="team-number">{{ level2|length }}</div>
            <p class="team-muted">Members</p>
        </div>

        <div class="team-card">
            <div class="team-level">
                <div>
                    <h3>Level 3</h3>
                    <p class="team-muted">Third level</p>
                </div>
                <div class="team-rate">1%</div>
            </div>
            <div class="team-number">{{ level3|length }}</div>
            <p class="team-muted">Members</p>
        </div>

        <div class="team-card">
            <h3>Referral Commission</h3>
            <p>
                Level 1: <strong>10%</strong><br>
                Level 2: <strong>3%</strong><br>
                Level 3: <strong>1%</strong>
            </p>

            <p class="team-muted">
                Commission earnings will appear when verified
                product sales are supported by the order system.
            </p>
        </div>

    </section>

    <script>
        function copyTeamText(elementId) {
            const field = document.getElementById(elementId);

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(field.value)
                    .then(() => alert("Copied successfully!"))
                    .catch(() => alert("Unable to copy. Please copy manually."));
            } else {
                field.select();
                field.setSelectionRange(0, 99999);
                document.execCommand("copy");
                alert("Copied successfully!");
            }
        }
    </script>
    """

    return page(
        "My Team",
        body,
        user=user,
        level1=level1,
        level2=level2,
        level3=level3,
        referral_link=referral_link,
        referral_active=referral_active,
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

    history_type = request.args.get("history", "all")

    transaction_query = WalletTransaction.query.filter_by(
        wallet_id=wallet.id
    )

    if history_type == "deposit":
        transaction_query = transaction_query.filter_by(
            transaction_type="deposit"
        )

    elif history_type == "withdrawal":
        transaction_query = transaction_query.filter_by(
            transaction_type="withdrawal"
        )

    transactions = transaction_query.order_by(
        WalletTransaction.created_at.desc()
    ).limit(50).all()

    body = """
    <section class="card">
        <p class="muted">TOTAL WALLET BALANCE</p>

        <h1 style="font-size: 32px; color: #1769aa;">
            ₦{{ "%.2f"|format(wallet.balance) }}
        </h1>

        <p class="muted">Available balance</p>

        <div style="
            display: flex;
            gap: 12px;
            margin-top: 22px;
        ">
            <a class="button"
               href="{{ url_for('deposit_funds') }}"
               style="flex: 1; text-align: center;">
                Deposit
            </a>

            <a class="button danger"
               href="{{ url_for('request_withdrawal') }}"
               style="flex: 1; text-align: center;">
                Withdraw
            </a>
        </div>
    </section>

    <section class="card">
        <h2>Account Activities</h2>

        <p>
            <a class="button"
               href="{{ url_for('my_wallet', history='all') }}">
                Transaction History
            </a>
        </p>

        <p>
            <a class="button"
               href="{{ url_for('my_wallet', history='deposit') }}">
                Deposit History
            </a>
        </p>

        <p>
            <a class="button"
               href="{{ url_for('my_wallet', history='withdrawal') }}">
                Withdrawal History
            </a>
        </p>

        <p>
            <a class="button"
               href="#gift-code">
                Gift Code
            </a>
        </p>
    </section>

    <section class="card" id="gift-code">
        <h2>Redeem Gift Code</h2>

        <p>
            Enter your daily gift code to receive ₦100
            in your wallet.
        </p>

        <form method="POST"
              action="{{ url_for('redeem_gift_code') }}">

            <input type="hidden"
                   name="csrf_token"
                   value="{{ csrf_token() }}">

            <label for="gift_code">Gift Code</label>

            <input type="text"
                   id="gift_code"
                   name="gift_code"
                   placeholder="Enter your gift code"
                   maxlength="50"
                   required>

            <button type="submit">
                Redeem ₦100
            </button>
        </form>
    </section>

    <section class="card">
        <h2>
            {% if history_type == "deposit" %}
                Deposit History
            {% elif history_type == "withdrawal" %}
                Withdrawal History
            {% else %}
                Transaction History
            {% endif %}
        </h2>

        {% if transactions %}
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Amount</th>
                            <th>Status</th>
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
                                ₦{{ "%.2f"|format(transaction.amount) }}
                            </td>

                            <td>
                                {{ transaction.status|title }}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <p>No records found.</p>
        {% endif %}
    </section>
    """

    return page(
        "My Account",
        body,
        user=user,
        wallet=wallet,
        transactions=transactions,
        history_type=history_type,
        )



@app.route("/redeem-gift-code", methods=["POST"])
@login_required
def redeem_gift_code():
    user = get_current_user()

    if user is None:
        return redirect(url_for("login"))

    code_text = request.form.get("gift_code", "").strip().upper()

    if not code_text:
        flash("Please enter a gift code.")
        return redirect(url_for("my_wallet"))

    try:
        # Lock the gift code to prevent two users taking the final slot.
        gift = GiftCode.query.filter_by(
            code=code_text
        ).with_for_update().first()

        if gift is None:
            flash("Invalid gift code.")
            return redirect(url_for("my_wallet"))

        if not gift.is_active:
            flash("This gift code is no longer active.")
            return redirect(url_for("my_wallet"))

        if datetime.utcnow() >= gift.expires_at:
            flash("This gift code has expired.")
            return redirect(url_for("my_wallet"))

        if gift.redeemed_count >= gift.max_redemptions:
            flash("This gift code has reached its redemption limit.")
            return redirect(url_for("my_wallet"))

        existing = GiftCodeRedemption.query.filter_by(
            gift_code_id=gift.id,
            user_id=user.id,
        ).first()

        if existing:
            flash("You have already redeemed this gift code.")
            return redirect(url_for("my_wallet"))

        wallet = Wallet.query.filter_by(
            user_id=user.id
        ).with_for_update().first()

        if wallet is None:
            wallet = Wallet(
                user_id=user.id,
                balance=Decimal("0.00"),
                currency="NGN",
            )
            db.session.add(wallet)
            db.session.flush()

        wallet.balance = (
            Decimal(str(wallet.balance)) + Decimal("100.00")
        )

        gift.redeemed_count += 1

        redemption = GiftCodeRedemption(
            gift_code_id=gift.id,
            user_id=user.id,
        )

        transaction = WalletTransaction(
            wallet_id=wallet.id,
            user_id=user.id,
            transaction_type="gift",
            amount=Decimal("100.00"),
            status="approved",
            reference="GIFT-" + secrets.token_hex(12).upper(),
            description="Gift code reward: " + gift.code,
        )

        db.session.add(redemption)
        db.session.add(transaction)
        db.session.commit()

        flash("Congratulations! ₦100 has been added to your wallet.")

    except Exception:
        db.session.rollback()
        flash("We could not process your gift code. Please try again.")

    return redirect(url_for("my_wallet"))

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
            Transfer your deposit to the BFT receiving bank account below.
        </p>

        <h2>Bank Transfer Details</h2>

        <p>
            <strong>Bank Name:</strong>
            9Payment Service Bank (9PSB)
        </p>

        <p>
            <strong>Account Name:</strong>
            AmeX Network
        </p>

        <p>
            <strong>Account Number:</strong>
            6718461313
        </p>

        <p class="muted">
            After making your transfer, complete the form below
            and provide your payment reference.
        </p>
    </section>

    <section class="card">
        <h2>Submit Your Transfer</h2>

        <form method="POST" action="{{ url_for('deposit_funds') }}">

            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token() }}"
            >

            <label for="amount">Amount (NGN)</label>
            <input
                type="number"
                id="amount"
                name="amount"
                min="0.01"
                step="0.01"
                required
            >

            <label for="sender_name">
                Account Name Used for Transfer
            </label>
            <input
                type="text"
                id="sender_name"
                name="sender_name"
                maxlength="120"
                required
            >

            <label for="payment_reference">
                Transfer Reference
            </label>
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
        
        <input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token() }}"
>
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
            <a class="button" href="{{ url_for('dashboard') }}">
                Back to My Page
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

class BankDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        unique=True,
        index=True,
    )

    bank_name = db.Column(db.String(120), nullable=False)
    account_name = db.Column(db.String(120), nullable=False)
    account_number = db.Column(db.String(30), nullable=False)

    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
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
# ADMINISTRATOR DASHBOARD
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
    referral_statuses = {
    status.user_id: status.is_active
    for status in ReferralCodeStatus.query.all()
    }

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


        <!-- USER STATISTICS -->

        <div class="card">

            <h2>User Statistics</h2>

            <p>
                Total users:
                <strong>{{ total_users }}</strong>
            </p>

            <p>
                Active users:
                <strong>{{ active_users }}</strong>
            </p>

            <p>
                Deactivated users:
                <strong>{{ inactive_users }}</strong>
            </p>

        </div>


        <!-- SEARCH USERS -->

        <h2>Search Users</h2>

        <form method="GET">

            <label for="search">
                Search by name or email
            </label>

            <input
                id="search"
                name="search"
                value="{{ search }}"
                placeholder="Enter name or email"
            >

            <button type="submit">
                Search
            </button>

            <a href="{{ url_for('admin_dashboard') }}">
                Clear
            </a>

        </form>


        <!-- DEPOSIT MANAGEMENT -->

        <h2>Deposit Management</h2>

        <p>
            <a
                class="button"
                href="{{ url_for('admin_deposits') }}"
            >
                View Deposit Requests
            </a>
        </p>


        <!-- WITHDRAWAL MANAGEMENT -->

        <h2>Withdrawal Management</h2>

        <p>
            <a
                class="button"
                href="{{ url_for('admin_withdrawals') }}"
            >
                View Withdrawal Requests
            </a>
        </p>


<h2>Gift Code Management</h2>

<p>
    <a
        class="button"
        href="{{ url_for('admin_gift_codes') }}"
    >
        Create and Manage Gift Codes
    </a>
</p>

        <!-- REGISTERED USERS -->

        <h2>Registered Users</h2>

        {% for member in users %}

            <div class="card">

                <h3>{{ member.full_name }}</h3>

                <p>
                    <strong>ID:</strong>
                    {{ member.id }}
                </p>

                <p>
                    <strong>Email:</strong>
                    {{ member.email }}
                </p>

                <p>
                    <strong>Phone:</strong>
                    {{ member.phone }}
                </p>

                <p>
                    <strong>Referral code:</strong>
                    {{ member.referral_code }}
                </p>

                <p>
                    <strong>Referred by:</strong>
                    {{ member.referred_by or "None" }}
                </p>

                <p>
    <strong>Referral Code Status:</strong>

    {% if referral_statuses.get(member.id, True) %}
        <span style="color: green;">Active</span>
    {% else %}
        <span style="color: red;">Disabled</span>
    {% endif %}
</p>

{% if referral_statuses.get(member.id, True) %}

    <form
        method="POST"
        action="{{ url_for(
            'admin_disable_referral_code',
            user_id=member.id
        ) }}"
        onsubmit="return confirm('Disable this referral code?');"
    >
        <input
            type="hidden"
            name="csrf_token"
            value="{{ csrf_token() }}"
        >

        <button type="submit">
            Disable Referral Code
        </button>
    </form>

{% else %}

    <form
        method="POST"
        action="{{ url_for(
            'admin_enable_referral_code',
            user_id=member.id
        ) }}"
    >
        <input
            type="hidden"
            name="csrf_token"
            value="{{ csrf_token() }}"
        >

        <button type="submit">
            Enable Referral Code
        </button>
    </form>

{% endif %}


                <!-- EDIT USER -->

                <p>
                    <a
                        class="button"
                        href="{{ url_for(
                            'admin_edit_user',
                            user_id=member.id
                        ) }}"
                    >
                        Edit User
                    </a>
                </p>


                <!-- ACTIVE USER -->

                {% if user_is_active(member) %}

                    <p>
                        <strong>Status:</strong>
                        Active
                    </p>

                    <form
                        method="POST"
                        action="{{ url_for(
                            'admin_deactivate_user',
                            user_id=member.id
                        ) }}"
                        onsubmit="return confirm(
                            'Deactivate this user?'
                        );"
                    >

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="{{ csrf_token() }}"
                        >

                        <button type="submit">
                            Deactivate
                        </button>

                    </form>


                <!-- DEACTIVATED USER -->

                {% else %}

                    <p>
                        <strong>Status:</strong>
                        Deactivated
                    </p>

                    <form
                        method="POST"
                        action="{{ url_for(
                            'admin_activate_user',
                            user_id=member.id
                        ) }}"
                    >

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="{{ csrf_token() }}"
                        >

                        <button type="submit">
                            Activate
                        </button>

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
        referral_statuses=referral_statuses,
    )

@app.route(
    "/admin/referral-code/<int:user_id>/disable",
    methods=["POST"],
)
@admin_required
def admin_disable_referral_code(user_id):
    member = db.session.get(User, user_id)

    if member is None:
        flash("User not found.")
        return redirect(url_for("admin_dashboard"))

    status = ReferralCodeStatus.query.filter_by(
        user_id=member.id
    ).first()

    if status is None:
        status = ReferralCodeStatus(
            user_id=member.id,
            is_active=False,
        )
        db.session.add(status)
    else:
        status.is_active = False

    db.session.commit()

    flash("Referral code disabled successfully.")
    return redirect(url_for("admin_dashboard"))


@app.route(
    "/admin/referral-code/<int:user_id>/enable",
    methods=["POST"],
)
@admin_required
def admin_enable_referral_code(user_id):
    member = db.session.get(User, user_id)

    if member is None:
        flash("User not found.")
        return redirect(url_for("admin_dashboard"))

    status = ReferralCodeStatus.query.filter_by(
        user_id=member.id
    ).first()

    if status is None:
        status = ReferralCodeStatus(
            user_id=member.id,
            is_active=True,
        )
        db.session.add(status)
    else:
        status.is_active = True

    db.session.commit()

    flash("Referral code enabled successfully.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/gift-codes", methods=["GET", "POST"])
@admin_required
def admin_gift_codes():

    if request.method == "POST":
        local_now = datetime.now(ZoneInfo("Africa/Lagos"))

        tomorrow = local_now.date() + timedelta(days=1)

        expiry_local = datetime.combine(
            tomorrow,
            datetime.min.time(),
            tzinfo=ZoneInfo("Africa/Lagos"),
        )

        expiry_utc = expiry_local.astimezone(
            timezone.utc
        ).replace(tzinfo=None)

        code = "BFT-" + secrets.token_hex(4).upper()

        while GiftCode.query.filter_by(code=code).first():
            code = "BFT-" + secrets.token_hex(4).upper()

        gift_code = GiftCode(
            code=code,
            amount=Decimal("100.00"),
            max_redemptions=20,
            redeemed_count=0,
            expires_at=expiry_utc,
            is_active=True,
        )

        db.session.add(gift_code)
        db.session.commit()

        flash("Gift code created successfully: " + code)

        return redirect(url_for("admin_gift_codes"))

    gift_codes = GiftCode.query.order_by(
        GiftCode.created_at.desc()
    ).all()

    body = """
    <section class="card">
        <h1>Gift Code Management</h1>

        <p>Reward per user: ₦100</p>
        <p>Maximum users per code: 20</p>
        <p>Total reward budget: ₦2,000</p>

        <form method="POST">
            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token() }}"
            >

            <button type="submit">
                Create New Gift Code
            </button>
        </form>
    </section>

    <section class="card">
        <h2>Created Gift Codes</h2>

        {% for gift in gift_codes %}
            <div class="card">
                <h3>{{ gift.code }}</h3>

                <p>Reward: ₦{{ "%.2f"|format(gift.amount) }}</p>

                <p>
                    Redemptions:
                    {{ gift.redeemed_count }}/{{ gift.max_redemptions }}
                </p>

                <p>
                    Expires:
                    {{ gift.expires_at.strftime("%d %b %Y %H:%M") }}
                    UTC
                </p>

                <p>
                    Status:
                    {{ "Active" if gift.is_active else "Inactive" }}
                </p>
            </div>
        {% else %}
            <p>No gift codes created yet.</p>
        {% endfor %}
    </section>
    """

    return page(
        "Gift Code Management",
        body,
        gift_codes=gift_codes,
    )

# ==========================================
# EDIT USER
# ==========================================

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

        full_name = request.form.get(
            "full_name", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        phone = request.form.get(
            "phone", ""
        ).strip()

        if not full_name or not email:
            flash("Name and email are required.", "error")

            return redirect(
                url_for(
                    "admin_edit_user",
                    user_id=user_id
                )
            )

        existing_email = User.query.filter(
            db.func.lower(User.email) == email,
            User.id != user_id,
        ).first()

        if existing_email:
            flash(
                "That email address is already in use.",
                "error",
            )

            return redirect(
                url_for(
                    "admin_edit_user",
                    user_id=user_id
                )
            )

        target.full_name = full_name
        target.email = email
        target.phone = phone

        try:

            db.session.commit()

            flash(
                "User details updated successfully.",
                "success",
            )

            return redirect(
                url_for("admin_dashboard")
            )

        except Exception:

            db.session.rollback()

            app.logger.exception(
                "Failed to update user details."
            )

            flash(
                "Could not update user details.",
                "error",
            )

            return redirect(
                url_for(
                    "admin_edit_user",
                    user_id=user_id
                )
            )

    body = """
    <section class="card">

        <h1>Edit User</h1>

        <form method="POST">

            <input
                type="hidden"
                name="csrf_token"
                value="{{ csrf_token() }}"
            >

            <label for="full_name">
                Full Name
            </label>

            <input
                id="full_name"
                name="full_name"
                value="{{ target.full_name }}"
                maxlength="120"
                required
            >

            <label for="email">
                Email
            </label>

            <input
                id="email"
                name="email"
                type="email"
                value="{{ target.email }}"
                maxlength="150"
                required
            >

            <label for="phone">
                Phone
            </label>

            <input
                id="phone"
                name="phone"
                value="{{ target.phone }}"
                maxlength="40"
            >

            <button type="submit">
                Save Changes
            </button>

        </form>

        <p>
            <a
                class="button"
                href="{{ url_for('admin_dashboard') }}"
            >
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

<input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token() }}"
>

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

                        <input
    type="hidden"
    name="csrf_token"
    value="{{ csrf_token() }}"
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
            flash(
                "You cannot deactivate the administrator account.",
                "error",
            )
        else:
            set_user_active(target, False)
            flash("User deactivated successfully.", "success")

    return redirect(url_for("admin_dashboard"))


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
