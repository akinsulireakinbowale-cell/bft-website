from flask import Flask, render_template_string

app = Flask(__name__)

@app.route("/")
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>BFT - Home</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f2f5f9;
                text-align: center;
                padding: 40px 15px;
            }
            .card {
                background: white;
                max-width: 400px;
                margin: auto;
                padding: 30px;
                border-radius: 15px;
                box-shadow: 0 4px 15px #ddd;
            }
            h1 { color: #174ea6; }
            p { color: #555; }
            a {
                display: block;
                background: #174ea6;
                color: white;
                padding: 13px;
                margin-top: 15px;
                border-radius: 8px;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Welcome to BFT</h1>
            <p>Your journey starts here.</p>
            <a href="/register">Create an Account</a>
            <a href="/login">Log In</a>
        </div>
    </body>
    </html>
    """)

@app.route("/register")
def register():
    return "<h1>BFT Registration</h1><p>Registration form coming next.</p><a href='/'>Home</a>"

@app.route("/login")
def login():
    return "<h1>BFT Login</h1><p>Login form coming next.</p><a href='/'>Home</a>"

if __name__ == "__main__":
    app.run()
