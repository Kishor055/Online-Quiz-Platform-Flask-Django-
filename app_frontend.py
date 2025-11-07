from flask import Flask, render_template_string, request, redirect, url_for, flash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'

base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Quiz Platform - {% block title %}{% endblock %}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('home') }}">Quiz Platform</a>
    <div>
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
      </ul>
    </div>
  </div>
</nav>

<div class="container">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
          {{ message }}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

home_template = """
{% extends 'base.html' %}
{% block title %}Home{% endblock %}
{% block content %}
<h1>Welcome to the Quiz Platform Frontend</h1>
<p>This is a demo frontend. Please register or login.</p>
{% endblock %}
"""

register_template = """
{% extends 'base.html' %}
{% block title %}Register{% endblock %}
{% block content %}
<h2>Register</h2>
<form method="POST">
  <div class="mb-3">
    <label for="username" class="form-label">Username</label>
    <input type="text" class="form-control" name="username" id="username" required>
  </div>
  <div class="mb-3">
    <label for="email" class="form-label">Email</label>
    <input type="email" class="form-control" name="email" id="email" required>
  </div>
  <div class="mb-3">
    <label for="password" class="form-label">Password</label>
    <input type="password" class="form-control" name="password" id="password" required>
  </div>
  <div class="mb-3">
    <label for="confirm_password" class="form-label">Confirm Password</label>
    <input type="password" class="form-control" name="confirm_password" id="confirm_password" required>
  </div>
  <button type="submit" class="btn btn-primary">Register</button>
</form>
{% endblock %}
"""

login_template = """
{% extends 'base.html' %}
{% block title %}Login{% endblock %}
{% block content %}
<h2>Login</h2>
<form method="POST">
  <div class="mb-3">
    <label for="username" class="form-label">Username</label>
    <input type="text" class="form-control" name="username" id="username" required>
  </div>
  <div class="mb-3">
    <label for="password" class="form-label">Password</label>
    <input type="password" class="form-control" name="password" id="password" required>
  </div>
  <button type="submit" class="btn btn-primary">Login</button>
</form>
{% endblock %}
"""

@app.route('/')
def home():
    return render_template_string(home_template, **{'base.html': base_template})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Here you'd usually call the backend API to register the user
        flash('This demo does not actually register users.', 'warning')
        return redirect(url_for('register'))
    return render_template_string(register_template, **{'base.html': base_template})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Here you'd usually call the backend API to login the user
        flash('This demo does not actually login users.', 'warning')
        return redirect(url_for('login'))
    return render_template_string(login_template, **{'base.html': base_template})

if __name__ == '__main__':
    app.run(debug=True, port=5001)  # run frontend on different port
