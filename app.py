"""
app.py — Complete Flask application for an Online Quiz Platform
Author: Generated for your project (customized & documented)
Purpose: Single-file runnable backend for creating/taking quizzes with:
 - User registration/login (JWT)
 - Quiz creation (with categories & difficulty)
 - Questions (MCQ, True/False) and Choices
 - Submit attempts: grading, storing UserAttempt & AttemptAnswer
 - Dashboard: list quizzes + user attempts
Notes:
 - Requires templates and static files for a nicer UI; however API endpoints
   return JSON so you can test with curl/Postman immediately.
 - For production, set a secure JWT_SECRET and use proper environment config.
"""

import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, flash, abort)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    verify_jwt_in_request_optional
)

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("QUIZ_DB", "sqlite:///" + os.path.join(BASE_DIR, "quiz.db"))

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = DB_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-secret-for-submission")  # change for prod
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "another-dev-secret")  # used by flash/templates

# ---------------------------------------------------------------------
# Extensions (single-file wiring)
# ---------------------------------------------------------------------
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------
class User(db.Model):
    """Users who can create quizzes and attempt quizzes"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    quizzes = db.relationship("Quiz", backref="creator", lazy=True)
    attempts = db.relationship("UserAttempt", backref="user", lazy=True)

    def set_password(self, password: str):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)


class Quiz(db.Model):
    """
    Quiz metadata: title, description, category and difficulty.
    Each Quiz has many Questions.
    """
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    difficulty = db.Column(db.String(20), nullable=True)  # e.g. Easy/Medium/Hard
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    questions = db.relationship("Question", backref="quiz", cascade="all, delete", lazy=True)
    attempts = db.relationship("UserAttempt", backref="quiz", lazy=True)


class Question(db.Model):
    """
    Questions belong to a quiz.
    type: 'mcq' or 'tf'
    """
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(20), default="mcq")
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)

    choices = db.relationship("Choice", backref="question", cascade="all, delete", lazy=True)


class Choice(db.Model):
    """Answer choices for questions. At least one choice per question should be is_correct."""
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(300), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)


class UserAttempt(db.Model):
    """Stores a user's attempt at a quiz, plus summary score."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey("quiz.id"), nullable=False)
    score = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)

    answers = db.relationship("AttemptAnswer", backref="attempt", cascade="all, delete", lazy=True)


class AttemptAnswer(db.Model):
    """Per-question record for an attempt (what the user selected and correctness)."""
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey("user_attempt.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    selected_choice_id = db.Column(db.Integer, db.ForeignKey("choice.id"), nullable=True)
    correct = db.Column(db.Boolean, default=False)


# ---------------------------------------------------------------------
# Utility / helper functions
# ---------------------------------------------------------------------
def optional_jwt_or_none():
    """
    Decorator that attempts to verify a JWT, but does not require it.
    Useful for pages that can be anonymous or logged-in.
    The route function can call get_jwt_identity() to detect user id or None.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request_optional()
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_json(f):
    """Ensure request is application/json and has JSON body."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"message": "Expected application/json"}), 400
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------
# Authentication routes (JSON API)
# ---------------------------------------------------------------------
@app.route("/auth/register", methods=["POST"])
@require_json
def register():
    """
    Register a new user.
    Request JSON: { "email": str, "password": str, "name": optional str }
    Response: { token, user }
    """
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    user = User(email=email, name=name)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=user.id)
    return jsonify({"message": "Registered", "token": token, "user": {"id": user.id, "email": user.email, "name": user.name}}), 201


@app.route("/auth/login", methods=["POST"])
@require_json
def login():
    """
    Login endpoint.
    Request JSON: { "email": str, "password": str }
    Response: { token, user }
    """
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"message": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    token = create_access_token(identity=user.id)
    return jsonify({"message": "OK", "token": token, "user": {"id": user.id, "email": user.email, "name": user.name}}), 200


@app.route("/auth/profile", methods=["GET"])
@jwt_required()
def profile():
    """Return profile of logged-in user."""
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({"id": user.id, "email": user.email, "name": user.name, "created_at": user.created_at.isoformat()})


@app.route("/auth/profile", methods=["PUT"])
@jwt_required()
@require_json
def update_profile():
    """Update name and/or password."""
    uid = get_jwt_identity()
    user = User.query.get(uid)
    if not user:
        return jsonify({"message": "User not found"}), 404
    data = request.get_json()
    new_name = data.get("name")
    new_password = data.get("password")
    if new_name:
        user.name = new_name
    if new_password:
        user.set_password(new_password)
    db.session.commit()
    return jsonify({"message": "Updated", "user": {"id": user.id, "email": user.email, "name": user.name}})


# ---------------------------------------------------------------------
# Quiz management routes (creation, listing, read)
# ---------------------------------------------------------------------
@app.route("/quizzes", methods=["GET"])
@optional_jwt_or_none()
def list_quizzes():
    """List quizzes; supports optional filters: ?category=...&difficulty=..."""
    category = request.args.get("category")
    difficulty = request.args.get("difficulty")
    query = Quiz.query
    if category:
        query = query.filter_by(category=category)
    if difficulty:
        query = query.filter_by(difficulty=difficulty)
    quizzes = query.order_by(Quiz.created_at.desc()).all()
    # Return minimal data for listing
    results = []
    for q in quizzes:
        results.append({
            "id": q.id,
            "title": q.title,
            "description": q.description,
            "category": q.category,
            "difficulty": q.difficulty,
            "created_by": q.user_id,
            "questions_count": len(q.questions)
        })
    return jsonify(results)


@app.route("/quizzes", methods=["POST"])
@jwt_required()
@require_json
def create_quiz():
    """
    Create a new quiz (authenticated).
    Body:
    {
      "title": "...",
      "description": "...",
      "category": "Programming",
      "difficulty": "Easy",
      "questions": [ { "type":"mcq", "text":"...", "choices":[ {"text":"A","is_correct":true}, ... ] }, ... ]
    }
    """
    uid = get_jwt_identity()
    data = request.get_json()
    title = data.get("title", "").strip()
    if not title:
        return jsonify({"message": "Title required"}), 400

    category = data.get("category")
    difficulty = data.get("difficulty")
    description = data.get("description")

    quiz = Quiz(title=title, description=description, category=category, difficulty=difficulty, user_id=uid)
    db.session.add(quiz)
    db.session.flush()  # get quiz.id without commit

    # Validate and add questions
    questions = data.get("questions", [])
    if not isinstance(questions, list) or len(questions) == 0:
        db.session.rollback()
        return jsonify({"message": "Quiz must contain at least one question"}), 400

    for qidx, qdata in enumerate(questions):
        qtext = qdata.get("text", "").strip()
        qtype = qdata.get("type", "mcq")
        qchoices = qdata.get("choices", [])

        if not qtext:
            db.session.rollback()
            return jsonify({"message": f"Question {qidx+1}: text required"}), 400
        if qtype not in ("mcq", "tf"):
            db.session.rollback()
            return jsonify({"message": f"Question {qidx+1}: invalid type"}), 400
        if not isinstance(qchoices, list) or len(qchoices) < 2:
            db.session.rollback()
            return jsonify({"message": f"Question {qidx+1}: at least two choices required"}), 400

        question = Question(text=qtext, type=qtype, quiz_id=quiz.id)
        db.session.add(question)
        db.session.flush()

        # Create choices; ensure exactly one correct for MCQ
        correct_count = 0
        for c in qchoices:
            ctext = c.get("text", "").strip()
            is_correct = bool(c.get("is_correct", False))
            if is_correct:
                correct_count += 1
            choice = Choice(text=ctext or "—", is_correct=is_correct, question_id=question.id)
            db.session.add(choice)

        if qtype == "mcq" and correct_count != 1:
            db.session.rollback()
            return jsonify({"message": f"Question {qidx+1}: MCQ must have exactly one correct choice"}), 400
        # For TF you may ensure choices are True/False optionally

    db.session.commit()

    return jsonify({"message": "Quiz created", "quiz_id": quiz.id}), 201


@app.route("/quizzes/<int:quiz_id>", methods=["GET"])
@optional_jwt_or_none()
def get_quiz(quiz_id):
    """Return full quiz with questions and choices (answers NOT included)."""
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = []
    for q in quiz.questions:
        questions.append({
            "id": q.id,
            "text": q.text,
            "type": q.type,
            "choices": [{"id": c.id, "text": c.text} for c in q.choices]
        })
    return jsonify({
        "id": quiz.id,
        "title": quiz.title,
        "description": quiz.description,
        "category": quiz.category,
        "difficulty": quiz.difficulty,
        "questions": questions
    })


# ---------------------------------------------------------------------
# Quiz-taking endpoints (display + submit)
# ---------------------------------------------------------------------
@app.route("/take/<int:quiz_id>", methods=["GET"])
@optional_jwt_or_none()
def take_quiz_page(quiz_id):
    """
    Render a template for taking the quiz (if templates exist).
    If you prefer API-only, use GET /quizzes/<id> to fetch JSON and build a frontend.
    """
    quiz = Quiz.query.get_or_404(quiz_id)
    # Build minimal structure for client-side (no is_correct flags)
    questions = []
    for q in quiz.questions:
        questions.append({
            "id": q.id,
            "text": q.text,
            "type": q.type,
            "choices": [{"id": c.id, "text": c.text} for c in q.choices]
        })
    # If templates are present, render them. Otherwise return JSON.
    if os.path.isdir(os.path.join(BASE_DIR, "templates")):
        return render_template("take_quiz.html", quiz=quiz, questions=questions)
    return jsonify({"quiz": {"id": quiz.id, "title": quiz.title}, "questions": questions})


@app.route("/take/submit/<int:quiz_id>", methods=["POST"])
@jwt_required()
@require_json
def submit_quiz(quiz_id):
    """
    Process submission: expects JSON:
    { "answers": [ {"question_id": int, "choice_id": int}, ... ] }
    Calculates score, stores UserAttempt and AttemptAnswer rows.
    """
    uid = get_jwt_identity()
    data = request.get_json()
    answers = data.get("answers", [])

    if not isinstance(answers, list):
        return jsonify({"message": "Invalid answers payload"}), 400

    quiz = Quiz.query.get_or_404(quiz_id)

    # Create attempt row early (we'll update score/total later)
    attempt = UserAttempt(user_id=uid, quiz_id=quiz_id, total=len(answers))
    db.session.add(attempt)
    db.session.flush()  # get attempt.id

    score = 0
    for ans in answers:
        qid = ans.get("question_id")
        cid = ans.get("choice_id")
        # Defensive checks
        question = Question.query.filter_by(id=qid, quiz_id=quiz_id).first()
        if not question:
            # skip or return error; we choose to rollback & error to prevent bad data
            db.session.rollback()
            return jsonify({"message": f"Question {qid} not found in quiz"}), 400
        choice = Choice.query.filter_by(id=cid, question_id=qid).first() if cid else None
        is_correct = bool(choice.is_correct) if choice else False
        if is_correct:
            score += 1
        attempt_answer = AttemptAnswer(attempt_id=attempt.id, question_id=qid, selected_choice_id=cid, correct=is_correct)
        db.session.add(attempt_answer)

    attempt.score = score
    attempt.total = len(answers)
    db.session.commit()

    # Build details for response (optionally include selected/ correct text)
    details = []
    for a in attempt.answers:
        # find selected & correct text
        sel = Choice.query.get(a.selected_choice_id) if a.selected_choice_id else None
        corr = Choice.query.filter_by(question_id=a.question_id, is_correct=True).first()
        details.append({
            "question_id": a.question_id,
            "selected_choice_id": a.selected_choice_id,
            "selected_text": sel.text if sel else None,
            "correct_choice_id": corr.id if corr else None,
            "correct_text": corr.text if corr else None,
            "correct": a.correct
        })

    return jsonify({
        "message": "Submitted",
        "attempt_id": attempt.id,
        "score": score,
        "total": attempt.total,
        "details": details
    }), 200


# ---------------------------------------------------------------------
# Dashboard / attempts
# ---------------------------------------------------------------------
@app.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    """
    Dashboard for the logged-in user: list available quizzes and past attempts.
    Renders a template if available; otherwise returns JSON.
    """
    uid = get_jwt_identity()
    quizzes = Quiz.query.order_by(Quiz.created_at.desc()).all()
    attempts = UserAttempt.query.filter_by(user_id=uid).order_by(UserAttempt.attempted_at.desc()).all()

    if os.path.isdir(os.path.join(BASE_DIR, "templates")):
        return render_template("dashboard.html", quizzes=quizzes, attempts=attempts)
    # JSON fallback
    return jsonify({
        "quizzes": [{"id": q.id, "title": q.title, "category": q.category, "difficulty": q.difficulty} for q in quizzes],
        "attempts": [{"id": a.id, "quiz_id": a.quiz_id, "score": a.score, "total": a.total, "attempted_at": a.attempted_at.isoformat()} for a in attempts]
    })


@app.route("/attempts/<int:attempt_id>", methods=["GET"])
@jwt_required()
def attempt_detail(attempt_id):
    """
    Return detailed breakdown for a specific attempt (question-by-question).
    """
    uid = get_jwt_identity()
    attempt = UserAttempt.query.get_or_404(attempt_id)
    if attempt.user_id != uid:
        return jsonify({"message": "Forbidden"}), 403

    items = []
    for ans in attempt.answers:
        q = Question.query.get(ans.question_id)
        sel = Choice.query.get(ans.selected_choice_id) if ans.selected_choice_id else None
        corr = Choice.query.filter_by(question_id=ans.question_id, is_correct=True).first()
        items.append({
            "question": q.text if q else None,
            "selected": sel.text if sel else None,
            "correct": corr.text if corr else None,
            "is_correct": ans.correct
        })
    return jsonify({
        "attempt_id": attempt.id,
        "quiz_id": attempt.quiz_id,
        "score": attempt.score,
        "total": attempt.total,
        "attempted_at": attempt.attempted_at.isoformat(),
        "answers": items
    })


# ---------------------------------------------------------------------
# Simple admin/debug routes (development only)
# ---------------------------------------------------------------------
@app.route("/_bootstrap", methods=["POST"])
def bootstrap_sample_data():
    """
    Create a demo user and a sample quiz — useful while developing.
    WARNING: keep this disabled/removed in production.
    """
    data = request.get_json() or {}
    # Create demo user if not exists
    demo_email = data.get("email", "demo@example.com")
    demo = User.query.filter_by(email=demo_email).first()
    if not demo:
        demo = User(email=demo_email, name="Demo User")
        demo.set_password("demo123")
        db.session.add(demo)
        db.session.commit()

    # Create a sample quiz if none exists
    if Quiz.query.count() == 0:
        quiz = Quiz(title="Sample: Basic Math", description="Auto-created demo quiz", category="Math", difficulty="Easy", user_id=demo.id)
        db.session.add(quiz)
        db.session.flush()
        # question 1
        q1 = Question(text="What is 2 + 2?", type="mcq", quiz_id=quiz.id)
        db.session.add(q1); db.session.flush()
        Choice(text="3", is_correct=False, question_id=q1.id)
        Choice(text="4", is_correct=True, question_id=q1.id)
        Choice(text="5", is_correct=False, question_id=q1.id)
        # question 2 (tf)
        q2 = Question(text="The earth is flat.", type="tf", quiz_id=quiz.id)
        db.session.add(q2); db.session.flush()
        Choice(text="True", is_correct=False, question_id=q2.id)
        Choice(text="False", is_correct=True, question_id=q2.id)

        db.session.commit()
        return jsonify({"message": "Demo user and sample quiz created", "demo_email": demo_email}), 201

    return jsonify({"message": "Already has quizzes"}), 200


# ---------------------------------------------------------------------
# Error handlers & small helpers
# ---------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return jsonify({"message": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    # In production, log exception details securely
    return jsonify({"message": "Server error"}), 500


# ---------------------------------------------------------------------
# Run server
# ---------------------------------------------------------------------
if __name__ == "__main__":
    # Create DB file & tables on first run if not present
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
from routes.dashboard_routes import dashboard_bp
app.register_blueprint(dashboard_bp)
