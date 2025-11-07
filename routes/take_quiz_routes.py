from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import Quiz, Question, Choice, UserAttempt

take_quiz_bp = Blueprint("take_quiz_bp", __name__, url_prefix="/take")

@take_quiz_bp.route("/<int:quiz_id>")
@jwt_required()
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template("take_quiz.html", quiz=quiz)

@take_quiz_bp.route("/submit/<int:quiz_id>", methods=["POST"])
@jwt_required()
def submit_quiz(quiz_id):
    user_id = get_jwt_identity()
    quiz = Quiz.query.get_or_404(quiz_id)
    score, total = 0, len(quiz.questions)

    for question in quiz.questions:
        selected = request.form.get(str(question.id))
        correct_choice = next((c for c in question.choices if c.is_correct), None)
        if selected and str(correct_choice.id) == selected:
            score += 1

    attempt = UserAttempt(user_id=user_id, quiz_id=quiz.id, score=score, total=total)
    db.session.add(attempt)
    db.session.commit()
    flash(f"You scored {score}/{total}", "info")
    return redirect(url_for("dashboard_bp.dashboard"))
