from flask import Blueprint, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import Quiz, UserAttempt

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

# 📊 Dashboard showing available quizzes and user's past attempts
@dashboard_bp.route("/")
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()

    # All available quizzes
    quizzes = Quiz.query.all()

    # Past attempts by the logged-in user
    attempts = (
        UserAttempt.query
        .filter_by(user_id=user_id)
        .order_by(UserAttempt.attempted_at.desc())
        .all()
    )

    return render_template("dashboard.html", quizzes=quizzes, attempts=attempts)
