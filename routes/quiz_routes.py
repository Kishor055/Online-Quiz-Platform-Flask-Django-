from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from extensions import db
from models import Quiz, Question, Choice

quiz_bp = Blueprint("quiz_bp", __name__, url_prefix="/quiz")

@quiz_bp.route("/create", methods=["POST"])
@jwt_required()
def create_quiz():
    data = request.get_json()
    uid = get_jwt_identity()

    quiz = Quiz(
        title=data["title"],
        description=data.get("description"),
        category=data.get("category"),
        difficulty=data.get("difficulty"),
        user_id=uid
    )
    db.session.add(quiz)
    db.session.flush()

    for q in data["questions"]:
        question = Question(text=q["text"], type=q.get("type", "mcq"), quiz_id=quiz.id)
        db.session.add(question)
        db.session.flush()
        for c in q["choices"]:
            choice = Choice(text=c["text"], is_correct=c.get("is_correct", False), question_id=question.id)
            db.session.add(choice)

    db.session.commit()
    return jsonify({"message": "Quiz created successfully!"}), 201
