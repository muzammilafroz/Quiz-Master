from datetime import datetime
import pytz
from flask_login import UserMixin
from extensions import db

# Helper function for IST timezone
def get_ist_time():
    utc_now = datetime.utcnow()
    ist_tz = pytz.timezone('Asia/Kolkata')
    return utc_now.replace(tzinfo=pytz.UTC).astimezone(ist_tz)

class Admin(UserMixin, db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    qualification = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=get_ist_time)
    scores = db.relationship('Score', backref='user', lazy=True)

class Subject(db.Model):
    __tablename__ = 'subject'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    chapters = db.relationship('Chapter', backref='subject', lazy=True)
    __table_args__ = (db.UniqueConstraint('name'),)
    

class Chapter(db.Model):
    __tablename__ = 'chapter'
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    quizzes = db.relationship('Quiz', backref='chapter', lazy=True)
    __table_args__ = (db.UniqueConstraint('name'),)

class Quiz(db.Model):
    __tablename__ = 'quiz'
    id = db.Column(db.Integer, primary_key=True)
    chapter_id = db.Column(db.Integer, db.ForeignKey('chapter.id'), nullable=False)
    date_of_quiz = db.Column(db.DateTime, nullable=False)
    time_duration = db.Column(db.Integer, nullable=False)  # in minutes
    remarks = db.Column(db.Text)
    questions = db.relationship('Question', backref='quiz', lazy=True)
    scores = db.relationship('Score', backref='quiz', lazy=True)

class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_statement = db.Column(db.Text, nullable=False)
    question_image = db.Column(db.String(255))  # Path to the image file
    option_1 = db.Column(db.Text, nullable=False)
    option_2 = db.Column(db.Text, nullable=False)
    option_3 = db.Column(db.Text, nullable=False)
    option_4 = db.Column(db.Text, nullable=False)
    correct_option = db.Column(db.Integer, nullable=False)

class Score(db.Model):
    __tablename__ = 'score'
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_stamp_of_attempt = db.Column(db.DateTime, default=get_ist_time)
    
    # Updated scoring metrics
    total_scored = db.Column(db.Float, nullable=False)  # Store as a percentage
    max_score = db.Column(db.Integer, nullable=False, default=100)  # Maximum possible score
    total_questions = db.Column(db.Integer, nullable=False, default=0)  # Total number of questions
    correct_answers = db.Column(db.Integer, nullable=False, default=0)  # Number of correct answers
    wrong_answers = db.Column(db.Integer, nullable=False, default=0)  # Number of incorrect answers
    not_attempted = db.Column(db.Integer, nullable=False, default=0)  # Number of unanswered questions