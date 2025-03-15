from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import Subject, Chapter, Quiz, Question, db, Admin
from werkzeug.security import generate_password_hash
import json

# Create a blueprint for API routes
api_bp = Blueprint('api', __name__, url_prefix='/api')

# Authentication decorator
def admin_required(f):
    @login_required
    def decorated_function(*args, **kwargs):
        if not isinstance(current_user, Admin):
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# API endpoints for Subjects
@api_bp.route('/subjects', methods=['GET'])
def get_subjects():
    subjects = Subject.query.all()
    result = []
    for subject in subjects:
        result.append({
            'id': subject.id,
            'name': subject.name,
            'description': subject.description,
            'chapter_count': len(subject.chapters)
        })
    return jsonify(result)

@api_bp.route('/subjects', methods=['POST'])
@admin_required
def create_subject():
    data = request.get_json()
    
    # Handle both single subject and multiple subjects
    subjects_data = data if isinstance(data, list) else [data]
    
    if not subjects_data:
        return jsonify({'error': 'No data provided'}), 400
    
    results = []
    errors = []
    
    for subject_data in subjects_data:
        if not subject_data or not subject_data.get('name'):
            errors.append({'error': 'Name is required', 'data': subject_data})
            continue

        # Check for duplicate subject name
        existing_subject = Subject.query.filter_by(name=subject_data['name']).first()
        if existing_subject:
            errors.append({'error': 'A subject with this name already exists', 'name': subject_data['name']})
            continue
            
        subject = Subject(
            name=subject_data['name'],
            description=subject_data.get('description', '')
        )
        
        db.session.add(subject)
        results.append(subject)
    
    if not results:
        db.session.rollback()
        return jsonify({'errors': errors}), 400
    
    try:
        db.session.commit()
        response = {
            'subjects': [{
                'id': subject.id,
                'name': subject.name,
                'description': subject.description
            } for subject in results],
            'message': f'Successfully created {len(results)} subject(s)'
        }
        
        if errors:
            response['errors'] = errors
            
        return jsonify(response), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/subjects/<int:subject_id>', methods=['GET'])
def get_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = []
    
    for chapter in subject.chapters:
        chapters.append({
            'id': chapter.id,
            'name': chapter.name,
            'description': chapter.description,
            'quiz_count': len(chapter.quizzes)
        })
    
    return jsonify({
        'id': subject.id,
        'name': subject.name,
        'description': subject.description,
        'chapters': chapters
    })

@api_bp.route('/subjects/<int:subject_id>', methods=['PUT'])
@admin_required
def update_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    data = request.get_json()
    
    if 'name' in data:
        subject.name = data['name']
    if 'description' in data:
        subject.description = data['description']
    
    try:
        db.session.commit()
        return jsonify({
            'id': subject.id,
            'name': subject.name,
            'description': subject.description,
            'message': 'Subject updated successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/subjects/<int:subject_id>', methods=['DELETE'])
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    
    # Check if there are chapters associated with this subject
    if subject.chapters:
        return jsonify({'error': 'Cannot delete subject with associated chapters. Delete chapters first.'}), 400
        
    try:
        db.session.delete(subject)
        db.session.commit()
        return jsonify({'message': 'Subject deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# API endpoints for Chapters
@api_bp.route('/chapters', methods=['GET'])
def get_chapters():
    chapters = Chapter.query.all()
    result = []
    for chapter in chapters:
        result.append({
            'id': chapter.id,
            'name': chapter.name,
            'description': chapter.description,
            'subject_id': chapter.subject_id,
            'subject_name': chapter.subject.name,
            'quiz_count': len(chapter.quizzes)
        })
    return jsonify(result)

@api_bp.route('/chapters', methods=['POST'])
@admin_required
def create_chapter():
    data = request.get_json()
    
    # Handle both single chapter and multiple chapters
    chapters_data = data if isinstance(data, list) else [data]
    
    if not chapters_data:
        return jsonify({'error': 'No data provided'}), 400
    
    results = []
    errors = []
    
    for chapter_data in chapters_data:
        if not chapter_data or not chapter_data.get('name') or not chapter_data.get('description') or not chapter_data.get('subject_id'):
            errors.append({'error': 'Name, description and subject_id required', 'data': chapter_data})
            continue
        
        # Check if subject exists
        subject = Subject.query.get(chapter_data['subject_id'])
        if not subject:
            errors.append({'error': 'Subject not found', 'subject_id': chapter_data['subject_id']})
            continue
            
        # Check for duplicate chapter name within the subject
        existing_chapter = Chapter.query.filter_by(
            name=chapter_data['name'],
            subject_id=chapter_data['subject_id']
        ).first()
        
        if existing_chapter:
            errors.append({'error': 'A chapter with this name already exists for the selected subject', 'name': chapter_data['name']})
            continue
            
        chapter = Chapter(
            subject_id=chapter_data['subject_id'],
            name=chapter_data['name'],
            description=chapter_data['description']
        )
        
        db.session.add(chapter)
        results.append(chapter)
    
    if not results:
        db.session.rollback()
        return jsonify({'errors': errors}), 400
    
    try:
        db.session.commit()
        response = {
            'chapters': [{
                'id': chapter.id,
                'name': chapter.name,
                'description': chapter.description,
                'subject_id': chapter.subject_id
            } for chapter in results],
            'message': f'Successfully created {len(results)} chapter(s)'
        }
        
        if errors:
            response['errors'] = errors
            
        return jsonify(response), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
# API endpoints for Quizzes
@api_bp.route('/quizzes', methods=['GET'])
def get_quizzes():
    quizzes = Quiz.query.all()
    result = []
    for quiz in quizzes:
        result.append({
            'id': quiz.id,
            'chapter_id': quiz.chapter_id,
            'chapter_name': quiz.chapter.name,
            'subject_name': quiz.chapter.subject.name,
            'date_of_quiz': quiz.date_of_quiz.strftime('%Y-%m-%d'),
            'time_duration': quiz.time_duration,
            'remarks': quiz.remarks,
            'question_count': len(quiz.questions)
        })
    return jsonify(result)

@api_bp.route('/quizzes', methods=['POST'])
@admin_required
def create_quiz():
    data = request.get_json()
    
    # Handle both single quiz and multiple quizzes
    quizzes_data = data if isinstance(data, list) else [data]
    
    if not quizzes_data:
        return jsonify({'error': 'No data provided'}), 400
    
    results = []
    errors = []
    
    for quiz_data in quizzes_data:
        if not quiz_data or not quiz_data.get('chapter_id') or not quiz_data.get('date_of_quiz') or not quiz_data.get('time_duration'):
            errors.append({'error': 'Chapter ID, date and duration required', 'data': quiz_data})
            continue
        
        # Check if chapter exists
        chapter = Chapter.query.get(quiz_data['chapter_id'])
        if not chapter:
            errors.append({'error': 'Chapter not found', 'chapter_id': quiz_data['chapter_id']})
            continue
            
        try:
            quiz = Quiz(
                chapter_id=quiz_data['chapter_id'],
                date_of_quiz=quiz_data['date_of_quiz'],
                time_duration=quiz_data['time_duration'],
                remarks=quiz_data.get('remarks', '')
            )
            
            db.session.add(quiz)
            results.append(quiz)
        except Exception as e:
            errors.append({'error': str(e), 'data': quiz_data})
    
    if not results:
        db.session.rollback()
        return jsonify({'errors': errors}), 400
    
    try:
        db.session.commit()
        response = {
            'quizzes': [{
                'id': quiz.id,
                'chapter_id': quiz.chapter_id,
                'date_of_quiz': quiz.date_of_quiz.strftime('%Y-%m-%d'),
                'time_duration': quiz.time_duration,
                'remarks': quiz.remarks
            } for quiz in results],
            'message': f'Successfully created {len(results)} quiz(zes)'
        }
        
        if errors:
            response['errors'] = errors
            
        return jsonify(response), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
# API endpoint for dashboard stats
@api_bp.route('/stats', methods=['GET'])
@admin_required
def get_stats():
    subject_count = Subject.query.count()
    chapter_count = Chapter.query.count()
    quiz_count = Quiz.query.count()
    question_count = Question.query.count()
    
    return jsonify({
        'subjects': subject_count,
        'chapters': chapter_count,
        'quizzes': quiz_count,
        'questions': question_count
    })