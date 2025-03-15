import os
import logging
import pandas as pd
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import jsonify, render_template, redirect, url_for, flash, request, send_from_directory, session
from flask_login import login_user, logout_user, login_required, current_user, LoginManager
from werkzeug.security import generate_password_hash, check_password_hash

from app import app, db

login_manager = LoginManager()
login_manager.init_app(app)
from models import User, Admin, Subject, Chapter, Quiz, Question, Score
from forms import (LoginForm, RegisterForm, SubjectForm, ChapterForm, QuizForm, 
                  QuestionForm, QuestionImportForm, UserProfileForm, AdminProfileForm, AdminRegistrationForm)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def handle_file_upload(file, folder=''):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], folder, filename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        file.save(path)
        return os.path.join(folder, filename) if folder else filename
    return None

@app.route('/admin/quizzes/<int:quiz_id>/questions', methods=['GET', 'POST'])
@login_required
def manage_questions(quiz_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    question_form = QuestionForm()
    question_form.quiz_id.choices = [(quiz_id, quiz.chapter.name)]  # Set choices for the quiz_id field
    question_form.quiz_id.data = quiz_id

    import_form = QuestionImportForm()
    import_form.quiz_id.choices = [(quiz_id, quiz.chapter.name)]  # Set choices for the quiz_id field
    import_form.quiz_id.data = quiz_id

    if request.method == 'POST':
        form_type = request.form.get('form_type')
        logging.debug(f"Form type: {form_type}")
        logging.debug(f"Form data: {request.form}")
        logging.debug(f"Files: {request.files}")

        if form_type == 'question':
            if question_form.validate_on_submit():
                try:
                    question_image_path = None
                    if question_form.question_image.data:
                        question_image_path = handle_file_upload(
                            question_form.question_image.data, 
                            folder=f'questions/quiz_{quiz_id}'
                        )

                    question = Question(
                        quiz_id=quiz_id,
                        question_statement=question_form.question_statement.data,
                        question_image=question_image_path,
                        option_1=question_form.option_1.data,
                        option_2=question_form.option_2.data,
                        option_3=question_form.option_3.data,
                        option_4=question_form.option_4.data,
                        correct_option=int(question_form.correct_option.data)
                    )
                    db.session.add(question)
                    db.session.commit()
                    flash('Question added successfully!', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'Error adding question: {str(e)}', 'danger')
                    logging.error(f"Error adding question: {str(e)}")
            else:
                for field, errors in question_form.errors.items():
                    for error in errors:
                        flash(f'{field}: {error}', 'danger')
                        logging.error(f"Form validation error - {field}: {error}")

        elif form_type == 'import':
            if import_form.validate_on_submit():
                file_path = handle_file_upload(import_form.file.data)
                if file_path:
                    try:
                        if file_path.endswith('.csv'):
                            df = pd.read_csv(os.path.join(app.config['UPLOAD_FOLDER'], file_path), dtype=str)
                        else:  # Excel file
                            df = pd.read_excel(os.path.join(app.config['UPLOAD_FOLDER'], file_path), dtype=str)

                        required_columns = ['question_statement', 'option_1', 'option_2', 'option_3', 'option_4', 'correct_option']
                        if not all(col in df.columns for col in required_columns):
                            missing_cols = [col for col in required_columns if col not in df.columns]
                            raise ValueError(f"Missing required columns: {', '.join(missing_cols)}")

                        for index, row in df.iterrows():
                            try:
                                logging.info(f"Processing row {index + 1}: {row}")

                                # Ensure all required fields are present and not empty (except option_4 which can be "None")
                                for field in required_columns:
                                    if field == 'option_4':
                                        # Allow "None" as text for option_4, but convert to empty string
                                        if pd.isna(row[field]) or (str(row[field]).strip().lower() == 'none' and field == 'option_4'):
                                            row[field] = "Not applicable"
                                    elif pd.isna(row[field]) or str(row[field]).strip() == '':
                                        raise ValueError(f"Field '{field}' is required but empty")

                                # Convert correct_option to integer after validation
                                try:
                                    correct_option = int(float(row['correct_option']))
                                    if not 1 <= correct_option <= 4:
                                        raise ValueError(f"Correct option must be between 1 and 4, got {correct_option}")
                                except (ValueError, TypeError) as e:
                                    db.session.rollback()
                                    raise ValueError(f"Invalid correct_option value in row {index + 1}: {str(e)}")

                                # Create and add question with proper type handling
                                option_4_value = str(row['option_4']).strip()
                                if option_4_value.lower() == 'none':
                                    option_4_value = "Not applicable"

                                question = Question(
                                    quiz_id=quiz_id,
                                    question_statement=str(row['question_statement']).strip(),
                                    question_image=None if pd.isna(row.get('image_url')) else str(row.get('image_url')),
                                    option_1=str(row['option_1']).strip(),
                                    option_2=str(row['option_2']).strip(),
                                    option_3=str(row['option_3']).strip(),
                                    option_4=option_4_value,
                                    correct_option=correct_option
                                )
                                db.session.add(question)
                                logging.info(f"Successfully added question from row {index + 1}")

                            except Exception as row_error:
                                db.session.rollback()
                                logging.error(f"Error processing row {index + 1}: {row}")
                                logging.error(f"Error details: {str(row_error)}")
                                raise ValueError(f"Error in row {index + 1}: {str(row_error)}")

                        db.session.commit()
                        flash(f'Successfully imported {len(df)} questions!', 'success')
                        logging.info(f"Successfully imported {len(df)} questions")

                    except Exception as e:
                        db.session.rollback()
                        flash(f'Error importing questions: {str(e)}', 'danger')
                        logging.error(f"Error importing questions: {str(e)}")
                    finally:
                        if file_path and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], file_path)):
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_path))

            else:
                for field, errors in import_form.errors.items():
                    for error in errors:
                        flash(f'{field}: {error}', 'danger')
                        logging.error(f"Import form validation error - {field}: {error}")

        return redirect(url_for('manage_questions', quiz_id=quiz_id))

    return render_template('admin/questions.html', 
                         quiz=quiz, 
                         questions=questions,
                         question_form=question_form,
                         import_form=import_form)

# View score details
@app.route('/user/score/<int:score_id>')
@login_required
def view_score(score_id):
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    score = Score.query.get_or_404(score_id)

    # Ensure user can only see their own scores
    if score.user_id != current_user.id:
        flash('You do not have permission to view this score', 'danger')
        return redirect(url_for('user_dashboard'))

    quiz = score.quiz
    questions = Question.query.filter_by(quiz_id=quiz.id).all()

    # Get user answers from session if available
    user_answers = session.get(f'user_answers_{score.id}', {})

    # Calculate actual metrics based on stored answers
    correct_answers = 0
    wrong_answers = 0
    not_attempted = 0

    for question in questions:
        if question.id in user_answers:
            if user_answers[question.id] == question.correct_option:
                correct_answers += 1
            else:
                wrong_answers += 1
        else:
            not_attempted += 1

    # Calculate accuracy
    accuracy = 0
    if (correct_answers + wrong_answers) > 0:
        accuracy = round((correct_answers / (correct_answers + wrong_answers)) * 100)

    # Get historical score data for progress chart
    user_scores = Score.query.filter_by(user_id=current_user.id).order_by(Score.time_stamp_of_attempt).limit(10).all()
    progress_labels = [s.time_stamp_of_attempt.strftime('%d/%m/%Y') for s in user_scores]
    progress_data = [s.total_scored for s in user_scores]

    return render_template('user/results.html', 
                          quiz=quiz,
                          score=score,
                          correct_answers=correct_answers,
                          wrong_answers=wrong_answers,
                          not_attempted=not_attempted,
                          total_questions=len(questions),
                          accuracy=accuracy,
                          progress_labels=progress_labels,
                          progress_data=progress_data,
                          user_answers=user_answers,
                          questions=questions)

@app.route('/user/quiz/<int:quiz_id>/review/<int:score_id>')
@login_required
def review_quiz(quiz_id, score_id):
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    score = Score.query.get_or_404(score_id)

    # Ensure user can only see their own scores
    if score.user_id != current_user.id:
        flash('You do not have permission to view this score', 'danger')
        return redirect(url_for('user_dashboard'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    # Get user answers from session if available
    session_answers = session.get(f'user_answers_{score.id}', {})
    # Convert string keys back to integers for template
    user_answers = {int(k): v for k, v in session_answers.items()} if session_answers else {}

    # Calculate actual metrics based on stored answers
    correct_answers = 0
    wrong_answers = 0
    not_attempted = 0

    for question in questions:
        if question.id in user_answers:
            if user_answers[question.id] == question.correct_option:
                correct_answers += 1
            else:
                wrong_answers += 1
        else:
            not_attempted += 1

    return render_template('user/review_quiz.html', 
                          quiz=quiz,
                          score=score,
                          questions=questions,
                          user_answers=user_answers,
                          correct_answers=correct_answers,
                          wrong_answers=wrong_answers,
                          not_attempted=not_attempted)

    # Add route for serving uploaded files
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@login_manager.user_loader
@login_manager.user_loader
def load_user(user_id):
    try:
        # Check the session to determine user type
        user_type = session.get('user_type')
        
        if user_type == 'admin':
            return Admin.query.get(int(user_id))
        else:
            return User.query.get(int(user_id))
    except Exception as e:
        logging.error(f"Error in load_user: {str(e)}")
        return None

@app.route('/admin/profile', methods=['GET', 'POST'])
@login_required
def admin_profile():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    form = AdminProfileForm()
    
    if form.validate_on_submit():
        admin = Admin.query.get(current_user.id)
        
        # Verify current password
        if check_password_hash(admin.password, form.current_password.data):
            # Update username if it has changed
            if form.username.data != admin.username:
                # Check if the new username is already taken
                if Admin.query.filter_by(username=form.username.data).first() and form.username.data != admin.username:
                    flash('Username already exists. Please choose another username.', 'danger')
                    return redirect(url_for('admin_profile'))
                admin.username = form.username.data
                
            # Update password if new password is provided
            if form.new_password.data:
                admin.password = generate_password_hash(form.new_password.data)
                
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Current password is incorrect.', 'danger')
            
    # Pre-populate username field
    if request.method == 'GET':
        form.username.data = current_user.username
        
    return render_template('admin/profile.html', form=form)

@app.route('/admin/register', methods=['GET', 'POST'])
@login_required
def admin_register():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    form = AdminRegistrationForm()
    
    if form.validate_on_submit():
        # Check if username already exists
        if Admin.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose another username.', 'danger')
            return redirect(url_for('admin_register'))
            
        new_admin = Admin(
            username=form.username.data,
            password=generate_password_hash(form.password.data)
        )
        
        db.session.add(new_admin)
        db.session.commit()
        flash('New admin registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin/register_admin.html', form=form)
# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated and isinstance(current_user, User):
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('user_login'))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If already logged in as admin, redirect to admin dashboard
    if current_user.is_authenticated and isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    # For user, we'll show the admin login page instead of redirecting
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data != 'admin':
            flash('Invalid admin username', 'danger')
            return redirect(url_for('admin_login'))

        admin = Admin.query.filter_by(username='admin').first()
        if admin and check_password_hash(admin.password, form.password.data):
            # Set session user type before login
            session['user_type'] = 'admin'
            # Login as admin without logging out the current user
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials', 'danger')
    return render_template('auth/admin_login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    # If already logged in as user, redirect to user dashboard
    if current_user.is_authenticated and isinstance(current_user, User):
        return redirect(url_for('user_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user and check_password_hash(user.password, form.password.data):
                # Set session user type before login
                session['user_type'] = 'user'
                # Login as user without logging out the current admin
                login_user(user)
                return redirect(url_for('user_dashboard'))
            flash('Invalid email or password', 'danger')
        except Exception as e:
            logging.error(f"Database error during login: {str(e)}")
            flash('Login failed due to a server error. Please try again later.', 'danger')
            db.session.rollback()  # Roll back any failed transaction
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated and isinstance(current_user, User):
        return redirect(url_for('user_dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        user = User(
            email=form.email.data,
            password=generate_password_hash(form.password.data),
            full_name=form.full_name.data,
            qualification=form.qualification.data,
            dob=form.dob.data
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('user_login'))
    return render_template('auth/register.html', form=form)

@app.route('/admin/logout')
@login_required
def admin_logout():
    if isinstance(current_user, Admin):
        logout_user()
        flash('Admin logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/user/logout')
@login_required
def user_logout():
    if isinstance(current_user, User):
        logout_user()
        flash('Student logged out successfully', 'success')
    return redirect(url_for('user_login'))

# Keep the original logout function but make it check the user type
@app.route('/logout')
@login_required
def logout():
    if isinstance(current_user, Admin):
        logout_user()
        return redirect(url_for('admin_login'))
    else:
        logout_user()
        return redirect(url_for('user_login'))

# Admin routes
# Example update for admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    subjects = Subject.query.all()
    users = User.query.all()
    total_quizzes = Quiz.query.count()
    return render_template('admin/dashboard.html', subjects=subjects, users=users, total_quizzes=total_quizzes)

@app.route('/admin/api-docs')
@login_required
def api_docs():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    return render_template('admin/api_docs.html')

@app.route('/admin/subjects', methods=['GET', 'POST'])
@login_required
def manage_subjects():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = SubjectForm()
    if form.validate_on_submit():
        if Subject.query.filter_by(name=form.name.data).first():
            flash('Subject already exists. Please choose another name.', 'danger')
            return redirect(url_for('manage_subjects'))
        subject = Subject(name=form.name.data, description=form.description.data)
        db.session.add(subject)
        db.session.commit()
        flash('Subject added successfully!', 'success')
        return redirect(url_for('manage_subjects'))

    subjects = Subject.query.all()
    return render_template('admin/subjects.html', form=form, subjects=subjects)

@app.route('/admin/subjects/<int:subject_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_subject(subject_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    subject = Subject.query.get_or_404(subject_id)
    form = SubjectForm(obj=subject)

    if form.validate_on_submit():
        subject.name = form.name.data
        subject.description = form.description.data

        db.session.commit()
        flash('Subject updated successfully!', 'success')
        return redirect(url_for('manage_subjects'))

    return render_template('admin/edit_subject.html', form=form, subject=subject)

@app.route('/admin/subjects/<int:subject_id>/delete', methods=['POST'])
@login_required
def delete_subject(subject_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    subject = Subject.query.get_or_404(subject_id)

    try:
        # Check if there are chapters associated with this subject
        if subject.chapters:
            flash('Cannot delete subject. Please delete associated chapters first.', 'danger')
            return redirect(url_for('manage_subjects'))

        db.session.delete(subject)
        db.session.commit()
        flash('Subject deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting subject: {str(e)}', 'danger')

    return redirect(url_for('manage_subjects'))

@app.route('/admin/chapters', methods=['GET', 'POST'])
@login_required
def manage_chapters():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = ChapterForm()
    # Populate subject choices
    form.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]

    if form.validate_on_submit():
        chapter = Chapter(
            subject_id=form.subject_id.data,
            name=form.name.data,
            description=form.description.data
        )
        db.session.add(chapter)
        db.session.commit()
        flash('Chapter added successfully!', 'success')
        return redirect(url_for('manage_chapters'))

    chapters = Chapter.query.all()
    return render_template('admin/chapters.html', form=form, chapters=chapters)

@app.route('/admin/chapters/<int:chapter_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_chapter(chapter_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    chapter = Chapter.query.get_or_404(chapter_id)
    form = ChapterForm(obj=chapter)
    form.subject_id.choices = [(s.id, s.name) for s in Subject.query.all()]

    if form.validate_on_submit():
        chapter.subject_id = form.subject_id.data
        chapter.name = form.name.data
        chapter.description = form.description.data

        db.session.commit()
        flash('Chapter updated successfully!', 'success')
        return redirect(url_for('manage_chapters'))

    return render_template('admin/edit_chapter.html', form=form, chapter=chapter)

@app.route('/admin/chapters/<int:chapter_id>/delete', methods=['POST'])
@login_required
def delete_chapter(chapter_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    chapter = Chapter.query.get_or_404(chapter_id)

    try:
        # Check if there are quizzes associated with this chapter
        if chapter.quizzes:
            flash('Cannot delete chapter. Please delete associated quizzes first.', 'danger')
            return redirect(url_for('manage_chapters'))

        db.session.delete(chapter)
        db.session.commit()
        flash('Chapter deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting chapter: {str(e)}', 'danger')

    return redirect(url_for('manage_chapters'))

@app.route('/admin/quizzes', methods=['GET', 'POST'])
@login_required
def manage_quizzes():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = QuizForm()
    # Populate chapter choices
    form.chapter_id.choices = [(c.id, f"{c.subject.name} - {c.name}") for c in Chapter.query.all()]

    if form.validate_on_submit():
        quiz = Quiz(
            chapter_id=form.chapter_id.data,
            date_of_quiz=form.date_of_quiz.data,
            time_duration=form.time_duration.data,
            remarks=form.remarks.data
        )
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz added successfully!', 'success')
        return redirect(url_for('manage_quizzes'))

    quizzes = Quiz.query.all()
    return render_template('admin/quizzes.html', form=form, quizzes=quizzes)

@app.route('/admin/quizzes/<int:quiz_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    quiz = Quiz.query.get_or_404(quiz_id)
    form = QuizForm(obj=quiz)
    form.chapter_id.choices = [(c.id, f"{c.subject.name} - {c.name}") for c in Chapter.query.all()]

    if form.validate_on_submit():
        quiz.chapter_id = form.chapter_id.data
        quiz.date_of_quiz = form.date_of_quiz.data
        quiz.time_duration = form.time_duration.data
        quiz.remarks = form.remarks.data

        db.session.commit()
        flash('Quiz updated successfully!', 'success')
        return redirect(url_for('manage_quizzes'))

    return render_template('admin/edit_quiz.html', form=form, quiz=quiz)

@app.route('/admin/quizzes/<int:quiz_id>/delete', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    quiz = Quiz.query.get_or_404(quiz_id)

    try:
        # First delete associated questions to avoid foreign key constraints
        Question.query.filter_by(quiz_id=quiz.id).delete()
        # Then delete associated scores
        Score.query.filter_by(quiz_id=quiz.id).delete()
        # Finally delete the quiz
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting quiz: {str(e)}', 'danger')

    return redirect(url_for('manage_quizzes'))

@app.route('/admin/users')
@login_required
def manage_users():
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>')
@login_required
def user_detail(user_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    user = User.query.get_or_404(user_id)
    scores = Score.query.filter_by(user_id=user_id).order_by(Score.time_stamp_of_attempt.desc()).all()

    # Calculate statistics
    total_quizzes = len(scores)
    avg_score = sum(score.total_scored for score in scores) / total_quizzes if total_quizzes > 0 else 0
    highest_score = max((score.total_scored for score in scores), default=0)
    lowest_score = min((score.total_scored for score in scores), default=0)

    # Get performance trend data
    progress_labels = [s.time_stamp_of_attempt.strftime('%d/%m/%Y') for s in scores[:10]]
    progress_data = [s.total_scored for s in scores[:10]]

    # Reverse to show chronological order
    progress_labels.reverse()
    progress_data.reverse()

    return render_template('admin/user_detail.html', 
                          user=user,
                          scores=scores,
                          total_quizzes=total_quizzes,
                          avg_score=avg_score,
                          highest_score=highest_score,
                          lowest_score=lowest_score,
                          progress_labels=progress_labels,
                          progress_data=progress_data)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not isinstance(current_user, Admin):
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('user_dashboard'))

    user = User.query.get_or_404(user_id)

    try:
        # Delete associated scores first
        Score.query.filter_by(user_id=user_id).delete()
        # Then delete the user
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')

    return redirect(url_for('manage_users'))


# User routes
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    # Get all subjects with chapters and quizzes
    subjects = Subject.query.all()

    # Get recent scores for the user
    recent_scores = Score.query.filter_by(user_id=current_user.id).order_by(Score.time_stamp_of_attempt.desc()).limit(5).all()

    # Get progress data for chart
    progress_labels = []
    progress_data = []

    if recent_scores:
        # Reverse to show oldest to newest for progression chart
        scores_for_chart = recent_scores.copy()
        scores_for_chart.reverse()

        progress_labels = [s.time_stamp_of_attempt.strftime('%d/%m/%Y') for s in scores_for_chart]
        progress_data = [s.total_scored for s in scores_for_chart]

    return render_template('user/dashboard.html', 
                          subjects=subjects, 
                          recent_scores=recent_scores,
                          progress_labels=progress_labels,
                          progress_data=progress_data)

@app.route('/user/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))
        
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    
    # Import the QuizHandler at the top of routes.py if not already imported
    from quiz_handler import QuizHandler
    
    # Initialize quiz if not already in progress
    if not QuizHandler.check_if_quiz_in_progress(quiz_id):
        QuizHandler.initialize_quiz(quiz, current_user)
    
    # Get time information for the quiz
    time_info = QuizHandler.get_remaining_time()
    
    # Get quiz progress summary
    quiz_summary = QuizHandler.get_quiz_summary()
    
    # Get quiz data from session
    quiz_data = QuizHandler.get_quiz_data() or {'answers': {}, 'question_status': {}}
    
    # Get current question position
    current_question_num = quiz_data.get('current_question', 1)
    
    return render_template('user/quiz.html', 
                          quiz=quiz, 
                          questions=questions, 
                          quiz_data=quiz_data,
                          time_info=time_info,
                          current_question_num=current_question_num,
                          quiz_summary=quiz_summary)

@app.route('/user/quiz/<int:quiz_id>/submit', methods=['GET', 'POST'])
@login_required
def submit_quiz(quiz_id):
    """Process quiz submission and show results"""
    # Redirect admins to their dashboard
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    try:
        # Get quiz and questions
        quiz = Quiz.query.get_or_404(quiz_id)
        questions = Question.query.filter_by(quiz_id=quiz_id).all()
        total_questions = len(questions)
        
        if total_questions == 0:
            flash('This quiz has no questions.', 'warning')
            return redirect(url_for('user_dashboard'))
            
        # Import QuizHandler here to avoid circular imports
        from quiz_handler import QuizHandler
        
        # Check if quiz time is up
        time_info = QuizHandler.get_remaining_time()
        
        # Check for forced_submit from both query parameters (GET) and form data (POST)
        forced_submit = request.args.get('forced_submit') or request.form.get('forced_submit')
        
        if time_info.get('is_time_up', False) and not forced_submit:
            flash('Quiz time is up! Your answers have been automatically submitted.', 'warning')
        
        # Process answers
        correct_answers = 0
        wrong_answers = 0
        user_answers = {}
        
        # Get answers from session if available, otherwise from form
        session_answers = session.get('current_quiz_answers', {})

        for question in questions:
            question_id = str(question.id)
            # First check session, then form
            if question_id in session_answers:
                user_answer = int(session_answers[question_id])
            else:
                form_key = f'question_{question.id}'
                form_answer = request.form.get(form_key)
                user_answer = int(form_answer) if form_answer else None
                
            if user_answer:
                user_answers[question.id] = user_answer
                if user_answer == question.correct_option:
                    correct_answers += 1
                else:
                    wrong_answers += 1
        
        # Calculate metrics
        not_attempted = total_questions - (correct_answers + wrong_answers)
        total_scored = round((correct_answers / total_questions) * 100) if total_questions > 0 else 0
        accuracy = round((correct_answers / (correct_answers + wrong_answers) * 100) if (correct_answers + wrong_answers) > 0 else 0)
        
        # Save score to database
        score = Score(
            quiz_id=quiz_id,
            user_id=current_user.id,
            total_scored=total_scored,
            max_score=100,  # Store as percentage out of 100
            total_questions=total_questions,
            correct_answers=correct_answers,
            wrong_answers=wrong_answers,
            not_attempted=not_attempted,
            time_stamp_of_attempt=datetime.now()
        )
        db.session.add(score)
        db.session.commit()
        
        # Store answers in session for review
        session[f'user_answers_{score.id}'] = user_answers
        
        # Clean up quiz session data
        if 'quiz_data' in session:
            del session['quiz_data']
        if 'current_quiz_answers' in session:
            del session['current_quiz_answers']
        
        # Get historical score data for progress chart
        user_scores = Score.query.filter_by(user_id=current_user.id)\
            .order_by(Score.time_stamp_of_attempt.desc())\
            .limit(10).all()
            
        progress_labels = [s.time_stamp_of_attempt.strftime('%d/%m/%Y') for s in user_scores]
        progress_data = [s.total_scored for s in user_scores]
        
        flash('Quiz submitted successfully!', 'success')
        return render_template('user/results.html', 
                            quiz=quiz,
                            score=score,
                            correct_answers=correct_answers,
                            wrong_answers=wrong_answers,
                            not_attempted=not_attempted,
                            total_questions=total_questions,
                            accuracy=accuracy,
                            progress_labels=progress_labels,
                            progress_data=progress_data,
                            user_answers=user_answers,
                            questions=questions)
                            
    except Exception as e:
        logging.error(f"Error in submit_quiz: {str(e)}")
        flash('An error occurred while submitting your quiz. Please try again.', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/user/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))
    
    form = UserProfileForm()
    
    if form.validate_on_submit():
        user = User.query.get(current_user.id)
        
        # Verify current password
        if check_password_hash(user.password, form.current_password.data):
            # Update email if it has changed
            if form.email.data != user.email:
                # Check if the new email is already taken
                if User.query.filter_by(email=form.email.data).first() and form.email.data != user.email:
                    flash('Email already exists. Please choose another email.', 'danger')
                    return redirect(url_for('user_settings'))
                user.email = form.email.data
                
            # Update other fields
            user.full_name = form.full_name.data
            user.qualification = form.qualification.data
            user.dob = form.dob.data
            
            # Update password if new password is provided
            if form.new_password.data:
                user.password = generate_password_hash(form.new_password.data)
                
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Current password is incorrect.', 'danger')
            
    # Pre-populate fields
    if request.method == 'GET':
        form.email.data = current_user.email
        form.full_name.data = current_user.full_name
        form.qualification.data = current_user.qualification
        form.dob.data = current_user.dob
        
    return render_template('user/settings.html', form=form)


    """AJAX endpoint to navigate between questions without refreshing the page"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get JSON data
    data = request.get_json()
    question_number = data.get('question_number')
    
    if not question_number:
        return jsonify({'success': False, 'error': 'Missing question number'}), 400
    
    # Navigate to question using QuizHandler
    from quiz_handler import QuizHandler
    success = QuizHandler.navigate_to_question(int(question_number))
    
    if not success:
        return jsonify({'success': False, 'error': 'Navigation failed'}), 400
    
    # Get question data for the new position
    quiz_data = QuizHandler.get_quiz_data()
    question_map = quiz_data.get('question_map', {})
    current_question_num = quiz_data.get('current_question', 1)
    question_id = question_map.get(current_question_num)
    
    # Get the question from database
    question = Question.query.get(question_id)
    if not question:
        return jsonify({'success': False, 'error': 'Question not found'}), 404
    
    # Get user's answer for this question, if any
    user_answers = QuizHandler.get_user_answers()
    selected_option = user_answers.get(str(question_id))
    
    # Return question data for rendering
    return jsonify({
        'success': True,
        'question_data': {
            'id': question.id,
            'position': current_question_num,
            'statement': question.question_statement,
            'options': [
                question.option_1,
                question.option_2,
                question.option_3,
                question.option_4
            ],
            'selected_option': selected_option,
            'total': quiz_data.get('total_questions', 1)
        }
    })

@app.route('/user/quiz/<int:quiz_id>/save_answer', methods=['POST'])
@login_required
def save_quiz_answer(quiz_id):
    """AJAX endpoint to save an answer without refreshing the page"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get JSON data
    data = request.get_json()
    question_id = data.get('question_id')
    selected_option = data.get('selected_option')
    
    if not question_id or not selected_option:
        return jsonify({'success': False, 'error': 'Missing data'}), 400
    
    # Save answer using QuizHandler
    from quiz_handler import QuizHandler
    success = QuizHandler.save_answer(int(question_id), int(selected_option))
    
    # Get question number for the updated UI
    quiz_data = QuizHandler.get_quiz_data()
    position_to_id = {v: k for k, v in quiz_data.get('id_to_position', {}).items()}
    question_number = position_to_id.get(int(question_id))
    
    return jsonify({
        'success': success,
        'question_id': question_id,
        'selected_option': selected_option,
        'question_number': question_number
    })

@app.route('/user/quiz/<int:quiz_id>/navigate', methods=['POST'])
@login_required
def navigate_quiz(quiz_id):
    """AJAX endpoint to navigate between questions without refreshing the page"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get JSON data
    data = request.get_json()
    question_number = data.get('question_number')
    
    if not question_number:
        return jsonify({'success': False, 'error': 'Missing question number'}), 400
    
    # Navigate to question using QuizHandler
    from quiz_handler import QuizHandler
    success = QuizHandler.navigate_to_question(int(question_number))
    
    # Get the current status after navigation
    quiz_data = QuizHandler.get_quiz_data()
    status = quiz_data.get('question_status', {}).get(str(question_number))
    
    return jsonify({'success': success, 'status': status})

@app.route('/user/quiz/<int:quiz_id>/clear_answer', methods=['POST'])
@login_required
def clear_question_answer(quiz_id):
    """AJAX endpoint to clear an answer"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get JSON data
    data = request.get_json()
    question_id = data.get('question_id')
    
    if not question_id:
        return jsonify({'success': False, 'error': 'Missing question ID'}), 400
    
    # Clear answer using QuizHandler
    from quiz_handler import QuizHandler
    success = QuizHandler.clear_answer(int(question_id))
    
    # Get question number for the updated UI
    quiz_data = QuizHandler.get_quiz_data()
    position_to_id = {v: k for k, v in quiz_data.get('id_to_position', {}).items()}
    question_number = position_to_id.get(int(question_id))
    
    return jsonify({'success': success, 'question_number': question_number})

@app.route('/user/quiz/<int:quiz_id>/mark_for_review', methods=['POST'])
@login_required
def mark_question_for_review(quiz_id):
    """AJAX endpoint to mark a question for review"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get JSON data
    data = request.get_json()
    question_number = data.get('question_number')
    
    if not question_number:
        return jsonify({'success': False, 'error': 'Missing question number'}), 400
    
    # Mark for review using QuizHandler
    from quiz_handler import QuizHandler
    success = QuizHandler.mark_for_review(int(question_number))
    
    return jsonify({'success': success})

@app.route('/user/quiz/<int:quiz_id>/summary')
@login_required
def get_quiz_summary(quiz_id):
    """AJAX endpoint to get updated quiz summary"""
    if isinstance(current_user, Admin):
        return jsonify({'success': False, 'error': 'Admin cannot take quizzes'}), 403
    
    # Get summary using QuizHandler
    from quiz_handler import QuizHandler
    summary = QuizHandler.get_quiz_summary()
    
    return jsonify({'success': True, 'summary': summary})