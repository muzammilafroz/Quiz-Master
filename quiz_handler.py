from datetime import datetime
from flask import session, flash, redirect, url_for
import json

class QuizHandler:
    """
    Server-side quiz processing and management.
    Replaces client-side quiz.js functionality with server-side processing.
    """
    
    @staticmethod
    def initialize_quiz(quiz, user):
        """
        Initialize a new quiz session
        
        Args:
            quiz: The quiz model object
            user: The current user
            
        Returns:
            dict: Quiz session data
        """
        # Get all questions for this quiz
        questions = quiz.questions
        total_questions = len(questions)
        
        # Create mapping between question positions and IDs
        question_map = {i+1: q.id for i, q in enumerate(questions)}
        id_to_position = {q.id: i+1 for i, q in enumerate(questions)}
        
        # Initialize question status tracking
        question_status = {}
        for i in range(1, total_questions + 1):
            question_status[str(i)] = 'Not Visited'  # Convert to string for session storage compatibility
        
        # First question is considered visited
        question_status['1'] = 'Not Answered'
        
        # Create quiz session data
        quiz_data = {
            'quiz_id': quiz.id,
            'user_id': user.id,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'total_time': quiz.time_duration * 60,  # Convert to seconds
            'current_question': 1,
            'total_questions': total_questions,
            'question_status': question_status,
            'question_map': question_map,
            'id_to_position': id_to_position,
            'answers': {},
            'is_completed': False,
            'is_time_up': False
        }
        
        # Store in session
        session['quiz_data'] = quiz_data
        return quiz_data
    
    @staticmethod
    def get_remaining_time():
        """
        Calculate the remaining time for the quiz
        
        Returns:
            dict: Time information including minutes, seconds, percentage and if time is up
        """
        if 'quiz_data' not in session:
            return {'minutes': 0, 'seconds': 0, 'percentage': 0, 'is_time_up': True}
            
        quiz_data = session['quiz_data']
        
        # Parse start time from string if needed
        if isinstance(quiz_data['start_time'], str):
            start_time = datetime.fromisoformat(quiz_data['start_time'])
        else:
            start_time = quiz_data['start_time']
            
        total_time = quiz_data['total_time']
        
        # If quiz already marked as time up, return time up status
        if quiz_data.get('is_time_up', False):
            return {'minutes': 0, 'seconds': 0, 'percentage': 0, 'is_time_up': True}
        
        elapsed_seconds = (datetime.now() - start_time).total_seconds()
        remaining_seconds = max(0, total_time - elapsed_seconds)
        
        minutes = int(remaining_seconds // 60)
        seconds = int(remaining_seconds % 60)
        percentage = (remaining_seconds / total_time) * 100 if total_time > 0 else 0
        is_time_up = remaining_seconds <= 0
        
        # Update time up status in session if time is now up
        if is_time_up and not quiz_data.get('is_time_up', False):
            quiz_data['is_time_up'] = True
            session['quiz_data'] = quiz_data
        
        return {
            'minutes': minutes,
            'seconds': seconds,
            'percentage': percentage,
            'is_time_up': is_time_up
        }
    
    @staticmethod
    def navigate_to_question(question_number):
        """Navigate to a specific question in the quiz"""
        try:
            # Get quiz data from session
            quiz_data = QuizHandler.get_quiz_data()
            if not quiz_data:
                return False
                
            # Validate question number
            total_questions = quiz_data.get('total_questions', 0)
            if question_number < 1 or question_number > total_questions:
                return False
                
            # Set current question
            quiz_data['current_question'] = question_number
            
            # Mark as seen if not already seen
            question_status = quiz_data.get('question_status', {})
            current_status = question_status.get(str(question_number), 'Not Visited')
            
            # If previously "Not Visited", update to "Not Answered"
            if current_status == 'Not Visited':
                question_status[str(question_number)] = 'Not Answered'
                quiz_data['question_status'] = question_status
            
            # Update quiz data
            session['quiz_data'] = quiz_data
            
            return True
        except Exception as e:
            logging.error(f"Error in navigate_to_question: {str(e)}")
            return False

    @staticmethod
    def save_answer(question_id, selected_option):
        """
        Save a user's answer to a question
        
        Args:
            question_id: The ID of the question
            selected_option: The selected answer option
            
        Returns:
            bool: True if answer saved successfully, False otherwise
        """
        if 'quiz_data' not in session:
            return False
            
        quiz_data = session['quiz_data']
        
        # Convert ID to int if it's a string
        if isinstance(question_id, str) and question_id.isdigit():
            question_id = int(question_id)
            
        # Convert ID to position if id_to_position mapping is available
        id_to_position = quiz_data.get('id_to_position', {})
        if question_id in id_to_position:
            question_pos = id_to_position[question_id]
            
            # Save the answer (convert question_id to string for JSON serialization)
            quiz_data['answers'][str(question_id)] = int(selected_option)
            
            # Update status but preserve review status if present
            current_status = quiz_data['question_status'].get(str(question_pos), '')
            if 'Marked for Review' in current_status:
                quiz_data['question_status'][str(question_pos)] = 'Answered Marked for Review'
            else:
                quiz_data['question_status'][str(question_pos)] = 'Answered'
            
            # Also update current_quiz_answers for backup
            current_quiz_answers = session.get('current_quiz_answers', {})
            current_quiz_answers[str(question_id)] = int(selected_option)
            session['current_quiz_answers'] = current_quiz_answers
            
            session['quiz_data'] = quiz_data
            return True
            
        return False

    @staticmethod
    def mark_for_review(question_number):
        """Mark a question for review or toggle its review status"""
        try:
            # Get quiz data from session
            quiz_data = QuizHandler.get_quiz_data()
            if not quiz_data:
                return False
                
            question_status = quiz_data.get('question_status', {})
            
            # Toggle or set the status
            current_status = question_status.get(str(question_number), '')
            
            if 'Marked for Review' in current_status:
                # If already marked for review, remove that status but keep answered/not answered
                if 'Answered' in current_status:
                    question_status[str(question_number)] = 'Answered'
                else:
                    question_status[str(question_number)] = 'Not Answered'
            else:
                # Add review status but preserve answered status
                if 'Answered' in current_status:
                    question_status[str(question_number)] = 'Answered Marked for Review'
                else:
                    question_status[str(question_number)] = 'Not Answered Marked for Review'
                    
            # Update quiz data
            quiz_data['question_status'] = question_status
            session['quiz_data'] = quiz_data
            
            return True
        except Exception as e:
            logging.error(f"Error in mark_for_review: {str(e)}")
            return False

    @staticmethod
    def clear_answer(question_id):
        """
        Clear a user's answer for a question
        
        Args:
            question_id: The ID of the question to clear
            
        Returns:
            bool: True if answer cleared successfully, False otherwise
        """
        if 'quiz_data' not in session:
            return False
            
        quiz_data = session['quiz_data']
        
        # Convert to int if string
        if isinstance(question_id, str) and question_id.isdigit():
            question_id = int(question_id)
            
        # Get question position from ID
        id_to_position = quiz_data.get('id_to_position', {})
        if question_id not in id_to_position:
            return False
            
        question_pos = id_to_position[question_id]
        
        # Remove the answer if it exists
        str_question_id = str(question_id)
        if str_question_id in quiz_data['answers']:
            del quiz_data['answers'][str_question_id]
        
        # Remove from current_quiz_answers too
        if 'current_quiz_answers' in session:
            if str_question_id in session['current_quiz_answers']:
                del session['current_quiz_answers'][str_question_id]
            
        # Update status but preserve review status
        current_status = quiz_data['question_status'].get(str(question_pos), '')
        if 'Marked for Review' in current_status:
            quiz_data['question_status'][str(question_pos)] = 'Not Answered Marked for Review'
        else:
            quiz_data['question_status'][str(question_pos)] = 'Not Answered'
            
        session['quiz_data'] = quiz_data
        return True

    @staticmethod
    def get_quiz_summary():
        """
        Get summary of quiz progress
        
        Returns:
            dict: Summary of quiz progress
        """
        if 'quiz_data' not in session:
            return {
                'answered': 0,
                'marked_for_review': 0,
                'not_answered': 0,
                'not_visited': 0,
                'total': 0,
                'progress_percentage': 0
            }
            
        quiz_data = session['quiz_data']
        
        # Count status types
        answered = 0
        marked_for_review = 0
        not_answered = 0
        not_visited = 0
        
        for status in quiz_data['question_status'].values():
            if 'Not Visited' in status:
                not_visited += 1
            elif 'Marked for Review' in status:
                marked_for_review += 1
                if 'Answered' in status:
                    answered += 1
                else:
                    not_answered += 1
            elif 'Answered' in status:
                answered += 1
            elif 'Not Answered' in status:
                not_answered += 1
        
        total = quiz_data['total_questions']
        
        return {
            'answered': answered,
            'marked_for_review': marked_for_review,
            'not_answered': not_answered,
            'not_visited': not_visited,
            'total': total,
            'progress_percentage': (answered / total) * 100 if total > 0 else 0
        }
    @staticmethod
    def process_quiz_submission(db, models):
        """
        Process the quiz submission and save the score
        
        Args:
            db: Flask SQLAlchemy database instance
            models: Module containing model classes
            
        Returns:
            Score: The created score object or None if error
        """
        if 'quiz_data' not in session:
            return None
            
        quiz_data = session['quiz_data']
        
        # Mark quiz as completed
        quiz_data['is_completed'] = True
        quiz_data['end_time'] = datetime.now().isoformat()
        session['quiz_data'] = quiz_data
        
        # Get answers for processing
        answers = quiz_data['answers']
        quiz_id = quiz_data['quiz_id']
        user_id = quiz_data['user_id']
        
        # Get quiz and questions
        quiz = models.Quiz.query.get(quiz_id)
        if not quiz:
            return None
            
        questions = quiz.questions
        
        # Calculate score
        total_questions = len(questions)
        correct_answers = 0
        wrong_answers = 0
        
        for question in questions:
            q_id_str = str(question.id)
            if q_id_str in answers:
                selected_option = answers[q_id_str]
                if selected_option == question.correct_option:
                    correct_answers += 1
                else:
                    wrong_answers += 1
        
        not_attempted = total_questions - (correct_answers + wrong_answers)
        score_percentage = (correct_answers / total_questions * 100) if total_questions > 0 else 0
        
        # Create score record with comprehensive statistics
        score = models.Score(
            quiz_id=quiz_id,
            user_id=user_id,
            total_scored=score_percentage,
            max_score=100,  # Store as percentage out of 100
            total_questions=total_questions,
            correct_answers=correct_answers,
            wrong_answers=wrong_answers,
            not_attempted=not_attempted,
            time_stamp_of_attempt=datetime.now()
        )
        
        # Save to database
        db.session.add(score)
        db.session.commit()
        
        # Clear quiz data from session
        session.pop('quiz_data', None)
        
        return score
    
    @staticmethod
    def check_if_quiz_in_progress(quiz_id=None):
        """
        Check if there's a quiz already in progress
        
        Args:
            quiz_id: Optional quiz ID to check for specific quiz
            
        Returns:
            bool: True if quiz in progress, False otherwise
        """
        if 'quiz_data' not in session:
            return False
            
        quiz_data = session['quiz_data']
        
        # If quiz is already completed, it's not in progress
        if quiz_data.get('is_completed', False):
            return False
            
        # Check if it's the specific quiz requested
        if quiz_id is not None:
            return quiz_data.get('quiz_id') == quiz_id
            
        # Any quiz in progress
        return True
    
    @staticmethod
    def get_quiz_data():
        """
        Get the current quiz data from the session
        
        Returns:
            dict: Quiz data or None if not found
        """
        return session.get('quiz_data')
    
    @staticmethod
    def get_user_answers():
        """
        Get user answers for the current quiz
        
        Returns:
            dict: Dictionary of question IDs to selected options
        """
        if 'quiz_data' not in session:
            return {}
            
        return session['quiz_data'].get('answers', {})
    
    @staticmethod
    def clear_quiz_session():
        """Clear quiz data from session"""
        if 'quiz_data' in session:
            session.pop('quiz_data', None)
            return True
        return False

    @staticmethod
    def update_question_status(question_id, answered=True):
        """Update the status of a question in the quiz summary"""
        if 'quiz_data' not in session:
            return False
            
        if 'question_status' not in session['quiz_data']:
            session['quiz_data']['question_status'] = {}
        
        # Get the question position from the ID
        id_to_position = session['quiz_data'].get('id_to_position', {})
        question_pos = id_to_position.get(question_id)
        
        if not question_pos:
            return False
            
        question_status = session['quiz_data']['question_status']
        # Set the correct string status instead of boolean
        question_status[str(question_pos)] = 'Answered' if answered else 'Not Answered'
        session['quiz_data']['question_status'] = question_status
        
        # Also update the answers dictionary
        if 'current_quiz_answers' in session:
            answers = session['current_quiz_answers']
            # Make sure these are also accessible in quiz_data.answers
            session['quiz_data']['answers'] = answers
        
        return True