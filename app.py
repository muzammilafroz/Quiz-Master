import os
import logging
import sqlite3
from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from sqlalchemy.orm import DeclarativeBase
from extensions import db

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Initialize Flask app
class Base(DeclarativeBase):
    pass

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "my-secret-key")

# Database configuration
database_url = os.environ.get("DATABASE_URL", "sqlite:///quizmaster.db")
app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Set engine options based on database type
if database_url.startswith('sqlite'):
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,  # Test connections before using them
        "pool_recycle": 300,    # Recycle connections after 5 minutes
        "max_overflow": 15,     # Allow 15 connections beyond pool_size
    }

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'csv', 'xlsx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'
db.init_app(app)

# Import routes after initializing app and extensions
from routes import *

# Register API blueprint
from api import api_bp
app.register_blueprint(api_bp)

# Add error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# Initialize database
with app.app_context():
    # First check if the database exists
    db_exists = os.path.exists(database_url.replace('sqlite:///', ''))
    
    # If database exists, perform manual migration
    if db_exists:
        try:
            logging.info("Checking for created_at column in user table...")
            # Connect to the SQLite database directly
            conn = sqlite3.connect(database_url.replace('sqlite:///', ''))
            cursor = conn.cursor()
            
            # Check if created_at column exists
            cursor.execute("PRAGMA table_info(user)")
            columns = [info[1] for info in cursor.fetchall()]
            
            # If created_at column doesn't exist, add it
            if 'created_at' not in columns:
                logging.info("Adding created_at column to user table...")
                cursor.execute("ALTER TABLE user ADD COLUMN created_at TIMESTAMP")
                conn.commit()
                logging.info("Column created_at added successfully to user table")
            
            # Close connection
            conn.close()
        except Exception as e:
            logging.error(f"Error during manual database migration: {e}")
    
    # Now create all tables (this won't affect existing tables)
    db.create_all()
    
    from models import Admin, User
    from werkzeug.security import generate_password_hash
    from datetime import datetime
    import pytz
    
    # Create admin if not exists
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(
            username='admin',
            password=generate_password_hash('admin@123')
        )
        db.session.add(admin)
        db.session.commit()
        logging.info("Admin account created")

    # Update existing users that don't have created_at field set
    try:
        # Get IST timezone
        ist_tz = pytz.timezone('Asia/Kolkata')
        current_time = datetime.utcnow().replace(tzinfo=pytz.UTC).astimezone(ist_tz)
        
        # Update users without created_at timestamp
        users_without_created_at = User.query.filter_by(created_at=None).all()
        if users_without_created_at:
            for user in users_without_created_at:
                user.created_at = current_time
            db.session.commit()
            logging.info(f"Updated created_at for {len(users_without_created_at)} existing users")
    except Exception as e:
        logging.error(f"Error updating user created_at dates: {str(e)}")