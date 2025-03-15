
import sys
import os
from app import app, db
from models import Question

def migrate_database():
    """
    Script to migrate the database schema for the Question model
    """
    print("Starting database migration...")
    
    try:
        with app.app_context():
            print("Altering table 'question' to change column types...")
            # SQLite doesn't support ALTER TABLE to change column types directly, so we need to create a new table
            db.engine.execute("PRAGMA foreign_keys=OFF;")
            
            # Create a new temporary table with the new schema
            db.engine.execute("""
            CREATE TABLE question_new (
                id INTEGER PRIMARY KEY,
                quiz_id INTEGER NOT NULL,
                question_statement TEXT NOT NULL,
                question_image VARCHAR(255),
                option_1 TEXT NOT NULL,
                option_2 TEXT NOT NULL,
                option_3 TEXT NOT NULL,
                option_4 TEXT NOT NULL,
                correct_option INTEGER NOT NULL,
                FOREIGN KEY(quiz_id) REFERENCES quiz(id)
            );
            """)
            
            # Copy data from the old table to the new one
            db.engine.execute("""
            INSERT INTO question_new 
            SELECT id, quiz_id, question_statement, question_image, option_1, option_2, option_3, option_4, correct_option 
            FROM question;
            """)
            
            # Replace the old table with the new one
            db.engine.execute("DROP TABLE question;")
            db.engine.execute("ALTER TABLE question_new RENAME TO question;")
            
            # Re-enable foreign keys
            db.engine.execute("PRAGMA foreign_keys=ON;")
            
            print("Migration completed successfully!")
            
    except Exception as e:
        print(f"Error during migration: {str(e)}")
        return False
    
    return True

if __name__ == "__main__":
    migrate_database()
