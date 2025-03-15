import sqlite3
import os
import sys

def update_score_table():
    """Add missing columns to the score table"""
    # Find the SQLite database - common locations
    db_locations = [
        os.path.join('instance', 'quizmaster.db'),  # Flask default location
        os.path.join('instance', 'app.db'),
        'quizmaster.db',
        'app.db'
    ]
    
    db_path = None
    for location in db_locations:
        if os.path.exists(location):
            db_path = location
            break
    
    if not db_path:
        print("Database not found. Please specify the path to your SQLite database.")
        return False
    
    print(f"Using database at: {db_path}")
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if the score table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='score'")
    if not cursor.fetchone():
        print("Score table doesn't exist. Please check your database setup.")
        conn.close()
        return False
    
    # Get current columns in the score table
    cursor.execute('PRAGMA table_info(score)')
    columns = [column[1] for column in cursor.fetchall()]
    print(f"Existing columns: {columns}")
    
    # Define the columns we need to add
    needed_columns = {
        'max_score': 'INTEGER NOT NULL DEFAULT 100',
        'total_questions': 'INTEGER NOT NULL DEFAULT 0',
        'correct_answers': 'INTEGER NOT NULL DEFAULT 0',
        'wrong_answers': 'INTEGER NOT NULL DEFAULT 0',
        'not_attempted': 'INTEGER NOT NULL DEFAULT 0'
    }
    
    # Add missing columns
    for column_name, column_def in needed_columns.items():
        if column_name not in columns:
            print(f"Adding missing column: {column_name}")
            try:
                cursor.execute(f"ALTER TABLE score ADD COLUMN {column_name} {column_def}")
            except sqlite3.Error as e:
                print(f"Error adding column {column_name}: {e}")
                conn.rollback()
                conn.close()
                return False
    
    # Commit changes and close connection
    conn.commit()
    conn.close()
    
    print("Database update completed successfully!")
    return True

if __name__ == "__main__":
    if update_score_table():
        print("Database schema updated successfully!")
        sys.exit(0)
    else:
        print("Failed to update database schema.")
        sys.exit(1)
