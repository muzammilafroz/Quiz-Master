from app import app, db
import sys

def reset_database():
    """Reset the database by dropping all tables and recreating them"""
    try:
        with app.app_context():
            # Drop all tables
            db.drop_all()
            print("Dropped all tables from the database")
            
            # Create all tables according to current models
            db.create_all()
            print("Created all tables according to current models")
            
            # Optional: Add any initial seed data here if needed
            
            print("Database reset completed successfully!")
            return True
    except Exception as e:
        print(f"Error resetting database: {e}")
        return False

if __name__ == "__main__":
    if reset_database():
        print("Database has been reset successfully!")
        sys.exit(0)
    else:
        print("Failed to reset database.")
        sys.exit(1)
