"""
Database migration to add ticket_created column to VulnerabilityFinding model
Run this after updating your models

Usage:
    python add_ticket_tracking_migration.py
"""

from sqlalchemy import create_engine
from sqlalchemy.sql import text
import os
from pathlib import Path

def run_migration():
    """Add ticket_created column to vulnerability_findings table"""
    
    # Get database directory from environment or use default
    database_dir = os.environ.get('DATABASE_DIR', './data')
    
    # Construct the database path
    db_path = Path(database_dir) / 'tenable_dashboard.db'
    
    # Check if database exists
    if not db_path.exists():
        print(f"✗ Database not found at: {db_path}")
        print(f"  Please ensure your database exists before running migration.")
        return False
    
    database_url = f'sqlite:///{db_path}'
    print(f"Using database: {db_path}")
    
    engine = create_engine(database_url)
    
    try:
        with engine.connect() as conn:
            # Check if column already exists
            print("Checking if 'ticket_created' column exists...")
            result = conn.execute(text("PRAGMA table_info(vulnerability_findings)"))
            columns = [row[1] for row in result]
            
            if 'ticket_created' in columns:
                print("✓ Column 'ticket_created' already exists. Skipping migration.")
                return True
            
            # Add the column
            print("Adding 'ticket_created' column to vulnerability_findings table...")
            
            conn.execute(text("""
                ALTER TABLE vulnerability_findings 
                ADD COLUMN ticket_created BOOLEAN DEFAULT 0
            """))
            conn.commit()
            print("✓ Successfully added 'ticket_created' column")
            
            # Initialize all existing records to False
            print("Initializing existing records to False...")
            result = conn.execute(text("""
                UPDATE vulnerability_findings 
                SET ticket_created = 0 
                WHERE ticket_created IS NULL
            """))
            conn.commit()
            
            # Get count of updated records
            result = conn.execute(text("SELECT COUNT(*) FROM vulnerability_findings"))
            count = result.scalar()
            print(f"✓ Initialized {count} existing records")
            print("✓ Migration completed successfully!")
            
            return True
            
    except Exception as e:
        print(f"✗ Error during migration: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Tenable Dashboard - Add Ticket Tracking Migration")
    print("=" * 60)
    print()
    
    success = run_migration()
    
    if success:
        print()
        print("=" * 60)
        print("Migration completed successfully!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. ✓ The ticket_created column has been added to your database")
        print("2. ✓ Your models.py file should already have the field")
        print("3. → Restart your application: python run.py")
        print("4. → The ticket tracking feature is now ready to use!")
        print()
    else:
        print()
        print("=" * 60)
        print("Migration failed!")
        print("=" * 60)
        print()
        print("Please check the error message above.")
        print("If the database doesn't exist yet, run: python run.py")
        print("to create it, then run this migration again.")