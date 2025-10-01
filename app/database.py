import os
from flask_sqlalchemy import SQLAlchemy

# Create SQLAlchemy instance
db = SQLAlchemy()

def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    
    with app.app_context():
        try:
            # Get the database file path and ensure it's absolute
            db_file = app.config['DATABASE_FILE']
            db_file_abs = os.path.abspath(db_file)
            db_dir = os.path.dirname(db_file_abs)
            
            print(f"📁 Database directory: {db_dir}")
            print(f"📄 Database file: {db_file_abs}")
            print(f"🔗 Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
            
            # Ensure directory exists
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                print(f"📁 Created database directory: {db_dir}")
            
            # Test if we can create the database file
            try:
                # Try to create/touch the database file
                with open(db_file_abs, 'a'):
                    pass
                print(f"✅ Database file accessible: {db_file_abs}")
            except Exception as file_error:
                print(f"❌ Cannot access database file: {file_error}")
                raise
            
            # Import all models to ensure they're registered
            from app.models import (
                VulnerabilityFinding, 
                AttackPathFinding, 
                WASFinding, 
                ComplianceRequirement, 
                PluginComplianceMapping,
                ContainerSecurityFinding
            )
            
            # Create all tables
            print("📊 Creating database tables...")
            db.create_all()
            print(f"✅ Database tables created successfully")
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            import traceback
            traceback.print_exc()
            raise

def get_db_session():
    """Get database session for use outside Flask context"""
    return db.session