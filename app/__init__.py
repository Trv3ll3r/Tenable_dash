import logging
from flask import Flask
from config import Config, FeatureFlags

def create_app(config_class=Config):
    """
    Application factory pattern for Flask app creation
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize directories and validate configuration
    print("🚀 Starting Tenable One Enhanced Dashboard...")
    config_class.init_directories()
    
    if not config_class.validate_config():
        raise RuntimeError("❌ Configuration validation failed. Check your .env file.")
    
    # Print feature status
    FeatureFlags.print_feature_status()
    
    # Setup logging
    setup_logging(app)
    app.logger.info("Flask application starting up...")
    
    # Initialize database
    from app.database import init_db
    init_db(app)
    
    # Register blueprints
    from app.views.main import main_bp
    from app.views.export import export_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(export_bp, url_prefix='/export')
    
    # Print startup information
    print(f"✅ Database: {app.config['DATABASE_FILE']}")
    print(f"✅ Enabled features: {', '.join(FeatureFlags.get_enabled_features())}")
    print(f"✅ Server will start on {app.config['HOST']}:{app.config['PORT']}")
    
    return app

def setup_logging(app):
    """Configure application logging"""
    log_level = getattr(logging, app.config['LOG_LEVEL'], logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(app.config['LOG_FILE'])
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    
    # Configure app logger
    app.logger.setLevel(log_level)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    
    # Suppress some noisy loggers in development
    if app.config['DEBUG']:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('werkzeug').setLevel(logging.WARNING)