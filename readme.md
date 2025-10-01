import os
from pathlib import Path

class Config:
    """Application configuration class"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'yes']
    
    # Database settings
    DATABASE_DIR = os.environ.get('DATABASE_DIR') or os.path.join(os.getcwd(), 'data')
    DATABASE_FILE = os.path.join(DATABASE_DIR, 'tenable_dashboard.db')
    
    # CRITICAL: Use absolute path for SQLite URI on Windows
    DATABASE_FILE_ABSOLUTE = os.path.abspath(DATABASE_FILE)
    DATABASE_FILE_NORMALIZED = DATABASE_FILE_ABSOLUTE.replace('\\', '/')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_FILE_NORMALIZED}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Tenable API credentials
    TENABLE_ACCESS_KEY = os.environ.get('TENABLE_ACCESS_KEY')
    TENABLE_SECRET_KEY = os.environ.get('TENABLE_SECRET_KEY')
    
    # Ermetic API configuration (for Tenable customers using Ermetic)
    ERMETIC_API_URL = os.environ.get('ERMETIC_API_URL')
    ERMETIC_API_TOKEN = os.environ.get('ERMETIC_API_TOKEN')
    
    # Optional Tenable services
    TENABLE_CS_API_KEY = os.environ.get('TENABLE_CS_API_KEY')  # Container Security
    TENABLE_CS_URL = os.environ.get('TENABLE_CS_URL', 'https://cloud.tenable.com')
    
    # Application settings
    DEFAULT_DAYS_SINCE = int(os.environ.get('DEFAULT_DAYS_SINCE', '30'))
    
    # GRC mapping file path
    GRC_JSON_PATH = os.environ.get('GRC_JSON_PATH') or os.path.join(os.getcwd(), 'data', 'grc_mappings.json')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()
    LOG_FILE = os.environ.get('LOG_FILE') or os.path.join(DATABASE_DIR, 'tenable_dashboard.log')
    
    # Server settings
    HOST = os.environ.get('HOST', '127.0.0.1')  # Localhost only for security
    PORT = int(os.environ.get('PORT', 5000))
    
    @staticmethod
    def init_directories():
        """Create necessary directories if they don't exist"""
        try:
            # Ensure database directory exists using absolute path
            db_dir_abs = os.path.abspath(Config.DATABASE_DIR)
            Path(db_dir_abs).mkdir(parents=True, exist_ok=True)
            print(f"✅ Database directory created/verified: {db_dir_abs}")
            
            # Ensure we can write to the database file location
            db_file_abs = os.path.abspath(Config.DATABASE_FILE)
            try:
                # Test write access by touching the file
                Path(db_file_abs).touch(exist_ok=True)
                print(f"✅ Database file access verified: {db_file_abs}")
            except Exception as e:
                print(f"❌ Cannot access database file location: {e}")
                raise
            
            # Create logs directory if log file is in subdirectory
            log_dir = os.path.dirname(Config.LOG_FILE)
            if log_dir and log_dir != Config.DATABASE_DIR:
                log_dir_abs = os.path.abspath(log_dir)
                Path(log_dir_abs).mkdir(parents=True, exist_ok=True)
                print(f"✅ Log directory created/verified: {log_dir_abs}")
                
        except Exception as e:
            print(f"❌ Error creating directories: {e}")
            raise
    
    @staticmethod
    def validate_config():
        """Validate required configuration"""
        print("Validating configuration...")
        
        # Check for either Tenable.io or Ermetic credentials
        has_tenable_creds = Config.TENABLE_ACCESS_KEY and Config.TENABLE_SECRET_KEY
        has_ermetic_creds = Config.ERMETIC_API_URL and Config.ERMETIC_API_TOKEN
        
        if has_tenable_creds:
            print("✅ Tenable.io API credentials found")
        elif has_ermetic_creds:
            print("✅ Ermetic API credentials found")
        else:
            print("❌ Neither Tenable.io nor Ermetic API credentials found")
            print("Required: Either TENABLE_ACCESS_KEY + TENABLE_SECRET_KEY")
            print("      OR: ERMETIC_API_URL + ERMETIC_API_TOKEN")
            return False
        
        # Check optional credentials
        if Config.TENABLE_CS_API_KEY:
            print("✅ Container Security API key found")
        else:
            print("ℹ️  Container Security API key not found (optional)")
        
        # Validate paths
        try:
            Config.init_directories()
            print(f"✅ Database directory: {Config.DATABASE_DIR}")
            print(f"✅ GRC mappings path: {Config.GRC_JSON_PATH}")
        except Exception as e:
            print(f"❌ Error creating directories: {e}")
            return False
        
        return True

class FeatureFlags:
    """Feature flags to enable/disable functionality"""
    
    ENABLE_ATTACK_PATH_ANALYSIS = os.environ.get('ENABLE_ATTACK_PATH_ANALYSIS', 'true').lower() in ['true', '1', 'yes']
    ENABLE_WAS_FINDINGS = os.environ.get('ENABLE_WAS_FINDINGS', 'true').lower() in ['true', '1', 'yes']
    ENABLE_GRC_MAPPING = os.environ.get('ENABLE_GRC_MAPPING', 'true').lower() in ['true', '1', 'yes']
    ENABLE_CLOUD_METADATA = os.environ.get('ENABLE_CLOUD_METADATA', 'true').lower() in ['true', '1', 'yes']
    ENABLE_EXPOSURE_SCORING = os.environ.get('ENABLE_EXPOSURE_SCORING', 'true').lower() in ['true', '1', 'yes']
    ENABLE_CONTAINER_SECURITY = os.environ.get('ENABLE_CONTAINER_SECURITY', 'false').lower() in ['true', '1', 'yes']
    
    @classmethod
    def get_enabled_features(cls):
        """Return list of enabled features"""
        features = []
        if cls.ENABLE_ATTACK_PATH_ANALYSIS:
            features.append("Attack Path Analysis")
        if cls.ENABLE_WAS_FINDINGS:
            features.append("WAS Findings")
        if cls.ENABLE_GRC_MAPPING:
            features.append("GRC Compliance Mapping")
        if cls.ENABLE_CLOUD_METADATA:
            features.append("Cloud Metadata")
        if cls.ENABLE_EXPOSURE_SCORING:
            features.append("Exposure Scoring")
        if cls.ENABLE_CONTAINER_SECURITY:
            features.append("Container Security")
        return features
    
    @classmethod
    def print_feature_status(cls):
        """Print current feature flag status"""
        print("\nFeature Flags Status:")
        print(f"  Attack Path Analysis: {'✅' if cls.ENABLE_ATTACK_PATH_ANALYSIS else '❌'}")
        print(f"  WAS Findings: {'✅' if cls.ENABLE_WAS_FINDINGS else '❌'}")
        print(f"  GRC Mapping: {'✅' if cls.ENABLE_GRC_MAPPING else '❌'}")
        print(f"  Cloud Metadata: {'✅' if cls.ENABLE_CLOUD_METADATA else '❌'}")
        print(f"  Exposure Scoring: {'✅' if cls.ENABLE_EXPOSURE_SCORING else '❌'}")
        print(f"  Container Security: {'✅' if cls.ENABLE_CONTAINER_SECURITY else '❌'}")