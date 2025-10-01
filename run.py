#!/usr/bin/env python3
"""
Tenable One Enhanced Dashboard - Application Entry Point
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

def load_environment():
    """Load environment variables with proper error handling"""
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    env_file = script_dir / '.env'
    
    print(f"🔧 Looking for .env file at: {env_file}")
    
    if env_file.exists():
        print(f"✅ Loading environment from: {env_file}")
        load_dotenv(env_file)
        
        # Verify critical variables are loaded
        tenable_key = os.getenv('TENABLE_ACCESS_KEY')
        tenable_secret = os.getenv('TENABLE_SECRET_KEY')
        
        if tenable_key and tenable_secret:
            # Mask keys for security
            key_masked = f"{tenable_key[:4]}...{tenable_key[-4:]}" if len(tenable_key) > 8 else "****"
            secret_masked = f"{tenable_secret[:4]}...{tenable_secret[-4:]}" if len(tenable_secret) > 8 else "****"
            print(f"✅ Tenable credentials loaded (Access: {key_masked}, Secret: {secret_masked})")
            return True
        else:
            print("❌ Tenable API credentials not found in .env file")
            print("\nRequired environment variables:")
            print("  TENABLE_ACCESS_KEY=your_access_key")
            print("  TENABLE_SECRET_KEY=your_secret_key")
            return False
    else:
        print("❌ .env file not found")
        print(f"Please create a .env file at: {env_file}")
        print("\nRequired content:")
        print("TENABLE_ACCESS_KEY=your_access_key")
        print("TENABLE_SECRET_KEY=your_secret_key")
        return False

def run_initial_data_ingestion(app):
    """Run initial data ingestion if requested"""
    if '--skip-ingestion' in sys.argv:
        print("⏭️  Skipping initial data ingestion (--skip-ingestion flag provided)")
        return
    
    try:
        with app.app_context():
            from app.services.ingestion import run_full_ingestion
            print("\n📥 Starting initial data ingestion...")
            run_full_ingestion()
            print("✅ Initial data ingestion completed")
    except Exception as e:
        app.logger.error(f"Initial data ingestion failed: {e}")
        print(f"❌ Initial data ingestion failed: {e}")
        print("🔄 Application will continue - you can manually trigger ingestion from the web interface")

def main():
    """Main application entry point"""
    print("=" * 60)
    print("🛡️  TENABLE ONE ENHANCED DASHBOARD")
    print("=" * 60)
    
    try:
        # Load environment variables
        if not load_environment():
            print("\n❌ Failed to load required environment variables")
            return 1
        
        # Import and create Flask app
        from app import create_app
        from config import Config
        
        print("\n🏗️  Creating Flask application...")
        app = create_app(Config)
        
        # Run initial data ingestion
        run_initial_data_ingestion(app)
        
        # Start the web server
        print("\n🌐 Starting web server...")
        print(f"📊 Dashboard will be available at: http://{app.config['HOST']}:{app.config['PORT']}")
        print("🔒 Server restricted to localhost for security")
        print("\n⚡ Press Ctrl+C to stop the server")
        print("=" * 60)
        
        app.run(
            host=app.config['HOST'],
            port=app.config['PORT'],
            debug=app.config['DEBUG']
        )
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n👋 Application stopped by user")
        return 0
    except Exception as e:
        print(f"\n💥 Fatal error starting application: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    exit(main())