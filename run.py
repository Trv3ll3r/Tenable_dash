#!/usr/bin/env python3
"""
Tenable One Enhanced Dashboard - Application Entry Point
"""

import os
import sys
import json
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Deduplication tracking file
DEDUP_TRACKER_FILE = 'data/last_deduplication.json'


class DeduplicationScheduler:
    """Manages periodic deduplication tasks"""
    
    def __init__(self, app, interval_days=7):
        self.app = app
        self.interval_days = interval_days
        self.running = False
        self.thread = None
        
    def should_run_deduplication(self) -> bool:
        """Check if deduplication should run based on last run time"""
        tracker_path = Path(DEDUP_TRACKER_FILE)
        
        if not tracker_path.exists():
            self.app.logger.info("No deduplication history found - will run deduplication")
            return True
        
        try:
            with open(tracker_path, 'r') as f:
                data = json.load(f)
                last_run = datetime.fromisoformat(data['last_run'])
                next_run = last_run + timedelta(days=self.interval_days)
                
                if datetime.now() >= next_run:
                    self.app.logger.info(f"Deduplication scheduled - last run was {last_run.strftime('%Y-%m-%d')}")
                    return True
                else:
                    self.app.logger.info(f"Deduplication not needed - next run scheduled for {next_run.strftime('%Y-%m-%d')}")
                    return False
                    
        except Exception as e:
            self.app.logger.warning(f"Error reading deduplication tracker: {e} - will run deduplication")
            return True
    
    def update_last_run(self, stats: dict = None):
        """Update the last deduplication run timestamp"""
        tracker_path = Path(DEDUP_TRACKER_FILE)
        tracker_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            'last_run': datetime.now().isoformat(),
            'interval_days': self.interval_days,
            'stats': stats or {}
        }
        
        try:
            with open(tracker_path, 'w') as f:
                json.dump(data, f, indent=2)
            self.app.logger.info(f"Updated deduplication tracker")
        except Exception as e:
            self.app.logger.error(f"Error updating deduplication tracker: {e}")
    
    def run_deduplication_task(self):
        """Execute deduplication task"""
        print("\n" + "="*60)
        print("🔄 Starting Scheduled Database Deduplication")
        print("="*60)
        
        try:
            from database_deduplication import DeduplicationService
            from app.database import db
            
            with self.app.app_context():
                service = DeduplicationService(db)
                stats = service.run_full_deduplication()
                self.update_last_run(stats)
                
                print(f"✅ Deduplication completed successfully")
                print(f"📊 Removed {stats.get('duplicates_removed', 0)} duplicate asset-finding relationships")
                print("="*60 + "\n")
                
        except Exception as e:
            self.app.logger.error(f"Error during scheduled deduplication: {e}")
            print(f"❌ Deduplication failed: {e}")
            import traceback
            traceback.print_exc()
    
    def check_and_run(self):
        """Check if deduplication should run and execute if needed"""
        if self.should_run_deduplication():
            self.run_deduplication_task()
    
    def background_scheduler(self):
        """Background thread that checks daily for deduplication needs"""
        self.app.logger.info(f"Deduplication scheduler started - checking every 24 hours")
        
        while self.running:
            try:
                self.check_and_run()
                # Sleep for 24 hours
                time.sleep(86400)
            except Exception as e:
                self.app.logger.error(f"Error in deduplication scheduler: {e}")
                time.sleep(3600)  # Wait an hour before retrying
    
    def start(self):
        """Start the background scheduler"""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.background_scheduler, daemon=True)
            self.thread.start()
            print("🔄 Background deduplication scheduler started (checks every 24 hours)")
    
    def stop(self):
        """Stop the background scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)


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


def run_force_deduplication(app):
    """Force run deduplication immediately"""
    print("\n" + "="*60)
    print("🔄 FORCE DEDUPLICATION - Running immediately")
    print("="*60)
    
    try:
        from database_deduplication import run_deduplication
        
        with app.app_context():
            stats = run_deduplication()
            
            # Update tracker
            scheduler = DeduplicationScheduler(app)
            scheduler.update_last_run(stats)
            
            print("="*60)
            print("✅ Force Deduplication Complete")
            print(f"📊 Statistics:")
            print(f"   - Duplicate AssetFindings Removed: {stats.get('duplicates_removed', 0)}")
            print(f"   - Duplicate Assets Removed: {stats.get('assets_processed', 0)}")
            print(f"   - Duplicate Findings Removed: {stats.get('findings_processed', 0)}")
            print(f"   - Duration: {stats.get('duration_seconds', 0):.2f} seconds")
            print("="*60 + "\n")
            
            return 0
            
    except Exception as e:
        print(f"❌ Error during force deduplication: {e}")
        import traceback
        traceback.print_exc()
        return 1


def parse_dedup_interval():
    """Parse --dedup-interval argument from command line"""
    for i, arg in enumerate(sys.argv):
        if arg == '--dedup-interval' and i + 1 < len(sys.argv):
            try:
                return int(sys.argv[i + 1])
            except ValueError:
                print(f"⚠️  Invalid --dedup-interval value, using default (7 days)")
                return 7
    return 7  # Default interval


def main():
    """Main application entry point"""
    print("=" * 60)
    print("🛡️  TENABLE ONE ENHANCED DASHBOARD")
    print("=" * 60)
    
    try:
        # Check for force deduplication flag
        if '--force-dedup' in sys.argv:
            # Load environment for database access
            if not load_environment():
                print("\n❌ Failed to load required environment variables")
                return 1
            
            from app import create_app
            from config import Config
            
            app = create_app(Config)
            return run_force_deduplication(app)
        
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
        
        # Initialize and start deduplication scheduler
        dedup_interval = parse_dedup_interval()
        scheduler = DeduplicationScheduler(app, interval_days=dedup_interval)
        
        # Check if deduplication should run on startup
        print(f"\n🔍 Checking deduplication schedule (interval: {dedup_interval} days)...")
        scheduler.check_and_run()
        
        # Start background scheduler
        scheduler.start()
        
        # Start the web server
        print("\n🌐 Starting web server...")
        print(f"📊 Dashboard will be available at: http://{app.config['HOST']}:{app.config['PORT']}")
        print("🔒 Server restricted to localhost for security")
        print("⚡ Press Ctrl+C to stop the server")
        print("=" * 60)
        
        try:
            app.run(
                host=app.config['HOST'],
                port=app.config['PORT'],
                debug=app.config['DEBUG']
            )
        finally:
            # Cleanup on shutdown
            scheduler.stop()
            print("\n🛑 Deduplication scheduler stopped")
        
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