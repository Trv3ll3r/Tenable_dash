"""
Database Deduplication Service
Removes duplicate asset-finding relationships while preserving the most recent data
"""

import logging
from datetime import datetime
from sqlalchemy import func

logger = logging.getLogger(__name__)


class DeduplicationService:
    """Service to handle database deduplication operations"""
    
    def __init__(self, db):
        """
        Initialize deduplication service
        
        Args:
            db: Flask-SQLAlchemy database instance
        """
        self.db = db
        self.stats = {
            'asset_findings_before': 0,
            'asset_findings_after': 0,
            'duplicates_removed': 0,
            'assets_processed': 0,
            'findings_processed': 0
        }
    
    def deduplicate_asset_findings(self) -> dict:
        """
        Remove duplicate AssetFinding entries, keeping the most recent one
        Returns statistics about the deduplication process
        """
        # Import here to avoid circular imports
        from app.models import VulnerabilityFinding
        
        logger.info("Starting AssetFinding deduplication...")
        
        # Get initial count - using VulnerabilityFinding as that's your model
        self.stats['asset_findings_before'] = self.db.session.query(VulnerabilityFinding).count()
        
        # Find all duplicate combinations (asset_id + plugin_id pairs that appear more than once)
        # Group by hostname and plugin_id since those identify unique vulnerability instances
        duplicates = self.db.session.query(
            VulnerabilityFinding.asset_hostname,
            VulnerabilityFinding.plugin_id,
            func.count(VulnerabilityFinding.id).label('count')
        ).group_by(
            VulnerabilityFinding.asset_hostname,
            VulnerabilityFinding.plugin_id
        ).having(
            func.count(VulnerabilityFinding.id) > 1
        ).all()
        
        logger.info(f"Found {len(duplicates)} duplicate asset-finding pairs")
        
        removed_count = 0
        
        # Process each duplicate group
        for asset_hostname, plugin_id, count in duplicates:
            # Get all entries for this combination, ordered by last_found (most recent first)
            entries = self.db.session.query(VulnerabilityFinding).filter(
                VulnerabilityFinding.asset_hostname == asset_hostname,
                VulnerabilityFinding.plugin_id == plugin_id
            ).order_by(VulnerabilityFinding.last_found.desc()).all()
            
            # Keep the first (most recent), delete the rest
            entries_to_delete = entries[1:]
            
            for entry in entries_to_delete:
                logger.debug(f"Removing duplicate: Asset {asset_hostname}, Plugin {plugin_id}, "
                           f"Last found: {entry.last_found}")
                self.db.session.delete(entry)
                removed_count += 1
        
        # Commit the changes
        try:
            self.db.session.commit()
            self.stats['duplicates_removed'] = removed_count
            self.stats['asset_findings_after'] = self.db.session.query(VulnerabilityFinding).count()
            logger.info(f"Successfully removed {removed_count} duplicate entries")
        except Exception as e:
            self.db.session.rollback()
            logger.error(f"Error during deduplication commit: {e}")
            raise
        
        return self.stats
    
    def deduplicate_assets(self) -> int:
        """
        Remove duplicate assets based on hostname (since we don't have tenable_uuid in VulnerabilityFinding)
        Returns count of duplicates removed
        """
        logger.info("Skipping asset deduplication - not applicable to VulnerabilityFinding model")
        self.stats['assets_processed'] = 0
        return 0
    
    def deduplicate_findings(self) -> int:
        """
        Remove duplicate findings based on plugin_id (not needed for VulnerabilityFinding model)
        Returns count of duplicates removed
        """
        logger.info("Skipping finding deduplication - not applicable to VulnerabilityFinding model")
        self.stats['findings_processed'] = 0
        return 0
    
    def run_full_deduplication(self) -> dict:
        """
        Run complete deduplication process
        Returns comprehensive statistics
        """
        logger.info("="*60)
        logger.info("Starting Full Database Deduplication")
        logger.info("="*60)
        
        start_time = datetime.now()
        
        try:
            # Step 1: Deduplicate base entities first (Assets and Findings)
            self.deduplicate_assets()
            self.deduplicate_findings()
            
            # Step 2: Deduplicate the relationship table
            self.deduplicate_asset_findings()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            self.stats['duration_seconds'] = duration
            self.stats['timestamp'] = end_time.isoformat()
            
            logger.info("="*60)
            logger.info("Deduplication Complete")
            logger.info(f"Duration: {duration:.2f} seconds")
            logger.info(f"AssetFindings Before: {self.stats['asset_findings_before']}")
            logger.info(f"AssetFindings After: {self.stats['asset_findings_after']}")
            logger.info(f"Duplicates Removed: {self.stats['duplicates_removed']}")
            logger.info(f"Duplicate Assets Removed: {self.stats['assets_processed']}")
            logger.info(f"Duplicate Findings Removed: {self.stats['findings_processed']}")
            logger.info("="*60)
            
            return self.stats
            
        except Exception as e:
            logger.error(f"Error during deduplication: {e}")
            raise


def run_deduplication(db_path: str = None):
    """
    Standalone function to run deduplication
    Can be called from other scripts or run directly
    """
    from app import create_app
    from app.database import db
    
    # Create app context to initialize database
    app = create_app()
    
    with app.app_context():
        try:
            service = DeduplicationService(db)
            stats = service.run_full_deduplication()
            return stats
        except Exception as e:
            logger.error(f"Error in run_deduplication: {e}")
            raise


if __name__ == "__main__":
    # Configure logging for standalone execution
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("\n" + "="*60)
    print("Tenable Dashboard - Database Deduplication Utility")
    print("="*60 + "\n")
    
    try:
        stats = run_deduplication()
        
        print("\n" + "="*60)
        print("DEDUPLICATION SUMMARY")
        print("="*60)
        print(f"Total Duplicate AssetFindings Removed: {stats['duplicates_removed']}")
        print(f"Total Duplicate Assets Removed: {stats['assets_processed']}")
        print(f"Total Duplicate Findings Removed: {stats['findings_processed']}")
        print(f"Database Size Reduction: {stats['asset_findings_before'] - stats['asset_findings_after']} records")
        print(f"Completion Time: {stats['duration_seconds']:.2f} seconds")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ ERROR: Deduplication failed: {e}\n")
        raise