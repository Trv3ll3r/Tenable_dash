"""
Data Ingestion Service - Orchestrates data collection from Tenable APIs
"""

import os
import json
from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.tenable_client import get_tenable_client
from app.data_processor import VulnerabilityProcessor, AttackPathProcessor, WASProcessor
from app.database import db
from app.models import ComplianceRequirement, PluginComplianceMapping
from config import FeatureFlags


def run_full_ingestion(days_since=None, test_limit=None):
    """
    Run complete data ingestion from all Tenable sources
    
    Args:
        days_since: Number of days to look back (default from config)
        test_limit: Limit number of findings for testing
    """
    if days_since is None:
        days_since = current_app.config.get('DEFAULT_DAYS_SINCE', 30)
    
    current_app.logger.info(f"Starting full data ingestion for last {days_since} days")
    print(f"\n📥 STARTING FULL DATA INGESTION")
    print(f"📅 Time range: Last {days_since} days")
    if test_limit:
        print(f"🧪 Test mode: Limited to {test_limit} findings per source")
    print("=" * 50)
    
    try:
        # Get Tenable client
        tenable_client = get_tenable_client()
        
        # Ingest vulnerability findings
        vm_count = ingest_vulnerability_findings(tenable_client, days_since, test_limit)
        
        # Ingest WAS findings
        was_count = ingest_was_findings(tenable_client, days_since)
        
        # Ingest attack path findings
        attack_path_count = ingest_attack_path_findings(tenable_client)
        
        # Ingest GRC data
        grc_count = ingest_grc_mappings()
        
        # Summary
        print("\n" + "=" * 50)
        print("✅ DATA INGESTION COMPLETED")
        print(f"📊 Vulnerability Findings: {vm_count}")
        print(f"🌐 WAS Findings: {was_count}")
        print(f"🎯 Attack Paths: {attack_path_count}")
        print(f"📋 GRC Mappings: {grc_count}")
        print("=" * 50)
        
        current_app.logger.info(f"Full ingestion complete: VM={vm_count}, WAS={was_count}, Paths={attack_path_count}, GRC={grc_count}")
        
        return {
            'vulnerability_findings': vm_count,
            'was_findings': was_count, 
            'attack_paths': attack_path_count,
            'grc_mappings': grc_count
        }
        
    except Exception as e:
        current_app.logger.error(f"Full ingestion failed: {e}")
        print(f"❌ Full ingestion failed: {e}")
        raise


def ingest_vulnerability_findings(tenable_client, days_since=30, limit=None):
    """Ingest VM vulnerability findings"""
    current_app.logger.info("Starting vulnerability findings ingestion")
    print(f"\n🖥️  INGESTING VULNERABILITY FINDINGS")
    
    count_processed = 0
    count_saved = 0
    
    try:
        for finding_data in tenable_client.fetch_vulnerability_findings(days_since, limit):
            count_processed += 1
            
            if VulnerabilityProcessor.process_finding(finding_data):
                count_saved += 1
            
            # Progress update
            if count_processed % 500 == 0:
                print(f"📊 Processed {count_processed} findings, saved {count_saved}...")
                
        current_app.logger.info(f"Vulnerability findings ingestion complete: {count_processed} processed, {count_saved} saved")
        print(f"✅ Vulnerability findings: {count_processed} processed, {count_saved} saved")
        
        return count_saved
        
    except Exception as e:
        current_app.logger.error(f"Error ingesting vulnerability findings: {e}")
        print(f"❌ Error ingesting vulnerability findings: {e}")
        raise


def ingest_was_findings(tenable_client, days_since=30):
    """Ingest WAS findings"""
    if not FeatureFlags.ENABLE_WAS_FINDINGS:
        current_app.logger.info("WAS findings disabled by feature flag")
        print("⏭️  Skipping WAS findings (disabled)")
        return 0
    
    current_app.logger.info("Starting WAS findings ingestion")
    print(f"\n🌐 INGESTING WAS FINDINGS")
    
    count_processed = 0
    count_saved = 0
    
    try:
        for finding_data in tenable_client.fetch_was_findings(days_since):
            count_processed += 1
            
            if WASProcessor.process_finding(finding_data):
                count_saved += 1
            
            # Progress update
            if count_processed % 100 == 0:
                print(f"📊 Processed {count_processed} WAS findings, saved {count_saved}...")
                
        current_app.logger.info(f"WAS findings ingestion complete: {count_processed} processed, {count_saved} saved")
        print(f"✅ WAS findings: {count_processed} processed, {count_saved} saved")
        
        return count_saved
        
    except Exception as e:
        current_app.logger.error(f"Error ingesting WAS findings: {e}")
        print(f"❌ Error ingesting WAS findings: {e}")
        # Don't raise - WAS may not be available
        return 0


def ingest_attack_path_findings(tenable_client):
    """Ingest attack path findings"""
    if not FeatureFlags.ENABLE_ATTACK_PATH_ANALYSIS:
        current_app.logger.info("Attack path analysis disabled by feature flag")
        print("⏭️  Skipping attack path analysis (disabled)")
        return 0
    
    current_app.logger.info("Starting attack path findings ingestion")
    print(f"\n🎯 INGESTING ATTACK PATH FINDINGS")
    
    count_processed = 0
    count_saved = 0
    
    try:
        for attack_path_data in tenable_client.fetch_attack_path_candidates():
            count_processed += 1
            
            if AttackPathProcessor.process_finding(attack_path_data):
                count_saved += 1
                
        current_app.logger.info(f"Attack path findings ingestion complete: {count_processed} processed, {count_saved} saved")
        print(f"✅ Attack path findings: {count_processed} processed, {count_saved} saved")
        
        return count_saved
        
    except Exception as e:
        current_app.logger.error(f"Error ingesting attack path findings: {e}")
        print(f"❌ Error ingesting attack path findings: {e}")
        return 0


def ingest_grc_mappings():
    """Ingest GRC compliance mappings from JSON file"""
    if not FeatureFlags.ENABLE_GRC_MAPPING:
        current_app.logger.info("GRC mapping disabled by feature flag")
        print("⏭️  Skipping GRC mappings (disabled)")
        return 0
    
    grc_json_path = current_app.config.get('GRC_JSON_PATH')
    current_app.logger.info(f"Starting GRC mappings ingestion from: {grc_json_path}")
    print(f"\n📋 INGESTING GRC COMPLIANCE MAPPINGS")
    print(f"📁 Source file: {grc_json_path}")
    
    if not grc_json_path or not os.path.exists(grc_json_path):
        # Try alternative paths
        alt_paths = [
            os.path.join(os.getcwd(), 'data', 'grc_mappings.json'),
            os.path.join(os.getcwd(), 'grc_mappings.json'),
            './data/grc_mappings.json',
            'data/grc_mappings.json'
        ]
        
        for alt_path in alt_paths:
            if os.path.exists(alt_path):
                grc_json_path = alt_path
                print(f"✅ Found GRC file at: {alt_path}")
                break
        else:
            current_app.logger.warning(f"GRC JSON file not found at any location")
            print("❌ GRC JSON file not found - skipping GRC mappings")
            print("   Searched paths:")
            for path in alt_paths:
                print(f"     - {path}")
            print("   To enable GRC mappings, create data/grc_mappings.json")
            return 0
    
    try:
        # Read and validate JSON file
        print(f"📖 Reading file: {grc_json_path}")
        with open(grc_json_path, 'r', encoding='utf-8') as f:
            grc_data = json.load(f)
        
        if not isinstance(grc_data, list):
            current_app.logger.error("GRC JSON should contain a list of objects")
            print("❌ Invalid GRC JSON format - should be a list")
            return 0
        
        print(f"📊 Found {len(grc_data)} GRC entries in file")
        
        # Track what we process
        requirements_processed = 0
        requirements_new = 0
        requirements_updated = 0
        mappings_processed = 0
        mappings_new = 0
        mappings_existing = 0
        errors = 0
        
        for entry_index, entry in enumerate(grc_data, 1):
            try:
                # Validate entry structure
                if not isinstance(entry, dict):
                    current_app.logger.warning(f"Entry {entry_index} is not a dict, skipping")
                    errors += 1
                    continue
                
                # Process requirement
                req_detail = entry.get('requirement', {})
                if not isinstance(req_detail, dict):
                    current_app.logger.warning(f"Entry {entry_index} has invalid requirement, skipping")
                    errors += 1
                    continue
                
                framework = req_detail.get('framework')
                requirement_id = req_detail.get('requirement_id')
                
                if not framework or not requirement_id:
                    current_app.logger.warning(f"Entry {entry_index}: missing framework or requirement_id")
                    errors += 1
                    continue
                
                # Create or update requirement
                existing_req = db.session.query(ComplianceRequirement).filter_by(
                    requirement_id=requirement_id
                ).first()
                
                if existing_req:
                    # Update existing requirement
                    existing_req.framework = framework
                    existing_req.version = req_detail.get('version')
                    existing_req.description = req_detail.get('description')
                    requirement = existing_req
                    requirements_updated += 1
                    current_app.logger.debug(f"Updated requirement: {framework} {requirement_id}")
                else:
                    # Create new requirement
                    requirement = ComplianceRequirement(
                        framework=framework,
                        version=req_detail.get('version'),
                        requirement_id=requirement_id,
                        description=req_detail.get('description')
                    )
                    db.session.add(requirement)
                    requirements_new += 1
                    current_app.logger.debug(f"Created new requirement: {framework} {requirement_id}")
                
                requirements_processed += 1
                db.session.commit()  # Commit to get requirement.id
                
                # Process plugin mappings
                plugin_ids = entry.get('plugin_ids', [])
                if not isinstance(plugin_ids, list):
                    current_app.logger.warning(f"Entry {entry_index}: plugin_ids is not a list")
                    continue
                
                current_app.logger.debug(f"Processing {len(plugin_ids)} plugin mappings for {requirement_id}")
                
                for plugin_id in plugin_ids:
                    try:
                        plugin_id_int = int(plugin_id)
                        
                        # Check if mapping exists
                        existing_mapping = db.session.query(PluginComplianceMapping).filter_by(
                            plugin_id=plugin_id_int,
                            compliance_requirement_id=requirement.id
                        ).first()
                        
                        if not existing_mapping:
                            new_mapping = PluginComplianceMapping(
                                plugin_id=plugin_id_int,
                                compliance_requirement_id=requirement.id
                            )
                            db.session.add(new_mapping)
                            mappings_new += 1
                        else:
                            mappings_existing += 1
                        
                        mappings_processed += 1
                            
                    except ValueError:
                        current_app.logger.warning(f"Invalid plugin_id '{plugin_id}' in {requirement_id}")
                        errors += 1
                        continue
                    except IntegrityError as e:
                        current_app.logger.warning(f"Integrity error mapping plugin {plugin_id}: {e}")
                        db.session.rollback()
                        errors += 1
                        continue
                
                # Commit mappings for this requirement
                db.session.commit()
                
                # Progress update every 5 entries
                if entry_index % 5 == 0:
                    print(f"   Processed {entry_index}/{len(grc_data)} entries...")
                
            except Exception as e:
                current_app.logger.error(f"Error processing GRC entry {entry_index}: {e}")
                print(f"⚠️  Error on entry {entry_index}: {e}")
                db.session.rollback()
                errors += 1
                continue
        
        # Final summary
        print(f"\n📊 GRC INGESTION SUMMARY:")
        print(f"   Requirements: {requirements_processed} total ({requirements_new} new, {requirements_updated} updated)")
        print(f"   Mappings: {mappings_processed} total ({mappings_new} new, {mappings_existing} existing)")
        if errors > 0:
            print(f"   ⚠️  Errors: {errors}")
        
        current_app.logger.info(
            f"GRC ingestion complete: {requirements_processed} requirements "
            f"({requirements_new} new, {requirements_updated} updated), "
            f"{mappings_new} new mappings, {errors} errors"
        )
        
        # Return total new mappings created (this is what matters for the summary)
        return mappings_new
        
    except FileNotFoundError:
        current_app.logger.error(f"GRC JSON file not found: {grc_json_path}")
        print(f"❌ File not found: {grc_json_path}")
        return 0
    except json.JSONDecodeError as e:
        current_app.logger.error(f"Invalid JSON in GRC file: {e}")
        print(f"❌ Invalid JSON format: {e}")
        return 0
    except Exception as e:
        current_app.logger.error(f"Error ingesting GRC mappings: {e}")
        print(f"❌ Error ingesting GRC mappings: {e}")
        db.session.rollback()
        return 0


def run_test_ingestion(limit=100):
    """Run a limited ingestion for testing purposes"""
    current_app.logger.info(f"Running test ingestion with limit={limit}")
    print(f"\n🧪 RUNNING TEST INGESTION")
    print(f"📊 Limited to {limit} findings per source")
    
    return run_full_ingestion(days_since=7, test_limit=limit)


def quick_connection_test():
    """Quick test to verify Tenable API connection"""
    current_app.logger.info("Running quick connection test")
    print(f"\n🔗 TESTING TENABLE API CONNECTION")
    
    try:
        tenable_client = get_tenable_client()
        tenable_client.validate_connection()
        print("✅ Tenable API connection successful")
        return True
    except Exception as e:
        print(f"❌ Tenable API connection failed: {e}")
        return False