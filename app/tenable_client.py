"""
Tenable API Client - Clean implementation with pytenable 1.8.4 support
Supports both Tenable.io and Ermetic endpoints
Fixed to use Tenable.io for vulnerability/WAS data and Ermetic for cloud data
"""

import os
import requests
from datetime import datetime, timedelta, timezone
from tenable.io import TenableIO
from flask import current_app


class TenableClient:
    """Clean Tenable API client wrapper with Ermetic support"""
    
    def __init__(self, access_key=None, secret_key=None, ermetic_url=None, ermetic_token=None):
        """Initialize Tenable client with credentials"""
        # Standard Tenable.io credentials
        self.access_key = access_key or current_app.config.get('TENABLE_ACCESS_KEY') or os.getenv('TENABLE_ACCESS_KEY')
        self.secret_key = secret_key or current_app.config.get('TENABLE_SECRET_KEY') or os.getenv('TENABLE_SECRET_KEY')
        
        # Ermetic API credentials  
        self.ermetic_url = ermetic_url or current_app.config.get('ERMETIC_API_URL') or os.getenv('ERMETIC_API_URL')
        self.ermetic_token = ermetic_token or current_app.config.get('ERMETIC_API_TOKEN') or os.getenv('ERMETIC_API_TOKEN')
        
        # Determine which APIs are available
        self.has_ermetic = bool(self.ermetic_url and self.ermetic_token)
        self.has_tenable = bool(self.access_key and self.secret_key)
        
        if self.has_ermetic and self.has_tenable:
            current_app.logger.info("Both Tenable.io and Ermetic APIs available - using hybrid mode")
            print("🔗 Hybrid mode: Tenable.io for vulnerabilities, Ermetic for cloud")
        elif self.has_tenable:
            current_app.logger.info("Using standard Tenable.io API only")
            print("🔗 Using standard Tenable.io API")
        elif self.has_ermetic:
            current_app.logger.warning("Only Ermetic API available - limited functionality")
            print("⚠️ Only Ermetic API available - vulnerability data will be limited")
        else:
            raise ValueError("Either Tenable.io credentials OR Ermetic API credentials required. Check your .env file.")
        
        self._tenable_client = None
        self._ermetic_client = None
        self._validated = False
    
    @property
    def tenable_client(self):
        """Get Tenable.io client instance with lazy initialization"""
        if self._tenable_client is None and self.has_tenable:
            current_app.logger.info("Creating Tenable.io client...")
            self._tenable_client = TenableIO(self.access_key, self.secret_key)
        return self._tenable_client
    
    @property
    def ermetic_client(self):
        """Get Ermetic client instance with lazy initialization"""
        if self._ermetic_client is None and self.has_ermetic:
            current_app.logger.info("Creating Ermetic API client...")
            self._ermetic_client = self._create_ermetic_client()
        return self._ermetic_client
    
    def _create_ermetic_client(self):
        """Create custom Ermetic API client"""
        class ErmeticClient:
            def __init__(self, url, token):
                self.url = url.rstrip('/')
                self.token = token
                self.headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'User-Agent': 'TenableDashboard/1.0 (pytenable/1.8.4)'
                }
                self.session = requests.Session()
                self.session.headers.update(self.headers)
            
            def test_connection(self):
                """Test Ermetic API connection"""
                try:
                    # Try multiple possible health check endpoints
                    health_endpoints = [
                        '/api/v1/health',
                        '/api/health', 
                        '/health',
                        '/api/v1/status',
                        '/status'
                    ]
                    
                    for endpoint in health_endpoints:
                        try:
                            response = self.session.get(f'{self.url}{endpoint}', timeout=10)
                            if response.status_code == 200:
                                current_app.logger.info(f"Ermetic health check successful via {endpoint}")
                                return True
                        except requests.exceptions.RequestException:
                            continue
                    
                    # If health checks fail, try a simple API call
                    response = self.session.get(f'{self.url}/api/v1', timeout=10)
                    return response.status_code in [200, 401, 403]  # 401/403 means API is responding
                    
                except Exception as e:
                    current_app.logger.error(f"Ermetic connection test failed: {e}")
                    return False
            
            def get_cloud_findings(self, since_date=None, limit=None):
                """
                Fetch cloud security findings from Ermetic
                This would need to be implemented based on actual Ermetic API documentation
                """
                current_app.logger.info("Fetching cloud security findings from Ermetic...")
                
                try:
                    # This is a placeholder implementation
                    # Replace with actual Ermetic API calls for cloud security data
                    endpoint = '/api/v1/cloud/findings'  # Example endpoint
                    params = {}
                    
                    if since_date:
                        params['since'] = since_date.isoformat()
                    if limit:
                        params['limit'] = limit
                    
                    response = self.session.get(f'{self.url}{endpoint}', params=params, timeout=30)
                    
                    if response.status_code == 200:
                        data = response.json()
                        # Process the response according to Ermetic API format
                        findings = data.get('findings', [])
                        current_app.logger.info(f"Retrieved {len(findings)} cloud findings from Ermetic")
                        return findings
                    else:
                        current_app.logger.warning(f"Ermetic API returned status {response.status_code}")
                        return []
                        
                except Exception as e:
                    current_app.logger.error(f"Error fetching Ermetic cloud findings: {e}")
                    return []
        
        return ErmeticClient(self.ermetic_url, self.ermetic_token)
    
    def validate_connection(self):
        """Test the API connections"""
        if self._validated:
            return True
        
        success = False
        
        # Test Tenable.io connection if available
        if self.has_tenable:
            try:
                current_app.logger.info("Testing Tenable.io connection...")
                session_info = self.tenable_client.session.details()
                user_name = session_info.get('name', 'Unknown')
                user_email = session_info.get('email', 'Unknown')
                
                current_app.logger.info(f"✅ Connected to Tenable.io as: {user_name} ({user_email})")
                print(f"✅ Tenable.io API connection successful - User: {user_name}")
                success = True
                
            except Exception as e:
                current_app.logger.error(f"Tenable.io connection failed: {e}")
                print(f"❌ Tenable.io connection failed: {e}")
        
        # Test Ermetic connection if available
        if self.has_ermetic:
            try:
                current_app.logger.info("Testing Ermetic connection...")
                if self.ermetic_client.test_connection():
                    current_app.logger.info("✅ Connected to Ermetic API")
                    print("✅ Ermetic API connection successful")
                    success = True
                else:
                    current_app.logger.warning("Ermetic API connection test failed")
                    print("⚠️ Ermetic API connection test failed")
                    
            except Exception as e:
                current_app.logger.error(f"Ermetic connection test error: {e}")
                print(f"⚠️ Ermetic connection test error: {e}")
        
        if not success:
            raise Exception("No API connections successful")
        
        self._validated = True
        return True
    
    def fetch_vulnerability_findings(self, days_since=30, limit=None):
        """
        Fetch vulnerability findings from Tenable.io (ALWAYS use Tenable for vulnerabilities)
        
        Args:
            days_since: Number of days to look back
            limit: Maximum number of findings to return (for testing)
        
        Yields:
            dict: Vulnerability finding data
        """
        if not self.has_tenable:
            current_app.logger.error("Tenable.io credentials required for vulnerability findings")
            raise ValueError("Tenable.io credentials required for vulnerability findings")
        
        # Always validate Tenable.io connection for vulnerability data
        try:
            session_info = self.tenable_client.session.details()
            current_app.logger.info(f"Using Tenable.io for vulnerability data - User: {session_info.get('name', 'Unknown')}")
        except Exception as e:
            current_app.logger.error(f"Tenable.io connection failed: {e}")
            raise
        
        # Calculate date range
        past_date = datetime.now(timezone.utc) - timedelta(days=days_since)
        since_timestamp = int(past_date.timestamp())
        
        current_app.logger.info(f"Fetching vulnerability findings since: {past_date.isoformat()}")
        print(f"📥 Fetching vulnerability findings since: {past_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        count = 0
        try:
            # ALWAYS use Tenable.io for vulnerability data
            current_app.logger.info("Using Tenable.io API for vulnerability data")
            print("🔗 Using Tenable.io API endpoint")
            
            export_params = {
                'since': since_timestamp,
                'state': ['open', 'reopened'],
                'severity': ['critical', 'high', 'medium', 'low']
            }
            
            for finding_data in self.tenable_client.exports.vulns(**export_params):
                yield finding_data
                count += 1
                
                if count % 1000 == 0:
                    current_app.logger.info(f"Fetched {count} vulnerability findings...")
                    print(f"📊 Fetched {count} vulnerability findings...")
                
                if limit and count >= limit:
                    current_app.logger.info(f"Reached limit of {limit} findings")
                    break
                        
        except Exception as e:
            current_app.logger.error(f"Error fetching vulnerability findings: {e}")
            raise
        
        current_app.logger.info(f"Total vulnerability findings retrieved: {count}")
        print(f"✅ Total vulnerability findings retrieved: {count}")
    
    def fetch_was_findings(self, days_since=30):
        """
        Fetch WAS findings from Tenable.io (ALWAYS use Tenable for WAS)
        
        Args:
            days_since: Number of days to look back
            
        Yields:
            dict: WAS finding data
        """
        from config import FeatureFlags
        
        if not FeatureFlags.ENABLE_WAS_FINDINGS:
            current_app.logger.info("WAS findings disabled by feature flag")
            return
        
        if not self.has_tenable:
            current_app.logger.warning("Tenable.io credentials required for WAS findings")
            return
        
        # Always use Tenable.io for WAS data
        past_date = datetime.now(timezone.utc) - timedelta(days=days_since)
        since_date_str = past_date.strftime('%Y/%m/%d')
        
        current_app.logger.info(f"Fetching WAS findings since: {since_date_str}")
        print(f"🌐 Fetching WAS findings since: {since_date_str}")
        
        count = 0
        try:
            was_findings = self.tenable_client.was.export(
                and_filter=[
                    ("scans_started_at", "gte", since_date_str),
                    ("scans_status", "eq", "completed")
                ]
            )
            
            for finding_data in was_findings:
                finding_detail = finding_data.get('finding', {})
                risk_factor = finding_detail.get('risk_factor', '').lower()
                
                if risk_factor == 'info':
                    continue
                
                yield finding_data
                count += 1
                
                if count % 100 == 0:
                    current_app.logger.info(f"Fetched {count} WAS findings...")
                    print(f"📊 Fetched {count} WAS findings...")
                    
        except Exception as e:
            current_app.logger.warning(f"WAS findings not available: {e}")
            print("ℹ️  WAS findings not available - this is normal if you don't have WAS licensing")
            return
        
        current_app.logger.info(f"Total WAS findings retrieved: {count}")
        print(f"✅ Total WAS findings retrieved: {count}")
    
    def fetch_attack_path_candidates(self):
        """
        Generate attack paths from Tenable.io assets (ALWAYS use Tenable for attack paths)
        """
        from config import FeatureFlags
        
        if not FeatureFlags.ENABLE_ATTACK_PATH_ANALYSIS:
            current_app.logger.info("Attack path analysis disabled by feature flag")
            return
        
        if not self.has_tenable:
            current_app.logger.warning("Tenable.io credentials required for attack path generation")
            return
        
        current_app.logger.info("Generating attack path candidates from high-risk assets...")
        print("🎯 Generating attack path candidates...")
        
        count = 0
        try:
            assets = list(self.tenable_client.exports.assets())
            
            for asset in assets:
                critical_count = asset.get('critical_count', 0)
                high_count = asset.get('high_count', 0)
                
                if critical_count > 2 or (critical_count > 0 and high_count > 5):
                    asset_name = asset.get('hostname') or asset.get('ipv4') or f"Asset-{asset.get('id')}"
                    
                    attack_path_data = {
                        'id': f"synthetic_path_{asset.get('id')}",
                        'name': f"High Risk Path: {asset_name}",
                        'description': f"Asset with {critical_count} critical and {high_count} high severity vulnerabilities",
                        'risk_score': min(10.0, 5.0 + (critical_count * 1.5) + (high_count * 0.3)),
                        'path_length': critical_count + high_count,
                        'assets': [asset.get('id')],
                        'critical_assets': [asset.get('id')] if critical_count > 2 else [],
                        'status': 'ACTIVE',
                        'created_at': datetime.now(timezone.utc).isoformat(),
                        'updated_at': datetime.now(timezone.utc).isoformat()
                    }
                    
                    yield attack_path_data
                    count += 1
                    
                    if count >= 20:
                        break
                        
        except Exception as e:
            current_app.logger.error(f"Error generating attack path candidates: {e}")
            raise
        
        current_app.logger.info(f"Generated {count} attack path candidates")
        print(f"✅ Generated {count} attack path candidates")
    
    def fetch_cloud_findings(self, days_since=30):
        """
        Fetch cloud security findings from Ermetic (if available)
        
        Args:
            days_since: Number of days to look back
            
        Yields:
            dict: Cloud security finding data
        """
        from config import FeatureFlags
        
        if not FeatureFlags.ENABLE_CLOUD_METADATA:
            current_app.logger.info("Cloud findings disabled by feature flag")
            return
        
        if not self.has_ermetic:
            current_app.logger.info("Ermetic credentials not available - skipping cloud findings")
            print("ℹ️  Ermetic API not configured - skipping cloud-specific findings")
            return
        
        past_date = datetime.now(timezone.utc) - timedelta(days=days_since)
        
        current_app.logger.info(f"Fetching cloud findings from Ermetic since: {past_date.isoformat()}")
        print(f"☁️ Fetching cloud findings since: {past_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        count = 0
        try:
            # Use Ermetic client for cloud-specific data
            cloud_findings = self.ermetic_client.get_cloud_findings(since_date=past_date, limit=1000)
            
            for finding_data in cloud_findings:
                yield finding_data
                count += 1
                
                if count % 100 == 0:
                    current_app.logger.info(f"Fetched {count} cloud findings...")
                    print(f"📊 Fetched {count} cloud findings...")
                    
        except Exception as e:
            current_app.logger.error(f"Error fetching cloud findings: {e}")
            print(f"⚠️ Error fetching cloud findings: {e}")
            return
        
        current_app.logger.info(f"Total cloud findings retrieved: {count}")
        print(f"✅ Total cloud findings retrieved: {count}")
    
    def fetch_container_findings(self):
        """
        Fetch container security findings (placeholder)
        Requires separate Container Security API key
        """
        from config import FeatureFlags
        
        if not FeatureFlags.ENABLE_CONTAINER_SECURITY:
            current_app.logger.info("Container security disabled by feature flag")
            return
        
        cs_api_key = current_app.config.get('TENABLE_CS_API_KEY')
        if not cs_api_key:
            current_app.logger.info("Container Security API key not configured")
            print("ℹ️  Container Security API key not found - skipping container findings")
            return
        
        current_app.logger.info("Container security integration would be implemented here")
        print("🐳 Container security integration not yet implemented")
        return
        yield  # Make this a generator


def get_tenable_client():
    """Get a configured Tenable client instance"""
    return TenableClient()