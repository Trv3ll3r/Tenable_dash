"""
Tenable Cloud Security (Ermetic) Client Implementation
Updated with working API calls, PAGINATION, and improved resource handling
"""

import os
import json
import requests
from datetime import datetime, timedelta, timezone
from flask import current_app

class ErmeticClient:
    """Working Tenable Cloud Security GraphQL API client with pagination"""
    
    def __init__(self, api_url=None, token=None):
        # Get configuration from environment variables
        self.api_url = api_url or os.getenv('ERMETIC_API_URL')
        self.token = token or os.getenv('ERMETIC_API_TOKEN')
        
        if not self.api_url:
            raise ValueError("ERMETIC_API_URL not found in environment variables")
        if not self.token:
            raise ValueError("ERMETIC_API_TOKEN not found in environment variables")
        
        # Use the URL as-is from environment
        current_app.logger.info(f"Initializing Ermetic client with URL: {self.api_url}")
        
        # Set up headers with Bearer authentication (working format)
        self.headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json',
            'User-Agent': 'TenableDashboard/1.0'
        }
        
        # Create session with headers
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def test_connection(self):
        """Test connection to Tenable Cloud Security API"""
        try:
            # Use introspection query to test connection
            query = """
            query {
              __schema {
                queryType { name }
              }
            }
            """
            
            response = self.session.post(
                self.api_url,
                json={"query": query},
                timeout=10
            )
            
            current_app.logger.info(f"Connection test status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    current_app.logger.error(f"GraphQL errors: {data['errors']}")
                    return False
                return 'data' in data and data['data'] is not None
            else:
                current_app.logger.error(f"Connection test failed: {response.status_code}")
                return False
            
        except Exception as e:
            current_app.logger.error(f"Connection test exception: {str(e)}")
            return False

    def _execute_query(self, query, variables=None):
        """Execute GraphQL query"""
        try:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables
            
            response = self.session.post(
                self.api_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'errors' in data:
                    current_app.logger.warning(f"GraphQL errors: {data['errors']}")
                    return {}
                return data.get('data', {})
            else:
                current_app.logger.error(f"Query failed: {response.status_code} - {response.text[:500]}")
                return {}
                
        except Exception as e:
            current_app.logger.error(f"Query execution error: {str(e)}")
            return {}

    def get_findings_paginated(self, statuses=None, severities=None, page_size=100):
        """
        Get ALL findings from Tenable Cloud Security using pagination
        This is a generator that yields findings page by page
        
        Args:
            statuses: List of statuses to filter by (e.g., ['Open'])
            severities: List of severities to filter by (e.g., ['Critical', 'High'])
            page_size: Number of findings per page (default 100)
        
        Yields:
            dict: Individual finding nodes
        """
        try:
            # Build filter conditions
            filter_parts = []
            if statuses:
                if isinstance(statuses, list):
                    status_list = ', '.join(statuses)
                else:
                    status_list = statuses
                filter_parts.append(f'Statuses: [{status_list}]')
            
            if severities:
                if isinstance(severities, list):
                    severity_list = ', '.join(severities)
                else:
                    severity_list = severities
                filter_parts.append(f'Severities: [{severity_list}]')
            
            filter_str = ', '.join(filter_parts) if filter_parts else ''
            
            cursor = None
            has_next_page = True
            page_num = 0
            total_fetched = 0
            
            while has_next_page:
                page_num += 1
                
                # Build query with pagination
                after_clause = f'after: "{cursor}"' if cursor else 'after: null'
                
                query = f"""
                query {{
                  Findings(
                    first: {page_size},
                    {after_clause}
                    {f'filter: {{{filter_str}}}' if filter_str else ''}
                  ) {{
                    totalCount
                    nodes {{
                      Id
                      CreationTime
                      Status
                      Severity
                      Policy {{
                        Name
                        Description
                        Category
                      }}
                      Resources {{
                        ... on AwsResource {{
                          Name
                          Arn
                          Region
                          AccountId
                          __typename
                        }}
                        ... on AzureResource {{
                          Name
                          Id
                          Region
                          AccountId
                          __typename
                        }}
                        ... on GcpResource {{
                          Name
                          Id
                          Region
                          AccountId
                          __typename
                        }}
                      }}
                      Remediation {{
                        Console {{
                          Steps
                        }}
                      }}
                    }}
                    pageInfo {{
                      hasNextPage
                      endCursor
                    }}
                  }}
                }}
                """
                
                data = self._execute_query(query)
                findings = data.get('Findings', {})
                
                if not findings:
                    current_app.logger.warning(f"No findings data on page {page_num}")
                    break
                
                nodes = findings.get('nodes', [])
                page_info = findings.get('pageInfo', {})
                total_count = findings.get('totalCount', 0)
                
                if page_num == 1 and total_count > 0:
                    current_app.logger.info(f"Total findings available: {total_count}")
                
                if not nodes:
                    current_app.logger.info(f"No more findings on page {page_num}")
                    break
                
                # Yield each finding
                for node in nodes:
                    yield node
                    total_fetched += 1
                
                current_app.logger.info(f"Page {page_num}: Fetched {len(nodes)} findings (total: {total_fetched}/{total_count})")
                
                # Check pagination
                has_next_page = page_info.get('hasNextPage', False)
                cursor = page_info.get('endCursor')
                
                if not has_next_page:
                    current_app.logger.info(f"Reached last page. Total findings retrieved: {total_fetched}")
                    break
                
                if not cursor:
                    current_app.logger.warning("No cursor but hasNextPage is True - stopping")
                    break
            
        except Exception as e:
            current_app.logger.error(f"Error fetching paginated findings: {str(e)}")
            raise

    def get_findings(self, first=100, statuses=None, severities=None):
        """
        Get findings from Tenable Cloud Security (single page - kept for compatibility)
        For all findings, use get_findings_paginated() instead
        
        Args:
            first: Number of findings to retrieve (default 100)
            statuses: List of statuses to filter by (e.g., ['Open'])
            severities: List of severities to filter by (e.g., ['Critical', 'High'])
        
        Returns:
            Dictionary with findings data including nodes and totalCount
        """
        try:
            # Build filter conditions
            filter_parts = []
            if statuses:
                if isinstance(statuses, list):
                    status_list = ', '.join(statuses)
                else:
                    status_list = statuses
                filter_parts.append(f'Statuses: [{status_list}]')
            
            if severities:
                if isinstance(severities, list):
                    severity_list = ', '.join(severities)
                else:
                    severity_list = severities
                filter_parts.append(f'Severities: [{severity_list}]')
            
            filter_str = ', '.join(filter_parts) if filter_parts else ''
            
            # Query based on API documentation (single page)
            query = f"""
            query {{
              Findings(
                first: {first}
                {f'filter: {{{filter_str}}}' if filter_str else ''}
              ) {{
                totalCount
                nodes {{
                  Id
                  CreationTime
                  Status
                  Severity
                  Policy {{
                    Name
                    Description
                    Category
                  }}
                  Resources {{
                    ... on AwsResource {{
                      Name
                      Arn
                      Region
                      AccountId
                    }}
                    ... on AzureResource {{
                      Name
                      Id
                      Region
                      AccountId
                    }}
                    ... on GcpResource {{
                      Name
                      Id
                      Region
                      AccountId
                    }}
                  }}
                  Remediation {{
                    Console {{
                      Steps
                    }}
                  }}
                }}
                pageInfo {{
                  hasNextPage
                  endCursor
                }}
              }}
            }}
            """
            
            data = self._execute_query(query)
            findings = data.get('Findings', {})
            
            if findings:
                current_app.logger.info(f"Retrieved {len(findings.get('nodes', []))} findings from Tenable Cloud Security")
            
            return findings
            
        except Exception as e:
            current_app.logger.error(f"Error fetching findings: {str(e)}")
            return {}

    def get_cloud_findings(self, since_date=None, limit=None):
        """
        Get cloud security findings transformed for dashboard compatibility
        NOW USES PAGINATION to fetch all findings
        
        Args:
            since_date: Optional datetime to filter findings created after this date
            limit: Maximum number of findings to return (None = all findings)
        
        Returns:
            Generator that yields transformed findings ready for the dashboard
        """
        try:
            current_app.logger.info("Fetching cloud security findings with pagination...")
            
            count = 0
            skipped = 0
            
            # Use the paginated version to get ALL findings (no status filter to get everything)
            for node in self.get_findings_paginated(statuses=None, page_size=100):
                # Transform to dashboard format
                finding = self._transform_finding(node)
                
                # Skip findings that couldn't be transformed (no resources)
                if finding is None:
                    skipped += 1
                    continue
                
                # Apply date filter if specified
                if since_date and finding.get('created_at'):
                    try:
                        finding_date = datetime.fromisoformat(finding['created_at'].replace('Z', '+00:00'))
                        if finding_date < since_date:
                            continue
                    except Exception as e:
                        current_app.logger.debug(f"Date parsing error: {e}")
                        pass  # Include if date parsing fails
                
                yield finding
                count += 1
                
                # Apply limit if specified
                if limit and count >= limit:
                    current_app.logger.info(f"Reached limit of {limit} findings")
                    break
            
            current_app.logger.info(f"Cloud findings: {count} yielded, {skipped} skipped (no resources)")
            
        except Exception as e:
            current_app.logger.error(f"Error in get_cloud_findings: {str(e)}")
            return

    def _transform_finding(self, node):
        """Transform Tenable Cloud Security finding to dashboard format"""
        policy = node.get('Policy', {})
        resources = node.get('Resources', [])
        
        # Handle cases where Resources is empty or missing
        if not resources or len(resources) == 0:
            current_app.logger.debug(f"Finding {node.get('Id')} has no resources - skipping")
            return None  # Return None to signal this should be filtered out
        
        resource = resources[0]
        
        # Verify resource has minimum required data
        if not resource or not isinstance(resource, dict):
            current_app.logger.debug(f"Finding {node.get('Id')} has invalid resource data")
            return None
        
        # Extract resource information with better defaults
        resource_info = {
            'id': resource.get('Arn') or resource.get('Id', ''),
            'name': resource.get('Name', 'Unknown'),
            'type': resource.get('__typename', 'Unknown'),
            'region': resource.get('Region', ''),
            'account_id': resource.get('AccountId', ''),
        }
        
        # Determine cloud provider from resource type
        resource_type = resource.get('__typename', '')
        
        # More aggressive provider detection
        if 'Aws' in resource_type or 'AWS' in resource_type:
            provider = 'AWS'
        elif 'Azure' in resource_type or 'AZURE' in resource_type:
            provider = 'Azure'
        elif 'Gcp' in resource_type or 'GCP' in resource_type or 'Google' in resource_type:
            provider = 'GCP'
        else:
            # Try to detect from resource ID/ARN as fallback
            resource_id = resource_info['id']
            if resource_id.startswith('arn:aws:'):
                provider = 'AWS'
            elif '/subscriptions/' in resource_id or resource_id.startswith('/providers/'):
                provider = 'Azure'
            elif resource_id.startswith('//'):
                provider = 'GCP'
            else:
                # Log when we can't determine provider
                current_app.logger.debug(
                    f"Could not determine provider for finding {node.get('Id')}: "
                    f"typename={resource_type}, id={resource_id[:50] if resource_id else 'empty'}"
                )
                provider = 'Unknown'
        
        resource_info['cloud_provider'] = provider
        
        # Map severity to risk score
        severity = node.get('Severity', 'Medium')
        risk_score_map = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0
        }
        
        return {
            'id': f"tcs_{node.get('Id', 'unknown')}",
            'title': policy.get('Name', 'Security Finding'),
            'description': policy.get('Description', 'Cloud security finding detected'),
            'severity': severity,
            'status': node.get('Status', 'Open'),
            'resource': resource_info,
            'policy_violated': policy.get('Name', 'Unknown Policy'),
            'risk_score': risk_score_map.get(severity, 5.0),
            'created_at': node.get('CreationTime', datetime.now(timezone.utc).isoformat()),
            'updated_at': node.get('CreationTime', datetime.now(timezone.utc).isoformat()),
            'compliance_frameworks': ['Tenable Cloud Security', policy.get('Category', 'Security')],
            'remediation': self._extract_remediation(node.get('Remediation'))
        }

    def _extract_remediation(self, remediation):
        """Extract remediation steps"""
        if not remediation:
            return "Review and remediate security finding"
        
        console = remediation.get('Console', {})
        steps = console.get('Steps', [])
        
        if steps:
            return ' '.join(steps)
        
        return "Review security configuration and apply recommended fixes"
    
    def get_finding_statistics(self):
        """
        Get statistics about findings without fetching all data
        Useful for debugging and monitoring
        
        Returns:
            Dictionary with statistics
        """
        try:
            query = """
            query {
              Findings(first: 1) {
                totalCount
              }
            }
            """
            
            data = self._execute_query(query)
            findings = data.get('Findings', {})
            total = findings.get('totalCount', 0)
            
            current_app.logger.info(f"Total findings in Tenable Cloud Security: {total}")
            return {'total_count': total}
            
        except Exception as e:
            current_app.logger.error(f"Error getting statistics: {str(e)}")
            return {'total_count': 0}