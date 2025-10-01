# Tenable One Enhanced Dashboard

A comprehensive Flask-based dashboard for visualizing and managing Tenable vulnerability findings with enhanced features including attack path analysis, cloud metadata, and GRC compliance mapping.

## 🚀 Features

### Core Functionality
- **Multi-Source Data Integration**: Supports both Tenable.io and Ermetic endpoints
- **Comprehensive Vulnerability Management**: VM findings with advanced filtering and sorting
- **Attack Path Analysis**: Identify vulnerabilities that could be chained together
- **Web Application Security**: WAS findings integration
- **Cloud Infrastructure**: AWS, Azure, and GCP metadata extraction
- **GRC Compliance**: Map findings to compliance frameworks (SOX, PCI-DSS, etc.)

### Dashboard Capabilities
- **Multi-Tab Interface**: Organized views for different finding types
- **Advanced Filtering**: By severity, state, time period, cloud provider
- **Grouped Views**: See vulnerabilities grouped by plugin with affected assets
- **Export Functions**: CSV and TXT formats for reporting and ticketing
- **Real-Time Metrics**: Executive summary with key statistics

### Technical Features
- **Modular Architecture**: Clean, maintainable codebase
- **Feature Flags**: Enable/disable functionality as needed
- **Comprehensive Logging**: Full audit trail of operations
- **Error Handling**: Robust error handling and recovery

## 📋 Requirements

- Python 3.8+
- pytenable 1.8.4 (latest version)
- Flask 2.3.3+
- SQLAlchemy 2.0+
- Tenable.io API access OR Ermetic API access

## ⚡ Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd tenable-dashboard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API credentials
```

#### For Tenable.io:
```bash
TENABLE_ACCESS_KEY=your_tenable_access_key_here
TENABLE_SECRET_KEY=your_tenable_secret_key_here
```

#### For Ermetic:
```bash
ERMETIC_API_URL=https://your-tenant.ermetic-api.com
ERMETIC_API_TOKEN=your_ermetic_api_token_here
```

### 3. Run the Application

```bash
# Full startup with data ingestion
python run.py

# Quick startup without data ingestion (for testing)
python run.py --skip-ingestion
```

The dashboard will be available at `http://localhost:5000`

## 🔧 Configuration Options

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TENABLE_ACCESS_KEY` | Yes* | Tenable.io Access Key |
| `TENABLE_SECRET_KEY` | Yes* | Tenable.io Secret Key |
| `ERMETIC_API_URL` | Yes* | Ermetic API Base URL |
| `ERMETIC_API_TOKEN` | Yes* | Ermetic API Token |
| `DEFAULT_DAYS_SINCE` | No | Days of historical data (default: 30) |
| `HOST` | No | Server host (default: 127.0.0.1) |
| `PORT` | No | Server port (default: 5000) |

*Either Tenable.io OR Ermetic credentials required

### Feature Flags

All features are enabled by default. Set to `false` to disable:

```bash
ENABLE_ATTACK_PATH_ANALYSIS=true
ENABLE_WAS_FINDINGS=true
ENABLE_GRC_MAPPING=true
ENABLE_CLOUD_METADATA=true
ENABLE_EXPOSURE_SCORING=true
ENABLE_CONTAINER_SECURITY=false
```

## 📊 API Integration

### Tenable.io Integration
- Uses pytenable 1.8.4 for optimal performance and latest features
- Supports vulnerability exports with advanced filtering
- Includes WAS findings and asset metadata
- Automatic retry and error handling

### Ermetic Integration
- Custom REST API client for Ermetic endpoints
- Automatic endpoint detection and health checking
- Extensible framework for Ermetic-specific features
- Graceful fallback handling

## 🗂️ Data Sources

### Vulnerability Findings
- **VM Vulnerabilities**: Traditional vulnerability scanner results
- **Web Application Security**: OWASP-based web app findings
- **Container Security**: Container and image vulnerabilities (if configured)
- **Attack Path Analysis**: Multi-step attack scenario identification

### Asset Information
- **On-Premises**: Traditional network-based assets
- **Cloud Infrastructure**: AWS, Azure, GCP instances
- **Metadata Enrichment**: OS, business criticality, exposure scores

### Compliance Mapping
- **GRC Frameworks**: SOX, PCI-DSS, NIST, ISO 27001, etc.
- **Requirement Mapping**: Plugin-to-requirement relationships
- **Compliance Reporting**: Framework-specific finding reports

## 📈 Dashboard Views

### Main Dashboard
- Executive summary with key metrics
- Filterable findings table with sorting
- Cloud and attack path indicators
- Export capabilities

### Grouped Findings
- Vulnerabilities grouped by plugin type
- Shows all affected assets per vulnerability
- Useful for bulk remediation planning

### Attack Paths
- High-risk attack scenario identification
- Path risk scoring and length analysis
- Critical asset involvement

## 🔄 Data Management

### Initial Data Load
- Automatic on startup (configurable)
- Supports date range selection
- Progress tracking and logging

### Manual Data Refresh
- Web UI trigger for manual updates
- API endpoint for programmatic refresh
- Test mode with limited data for development

### Data Retention
- SQLite database storage
- Configurable data directory
- Built-in data deduplication

## 🛡️ Security

- **Local Hosting**: Binds to localhost only by default
- **API Key Security**: Credentials masked in logs
- **Input Validation**: SQL injection prevention
- **Error Handling**: No sensitive data in error messages

## 🐛 Troubleshooting

### Common Issues

**Connection Failures**:
- Verify API credentials in `.env` file
- Check network connectivity to Tenable/Ermetic endpoints
- Review logs in `data/tenable_dashboard.log`

**No Data Appearing**:
- Ensure API credentials have proper permissions
- Check date range settings (default: last 30 days)
- Verify feature flags are enabled for desired data types

**Performance Issues**:
- Use `--skip-ingestion` for faster startup during development
- Enable only needed features via feature flags
- Consider using test mode with limited data

### Debug Information
Visit `/debug` for system status and configuration details.

## 📝 API Endpoints

- `GET /` - Main dashboard
- `GET /grouped_findings` - Grouped findings view
- `GET /api/ingest_data` - Trigger data ingestion
- `GET /api/test_connection` - Test API connectivity
- `GET /export/*` - Various export formats

## 🤝 Contributing

1. Follow the modular architecture pattern
2. Add feature flags for new optional functionality
3. Include comprehensive error handling
4. Update documentation for new features

## 📄 License

[Your license here]

## 🆘 Support

- Check the debug page at `/debug` for system status
- Review application logs in `data/tenable_dashboard.log`
- Ensure you're using pytenable 1.8.4 for best compatibility