# Data Governance Application

An enterprise-grade AI-powered Streamlit application for comprehensive data classification, compliance monitoring, and governance with advanced Snowflake integration.

## Features

### Core Data Governance
- **AI-Powered Data Classification**: Automated sensitive data detection and classification using machine learning
- **Advanced Data Discovery**: Intelligent scanning and cataloging of data assets across Snowflake environments
- **CIA Triad Assessment**: Comprehensive Confidentiality, Integrity, and Availability evaluations
- **Dynamic Policy Management**: Flexible, configurable data governance policies and rules
- **Real-time Compliance Monitoring**: SOC 2, SOX, GDPR, and custom compliance framework support

### Intelligence & Analytics
- **Data Intelligence Dashboard**: Advanced analytics and insights into data usage patterns
- **Behavior Analytics**: Anomaly detection and user behavior monitoring
- **Classification Review Workflows**: Streamlined processes for data steward reviews and approvals
- **Audit Trail Management**: Comprehensive logging and audit capabilities with detailed evidence collection
- **Metrics & Reporting**: Executive dashboards and compliance reporting

### Advanced Capabilities
- **Continuous Data Scanning**: Automated, scheduled data discovery and classification updates
- **Reclassification Workflows**: Managed processes for updating data classifications
- **Exception Management**: Handling and tracking of classification exceptions and edge cases
- **OIDC Authentication**: Enterprise-grade authentication and authorization
- **Role-Based Access Control (RBAC)**: Granular permissions and access management
- **API Integration**: RESTful APIs for integration with external systems

## Project Structure

```
data-governance-app/
├── src/
│   ├── app.py                          # Main Streamlit application
│   ├── config/
│   │   ├── settings.py                 # Application configuration
│   │   └── constants.py                # Application constants
│   ├── connectors/
│   │   └── snowflake_connector.py      # Snowflake database connectivity
│   ├── models/
│   │   └── data_models.py              # Pydantic data models
│   ├── ml/
│   │   └── classifier.py               # Machine learning classification models
│   ├── services/                       # Business logic services
│   │   ├── ai_classification_service.py
│   │   ├── ai_sensitive_detection_service.py
│   │   ├── audit_service.py
│   │   ├── authorization_service.py
│   │   ├── behavior_analytics_service.py
│   │   ├── classification_review_service.py
│   │   ├── compliance_service.py
│   │   ├── continuous_classifier_service.py
│   │   ├── discovery_service.py
│   │   ├── metadata_catalog_service.py
│   │   ├── oidc_service.py
│   │   ├── policy_enforcement_service.py
│   │   ├── reclassification_service.py
│   │   ├── sensitive_detection_service.py
│   │   └── [25+ additional services]
│   ��── pages/                          # Streamlit pages
│   │   ├── 1_Dashboard.py
│   │   ├── 2_Data_Assets.py
│   │   ├── 3_Classification.py
│   │   ├── 4_Compliance.py
│   │   ├── 6_Data_Intelligence.py
│   │   ├── 10_Administration.py
│   │   └── 12_Policy_Guidance.py
│   ├── components/                     # Reusable UI components
│   │   └── filters.py
│   └── ui/                            # UI-specific modules
│       ├── classification_history_tab.py
│       ├── reclassification_requests.py
│       ├── quick_links.py
│       └── theme.py
├── sql/                               # Database schema and migrations
│   ├── 001_governance_schema.sql
│   ├── 002_tags_and_policies.sql
│   ├── 003_streams_and_tasks.sql
│   └── [15+ additional SQL files]
├── tests/
│   ├── unit/                          # Unit tests
│   ├── integration/                   # Integration tests
│   └── fixtures/                      # Test fixtures
├── docs/                              # Documentation
│   ├── API.md
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── AI_CLASSIFICATION.md
│   ├── COMPLIANCE_PAGE.md
│   └── [8+ additional docs]
├── scripts/                           # Automation scripts
│   ├── setup.ps1                      # Windows setup script
│   ├── run.ps1                        # Windows run script
│   ├── test.ps1                       # Windows test script
│   ├── lint.ps1                       # Windows linting script
│   ├── setup.sh                       # Unix setup script
│   ├── deploy.sh                      # Deployment script
│   └── healthcheck.py                 # Health check utilities
├── .env.example                       # Environment variables template
├── requirements.txt                   # Python dependencies
├── pyproject.toml                     # Project configuration
└── README.md                          # This file
```

## Prerequisites

- **Python 3.8+** (tested with Python 3.8, 3.9, 3.10, 3.11)
- **Snowflake Account** with appropriate permissions for data discovery and governance
- **Environment Variables**: Snowflake credentials, authentication settings, and application secrets

## Key Dependencies

- **Streamlit 1.28+**: Web application framework
- **Snowflake Connector 3.0+**: Database connectivity and Snowpark integration
- **Pandas 2.0+** & **NumPy 1.24+**: Data manipulation and analysis
- **Scikit-learn 1.3+**: Machine learning for AI classification
- **Pydantic 2.0+**: Data validation and settings management
- **Plotly 5.0+** & **Altair 5.0+**: Interactive data visualizations
- **AuthLib 1.2+**: OIDC authentication support
- **Loguru 0.7+**: Advanced logging capabilities

## Getting Started

### Quick Setup

1. **Clone and navigate to the project**:
   ```bash
   cd data-governance-app
   ```

2. **Create and activate virtual environment**:
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. **Install the project in development mode**:
   ```bash
   # Install dependencies and the project itself
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   ```

4. **Configure environment variables**:
   ```bash
   # Copy the example environment file
   cp .env.example .env
   # Edit .env with your Snowflake credentials and configuration
   # Note: The app expects environment variables to be set in the system environment
   # or through a secrets manager, not from .env file in production
   ```

5. **Initialize database schema** (if needed):
   ```bash
   # Run SQL scripts in order from sql/ directory in your Snowflake environment
   # Start with: 001_governance_schema.sql, 002_tags_and_policies.sql, etc.
   # Or use the Administration page in the application for guided setup
   ```

6. **Run the application**:
   ```bash
   streamlit run src/app.py
   ```

   The application will be available at `http://localhost:8501`

## Windows Quickstart

For Windows users, PowerShell helper scripts are provided in `scripts/` to simplify setup and daily workflows.

1. Create/activate a virtual environment and install dependencies:
   ```powershell
   # From the project root: data-governance-app/
   powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
   # Note: Development tools are included in main requirements.txt
   ```

2. Create the `.env` file:
   ```powershell
   Copy-Item .env.example .env
   # Then edit .env and fill in your Snowflake credentials and SECRET_KEY
   ```

3. Run the app (defaults to port 8501):
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1
   # Or specify a different app or port
   powershell -ExecutionPolicy Bypass -File .\scripts\run.ps1 -App 'src/app.py' -Port 8502
   ```

4. Run tests:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1
   # Unit-only or integration-only
   powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1 -Unit
   powershell -ExecutionPolicy Bypass -File .\scripts\test.ps1 -Integration
   ```

5. Lint and type-check:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\lint.ps1
   ```

Notes:
- **Environment Variables**: The app does NOT load from `.env` files by default (see line 11 in `src/app.py`). Environment variables should be set in the system environment or through a secrets manager for production use.
- **Virtual Environment**: The setup script will use an existing `env/` directory if present, otherwise it will create `venv/` or `.venv/` as needed.
- **Development Mode**: The project should be installed in development mode (`pip install -e .`) to ensure proper module imports.

## Application Architecture

### Multi-Page Application Structure
The application is organized into several key pages accessible via Streamlit's navigation:

- **🏠 Dashboard**: Executive overview with key metrics and compliance status
- **📊 Data Assets**: Comprehensive data catalog and asset management
- **🔍 Classification**: AI-powered data classification and review workflows  
- **✅ Compliance**: SOC 2, SOX, and regulatory compliance monitoring
- **🧠 Data Intelligence**: Advanced analytics and behavioral insights
- **⚙️ Administration**: System configuration and user management
- **📋 Policy Guidance**: Data governance policies and procedures

### Core Services Architecture
The application follows a service-oriented architecture with:

- **AI Services**: Machine learning-powered classification and detection
- **Data Services**: Snowflake integration and metadata management
- **Compliance Services**: Regulatory framework monitoring and reporting
- **Authentication Services**: OIDC-based enterprise authentication
- **Audit Services**: Comprehensive logging and evidence collection

### Database Integration
- **Snowflake Data Warehouse**: Primary data source and governance target
- **Governance Schema**: Dedicated schema for classification metadata and audit trails
- **Streaming Updates**: Real-time data change detection and classification updates

## Configuration

### Environment Variables
Key configuration variables in `.env`:

```bash
# Snowflake Connection
SNOWFLAKE_ACCOUNT=your-account.region.cloud
SNOWFLAKE_USER=your-username
SNOWFLAKE_PASSWORD=your-password
SNOWFLAKE_WAREHOUSE=your-warehouse
SNOWFLAKE_DATABASE=your-database
SNOWFLAKE_SCHEMA=your-schema

# Application Security
SECRET_KEY=your-secret-key-for-session-management
OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
OIDC_DISCOVERY_URL=your-oidc-provider-url

# AI/ML Configuration
OPENAI_API_KEY=your-openai-key (optional, for enhanced AI features)
AI_CLASSIFICATION_ENABLED=true
CONTINUOUS_SCANNING_ENABLED=true

# Logging and Monitoring
LOG_LEVEL=INFO
AUDIT_RETENTION_DAYS=365
```

## Development

### Development Setup

1. **Install the project in development mode**:
   ```bash
   # Ensure you're in a virtual environment
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   # All development tools are included in main requirements.txt
   ```

2. **Run tests**:
   ```bash
   # All tests
   pytest
   
   # Unit tests only
   pytest tests/unit/
   
   # Integration tests (requires Snowflake connection)
   pytest tests/integration/
   ```

3. **Code quality checks**:
   ```bash
   # Format code
   black .
   
   # Lint code
   flake8 .
   
   # Type checking
   mypy .
   
   # Or run all checks with the script
   ./scripts/lint.ps1  # Windows
   ./scripts/lint.sh   # Unix
   ```

### Development Workflow

1. **Feature Development**: Create feature branches from `main`
2. **Testing**: Ensure all tests pass and maintain coverage
3. **Code Quality**: Run linting and type checking before commits
4. **Documentation**: Update relevant documentation in `docs/`
5. **Database Changes**: Add SQL migration scripts to `sql/` directory

## Troubleshooting

### Common Setup Issues

1. **Module Import Errors**:
   ```bash
   # Ensure the project is installed in development mode
   pip install -e .
   ```

2. **Streamlit Import Errors**:
   ```bash
   # Make sure you're running from the project root and have activated your virtual environment
   cd data-governance-app
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   streamlit run src/app.py
   ```

3. **Environment Variables Not Loading**:
   - The app does NOT automatically load `.env` files
   - Set environment variables in your system or use a secrets manager
   - For development, you can modify the app.py to load .env files temporarily

4. **Snowflake Connection Issues**:
   - Verify your Snowflake account identifier format
   - Ensure your user has appropriate permissions
   - Check network connectivity and firewall settings

5. **Python Path Issues**:
   - The app adds the project root to Python path automatically (see line 9 in app.py)
   - Ensure you're running from the correct directory

## Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for comprehensive deployment instructions including:
- Production environment setup
- Snowflake configuration requirements  
- Security considerations
- Performance tuning guidelines

## Documentation

Comprehensive documentation is available in the [docs](docs/) directory:

### Technical Documentation
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**: System architecture and design patterns
- **[API.md](docs/API.md)**: API reference and integration guides
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)**: Production deployment procedures

### Feature Documentation  
- **[AI_CLASSIFICATION.md](docs/AI_CLASSIFICATION.md)**: AI-powered classification system
- **[COMPLIANCE_PAGE.md](docs/COMPLIANCE_PAGE.md)**: Compliance monitoring features
- **[DATA_ASSETS_UI_UX_GUIDE.md](docs/DATA_ASSETS_UI_UX_GUIDE.md)**: Data assets interface guide

### Implementation Guides
- **[DATA_CLASSIFICATION_POLICY.md](docs/DATA_CLASSIFICATION_POLICY.md)**: Classification policies and procedures
- **[IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md)**: Current implementation status and roadmap

## Support and Contributing

For questions, issues, or contributions:
1. Check existing documentation in the `docs/` directory
2. Review the codebase and inline comments
3. Run the test suite to understand expected behavior
4. Follow the development workflow outlined above

## License

This project is proprietary software for enterprise data governance.