# Data Governance Application

An enterprise-grade Streamlit application for data classification and compliance monitoring with Snowflake integration.

## Features

- Data classification framework with CIA triad assessment
- Compliance monitoring for SOC 2 and SOX requirements
- Data quality assessment and monitoring
- Snowflake data warehouse integration
- Role-based access control
- Audit trails and reporting

## Project Structure

```
project_root/
├── src/
│   ├── __init__.py
│   ├── app.py
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py
│   │   └── constants.py
│   ├── connectors/
│   │   ├── __init__.py
│   │   └── snowflake_connector.py
│   ├── models/
│   │   ├── __init__.py
│   │   └── data_models.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── data_service.py
│   │   └── auth_service.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logger.py
│   │   └── validators.py
│   ├── pages/
│   │   └── [streamlit pages]
│   └── components/
│       └── [reusable UI components]
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── API.md
│   ├── DEPLOYMENT.md
│   └── ARCHITECTURE.md
├── scripts/
│   ├── setup.sh
│   └── deploy.sh
├── .env.example
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
├── setup.py
└── README.md
```

## Getting Started

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Set up environment variables (copy .env.example to .env and fill in values)

3. Run the application:
   ```
   streamlit run src/app.py
   ```

## Windows Quickstart

For Windows users, PowerShell helper scripts are provided in `scripts/` to simplify setup and daily workflows.

1. Create/activate a virtual environment and install dependencies:
   ```powershell
   # From the project root: data-governance-app/
   powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
   # For development tools as well (pytest, black, flake8, mypy):
   powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1 -Dev
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
- The app loads environment variables from `data-governance-app/.env`. This is handled both by `src/app.py` (via python-dotenv) and by `pydantic-settings` if configured.
- If you already have a virtual environment under `env/` (as included in this repo), scripts will prefer it; otherwise, they will create and use `.venv/`.

## Development

1. Install development dependencies:
   ```
   pip install -r requirements-dev.txt
   ```

2. Run tests:
   ```
   pytest
   ```

3. Run code quality checks:
   ```
   black .
   flake8 .
   mypy .
   ```

## Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for deployment instructions.

## Documentation

See the [docs](docs/) directory for detailed documentation.