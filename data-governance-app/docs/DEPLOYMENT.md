# Deployment Guide

## Overview

This guide provides instructions for deploying the Data Governance Application in different environments.

## Prerequisites

- Python 3.8 or higher
- Docker (for containerized deployment)
- Snowflake account with appropriate permissions
- Environment variables configured

## Local Development Deployment

### 1. Clone the Repository

```bash
git clone <repository-url>
cd data-governance-app
```

### 2. Set Up Environment

```bash
# Run the setup script
./scripts/setup.sh --dev

# Activate virtual environment
source venv/bin/activate

# Configure environment variables
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run the Application

```bash
streamlit run src/app.py
```

The application will be available at `http://localhost:8501`

## Docker Deployment

### 1. Build the Docker Image

```bash
docker build -t data-governance-app:latest .
```

### 2. Run with Docker

```bash
docker run -p 8501:8501 \
  -e SNOWFLAKE_ACCOUNT=your_account \
  -e SNOWFLAKE_USER=your_user \
  -e SNOWFLAKE_PASSWORD=your_password \
  -e SNOWFLAKE_WAREHOUSE=your_warehouse \
  data-governance-app:latest
```

### 3. Run with Docker Compose

```bash
docker-compose up
```

## Cloud Deployment

### AWS Deployment

1. Create an ECS cluster
2. Build and push Docker image to ECR
3. Deploy ECS service with appropriate task definition
4. Configure environment variables in AWS Systems Manager Parameter Store

### Azure Deployment

1. Create an Azure Container Instances deployment
2. Push Docker image to Azure Container Registry
3. Configure environment variables in Azure Key Vault

### Google Cloud Deployment

1. Create a Google Cloud Run service
2. Push Docker image to Google Container Registry
3. Configure environment variables in Secret Manager

## Environment Variables

The following environment variables must be configured:

| Variable | Description | Required |
|----------|-------------|----------|
| SNOWFLAKE_ACCOUNT | Snowflake account identifier | Yes |
| SNOWFLAKE_USER | Snowflake username | Yes |
| SNOWFLAKE_PASSWORD | Snowflake password | Yes |
| SNOWFLAKE_WAREHOUSE | Snowflake warehouse name | Yes |
| SNOWFLAKE_DATABASE | Snowflake database name | No |
| SNOWFLAKE_SCHEMA | Snowflake schema name | No |
| APP_NAME | Application name | No |
| DEBUG | Debug mode (True/False) | No |
| LOG_LEVEL | Logging level (DEBUG, INFO, WARNING, ERROR) | No |
| SECRET_KEY | Secret key for security | Yes |

## Database Setup

Before deploying, ensure the following Snowflake objects exist:

1. Database: `DATA_GOVERNANCE`
2. Schema: `DATA_GOVERNANCE`
3. Tables:
   - `DATA_ASSETS`
   - `CLASSIFICATIONS`
   - `COMPLIANCE_CONTROLS`
   - `DATA_QUALITY_METRICS`
   - `USERS`
   - `AUDIT_LOGS`

## Monitoring and Logging

- Application logs are written to stdout/stderr
- Configure log aggregation (e.g., ELK stack, Splunk) for production deployments
- Set up health checks using the `/healthz` endpoint

## Backup and Recovery

- Regular backups of Snowflake data
- Version control for application code
- Disaster recovery plan for cloud deployments

## Security Considerations

- Use secrets management for sensitive configuration
- Enable encryption at rest and in transit
- Regularly rotate credentials
- Implement network security groups/firewalls
- Regular security scanning of Docker images

## Scaling

- Horizontal scaling by increasing container instances
- Vertical scaling by increasing container resources
- Database scaling through Snowflake warehouse sizing

## Troubleshooting

### Common Issues

1. **Connection failures to Snowflake**
   - Verify Snowflake credentials
   - Check network connectivity
   - Ensure Snowflake account is accessible

2. **Application fails to start**
   - Check environment variables
   - Verify Docker image was built correctly
   - Check application logs

3. **Performance issues**
   - Monitor Snowflake query performance
   - Check container resource utilization
   - Review application logging for errors

### Health Checks

The application provides a health check endpoint at `/healthz` which returns HTTP 200 when the application is healthy.