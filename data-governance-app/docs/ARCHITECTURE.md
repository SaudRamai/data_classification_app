# Architecture Documentation

## Overview

The Data Governance Application is a Streamlit-based web application that provides data classification, compliance monitoring, and data quality assessment capabilities with Snowflake integration.

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   Streamlit     │    │   Application    │    │   Snowflake      │
│   Frontend      │◄──►│   Services       │◄──►│   Data Warehouse │
└─────────────────┘    └──────────────────┘    └──────────────────┘
                              │                         │
                              ▼                         ▼
                       ┌─────────────┐         ┌──────────────────┐
                       │   Models    │         │   Data Assets    │
                       └─────────────┘         └──────────────────┘
                              │
                              ▼
                       ┌─────────────┐
                       │  Utilities  │
                       └─────────────┘
```

## Component Diagram

### Frontend Layer
- **Streamlit UI**: Main user interface built with Streamlit
- **Pages**: Individual application pages for different functionalities
- **Components**: Reusable UI components

### Application Layer
- **Services**: Business logic layer (data_service, auth_service)
- **Models**: Data models and schemas
- **Connectors**: Database connectors (Snowflake)
- **Utilities**: Helper functions (logger, validators)

### Configuration Layer
- **Settings**: Application configuration
- **Constants**: Application constants

### Data Layer
- **Snowflake**: Data warehouse for storing data assets, classifications, and compliance data

## Data Flow

1. User interacts with Streamlit frontend
2. Frontend calls service layer for business logic
3. Services interact with Snowflake connector for data operations
4. Connectors execute queries against Snowflake
5. Results are returned to services
6. Services process and return data to frontend
7. Frontend renders results to user

## Security Architecture

- **Authentication**: Username/password authentication with secure password hashing
- **Authorization**: Role-based access control (RBAC)
- **Data Protection**: Environment variables for sensitive configuration
- **Connection Security**: Secure Snowflake connection with encrypted credentials
- **Audit Logging**: Comprehensive audit trails for all user actions

## Deployment Architecture

- **Containerization**: Docker container for consistent deployment
- **Orchestration**: Docker Compose for multi-container deployments
- **Environment Management**: Environment variables for configuration
- **Health Monitoring**: Health checks for application status

## Scalability Considerations

- **Connection Pooling**: Reuse of database connections
- **Caching**: Potential for implementing caching strategies
- **Pagination**: Handling large datasets with pagination
- **Asynchronous Operations**: Potential for async operations where applicable

## Compliance Architecture

- **Data Classification**: Implementation of CIA triad for data classification
- **Audit Trails**: Comprehensive logging for compliance requirements
- **Access Controls**: Role-based access to ensure proper data handling
- **Data Quality**: Quality metrics for compliance monitoring