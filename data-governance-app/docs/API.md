# API Documentation

## Overview

The Data Governance Application provides a RESTful API for programmatic access to data governance functionality. The API is built on top of the Streamlit application and provides endpoints for data assets, classifications, compliance, and user management.

## Authentication

All API endpoints require authentication. Currently, the application uses session-based authentication through the Streamlit interface.

For programmatic access, API tokens can be generated through the user interface and used in the `Authorization` header:

```
Authorization: Bearer <api_token>
```

## Data Assets API

### Get Data Assets

Retrieve a list of data assets.

```
GET /api/data-assets
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| limit | integer | Number of records to return (default: 50) |
| offset | integer | Number of records to skip (default: 0) |
| classification | string | Filter by classification level |
| owner | string | Filter by owner |

**Response:**

```json
{
  "data": [
    {
      "id": "asset_123",
      "name": "Customer Data Table",
      "description": "Table containing customer information",
      "location": "CUSTOMER_DB.CUSTOMER_SCHEMA.CUSTOMERS",
      "classification_level": "Confidential",
      "cia_rating": {
        "confidentiality": 3,
        "integrity": 2,
        "availability": 2
      },
      "owner": "john.doe@company.com",
      "tags": ["PII", "Customer"],
      "created_at": "2023-01-01T00:00:00Z",
      "updated_at": "2023-01-01T00:00:00Z",
      "last_classified": "2023-01-01T00:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### Get Data Asset by ID

Retrieve a specific data asset by ID.

```
GET /api/data-assets/{id}
```

**Response:**

```json
{
  "id": "asset_123",
  "name": "Customer Data Table",
  "description": "Table containing customer information",
  "location": "CUSTOMER_DB.CUSTOMER_SCHEMA.CUSTOMERS",
  "classification_level": "Confidential",
  "cia_rating": {
    "confidentiality": 3,
    "integrity": 2,
    "availability": 2
  },
  "owner": "john.doe@company.com",
  "tags": ["PII", "Customer"],
  "created_at": "2023-01-01T00:00:00Z",
  "updated_at": "2023-01-01T00:00:00Z",
  "last_classified": "2023-01-01T00:00:00Z"
}
```

### Create Data Asset

Create a new data asset.

```
POST /api/data-assets
```

**Request Body:**

```json
{
  "name": "New Data Table",
  "description": "Description of the new data table",
  "location": "DATABASE.SCHEMA.TABLE",
  "classification_level": "Internal",
  "cia_rating": {
    "confidentiality": 1,
    "integrity": 1,
    "availability": 1
  },
  "owner": "jane.doe@company.com",
  "tags": ["New", "Table"]
}
```

**Response:**

```json
{
  "id": "asset_456",
  "message": "Data asset created successfully"
}
```

### Update Data Asset

Update an existing data asset.

```
PUT /api/data-assets/{id}
```

**Request Body:**

```json
{
  "name": "Updated Data Table",
  "description": "Updated description",
  "classification_level": "Confidential",
  "cia_rating": {
    "confidentiality": 3,
    "integrity": 2,
    "availability": 2
  },
  "owner": "jane.doe@company.com",
  "tags": ["Updated", "PII", "Customer"]
}
```

**Response:**

```json
{
  "message": "Data asset updated successfully"
}
```

### Delete Data Asset

Delete a data asset.

```
DELETE /api/data-assets/{id}
```

**Response:**

```json
{
  "message": "Data asset deleted successfully"
}
```

## Classification API

### Update Classification

Update the classification of a data asset.

```
POST /api/classification
```

**Request Body:**

```json
{
  "asset_id": "asset_123",
  "classification_level": "Confidential",
  "cia_rating": {
    "confidentiality": 3,
    "integrity": 2,
    "availability": 2
  },
  "justification": "Contains personally identifiable information"
}
```

**Response:**

```json
{
  "message": "Classification updated successfully"
}
```

## Compliance API

### Get Compliance Controls

Retrieve compliance controls.

```
GET /api/compliance-controls
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| framework | string | Filter by compliance framework (SOC2, SOX, etc.) |
| status | string | Filter by implementation status |

**Response:**

```json
{
  "data": [
    {
      "id": "soc2_cc1.1",
      "name": "CC1.1 Risk Assessment",
      "framework": "SOC2",
      "description": "The entity identifies and analyzes risks relating to objectives",
      "implementation_status": "Implemented",
      "last_assessed": "2023-01-01T00:00:00Z"
    }
  ]
}
```

### Get Compliance Status

Get overall compliance status.

```
GET /api/compliance-status
```

**Response:**

```json
{
  "overall_score": 92,
  "frameworks": [
    {
      "name": "SOC2",
      "score": 95
    },
    {
      "name": "SOX",
      "score": 89
    }
  ]
}
```

## Data Quality API

### Get Data Quality Metrics

Retrieve data quality metrics for a data asset.

```
GET /api/data-quality/{asset_id}
```

**Response:**

```json
{
  "asset_id": "asset_123",
  "metrics": [
    {
      "dimension": "Completeness",
      "score": 0.95
    },
    {
      "dimension": "Accuracy",
      "score": 0.92
    },
    {
      "dimension": "Consistency",
      "score": 0.88
    }
  ]
}
```

## User Management API

### Get Current User

Get information about the current user.

```
GET /api/user
```

**Response:**

```json
{
  "id": "user_1",
  "username": "johndoe",
  "email": "john.doe@company.com",
  "role": "Admin",
  "created_at": "2023-01-01T00:00:00Z"
}
```

### Get User Permissions

Get permissions for the current user.

```
GET /api/user/permissions
```

**Response:**

```json
{
  "permissions": [
    "read",
    "write",
    "delete",
    "admin"
  ]
}
```

## Error Handling

The API uses standard HTTP status codes to indicate the success or failure of requests:

| Status Code | Description |
|-------------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 500 | Internal Server Error |

Error responses follow this format:

```json
{
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

## Rate Limiting

The API implements rate limiting to prevent abuse. Current limits are:

- 100 requests per minute per IP address
- 1000 requests per hour per user

Exceeding these limits will result in a 429 (Too Many Requests) response.