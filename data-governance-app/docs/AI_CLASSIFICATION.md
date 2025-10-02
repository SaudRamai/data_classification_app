# AI Classification Feature

## Overview

The AI Classification feature automatically classifies data assets and identifies applicable compliance frameworks using machine learning techniques that run locally without external APIs. This feature analyzes table metadata, column names, and sample data to determine appropriate classifications and compliance requirements.

## How It Works

1. **Feature Extraction**: The system extracts features from:
   - Table names and schema names
   - Column names and data types
   - Sample data content (first 50 rows)

2. **Classification**: Using rule-based algorithms enhanced with ML techniques:
   - Determines data classification level (Public, Internal, Restricted, Confidential)
   - Identifies applicable compliance frameworks (SOC 2, SOX, PII)
   - Provides confidence scores for classifications

3. **Compliance Mapping**: Maps data characteristics to compliance requirements:
   - PII detection based on column names and content patterns
   - Financial data identification for SOX compliance
   - Security-related data identification for SOC 2 compliance

## Key Components

- `src/ml/classifier.py`: Core ML classifier with rule-based and ML techniques
- `src/services/ai_classification_service.py`: Integration service with Snowflake
- `src/pages/3_Classification.py`: Updated UI with AI Classification tab

## Features

- **Individual Asset Classification**: Classify single data assets with detailed analysis
- **Bulk Classification**: Classify all data assets at once with summary statistics
- **Confidence Scoring**: Provides confidence levels for all classifications
- **No External Data Transfer**: All processing happens locally within your environment
- **Real-time Analysis**: Immediate results without batch processing delays

## Compliance Frameworks Detected

- **PII (Personally Identifiable Information)**: Identifies data containing personal information
- **SOX (Sarbanes-Oxley Act)**: Identifies financial data requiring SOX compliance
- **SOC 2**: Identifies data requiring security and privacy controls

## Usage

1. Navigate to the Classification page in the data governance app
2. Select the "AI Classification" tab
3. Choose a data asset from the dropdown
4. Click "Classify with AI" to analyze the asset
5. View classification results, compliance frameworks, and confidence scores

For bulk analysis, use the "Run Bulk AI Classification" button to classify all assets.

## Technical Details

The classifier uses a combination of:
- Keyword matching for compliance framework identification
- Pattern recognition in column names
- Statistical analysis of data content
- Rule-based scoring systems
- TF-IDF vectorization for text analysis (extensible)

All processing is done locally without sending data to external services, ensuring data privacy and compliance.