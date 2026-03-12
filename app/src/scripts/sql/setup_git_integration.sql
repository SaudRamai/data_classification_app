-- ============================================================================
-- SNOWFLAKE GIT INTEGRATION & DEPLOYMENT SCRIPT
-- ============================================================================
-- Description: Setup script for Snowflake Native Git Integration to deploy the app.
-- This allows you to pull code directly from your Git repository into Snowflake.
--
-- Prerequisites:
-- 1. A supported Git provider (GitHub, GitLab, Azure DevOps, Bitbucket).
-- 2. Privileges to create INTEGRATIONS and SECRETS (usually ACCOUNTADMIN).
-- 3. Update the placeholders <...> with your actual values.
-- ============================================================================

-- Switch to a role with sufficient privileges
USE ROLE ACCOUNTADMIN; 

-- ============================================================================
-- STEP 1: Create API Integration (One-time setup)
-- ============================================================================
-- NOTE: You must configure the trust relationship in your Git provider (e.g., AWS/Azure).
-- This step varies by provider. Below is a generic template for GitHub.
-- See docs: https://docs.snowflake.com/en/user-guide/git-integration-create-api-integration

/*
CREATE OR REPLACE API INTEGRATION git_api_integration
  API_PROVIDER = git_https_api
  API_ALLOWED_PREFIXES = ('https://github.com/<your-org>') -- REPLACE THIS
  ALLOWED_AUTHENTICATION_SECRETS = all
  ENABLED = TRUE;
*/

-- ============================================================================
-- STEP 2: Create Secret for Authentication (If repo is private)
-- ============================================================================
-- For private repos, you need a Personal Access Token (PAT) or similar credential.

/*
CREATE OR REPLACE SECRET git_pat_secret
  TYPE = password
  USERNAME = '<your-git-username>'
  PASSWORD = '<your-personal-access-token>';
*/

-- ============================================================================
-- STEP 3: Create Git Repository Object
-- ============================================================================
-- This creates the link between Snowflake and your Git repo.

CREATE OR REPLACE GIT REPOSITORY data_classification_app_repo
  API_INTEGRATION = git_api_integration
  -- Replace with your actual repository URL
  ORIGIN = 'https://github.com/<your-org>/<your-repo>.git' 
  -- SECRET = git_pat_secret -- Uncomment if using private repo
  ;

-- Verify the integration
-- LS @data_classification_app_repo/branches/main/;

-- ============================================================================
-- STEP 4: Fetch Latest Code from Git
-- ============================================================================
-- Run this whenever you push new changes to Git to update Snowflake's cache.

ALTER GIT REPOSITORY data_classification_app_repo FETCH;

-- ============================================================================
-- STEP 5: Create Application Package
-- ============================================================================

CREATE DATABASE IF NOT EXISTS DATA_CLASSIFICATION_APP_PACKAGE_DB;
CREATE APPLICATION PACKAGE IF NOT EXISTS data_classification_app_package;

USE APPLICATION PACKAGE data_classification_app_package;
CREATE SCHEMA IF NOT EXISTS app_schema;

-- ============================================================================
-- STEP 6: Deploy Files to Stage
-- ============================================================================
-- We copy the files from the Git repo to the application package stage.

CREATE OR REPLACE STAGE app_stage
  FILE_FORMAT = (TYPE = 'CSV' FIELD_DELIMITER = '|' SKIP_HEADER = 1); -- Dummy format

-- Copy all files from the root of the repo to the stage
-- Adjust the path if your app code is in a subdirectory (e.g. /src)
COPY FILES INTO @data_classification_app_package.app_schema.app_stage
  FROM @data_classification_app_repo/branches/main/
  PATTERN = '.*'
  ;

-- ============================================================================
-- STEP 7: Create/Update Application Instance
-- ============================================================================

-- Create the application instance from the package
CREATE APPLICATION IF NOT EXISTS DATA_CLASSIFICATION_APP
  FROM APPLICATION PACKAGE data_classification_app_package
  USING '@data_classification_app_package.app_schema.app_stage';

-- If the application already exists and you want to upgrade it (for development):
/*
ALTER APPLICATION DATA_CLASSIFICATION_APP 
  UPGRADE USING '@data_classification_app_package.app_schema.app_stage';
*/

-- Grants for the application
-- GRANT APPLICATION ROLE app_public TO ROLE ACCOUNTADMIN;
