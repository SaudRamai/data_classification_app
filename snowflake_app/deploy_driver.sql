-- IMPORTANT: You cannot run setup.sql directly in a worksheet.
-- It is executed automatically by Snowflake when you create or upgrade the Application.

-- Use these commands to deploy/update your app:

USE ROLE accountadmin; -- or your developer role

-- 1. Ensure Application Package exists
CREATE APPLICATION PACKAGE IF NOT EXISTS DATA_CLASSIFICATION_APP_PACKAGE;

-- 2. Create the Application (This will read manifest.yml and run setup.sql)
-- Make sure your files are uploaded to the stage defined in your package (e.g., named 'app_stage' or similar)
-- Structure on stage must be:
--   /setup.sql
--   /manifest.yml
--   /streamlit/streamlit_app.py
--   /streamlit/environment.yml
--   /streamlit/src/...

-- Option A: Fresh Install
DROP APPLICATION IF EXISTS DATA_CLASSIFICATION_APP;
CREATE APPLICATION DATA_CLASSIFICATION_APP
  FROM APPLICATION PACKAGE DATA_CLASSIFICATION_APP_PACKAGE
  USING '@DATA_CLASSIFICATION_APP_PACKAGE.APP_SCHEMA.APP_STAGE'; -- Checks for files here

-- Option B: Upgrade Existing App (Debug Mode)
-- ALTER APPLICATION DATA_CLASSIFICATION_APP UPGRADE USING '@DATA_CLASSIFICATION_APP_PACKAGE.APP_SCHEMA.APP_STAGE';
