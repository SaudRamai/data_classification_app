-- Setup script for Snowflake Native App
CREATE OR ALTER VERSIONED SCHEMA app_schema;

GRANT USAGE ON SCHEMA app_schema TO APPLICATION ROLE app_public;

CREATE OR REPLACE STREAMLIT app_schema.data_governance_streamlit
  FROM '/streamlit'
  MAIN_FILE = 'streamlit_app.py';

GRANT USAGE ON STREAMLIT app_schema.data_governance_streamlit TO APPLICATION ROLE app_public;