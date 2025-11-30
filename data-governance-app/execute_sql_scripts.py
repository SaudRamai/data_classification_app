import os
import sys
import re
import logging

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

from src.connectors.snowflake_connector import snowflake_connector
from src.config.settings import settings

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def remove_comments(sql):
    """Removes SQL comments (-- and /* */) from a string."""
    # Remove block comments
    sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)
    # Remove line comments
    lines = sql.split('\n')
    cleaned_lines = []
    for line in lines:
        # Simple removal of -- comments, handling potential quotes is harder but this usually works for DDL
        if '--' in line:
            line = line.split('--')[0]
        cleaned_lines.append(line)
    return '\n'.join(cleaned_lines)

def split_statements(sql):
    """Splits SQL string into individual statements by semicolon."""
    # This is a naive splitter. For complex SQL with semicolons in strings, this might fail.
    # However, for DDLs and simple inserts, it usually works.
    # A better approach would be to use a proper SQL parser, but we want to keep dependencies low.
    statements = []
    current_statement = []
    
    # Simple state machine to handle quotes
    in_single_quote = False
    in_double_quote = False
    
    for char in sql:
        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
        elif char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        
        if char == ';' and not in_single_quote and not in_double_quote:
            stmt = ''.join(current_statement).strip()
            if stmt:
                statements.append(stmt)
            current_statement = []
        else:
            current_statement.append(char)
            
    stmt = ''.join(current_statement).strip()
    if stmt:
        statements.append(stmt)
        
    return statements

def execute_sql_file(file_path):
    logger.info(f"Executing SQL file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()
            
        # Replace variables
        db_name = getattr(settings, "SNOWFLAKE_DATABASE", "DATA_CLASSIFICATION_DB")
        sql_content = sql_content.replace("$DATABASE", db_name)
        sql_content = sql_content.replace("$DB_NAME", db_name)
        
        # Remove comments
        sql_content = remove_comments(sql_content)
        
        # Split statements
        statements = split_statements(sql_content)
        
        for stmt in statements:
            if not stmt.strip():
                continue
                
            logger.info(f"Executing statement: {stmt[:50]}...")
            try:
                snowflake_connector.execute_non_query(stmt)
            except Exception as e:
                logger.error(f"Error executing statement: {stmt[:100]}...\nError: {e}")
                # We might want to continue or stop depending on severity. 
                # For DDLs, usually we want to stop, but for idempotent scripts, maybe continue.
                # Let's stop on error to be safe.
                raise e
                
        logger.info(f"Successfully executed {file_path}")
        
    except Exception as e:
        logger.error(f"Failed to execute {file_path}: {e}")
        raise

def main():
    scripts = [
        "sql/001_governance_schema.sql",
        "sql/002_governance_seed_data.sql",
        "populate_sensitive_patterns.sql",
        "sql/900_data_classification_governance_init.sql"
    ]
    
    for script in scripts:
        file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), script))
        if os.path.exists(file_path):
            execute_sql_file(file_path)
        else:
            logger.error(f"Script not found: {file_path}")

if __name__ == "__main__":
    main()
