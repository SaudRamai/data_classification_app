from src.connectors.snowflake_connector import snowflake_connector
try:
    roles = snowflake_connector.execute_query("SHOW ROLES")
    print(f"Total roles: {len(roles)}")
    for r in roles[:5]:
        print(f"Role: {r.get('name')}, Owner: {r.get('owner')}")
except Exception as e:
    print(f"Error: {e}")
