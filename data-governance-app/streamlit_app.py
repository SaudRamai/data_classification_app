import os
import sys
import pathlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get the directory containing this file
current_dir = pathlib.Path(__file__).resolve().parent
src_dir = current_dir / "src"

# Add the src directory to Python path
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

# Set environment variable to indicate we're running locally
os.environ["STREAMLIT_RUN_LOCAL"] = "true"

try:
    # Import the main application
    from app import app as application
    
    # For local development, run the app directly
    if __name__ == "__main__":
        import streamlit.web.bootstrap
        from streamlit.web.cli import _main_run
        
        # Set up command line arguments for Streamlit
        sys.argv = [
            "streamlit", "run",
            str(src_dir / "app.py"),
            "--server.port=8501",
            "--server.headless=true",
            "--server.fileWatcherType=none",
            "--browser.gatherUsageStats=false"
        ]
        
        # Run the Streamlit app
        _main_run(__file__, "", args=sys.argv[1:], flag_options={})
        
except Exception as e:
    logger.error("Failed to start application", exc_info=True)
    print(f"Error: {str(e)}", file=sys.stderr)
    sys.exit(1)