#!/bin/sh

# Wait for the PostgreSQL database to be ready (optional, but good practice)
# This is often done by checking if the DB is accepting connections.
# Assuming your Python code already has connection retry logic, we can skip this step for simplicity.

# 1. Run the table creation command (Using python to run the creation logic)
# The file is 'CyberX-2.py' in the container.
python -c "from CyberX_2 import db, app; app.app_context().push(); db.create_all()"
# 2. Start the Gunicorn server
exec gunicorn --bind 0.0.0.0:8080 CyberX_2:app