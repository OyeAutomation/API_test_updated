"""Start the mock server on port 5000."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mock_server.app import app
print("Mock server starting on http://localhost:5000", flush=True)
app.run(port=5000, debug=False)
