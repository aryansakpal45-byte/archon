import os
import shodan
from .base import BaseConnector

class ShodanConnector(BaseConnector):
    def __init__(self):
        # We fetch the API key from your .env file
        self.api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))

    def fetch(self, target):
        """
        Connects to Shodan and fetches host intelligence.
        """
        try:
            # target here could be an IP address
            data = self.api.host(target)
            return data
        except Exception as e:
            # Returning None or error message helps the main orchestrator handle failures
            return {"error": str(e)}