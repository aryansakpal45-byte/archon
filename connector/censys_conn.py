import os
from censys.search import CensysHosts
from .base import BaseConnector

class CensysConnector(BaseConnector):
    def __init__(self):
        # Ensure we are grabbing the exact key name from .env
        token = os.getenv("CENSYS_API_TOKEN")
        if not token:
            raise ValueError("CENSYS_API_TOKEN is missing from .env file!")
        
        # Explicitly passing api_token
        self.api = CensysHosts(api_token=token)

    def fetch(self, target):
        try:
            return self.api.view(target)
        except Exception as e:
            return {"error": str(e)}