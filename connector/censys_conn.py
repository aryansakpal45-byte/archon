import os
from censys.search import CensysHosts
from connector.base import BaseConnector

class CensysConnector(BaseConnector):
    def __init__(self):
        # Ensure we are pulling the correct key
        self.api_token = os.getenv("CENSYS_API_TOKEN")
        
        if not self.api_token:
            raise ValueError("CENSYS_API_TOKEN not found in .env file.")
        
        # EXPLICIT FIX: We pass api_token, and explicitly set id/secret to None
        # to prevent the library from searching the environment for legacy keys.
        self.api = CensysHosts(
            api_id=None, 
            api_secret=None, 
            api_token=self.api_token
        )

    def fetch(self, target):
        try:
            return self.api.view(target)
        except Exception as e:
            return {"error": f"Censys Fetch Error: {str(e)}"}