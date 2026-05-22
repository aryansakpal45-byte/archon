import os
from censys.search import CensysHosts
from connector.base import BaseConnector

class CensysConnector(BaseConnector):
    def __init__(self):
        # Explicitly get the token from your .env
        self.api_token = os.getenv("CENSYS_API_TOKEN")
        
        # This is the key: pass 'api_token' explicitly to the constructor
        # This overrides the library's internal search for ID/Secret
        self.api = CensysHosts(api_token=self.api_token)
        
        # 2. Force the client to use the token ONLY
        # Passing 'api_token' here overrides the library's search for ID/Secret
        self.api = CensysHosts(api_token=self.api_token)

    def fetch(self, target):
        try:
            return self.api.view(target)
        except Exception as e:
            return {"error": str(e)}