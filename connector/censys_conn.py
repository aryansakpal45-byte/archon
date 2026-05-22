import os
from censys.search import CensysHosts
from connector.base import BaseConnector

class CensysConnector(BaseConnector):
    def __init__(self):
        # 1. Grab your actual token
        token = os.getenv("CENSYS_API_TOKEN")
        
        # 2. Inject dummy environment variables to satisfy the library's internal check
        os.environ["CENSYS_API_ID"] = "DUMMY_ID"
        os.environ["CENSYS_API_SECRET"] = "DUMMY_SECRET"
        
        # 3. Initialize the client
        self.api = CensysHosts(api_token=token)

    def fetch(self, target):
        try:
            return self.api.view(target)
        except Exception as e:
            return {"error": str(e)}