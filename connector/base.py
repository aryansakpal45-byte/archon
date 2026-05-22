class BaseConnector:
    def fetch(self, target):
        # Every connector MUST have a fetch method
        raise NotImplementedError("Connectors must implement the fetch() method.")