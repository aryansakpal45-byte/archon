from abc import ABC, abstractmethod

class BaseConnector(ABC):
    @abstractmethod
    def fetch(self, target: str) -> dict:
        """Fetch intelligence for the given target."""
        pass
