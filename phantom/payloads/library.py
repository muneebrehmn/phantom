import json
import os
from glob import glob
from typing import List, Dict
from phantom.core.logger import get_logger

logger = get_logger(__name__)

class Payload:
    """Container for payload data loaded from JSON."""
    def __init__(self, data: Dict):
        self.id = data['id']
        self.text = data['text']
        self.description = data['description']
        self.success_pattern = data['success_pattern']
        self.severity = data['severity']
        self.tags = data.get('tags', [])

class PayloadLibrary:
    """Manages the loading and selection of prompt injection payloads."""
    
    def __init__(self, data_path: str = "phantom/payloads/data"):
        self.payloads: Dict[str, List[Payload]] = {}
        self._load_all(data_path)

    def _load_all(self, path: str):
        """Scans the data directory and loads valid JSON payload files."""
        for filepath in glob(os.path.join(path, "*.json")):
            category = os.path.basename(filepath).replace(".json", "")
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    # Validate schema
                    valid_list = [
                        Payload(p) for p in data 
                        if all(k in p for k in ("id", "text", "success_pattern"))
                    ]
                    self.payloads[category] = valid_list
                    logger.info(f"Loaded {len(valid_list)} payloads for '{category}'")
            except Exception as e:
                logger.error(f"Failed to load payload file {filepath}: {e}")

    def get_by_category(self, category: str) -> List[Payload]:
        """Fetch all payloads within a specific category (e.g., 'direct')."""
        return self.payloads.get(category, [])

    def get_by_surface_type(self, attack_vectors: List[str]) -> List[Payload]:
        """Matches payloads based on the attack vectors identified by the classifier."""
        selected = []
        for vector in attack_vectors:
            if vector in self.payloads:
                selected.extend(self.payloads[vector])
        
        # Default to direct injection if no specific vectors match
        return selected if selected else self.get_by_category("direct")