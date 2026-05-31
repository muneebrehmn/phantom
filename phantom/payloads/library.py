"""
Payload management and loading from JSON files.

Responsibilities:
- Load payloads from phantom/payloads/data/*.json
- Validate payload structure against schema
- Provide access by category or attack vector
- Track loading errors explicitly

Design:
- Lazy-loading of payload files (optional future enhancement)
- Schema validation at load time (fail fast)
- Explicit error handling with custom exceptions
- Type-safe access patterns
"""

from __future__ import annotations

import json
import os
from glob import glob
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from phantom.core.logger import get_logger

if TYPE_CHECKING:
    from phantom.core.types import PayloadDict

logger = get_logger(__name__)

# Required keys that all payloads must have
REQUIRED_PAYLOAD_KEYS = {"id", "text", "description", "success_pattern"}


class Payload:
    """Container for payload data loaded from JSON."""

    def __init__(self, data: Dict[str, Any]) -> None:
        """
        Initialize a Payload from JSON data.

        Args:
            data: Dictionary from parsed JSON

        Raises:
            ValueError: If required fields are missing
        """
        missing_keys = REQUIRED_PAYLOAD_KEYS - set(data.keys())
        if missing_keys:
            raise ValueError(f"Payload missing required keys: {missing_keys}")

        self.id: str = data["id"]
        self.text: str = data["text"]
        self.description: str = data["description"]
        self.success_pattern: str = data["success_pattern"]
        self.severity: str = data.get("severity", "medium")
        self.tags: List[str] = data.get("tags", [])
        self.model_targets: List[str] = data.get("model_targets", [])
        self.success_rate: float = data.get("success_rate", 0.0)
        self.mitigation_difficulty: str = data.get("mitigation_difficulty", "unknown")

    def __repr__(self) -> str:
        return f"Payload(id={self.id}, severity={self.severity})"


class PayloadLibrary:
    """Manages the loading and selection of prompt injection payloads."""

    def __init__(self, data_path: str = "phantom/payloads/data") -> None:
        """
        Initialize library and load all payload files.

        Args:
            data_path: Directory containing *.json payload files

        Raises:
            FileNotFoundError: If data_path doesn't exist
        """
        if not os.path.isdir(data_path):
            raise FileNotFoundError(f"Payload data directory not found: {data_path}")

        self.payloads: Dict[str, List[Payload]] = {}
        self.load_errors: List[tuple[str, Exception]] = []
        self._load_all(data_path)

    def _load_all(self, path: str) -> None:
        """Scans the data directory and loads valid JSON payload files."""
        for filepath in sorted(glob(os.path.join(path, "*.json"))):
            category = os.path.basename(filepath).replace(".json", "")
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Validate it's a list
                if not isinstance(data, list):
                    raise ValueError(f"Expected list, got {type(data).__name__}")

                # Load and validate each payload
                valid_payloads: List[Payload] = []
                for item in data:
                    try:
                        payload = Payload(item)
                        valid_payloads.append(payload)
                    except ValueError as e:
                        logger.warning(f"Skipping invalid payload in {filepath}: {e}")
                        continue

                if valid_payloads:
                    self.payloads[category] = valid_payloads
                    logger.info(f"Loaded {len(valid_payloads)} payloads for '{category}'")
                else:
                    logger.warning(f"No valid payloads found in {filepath}")

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse JSON in {filepath}: {e}"
                logger.error(error_msg)
                self.load_errors.append((filepath, e))
            except Exception as e:
                error_msg = f"Failed to load payload file {filepath}: {e}"
                logger.error(error_msg)
                self.load_errors.append((filepath, e))

    def get_by_category(self, category: str) -> List[Payload]:
        """
        Fetch all payloads within a specific category (e.g., 'direct').

        Args:
            category: Category name

        Returns:
            List of Payload objects, empty list if category not found
        """
        return self.payloads.get(category, [])

    def get_by_surface_type(self, attack_vectors: Optional[List[str]] = None) -> List[Payload]:
        """
        Match payloads based on attack vectors identified by classifier.

        Args:
            attack_vectors: List of attack vector names (e.g., ['direct', 'jailbreak'])

        Returns:
            List of matching Payload objects, defaults to 'direct' category if no matches
        """
        if not attack_vectors:
            return self.get_by_category("direct")

        selected: List[Payload] = []
        for vector in attack_vectors:
            payloads = self.get_by_category(vector)
            selected.extend(payloads)

        # Default to direct injection if no specific vectors match
        return selected if selected else self.get_by_category("direct")

    def validate_category(self, category: str) -> bool:
        """
        Check if a category exists and has payloads.

        Args:
            category: Category name to validate

        Returns:
            True if category exists and has at least one payload
        """
        return category in self.payloads and len(self.payloads[category]) > 0

    def get_all_categories(self) -> List[str]:
        """Return all available payload categories."""
        return sorted(self.payloads.keys())

    def get_stats(self) -> Dict[str, Any]:
        """Return statistics about loaded payloads."""
        total_payloads = sum(len(p) for p in self.payloads.values())
        return {
            "total_categories": len(self.payloads),
            "total_payloads": total_payloads,
            "categories": self.get_all_categories(),
            "load_errors": len(self.load_errors),
        }
