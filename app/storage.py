"""In-memory storage for EasyEnclave discovery service."""

from __future__ import annotations

import threading
from typing import Optional

from .models import ServiceRegistration


class InMemoryStore:
    """Thread-safe in-memory storage for service registrations."""

    def __init__(self):
        self._services: dict[str, ServiceRegistration] = {}
        self._lock = threading.RLock()

    def register(self, service: ServiceRegistration) -> str:
        """Register a new service. Returns the service_id."""
        with self._lock:
            self._services[service.service_id] = service
            return service.service_id

    def get(self, service_id: str) -> Optional[ServiceRegistration]:
        """Get a service by ID. Returns None if not found."""
        with self._lock:
            return self._services.get(service_id)

    def list(self, filters: Optional[dict] = None) -> list[ServiceRegistration]:
        """List all services, optionally filtered."""
        with self._lock:
            services = list(self._services.values())

        if not filters:
            return services

        result = services

        # Filter by name (partial match, case-insensitive)
        if filters.get("name"):
            name_filter = filters["name"].lower()
            result = [s for s in result if name_filter in s.name.lower()]

        # Filter by tags (any match)
        if filters.get("tags"):
            filter_tags = set(filters["tags"])
            result = [s for s in result if filter_tags & set(s.tags)]

        # Filter by environment (must have endpoint for this env)
        if filters.get("environment"):
            env = filters["environment"]
            result = [s for s in result if env in s.endpoints]

        # Filter by mrtd (exact match)
        if filters.get("mrtd"):
            mrtd = filters["mrtd"]
            result = [s for s in result if s.mrtd == mrtd]

        # Filter by health_status
        if filters.get("health_status"):
            status = filters["health_status"]
            result = [s for s in result if s.health_status == status]

        return result

    def delete(self, service_id: str) -> bool:
        """Delete a service by ID. Returns True if deleted, False if not found."""
        with self._lock:
            if service_id in self._services:
                del self._services[service_id]
                return True
            return False

    def update(self, service_id: str, **updates) -> Optional[ServiceRegistration]:
        """Update a service's fields. Returns updated service or None if not found."""
        with self._lock:
            service = self._services.get(service_id)
            if service is None:
                return None

            # Create updated service
            service_dict = service.model_dump()
            service_dict.update(updates)
            updated_service = ServiceRegistration(**service_dict)
            self._services[service_id] = updated_service
            return updated_service

    def search(self, query: str) -> list[ServiceRegistration]:
        """Search services by query string (matches name, description, tags)."""
        query_lower = query.lower()
        with self._lock:
            results = []
            for service in self._services.values():
                # Check name
                if query_lower in service.name.lower():
                    results.append(service)
                    continue
                # Check description
                if query_lower in service.description.lower():
                    results.append(service)
                    continue
                # Check tags
                if any(query_lower in tag.lower() for tag in service.tags):
                    results.append(service)
                    continue
                # Check source_repo
                if service.source_repo and query_lower in service.source_repo.lower():
                    results.append(service)
                    continue
            return results

    def count(self) -> int:
        """Return the total number of registered services."""
        with self._lock:
            return len(self._services)

    def clear(self) -> None:
        """Clear all services (useful for testing)."""
        with self._lock:
            self._services.clear()


# Global store instance
store = InMemoryStore()
