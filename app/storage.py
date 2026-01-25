"""In-memory storage for EasyEnclave discovery service."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta

from .models import ServiceRegistration

# How long a service can be unhealthy before being marked as "down"
UNHEALTHY_TIMEOUT = timedelta(hours=1)


class InMemoryStore:
    """Thread-safe in-memory storage for service registrations."""

    def __init__(self):
        self._services: dict[str, ServiceRegistration] = {}
        self._name_index: dict[str, str] = {}  # name -> service_id
        self._lock = threading.RLock()

    def register(self, service: ServiceRegistration) -> str:
        """Register a new service. Returns the service_id."""
        with self._lock:
            self._services[service.service_id] = service
            self._name_index[service.name] = service.service_id
            return service.service_id

    def get_by_name(self, name: str) -> ServiceRegistration | None:
        """Get a service by name. Returns None if not found."""
        with self._lock:
            service_id = self._name_index.get(name)
            if service_id:
                return self._services.get(service_id)
            return None

    def upsert(self, service: ServiceRegistration) -> tuple[str, bool]:
        """Register or update a service by name.

        Returns (service_id, is_new) where is_new is True if created, False if updated.
        """
        with self._lock:
            existing_id = self._name_index.get(service.name)
            if existing_id:
                # Update existing - preserve service_id and registered_at
                existing = self._services[existing_id]
                service_dict = service.model_dump()
                service_dict["service_id"] = existing_id
                service_dict["registered_at"] = existing.registered_at
                updated_service = ServiceRegistration(**service_dict)
                self._services[existing_id] = updated_service
                return existing_id, False
            else:
                # Create new
                self._services[service.service_id] = service
                self._name_index[service.name] = service.service_id
                return service.service_id, True

    def get(self, service_id: str) -> ServiceRegistration | None:
        """Get a service by ID. Returns None if not found."""
        with self._lock:
            return self._services.get(service_id)

    def _is_timed_out(self, service: ServiceRegistration) -> bool:
        """Check if a service has been unhealthy long enough to be considered down."""
        if service.health_status == "healthy":
            return False
        if service.last_health_check is None:
            # Never checked - not timed out yet
            return False
        return datetime.utcnow() - service.last_health_check > UNHEALTHY_TIMEOUT

    def list(
        self, filters: dict | None = None, include_down: bool = False
    ) -> list[ServiceRegistration]:
        """List all services, optionally filtered.

        Args:
            filters: Optional dict of filters
            include_down: If False (default), exclude services that have been
                         unhealthy for longer than UNHEALTHY_TIMEOUT
        """
        with self._lock:
            services = list(self._services.values())

        # Filter out timed-out services by default
        if not include_down:
            services = [s for s in services if not self._is_timed_out(s)]

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
                service = self._services[service_id]
                # Clean up name index
                if self._name_index.get(service.name) == service_id:
                    del self._name_index[service.name]
                del self._services[service_id]
                return True
            return False

    def get_all_for_health_check(self) -> list[ServiceRegistration]:
        """Get all services for health checking (includes timed-out services)."""
        with self._lock:
            return list(self._services.values())

    def update(self, service_id: str, **updates) -> ServiceRegistration | None:
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
            self._name_index.clear()


# Global store instance
store = InMemoryStore()
