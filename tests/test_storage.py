"""Tests for in-memory storage."""

import pytest
from app.storage import InMemoryStore
from app.models import ServiceRegistration


@pytest.fixture
def store():
    """Create a fresh store for each test."""
    s = InMemoryStore()
    yield s
    s.clear()


@pytest.fixture
def sample_service():
    """Create a sample service registration."""
    return ServiceRegistration(
        name="test-service",
        description="A test service",
        endpoints={"prod": "https://test.example.com"},
        tags=["test", "api"],
        mrtd="abc123",
    )


class TestInMemoryStore:
    def test_register(self, store, sample_service):
        """Test service registration."""
        service_id = store.register(sample_service)
        assert service_id == sample_service.service_id
        assert store.count() == 1

    def test_get(self, store, sample_service):
        """Test getting a service by ID."""
        store.register(sample_service)
        retrieved = store.get(sample_service.service_id)
        assert retrieved is not None
        assert retrieved.name == sample_service.name

    def test_get_not_found(self, store):
        """Test getting a non-existent service."""
        result = store.get("nonexistent")
        assert result is None

    def test_delete(self, store, sample_service):
        """Test deleting a service."""
        store.register(sample_service)
        assert store.delete(sample_service.service_id) is True
        assert store.count() == 0

    def test_delete_not_found(self, store):
        """Test deleting a non-existent service."""
        assert store.delete("nonexistent") is False

    def test_list_all(self, store):
        """Test listing all services."""
        s1 = ServiceRegistration(name="service-1")
        s2 = ServiceRegistration(name="service-2")
        store.register(s1)
        store.register(s2)

        services = store.list()
        assert len(services) == 2

    def test_list_filter_by_name(self, store):
        """Test filtering by name."""
        s1 = ServiceRegistration(name="alpha-service")
        s2 = ServiceRegistration(name="beta-service")
        store.register(s1)
        store.register(s2)

        services = store.list({"name": "alpha"})
        assert len(services) == 1
        assert services[0].name == "alpha-service"

    def test_list_filter_by_tags(self, store):
        """Test filtering by tags."""
        s1 = ServiceRegistration(name="service-1", tags=["api", "web"])
        s2 = ServiceRegistration(name="service-2", tags=["backend"])
        store.register(s1)
        store.register(s2)

        services = store.list({"tags": ["api"]})
        assert len(services) == 1
        assert services[0].name == "service-1"

    def test_list_filter_by_environment(self, store):
        """Test filtering by environment."""
        s1 = ServiceRegistration(
            name="service-1", endpoints={"prod": "https://prod.example.com"}
        )
        s2 = ServiceRegistration(
            name="service-2", endpoints={"staging": "https://staging.example.com"}
        )
        store.register(s1)
        store.register(s2)

        services = store.list({"environment": "prod"})
        assert len(services) == 1
        assert services[0].name == "service-1"

    def test_list_filter_by_mrtd(self, store):
        """Test filtering by MRTD."""
        s1 = ServiceRegistration(name="service-1", mrtd="mrtd-123")
        s2 = ServiceRegistration(name="service-2", mrtd="mrtd-456")
        store.register(s1)
        store.register(s2)

        services = store.list({"mrtd": "mrtd-123"})
        assert len(services) == 1
        assert services[0].name == "service-1"

    def test_search(self, store):
        """Test searching services."""
        s1 = ServiceRegistration(name="payment-service", description="Handles payments")
        s2 = ServiceRegistration(name="user-service", description="User management")
        store.register(s1)
        store.register(s2)

        # Search by name
        results = store.search("payment")
        assert len(results) == 1
        assert results[0].name == "payment-service"

        # Search by description
        results = store.search("management")
        assert len(results) == 1
        assert results[0].name == "user-service"

    def test_search_by_tag(self, store):
        """Test searching by tag."""
        s1 = ServiceRegistration(name="service-1", tags=["authentication"])
        s2 = ServiceRegistration(name="service-2", tags=["database"])
        store.register(s1)
        store.register(s2)

        results = store.search("auth")
        assert len(results) == 1
        assert results[0].name == "service-1"

    def test_update(self, store, sample_service):
        """Test updating a service."""
        store.register(sample_service)
        updated = store.update(sample_service.service_id, health_status="healthy")

        assert updated is not None
        assert updated.health_status == "healthy"
        assert updated.name == sample_service.name

    def test_update_not_found(self, store):
        """Test updating a non-existent service."""
        result = store.update("nonexistent", health_status="healthy")
        assert result is None

    def test_clear(self, store, sample_service):
        """Test clearing all services."""
        store.register(sample_service)
        store.clear()
        assert store.count() == 0
