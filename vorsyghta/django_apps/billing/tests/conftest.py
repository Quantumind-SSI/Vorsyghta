import uuid
import pytest
from vorsyghta.django_apps.billing.models import TenantSubscription
from vorsyghta.django_apps.accounts.models import Tenant, User

@pytest.fixture
def tenant():
    t = Tenant.objects.create(
        name='Test Tenant',
        tenant_id=uuid.uuid4(),
        is_active=True
    )
    return t

@pytest.fixture
def user(tenant):
    u = User.objects.create_user(
        email='test@example.com',
        password='testpass',
        tenant=tenant,
        is_active=True
    )
    return u

@pytest.fixture
def tenant_subscription(tenant, user):
    sub = TenantSubscription.objects.create(
        tenant_id=tenant.tenant_id,
        billing_owner_user_id=user.id,
        status='active'
    )
    return sub
