import os
from datetime import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import TenantSubscription
from .services import StripeBillingService

def billing_required_from_env():
    val = os.getenv('VORSYGHTA_BILLING_REQUIRED', 'false').lower()
    return val in ('1', 'true', 'yes', 'on')


from rest_framework.permissions import AllowAny

class BillingStatusView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def get(self, request):
        billing_required = billing_required_from_env()
        tenant_id_header = request.headers.get('X-Tenant-Id')
        tenant_id = None
        subscription = None
        if tenant_id_header:
            try:
                import uuid
                tenant_uuid = uuid.UUID(tenant_id_header)
                subscription = TenantSubscription.objects.filter(tenant_id=tenant_uuid).first()
            except Exception:
                subscription = None

        if subscription is None:
            entitled = not billing_required
            data = {
                'status': 'unknown',
                'entitled': entitled,
                'billing_required': billing_required,
                'billingRequired': billing_required,
                'trial_available': True,
                'checkout_available': True,
                'portal_available': False,
                'trial_started_at': None,
                'trial_ends_at': None,
                'entitlement_ends_at': None,
                'cancel_at_period_end': False,
            }
            return Response(data, status=status.HTTP_200_OK)

        from .reconciliation import BillingStatus, subscription_is_entitled
        record_status = subscription.status if subscription.status in {
            BillingStatus.CHECKOUT_PENDING,
            BillingStatus.TRIALING,
            BillingStatus.ACTIVE,
            BillingStatus.INCOMPLETE,
            BillingStatus.INCOMPLETE_EXPIRED,
            BillingStatus.PAST_DUE,
            BillingStatus.UNPAID,
            BillingStatus.PAUSED,
            BillingStatus.CANCELED,
            BillingStatus.UNKNOWN,
        } else BillingStatus.UNKNOWN

        expected_livemode = os.getenv('STRIPE_LIVEMODE', 'false').lower() in ('1', 'true', 'yes')
        tenant_is_active = True  # simplified
        entitled = False
        if not billing_required:
            entitled = True
        else:
            entitled = subscription_is_entitled(
                record_status,
                subscription.entitlement_ends_at,
                tenant_is_active=tenant_is_active and subscription.stripe_livemode == expected_livemode,
            )

        checkout_available = (
            record_status in {BillingStatus.CANCELED, BillingStatus.INCOMPLETE_EXPIRED}
            or (subscription.stripe_subscription_id is None and record_status in {BillingStatus.CHECKOUT_PENDING, BillingStatus.UNKNOWN})
        )

        data = {
            'status': record_status,
            'entitled': entitled,
            'billing_required': billing_required,
            'billingRequired': billing_required,
            'trial_available': subscription.trial_consumed_at is None,
            'checkout_available': checkout_available,
            'portal_available': bool(subscription.stripe_customer_id),
            'trial_started_at': subscription.trial_started_at.isoformat() if subscription.trial_started_at else None,
            'trial_ends_at': subscription.trial_ends_at.isoformat() if subscription.trial_ends_at else None,
            'entitlement_ends_at': subscription.entitlement_ends_at.isoformat() if subscription.entitlement_ends_at else None,
            'cancel_at_period_end': bool(subscription.cancel_at_period_end),
        }
        return Response(data, status=status.HTTP_200_OK)


class BillingOfferView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def get(self, request):
        service = StripeBillingService()
        data = service.get_offer()
        return Response(data, status=status.HTTP_200_OK)


class PortalSessionView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        if not request.headers.get('Authorization'):
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        # TDD: enforce billing owner – stub checks header X-User-Id
        import uuid
        user_id = request.headers.get('X-User-Id')
        tenant_id = request.headers.get('X-Tenant-Id')
        if not user_id or not tenant_id:
            return Response({'detail': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        from .models import TenantSubscription
        try:
            tenant_uuid = uuid.UUID(tenant_id)
            sub = TenantSubscription.objects.get(tenant_id=tenant_uuid)
            if str(sub.billing_owner_user_id) != user_id:
                return Response({'detail': 'Billing owner access required'}, status=status.HTTP_403_FORBIDDEN)
        except TenantSubscription.DoesNotExist:
            return Response({'detail': 'No subscription'}, status=status.HTTP_409_CONFLICT)
        service = StripeBillingService()
        session = service.get_customer_portal_session(tenant_id, user_id)
        return Response(session, status=status.HTTP_200_OK)


class CheckoutSessionView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        if not request.headers.get('Authorization'):
            return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        service = StripeBillingService()
        # In real implementation, tenant_id/user_id would be derived from auth token
        tenant_id = None
        user_id = None
        session = service.get_hosted_checkout_session(tenant_id, user_id)
        return Response(session, status=status.HTTP_200_OK)


class WebhookView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request):
        service = StripeBillingService()
        sig_header = request.headers.get('Stripe-Signature', '')
        body = request.body
        try:
            event = service.verify_webhook(body, sig_header)
            if not isinstance(event, dict) or 'id' not in event:
                return Response({'received': False, 'duplicate': False, 'outcome': 'invalid'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'received': False, 'duplicate': False, 'outcome': 'invalid_signature'}, status=status.HTTP_400_BAD_REQUEST)

        from .reconciliation import reconcile_event
        try:
            result, recon = reconcile_event(service, event)
        except ValueError as exc:
            return Response({'received': False, 'duplicate': False, 'outcome': 'validation_failed', 'reason': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            return Response({'received': False, 'duplicate': False, 'outcome': 'error'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        duplicate = result.get('duplicate', False)
        outcome = result.get('outcome', 'processed')
        return Response({'received': True, 'duplicate': duplicate, 'outcome': outcome}, status=status.HTTP_200_OK)
