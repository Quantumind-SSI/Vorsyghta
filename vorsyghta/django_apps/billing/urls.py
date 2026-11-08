from django.urls import path
from .views import BillingStatusView, BillingOfferView, CheckoutSessionView, WebhookView, PortalSessionView

urlpatterns = [
    path('status', BillingStatusView.as_view(), name='billing-status'),
    path('offer', BillingOfferView.as_view(), name='billing-offer'),
    path('checkout-session', CheckoutSessionView.as_view(), name='billing-checkout-session'),
    path('portal-session', PortalSessionView.as_view(), name='billing-portal-session'),
    path('webhook', WebhookView.as_view(), name='billing-webhook'),
]
