"""Audit API: read-only, authenticated access to the tamper-evident audit trail."""

from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination

from .models import AuditEvent


class AuditEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditEvent
        fields = [
            "id", "event_id", "event_type", "category", "severity",
            "actor", "target", "context", "timestamp", "correlation_id",
            "description", "prev_hash", "event_hash", "tenant_id", "created_at",
        ]


class AuditEventPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


class AuditEventListView(APIView):
    """GET /audit/events — paginated, newest-first."""

    permission_classes = [IsAuthenticated]

    def get(self, request):
        qs = AuditEvent.objects.all().order_by("-timestamp")
        paginator = AuditEventPagination()
        page = paginator.paginate_queryset(qs, request)
        return paginator.get_paginated_response(AuditEventSerializer(page, many=True).data)
