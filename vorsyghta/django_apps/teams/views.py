"""Color Teams API: Red/Blue/Yellow/Green team control endpoints."""

import asyncio
from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import UserRateThrottle

from vorsyghta.db.models.red_team import AttackPlanRecord
from vorsyghta.core.attack_orchestrator import AttackOrchestrator
from vorsyghta.vm.safety import VMSafetyController
from vorsyghta.defense.blue_team import BlueTeamBusIntegration

class TeamRateThrottle(UserRateThrottle):
    rate = "60/minute"

class RedTeamView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [TeamRateThrottle]

    def post(self, request):
        tenant_id = str(getattr(request.user, 'tenant_id', 'default'))
        scenario = request.data.get("scenario")
        target = request.data.get("target")
        engagement_id = request.data.get("engagement_id")

        if not scenario or not target:
            return Response({"error": "scenario and target required"}, status=status.HTTP_400_BAD_REQUEST)

        if not engagement_id and not getattr(settings, 'ALLOW_UNAUTHORIZED', False):
            return Response({"error": "engagement_id required"}, status=status.HTTP_403_FORBIDDEN)

        safety = VMSafetyController()
        if not safety.validate_target(target):
            return Response({"error": "target not in sanctioned list"}, status=status.HTTP_403_FORBIDDEN)

        return Response({
            "status": "red_team_triggered",
            "tenant_id": tenant_id,
            "scenario": scenario,
            "target": target
        }, status=status.HTTP_202_ACCEPTED)

    def get(self, request):
        return Response({"status": "red_team_active", "tenant_id": str(getattr(request.user, 'tenant_id', 'default'))})

class BlueTeamView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [TeamRateThrottle]

    def get(self, request):
        tenant_id = str(getattr(request.user, 'tenant_id', 'default'))
        # Integration stub
        return Response({"status": "blue_team_monitoring", "tenant_id": tenant_id, "alerts_count": 0})

class YellowTeamView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [TeamRateThrottle]

    def get(self, request):
        return Response({"status": "yellow_team_infra_ok", "tenant_id": str(getattr(request.user, 'tenant_id', 'default'))})

class GreenTeamView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [TeamRateThrottle]

    def get(self, request):
        return Response({"status": "green_team_training_ready", "tenant_id": str(getattr(request.user, 'tenant_id', 'default'))})
