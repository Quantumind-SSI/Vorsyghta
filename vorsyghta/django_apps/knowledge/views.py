from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import KnowledgeEntry

class KnowledgeEntryCreateView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        title = request.data.get('title')
        content = request.data.get('content')
        category = request.data.get('category')
        tags = request.data.get('tags') or []

        if not title or not content or not category:
            return Response({'detail': 'title, content and category required'}, status=status.HTTP_400_BAD_REQUEST)

        entry = KnowledgeEntry.objects.create(
            user=request.user,
            title=title,
            content=content,
            category=category,
            tags=tags,
        )
        return Response({'entry_id': str(entry.id), 'message': 'Entry created'}, status=status.HTTP_201_CREATED)
