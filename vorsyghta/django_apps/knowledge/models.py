import uuid
from django.db import models
from django.conf import settings

class KnowledgeEntry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='knowledge_entries')
    title = models.CharField(max_length=512)
    content = models.TextField()
    category = models.CharField(max_length=128)
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'knowledge_entries'
        ordering = ['-created_at']
