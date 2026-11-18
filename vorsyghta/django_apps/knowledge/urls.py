from django.urls import path
from .views import KnowledgeEntryCreateView

urlpatterns = [
    path('entries', KnowledgeEntryCreateView.as_view(), name='knowledge_entry_create'),
]
