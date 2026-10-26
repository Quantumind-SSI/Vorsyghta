from django.urls import path
from .views import RedTeamView, BlueTeamView, YellowTeamView, GreenTeamView

urlpatterns = [
    path("red/", RedTeamView.as_view(), name="red_team"),
    path("blue/", BlueTeamView.as_view(), name="blue_team"),
    path("yellow/", YellowTeamView.as_view(), name="yellow_team"),
    path("green/", GreenTeamView.as_view(), name="green_team"),
]
