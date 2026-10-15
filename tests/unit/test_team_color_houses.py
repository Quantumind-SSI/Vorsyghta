import pytest

from vorsyghta.core.team_playbooks import SecurityTeam, TEAM_COLOR_HOUSES, color_house


@pytest.mark.parametrize(
    ("team", "expected"),
    [
        (SecurityTeam.BLUE_TEAM, "blue"),
        (SecurityTeam.RED_TEAM, "red"),
        (SecurityTeam.PURPLE_TEAM, "purple"),
        (SecurityTeam.SOC, "blue"),
        (SecurityTeam.INCIDENT_RESPONSE, "blue"),
        (SecurityTeam.THREAT_INTEL, "purple"),
        (SecurityTeam.GRC, "orange"),
        (SecurityTeam.SECURITY_AWARENESS, "green"),
    ],
)
def test_color_house_assignment(team, expected):
    """Every SecurityTeam member resolves to its assigned color house."""
    assert color_house(team) == expected


def test_color_house_total_coverage():
    """Every enum member has an explicit house — no silent fallback."""
    all_members = set(SecurityTeam)
    assert set(TEAM_COLOR_HOUSES) | {
        SecurityTeam.BLUE_TEAM, SecurityTeam.RED_TEAM, SecurityTeam.PURPLE_TEAM,
    } == all_members


def test_color_house_unknown_team_defaults():
    """A team missing from both maps falls back to 'unassigned', not a crash."""

    class FakeTeam:
        pass

    assert color_house(FakeTeam()) == "unassigned"
