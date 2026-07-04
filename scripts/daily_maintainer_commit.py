#!/usr/bin/env python3
"""Generate one single-file commit per maintainer per day.

Reads the maintainer task plans in ``dev-docs/maintainers/`` and creates a daily
scaffolding commit for each maintainer. Each commit touches exactly one file and
advances the next pending atomic task from that maintainer's plan.

This is intentionally scaffolding: it creates file stubs and TODO markers so
maintainers have a concrete starting point. Real implementation must still be
done by humans.

Usage:
    python scripts/daily_maintainer_commit.py           # create commits
    python scripts/daily_maintainer_commit.py --dry-run # preview only
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OVERVIEW_PATH = REPO_ROOT / "dev-docs/maintainers/MAINTAINERS_OVERVIEW.md"
PLAN_DIR = REPO_ROOT / "dev-docs/maintainers/ThreatScene/maintainers"


@dataclass
class Maintainer:
    name: str
    github: str
    short: str
    role: str
    plan_file: Path


@dataclass
class Task:
    task_id: str
    title: str
    description: str
    new_files: list[str]
    edit_files: list[str]


class GitError(Exception):
    """Raised when a git command fails."""


def run_git(args: list[str], check: bool = True) -> str:
    """Run a git command and return its stdout."""
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def working_tree_is_clean() -> bool:
    """Return True if the working tree has no uncommitted changes."""
    return run_git(["status", "--porcelain"]) == ""


def stash_changes(message: str) -> bool:
    """Stash any uncommitted changes. Returns True if a stash was created."""
    if working_tree_is_clean():
        return False
    run_git(["stash", "push", "-m", message])
    return True


def unstash_changes() -> None:
    """Restore the most recent stash."""
    run_git(["stash", "pop"])


def last_commit_date_for_maintainer(short: str) -> datetime.date | None:
    """Return the most recent commit date for a maintainer prefix, if any."""
    try:
        log = run_git(
            [
                "log",
                "--oneline",
                "--format=%cs",
                "--grep",
                f"^({short}|{short.lower()})",
                "-1",
            ]
        )
    except GitError:
        return None
    if not log:
        return None
    try:
        return datetime.datetime.strptime(log, "%Y-%m-%d").date()
    except ValueError:
        return None


def maintainer_already_committed_today(short: str) -> bool:
    """Return True if a commit for this maintainer already exists today."""
    last = last_commit_date_for_maintainer(short)
    return last == datetime.date.today()


def parse_maintainers() -> list[Maintainer]:
    """Parse the maintainer roster and plan filenames from the overview document."""
    if not OVERVIEW_PATH.exists():
        raise FileNotFoundError(f"Maintainer overview not found: {OVERVIEW_PATH}")

    text = OVERVIEW_PATH.read_text(encoding="utf-8")

    # First table: map maintainer name to plan filename.
    plan_files: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(
            r"\|\s*([^|]+)\s*\|\s*`([^`]+)`\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|",
            line,
        )
        if not match:
            continue
        name = match.group(1).strip()
        plan_filename = match.group(2).strip()
        if name.lower() in {"maintainer", "maintainers"}:
            continue
        if not plan_filename.endswith("_IMPLEMENTATION.md"):
            continue
        plan_files[name] = plan_filename

    # Second table: maintainer roster with GitHub/role details.
    rows: list[Maintainer] = []
    for line in text.splitlines():
        match = re.match(
            r"\|\s*\d+\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|",
            line,
        )
        if not match:
            continue
        name = match.group(1).strip()
        github = match.group(2).strip()
        role = match.group(3).strip()
        if name.lower() in {"maintainer", "maintainers"}:
            continue

        plan_filename = plan_files.get(name)
        if not plan_filename:
            continue

        plan_file = PLAN_DIR / plan_filename
        rows.append(
            Maintainer(
                name=name,
                github=github,
                short=make_short_code(name),
                role=role,
                plan_file=plan_file,
            )
        )

    return rows


def make_short_code(name: str) -> str:
    """Create a short commit-scope code from a maintainer name.

    Examples:
        Temi Adebola -> temi
        David Onoja -> david
        Ajibola Shokunbi -> ajibola
        DevRel & PR -> devrel
    """
    clean = re.sub(r"[^a-zA-Z ]", "", name)
    parts = clean.split()
    if "DevRel" in name or "PR" in name or "Relations" in name:
        return "devrel"
    return parts[0].lower() if parts else "unknown"


def parse_task_plan(plan_path: Path) -> list[Task]:
    """Parse atomic tasks from a maintainer implementation plan."""
    if not plan_path.exists():
        return []

    text = plan_path.read_text(encoding="utf-8")
    tasks: list[Task] = []

    # Split on atomic task headers: ### TEMI-001: Title (Phase X, Weeks Y-Z)
    pattern = re.compile(
        r"###\s+([A-Z]+-\d+):\s+(.+?)\s+\(Phase\s+\d+,\s+Weeks\s+[^)]+\)",
        re.IGNORECASE,
    )
    matches = list(pattern.finditer(text))

    for i, match in enumerate(matches):
        task_id = match.group(1).upper()
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section = text[start:end]

        description = extract_description(section)
        new_files, edit_files = extract_deliverables(section)

        if new_files or edit_files:
            tasks.append(
                Task(
                    task_id=task_id,
                    title=title,
                    description=description,
                    new_files=new_files,
                    edit_files=edit_files,
                )
            )

    return tasks


def extract_description(section: str) -> str:
    """Extract the first paragraph of the description block."""
    match = re.search(
        r"\*\*Description:\*\*\s*(.+?)(?=\*\*Deliverables:\*\*)",
        section,
        re.DOTALL,
    )
    if not match:
        return ""
    desc = match.group(1).strip()
    # Collapse whitespace and line breaks.
    desc = re.sub(r"\s+", " ", desc)
    return desc[:200] + "..." if len(desc) > 200 else desc


def extract_deliverables(section: str) -> tuple[list[str], list[str]]:
    """Return (new_files, edit_files) from a task deliverables section."""
    new_files: list[str] = []
    edit_files: list[str] = []

    match = re.search(r"\*\*Deliverables:\*\*\s*(.+?)(?=\*\*Acceptance)", section, re.DOTALL)
    if not match:
        return new_files, edit_files

    deliverables = match.group(1)

    # NEW files: `- `path` — NEW file` or `- `path` — NEW file with:`
    for new_match in re.finditer(
        r"[-*]\s+`([^`]+)`\s*—\s*NEW\s+file", deliverables, re.IGNORECASE
    ):
        path = new_match.group(1).strip()
        if path:
            new_files.append(path)

    # EDIT files: `Edit `path` — description` or `Edit `path:lines` — description`
    for edit_match in re.finditer(
        r"Edit\s+`([^`]+)`\s*[-—]", deliverables, re.IGNORECASE
    ):
        path = edit_match.group(1).strip()
        # Strip line ranges like :239-243
        path = re.sub(r":\d+(-\d+)?$", "", path)
        if path:
            edit_files.append(path)

    return new_files, edit_files


def file_has_todo(file_path: Path, task_id: str) -> bool:
    """Return True if the file already contains a TODO for this task."""
    if not file_path.exists():
        return False
    try:
        return f"TODO({task_id})" in file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False


def build_stub_content(file_path: Path, task: Task) -> str:
    """Generate scaffolding content for a new file."""
    suffix = file_path.suffix.lower()
    task_ref = f"{task.task_id}"
    title = task.title
    description = task.description or title

    if suffix in {".py", ""}:
        return (
            f'"""{title}.\n\n'
            f"TODO({task_ref}): {description}\n"
            f'"""\n'
            f"\n"
            f"# TODO({task_ref}): Implement this module.\n"
        )

    if suffix in {".yaml", ".yml"}:
        return (
            f"# {title}\n"
            f"# TODO({task_ref}): {description}\n"
            f"---\n"
            f"# TODO({task_ref}): Add scenario configuration here.\n"
        )

    if suffix == ".md":
        return (
            f"# {title}\n\n"
            f"TODO({task_ref}): {description}\n\n"
            f"## Notes\n\n"
            f"- TODO({task_ref}): Add implementation notes.\n"
        )

    if suffix == ".sh":
        return (
            "#!/usr/bin/env bash\n"
            f"# {title}\n"
            f"# TODO({task_ref}): {description}\n"
            f"\n"
            f"# TODO({task_ref}): Implement this script.\n"
        )

    return (
        f"# {title}\n"
        f"# TODO({task_ref}): {description}\n"
    )


def create_stub(file_path: Path, task: Task) -> bool:
    """Create a stub file for a NEW deliverable. Returns True if created."""
    if file_path.exists():
        return False

    file_path.parent.mkdir(parents=True, exist_ok=True)
    content = build_stub_content(file_path, task)
    file_path.write_text(content, encoding="utf-8")

    if file_path.suffix == ".sh":
        file_path.chmod(0o755)

    return True


def add_todo_to_file(file_path: Path, task: Task) -> bool:
    """Add a TODO marker to an existing file for an EDIT deliverable."""
    if not file_path.exists():
        return False
    if file_has_todo(file_path, task.task_id):
        return False

    original = file_path.read_text(encoding="utf-8")
    marker = f"# TODO({task.task_id}): {task.description}\n"

    # If file has a module docstring, insert the TODO after it.
    if original.startswith('"""') or original.startswith("'''"):
        quote = original[:3]
        end_idx = original.find(quote, 3)
        if end_idx != -1:
            insert_pos = end_idx + 3
            if original[insert_pos:insert_pos + 1] == "\n":
                insert_pos += 1
            new_content = original[:insert_pos] + "\n" + marker + original[insert_pos:]
            file_path.write_text(new_content, encoding="utf-8")
            return True

    file_path.write_text(marker + "\n" + original, encoding="utf-8")
    return True


def find_next_action(maintainer: Maintainer, tasks: list[Task]) -> tuple[Path, str] | None:
    """Find the next single-file action for a maintainer.

    Returns a tuple of (relative_path, action_type) or None if no action.
    """
    for task in tasks:
        # Prefer creating NEW files that don't exist yet.
        for raw_path in task.new_files:
            file_path = REPO_ROOT / raw_path
            if not file_path.exists():
                return file_path, "new"

        # Then add TODO markers to EDIT files that don't have one.
        for raw_path in task.edit_files:
            file_path = REPO_ROOT / raw_path
            if file_path.exists() and not file_has_todo(file_path, task.task_id):
                return file_path, "edit"

    return None


def build_commit_message(maintainer: Maintainer, task: Task, action: str, rel_path: str) -> str:
    """Build a conventional commit message for the action."""
    scope = maintainer.short
    if action == "new":
        return f"feat({scope}): {task.task_id} scaffold {rel_path}"
    if action == "edit":
        return f"fix({scope}): {task.task_id} mark TODO in {rel_path}"
    return f"chore({scope}): {task.task_id} update {rel_path}"


def commit_single_file(rel_path: str, message: str, dry_run: bool) -> bool:
    """Stage and commit a single file. Returns True if committed."""
    if dry_run:
        print(f"  [dry-run] would commit: {rel_path}")
        print(f"  [dry-run] message: {message}")
        return True

    run_git(["add", "--", rel_path])
    if working_tree_is_clean():
        # Nothing staged, likely the file is already tracked with no changes.
        print(f"  No changes to commit for {rel_path}")
        return False

    run_git(
        [
            "commit",
            "-m",
            message,
            "-m",
            "Generated with Devin daily maintainer commit script.",
            "--",
            rel_path,
        ]
    )
    return True


def ensure_progress_tracker(maintainer: Maintainer, tasks: list[Task]) -> tuple[Path, str] | None:
    """Create or update a daily progress tracker when all deliverables are done."""
    tracker_dir = REPO_ROOT / "docs" / "maintainer-progress"
    tracker_dir.mkdir(parents=True, exist_ok=True)
    tracker_path = tracker_dir / f"{maintainer.short}.md"

    today = datetime.date.today().isoformat()
    content = (
        f"# {maintainer.name} — Daily Progress\n\n"
        f"**Last updated:** {today}\n\n"
        f"## Open Tasks\n\n"
    )
    for task in tasks:
        content += f"- {task.task_id}: {task.title}\n"
    content += "\n## Notes\n\n- All scaffolding files exist; awaiting implementation.\n"

    tracker_path.write_text(content, encoding="utf-8")
    return tracker_path, "progress"


def process_maintainer(maintainer: Maintainer, dry_run: bool, stash: bool) -> bool:
    """Create a single commit for a maintainer. Returns True if a commit was made."""
    print(f"\n{maintainer.name} ({maintainer.short})")

    if maintainer_already_committed_today(maintainer.short):
        print(f"  Already has a commit today; skipping.")
        return False

    tasks = parse_task_plan(maintainer.plan_file)
    if not tasks:
        print(f"  No atomic tasks found in {maintainer.plan_file}")
        return False

    action_info = find_next_action(maintainer, tasks)
    if action_info is None:
        # No actionable scaffolding; update progress tracker instead.
        tracker_info = ensure_progress_tracker(maintainer, tasks)
        if tracker_info is None:
            print("  No actionable item found; skipping.")
            return False
        file_path, action = tracker_info
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        # Determine which task to reference (use the first incomplete-looking one).
        task = tasks[0]
    else:
        file_path, action = action_info
        rel_path = file_path.relative_to(REPO_ROOT).as_posix()
        # Find the task that owns this file.
        task = None
        for t in tasks:
            if rel_path in t.new_files or rel_path in t.edit_files:
                task = t
                break
        if task is None:
            task = tasks[0]

    if action == "new":
        if not create_stub(file_path, task):
            print(f"  Could not create stub for {rel_path}; skipping.")
            return False
        print(f"  Created stub: {rel_path}")
    elif action == "edit":
        if not add_todo_to_file(file_path, task):
            print(f"  Could not add TODO to {rel_path}; skipping.")
            return False
        print(f"  Added TODO to: {rel_path}")
    else:
        print(f"  Updated progress tracker: {rel_path}")

    message = build_commit_message(maintainer, task, action, rel_path)
    return commit_single_file(rel_path, message, dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create one single-file commit per maintainer per day.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be committed without making changes.",
    )
    parser.add_argument(
        "--stash",
        action="store_true",
        help="Stash uncommitted changes before running (restore after).",
    )
    args = parser.parse_args()

    stashed = False
    if not args.dry_run and not working_tree_is_clean():
        if not args.stash:
            print(
                "Working tree has uncommitted changes. "
                "Commit or stash them first, or run with --stash."
            )
            return 1
        stashed = stash_changes("daily_maintainer_commit auto-stash")
        print("Stashed existing uncommitted changes.")

    try:
        maintainers = parse_maintainers()
        if not maintainers:
            print("No maintainers found in the overview document.")
            return 1

        print(f"Found {len(maintainers)} maintainers.")
        committed_count = 0
        for maintainer in maintainers:
            try:
                if process_maintainer(maintainer, args.dry_run, args.stash):
                    committed_count += 1
            except Exception as e:
                print(f"  Error processing {maintainer.name}: {e}")
                continue

        print(f"\nDone. {committed_count} maintainer commit(s) created.")
        return 0
    finally:
        if stashed:
            try:
                unstash_changes()
                print("Restored stashed changes.")
            except GitError as e:
                print(f"Could not restore stash: {e}")


if __name__ == "__main__":
    sys.exit(main())
