"""The allowlist: data/projects.yaml is the runner's one security boundary.

Only a project listed there is ever cloned, fetched, built or analysed. The
browser sends a project key and a ref and nothing else: never a URL, a path or
a profile. Anything that touches the disk or starts a subprocess is derived
from the allowlist entry, not from the request.

Parsing and validation only; this module never runs git.
"""

import dataclasses
import os
import re

import yaml

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_PROJECTS_YAML = os.path.join(REPO_ROOT, "data", "projects.yaml")

# A ref is a branch, tag or SHA: nothing git would read as a revision
# expression (`HEAD~3`, `a..b`, `@{u}`), as an option (leading `-`), or that a
# shell could mangle. Commands are argv lists, never a shell, so this is a
# second layer.
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$")
_BAD_REF_SUBSTRINGS = ("..", "//", "/.", ".lock", "@{")
_PROJECT_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")


class AllowlistError(ValueError):
    """The allowlist file is malformed. Raised at load time, never swallowed."""


class UnknownProject(LookupError):
    """The requested project key is not in the allowlist."""


class InvalidRef(ValueError):
    """The ref string is not something this runner will pass to git."""


class UnknownBuild(ValueError):
    """The build key is not one this project offers, or one was needed and not given."""


class InvalidUrl(ValueError):
    """The pasted text is not a GitHub repository URL this runner understands."""


@dataclasses.dataclass(frozen=True)
class VerifiedRef:
    ref: str
    label: str
    source: str  # which corpus file records this ref


@dataclasses.dataclass(frozen=True)
class Submodule:
    """A submodule the build needs, checked out at the SHA the project's own
    tree pins (see repo_cache.materialise_submodules)."""

    path: str
    url: str
    nested: tuple["Submodule", ...] = ()


@dataclasses.dataclass(frozen=True)
class Build:
    """One way of building a project that gets its own profile. A project with
    several (Trezor: the emulator, the device firmware, the device kernel) is
    traced once per build, and the results are read side by side."""

    key: str
    label: str
    summary: str
    profile: str  # absolute path to the profile YAML


@dataclasses.dataclass(frozen=True)
class Project:
    key: str
    name: str
    url: str
    profile: str  # absolute path to the base profile YAML
    summary: str
    refs: tuple[VerifiedRef, ...]
    submodules: tuple[Submodule, ...]
    prepare: tuple[tuple[str, ...], ...]  # argv lists, run in the worktree
    timeout_seconds: int
    prepare_timeout_seconds: int
    # Explains a build-set failure. `says` is shown only when the path check
    # (`exists` / `missing`, inside the checkout) holds for the ref that failed.
    build_hints: tuple["BuildHint", ...] = ()
    # Empty for a project with one profile. Otherwise `profile` is the first
    # build's, and every run must name one of these.
    builds: tuple[Build, ...] = ()


@dataclasses.dataclass(frozen=True)
class BuildHint:
    says: str
    exists: str | None = None
    missing: str | None = None


def _build_hint(raw: dict, where: str) -> BuildHint:
    if "says" not in raw or (("exists" in raw) == ("missing" in raw)):
        raise AllowlistError(f"{where}: a build_hint needs `says` and exactly one of `exists` / `missing`")
    for field in ("exists", "missing"):
        path = raw.get(field)
        if path is not None and (os.path.isabs(path) or ".." in path.split("/")):
            raise AllowlistError(f"{where}: build_hint path {path!r} must be relative and stay inside the checkout")
    return BuildHint(raw["says"], raw.get("exists"), raw.get("missing"))


def _submodule(raw: dict, where: str) -> Submodule:
    for field in ("path", "url"):
        if field not in raw:
            raise AllowlistError(f"{where}: submodule is missing {field!r}")
    if not _GITHUB_URL_RE.match(raw["url"]):
        raise AllowlistError(f"{where}: submodule url {raw['url']!r} is not a plain https://github.com/<owner>/<repo> URL")
    path = raw["path"]
    if os.path.isabs(path) or ".." in path.split("/"):
        raise AllowlistError(f"{where}: submodule path {path!r} must be relative and stay inside the worktree")
    nested = tuple(_submodule(n, where) for n in raw.get("nested", []))
    return Submodule(path, raw["url"], nested)


def _profile_path(profile: str, where: str) -> str:
    if not isinstance(profile, str) or os.path.isabs(profile) or ".." in profile.split("/"):
        raise AllowlistError(f"{where}: profile {profile!r} must be a repo-relative path")
    profile_abs = os.path.join(REPO_ROOT, profile)
    if not os.path.isfile(profile_abs):
        raise AllowlistError(f"{where}: profile {profile!r} does not exist")
    return profile_abs


def load_projects(path: str | None = None) -> dict[str, Project]:
    path = path or os.environ.get("ENTROPY_TRACE_PROJECTS_YAML") or DEFAULT_PROJECTS_YAML
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    entries = raw.get("projects")
    if not isinstance(entries, dict) or not entries:
        raise AllowlistError(f"{path}: needs a non-empty top-level `projects` mapping")

    projects: dict[str, Project] = {}
    for key, entry in entries.items():
        where = f"{path}: project {key!r}"
        if not _PROJECT_KEY_RE.match(str(key)):
            raise AllowlistError(f"{where}: key must be lowercase letters, digits and dashes")
        for field in ("name", "url", "refs"):
            if field not in entry:
                raise AllowlistError(f"{where}: missing required field {field!r}")
        if ("profile" in entry) == ("builds" in entry):
            raise AllowlistError(f"{where}: needs exactly one of `profile` (one build) or `builds` (several)")
        if not _GITHUB_URL_RE.match(entry["url"]):
            raise AllowlistError(f"{where}: url {entry['url']!r} is not a plain https://github.com/<owner>/<repo> URL")

        builds: list[Build] = []
        if "builds" in entry:
            raw_builds = entry["builds"]
            if not isinstance(raw_builds, dict) or len(raw_builds) < 2:
                raise AllowlistError(f"{where}: `builds` is a mapping of at least two builds; for one, use `profile`")
            for build_key, raw_build in raw_builds.items():
                if not _PROJECT_KEY_RE.match(str(build_key)):
                    raise AllowlistError(f"{where}: build key {build_key!r} must be lowercase letters, digits and dashes")
                for field in ("label", "profile"):
                    if field not in raw_build:
                        raise AllowlistError(f"{where}: build {build_key!r} is missing {field!r}")
                builds.append(
                    Build(str(build_key), raw_build["label"], raw_build.get("summary", ""),
                          _profile_path(raw_build["profile"], f"{where}: build {build_key!r}"))
                )
            profile_abs = builds[0].profile
        else:
            profile_abs = _profile_path(entry["profile"], where)

        refs = []
        for r in entry["refs"]:
            if not REF_RE.match(str(r.get("ref", ""))):
                raise AllowlistError(f"{where}: verified ref {r.get('ref')!r} is not a valid ref string")
            if "label" not in r or "source" not in r:
                raise AllowlistError(f"{where}: verified ref {r['ref']!r} needs `label` and `source`")
            refs.append(VerifiedRef(str(r["ref"]), r["label"], r["source"]))
        if not refs:
            raise AllowlistError(f"{where}: needs at least one verified ref")

        prepare = []
        for cmd in entry.get("prepare", []):
            if not isinstance(cmd, list) or not all(isinstance(a, str) for a in cmd) or not cmd:
                raise AllowlistError(f"{where}: each prepare step must be an argv list of strings")
            prepare.append(tuple(cmd))

        projects[key] = Project(
            key=key,
            name=entry["name"],
            url=entry["url"],
            profile=profile_abs,
            summary=entry.get("summary", ""),
            refs=tuple(refs),
            submodules=tuple(_submodule(s, where) for s in entry.get("submodules", [])),
            prepare=tuple(prepare),
            timeout_seconds=int(entry.get("timeout_seconds", 900)),
            prepare_timeout_seconds=int(entry.get("prepare_timeout_seconds", 1800)),
            build_hints=tuple(_build_hint(h, where) for h in entry.get("build_hints", [])),
            builds=tuple(builds),
        )
    return projects


def get_project(projects: dict[str, Project], key: object) -> Project:
    """Reject anything that is not exactly an allowlisted key, before any work
    happens: a non-string, a path, a URL and an unknown key all get the same
    answer."""
    if not isinstance(key, str) or key not in projects:
        raise UnknownProject(f"{key!r} is not an allowlisted project")
    return projects[key]


def get_build(project: Project, key: object) -> Build | None:
    """The build a run is for. A one-profile project has no builds and takes no
    key; a several-build project needs one of its own keys. Nothing is guessed:
    picking the emulator for someone who did not say which would answer a
    different question than the one they asked."""
    if not project.builds:
        if key is not None:
            raise UnknownBuild(f"{project.name} has a single build; do not name one")
        return None
    for build in project.builds:
        if key == build.key:
            return build
    raise UnknownBuild(f"{project.name} has several builds ({', '.join(b.key for b in project.builds)}); name one")


def validate_ref(ref: object) -> str:
    if not isinstance(ref, str) or not REF_RE.match(ref) or any(bad in ref for bad in _BAD_REF_SUBSTRINGS):
        raise InvalidRef(f"{ref!r} is not a branch name, tag name or commit SHA")
    return ref


# A pasted URL is only ever a lookup key into the allowlist: it is parsed, matched
# against the allowlisted URLs and discarded. It is never fetched or cloned.
_PASTED_URL_RE = re.compile(
    r"^(?:https://)?(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?(?P<rest>/.*)?$",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class PastedUrl:
    owner_repo: str  # lowercase "owner/repo"
    # Ref candidates named by the URL, longest first. Empty for a bare repository
    # URL. A branch like `release/1.0` is ambiguous inside /tree/release/1.0/src,
    # so the caller tries each against the repository's real refs.
    candidates: tuple[str, ...]


def parse_repo_url(text: object) -> PastedUrl:
    """Accept github.com/<owner>/<repo>, optionally followed by /tree/<ref>,
    /commit/<sha> or /releases/tag/<tag>. Anything else is rejected."""
    if not isinstance(text, str):
        raise InvalidUrl("expected a GitHub URL")
    text = text.strip()
    if not text or len(text) > 300 or any(c in text for c in "?#@ \t\r\n\\"):
        raise InvalidUrl("that does not look like a plain GitHub repository URL")
    m = _PASTED_URL_RE.match(text.rstrip("/"))
    if not m:
        raise InvalidUrl("expected https://github.com/<owner>/<repo>, optionally with /tree/<ref>")
    owner_repo = f"{m['owner']}/{m['repo']}".lower()
    segments = [seg for seg in (m["rest"] or "").split("/") if seg]
    if not segments:
        return PastedUrl(owner_repo, ())
    if segments[0] == "tree" and len(segments) > 1:
        tail = segments[1:]
    elif segments[0] == "commit" and len(segments) == 2:
        tail = segments[1:]
    elif segments[0] == "releases" and len(segments) > 2 and segments[1] == "tag":
        tail = segments[2:]
    else:
        raise InvalidUrl("use the repository URL, or a /tree/<ref>, /commit/<sha> or /releases/tag/<tag> URL")
    return PastedUrl(owner_repo, tuple("/".join(tail[:n]) for n in range(len(tail), 0, -1)))


def find_project_by_url(projects: dict[str, Project], pasted: PastedUrl) -> Project:
    for project in projects.values():
        if project.url.removeprefix("https://github.com/").lower() == pasted.owner_repo:
            return project
    raise UnknownProject(f"github.com/{pasted.owner_repo} is not a repository this runner is set up for")
