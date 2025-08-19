import re
import requests
import os
from collections import defaultdict
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

ARTIFACTORY_URL = os.environ["ARTIFACTORY_URL"].rstrip("/")+"/artifactory"
ARTIFACTORY_TOKEN = os.getenv("ARTIFACTORY_TOKEN")
TIME = os.getenv("TIME", "4w")
DOWNLOAD_TIME = os.getenv("DOWNLOAD_TIME", "")

NUGET_SNAPSHOT = "nuget-snapshot-local"
NUGET_RELEASE = "nuget-release-local"
NUGET_ARCHIVE = "nuget-release-archive"

MAX_WORKERS = int(os.getenv("MAX_WORKERS", 5))

ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")

if not ARTIFACTORY_TOKEN:
    from arti_cleanup.auth import *
    ARTIFACTORY_TOKEN_PATH = os.environ["ARTIFACTORY_TOKEN_PATH"]
    print("No Token was provided, will attempt to check in Vault")
    vault = get_vault_client()
    ARTIFACTORY_TOKEN = vault.read(ARTIFACTORY_TOKEN_PATH)["data"]["token"]

HEADER = {"content-type": "text/plain", "X-JFrog-Art-Api": ARTIFACTORY_TOKEN}

class ArtifactoryOperation(ABC):
    def __init__(self, name, days, test = True):
        self.test = test
        self.name = name
        self.cutoff_days = days
        self.cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    @abstractmethod
    def execute(self):
        pass

    def log(self, message):
        print(f"[{self.name}] {message}")

    def _get_artifacts_from_repo(self, repository):
        query = '''items.find({ "repo":"''' + repository + '''"}).include("name", "path", "created", "stat.downloaded", "stat.downloads")'''
        response = requests.post(f"{ARTIFACTORY_URL}/api/search/aql", data=query, headers=HEADER)
        response.raise_for_status()
        return response.json().get("results", [])


class ArchiveOperation(ArtifactoryOperation):
    def __init__(self, days):
        super().__init__("ARCHIVE", days)
        self.source_repo = NUGET_RELEASE
        self.target_repo = NUGET_ARCHIVE

    def execute(self):
        self.log(f"Starting archive from {self.source_repo} to {self.target_repo}")
        self.log(f"Archiving artifacts older than {self.cutoff_days} days")

        artifacts = self._get_artifacts_from_repo(self.source_repo)

        # Filter artifacts older than cutoff date
        old_artifacts = self._filter_old_artifacts(artifacts, self.cutoff)

        if len(old_artifacts) > 0:
            self._move_artifacts_threaded(old_artifacts)
            self.log(f"Finished archiving")
        else:
            self.log(f"There were no artifacts to archive")


    def _split_nuget_name(self, artifact):
        match = re.match(r"^(.*?)\.((?:\d+\.){2,}\d+(?:[-+][0-9A-Za-z\.\-]+)?)\.nupkg$", artifact)
        if match:
            package_id = match.group(1)
            version = match.group(2)
            return {"package": package_id, "version": version}
        return {"package": artifact, "version": "none"}

    def _parse_ts(self, ts: str | None):
        if not ts:
            return None
        for fmt in ISO_FORMATS:
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None


    def _best_download_ts(self, item: dict) -> datetime | None:
        stats = item.get("stats", [])
        if stats:
            downloaded_str = stats[0].get("downloaded")
            if downloaded_str:
                return self._parse_ts(downloaded_str)

        created_str = item.get("created")
        if created_str:
            return self._parse_ts(created_str)


    def _created_ts(self, item: dict) -> datetime | None:
        return self._parse_ts(item.get("created"))

    def _sort_key(self, item: dict):
        """
        Sort newest-first using:
          1) last_downloaded_dt (None -> oldest)
          2) created as a last resort
        """
        ld = self._best_download_ts(item)
        cr = self._created_ts(item)

        return (
            ld or datetime.fromtimestamp(0, tz=timezone.utc),
            cr or datetime.fromtimestamp(0, tz=timezone.utc),
        )

    def _filter_old_artifacts(self, artifacts, cutoff):

        for art in artifacts:
            art["package"] = self._split_nuget_name(art["name"])["package"]
            art["version"] = self._split_nuget_name(art["name"])["version"]

        grouped = defaultdict(list)
        for art in artifacts:
            grouped[art["package"]].append(art)

        to_delete: list[dict] = []

        for pkg, versions in grouped.items():
            if len(versions) <= 1:
                continue  # if theres only one, just leave it

            versions.sort(key=lambda x: self._sort_key(x), reverse=True)
            recent = []
            old = []
            for v in versions:
                ld = self._best_download_ts(v)
                if ld and ld >= cutoff:
                    recent.append(v)
                else:
                    old.append(v)

            if recent:
                # We have at least one "fresh" version → delete all old
                to_delete.extend(old)
            else:
                # No fresh versions → keep the newest old (versions already sorted desc)
                if len(old) > 1:
                    to_delete.extend(old[1:])

        return to_delete

    def _move_artifact(self, src_repo, path, name, dest_repo):
            if path == ".":
                src = f"{src_repo}/{name}"
            else:
                src = f"{src_repo}/{path}/{name}" if path else f"{src_repo}/{name}"
            dest = src.replace(src_repo, dest_repo)
            move_url = f"{ARTIFACTORY_URL}/api/move/{src}?to=/{dest}"
            if self.test:
                self.log(f'Faking the move {move_url}')
                return True
            else:
                response = requests.post(move_url, headers=HEADER)
                self.log(response.json())
                return response.status_code == 200

    def _move_artifacts_threaded(self, artifacts):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(self._move_artifact,self.source_repo, artifact["path"], artifact["name"], self.target_repo)
                for artifact in artifacts
            ]
            results = [f.result() for f in as_completed(futures)]
        self.log(f"Moved: {results.count(True)}. Failed: {results.count(False)}")


archive_op = ArchiveOperation(1)
archive_op.execute()
