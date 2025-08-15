import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")

class ArtiArchive:
    def __init__(self, artifacts, age):
        self.artifacts = artifacts
        self.age = age

    def split_nuget_name(self, artifact):
        match = re.match(r"^(.*?)\.((?:\d+\.){2,}\d+(?:[-+][0-9A-Za-z\.\-]+)?)\.nupkg$", artifact)
        if match:
            package_id = match.group(1)
            version = match.group(2)
            return {"package": package_id, "version": version}
        return {"package": artifact, "version": "none"}


    def parse_ts(self, ts: str | None):
        if not ts:
            return None
        for fmt in ISO_FORMATS:
            try:
                return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None


    def best_download_ts(self, item: dict) -> datetime | None:
        stats = item.get("stats", [])

        if stats:
            downloaded_str = stats[0].get("downloaded")
            if downloaded_str:
                return self.parse_ts(downloaded_str)

        created_str = item.get("created")
        if created_str:
            return self.parse_ts(created_str)


    def created_ts(self, item: dict) -> datetime | None:
        return self.parse_ts(item.get("created"))


    def sort_key(self, item: dict, cutoff: datetime):
        """
        Sort newest-first using:
          1) last_downloaded_dt (None -> oldest)
          2) created as a last resort
        """
        ld = self.best_download_ts(item)
        cr = self.created_ts(item)

        return (
            ld or datetime.fromtimestamp(0, tz=timezone.utc),
            cr or datetime.fromtimestamp(0, tz=timezone.utc),
        )


    def filter_old_artifacts_by_last_download(self):
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.age)

        # Add package and version to the artifact dict for grouping
        for art in self.artifacts:
            art["package"] = self.split_nuget_name(art["name"])["package"]
            art["version"] = self.split_nuget_name(art["name"])["version"]

        grouped = defaultdict(list)
        for art in self.artifacts:
            grouped[art["package"]].append(art)

        to_delete: list[dict] = []

        for pkg, versions in grouped.items():
            if len(versions) <= 1:
                continue  # if theres only one, just leave it

            # Sort newest-first by lastDownloaded, then by created
            versions.sort(key=lambda x: self.sort_key(x, cutoff), reverse=True)
            recent = []
            old = []
            for v in versions:
                ld = self.best_download_ts(v)
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
                    to_delete.extend(old[1:])  # keep old[0], delete the rest

        return to_delete
