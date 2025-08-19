"""
Artifactory NuGet Package Archive Manager

This module provides functionality to archive old NuGet packages from release
repositories to archive repositories based on age and download activity.
"""

import re
import requests
import os
from collections import defaultdict
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Config:
    """Configuration management for Artifactory operations."""
    
    def __init__(self):
        self.artifactory_url = self._get_artifactory_url()
        self.artifactory_token = self._get_artifactory_token()
        self.default_time = os.getenv("TIME", "4w")
        self.download_time = os.getenv("DOWNLOAD_TIME", "")
        self.max_workers = int(os.getenv("MAX_WORKERS", "5"))
        
        # Repository names
        self.nuget_snapshot = "nuget-snapshot-local"
        self.nuget_release = "nuget-release-local"
        self.nuget_archive = "nuget-release-archive"
    
    def _get_artifactory_url(self) -> str:
        """Get and format Artifactory URL."""
        base_url = os.environ.get("ARTIFACTORY_URL")
        if not base_url:
            raise ValueError("ARTIFACTORY_URL environment variable is required")
        return base_url.rstrip("/") + "/artifactory"
    
    def _get_artifactory_token(self) -> str:
        """Get Artifactory token from environment or vault."""
        token = os.getenv("ARTIFACTORY_TOKEN")
        if token:
            return token
            
        # Fallback to vault authentication
        try:
            from arti_cleanup.auth import get_vault_client
            token_path = os.environ.get("ARTIFACTORY_TOKEN_PATH")
            if not token_path:
                raise ValueError("Either ARTIFACTORY_TOKEN or ARTIFACTORY_TOKEN_PATH must be set")
            
            logger.info("No direct token provided, attempting vault authentication")
            vault = get_vault_client()
            return vault.read(token_path)["data"]["token"]
        except ImportError:
            raise ValueError("Vault authentication module not available and no direct token provided")

class NuGetPackageParser:
    """Utility class for parsing NuGet package information."""
    
    # Regex pattern for NuGet package naming convention
    NUGET_PATTERN = re.compile(r"^(.*?)\.((?:\d+\.){2,}\d+(?:[-+][0-9A-Za-z\.\-]+)?)\.nupkg$")
    
    # ISO timestamp formats supported by Artifactory
    ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")
    
    @classmethod
    def parse_package_name(cls, filename: str) -> Dict[str, str]:
        """
        Parse NuGet package filename to extract package ID and version.
        
        Args:
            filename: NuGet package filename (e.g., 'MyPackage.1.2.3.nupkg')
            
        Returns:
            Dictionary with 'package' and 'version' keys
        """
        match = cls.NUGET_PATTERN.match(filename)
        if match:
            return {
                "package": match.group(1),
                "version": match.group(2)
            }
        return {"package": filename, "version": "unknown"}
    
    @classmethod
    def parse_timestamp(cls, timestamp_str: Optional[str]) -> Optional[datetime]:
        """
        Parse ISO timestamp string to datetime object.
        
        Args:
            timestamp_str: ISO format timestamp string
            
        Returns:
            Parsed datetime object or None if parsing fails
        """
        if not timestamp_str:
            return None
            
        for fmt in cls.ISO_FORMATS:
            try:
                return datetime.strptime(timestamp_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        
        logger.warning(f"Failed to parse timestamp: {timestamp_str}")
        return None

class ArtifactoryClient:
    """Client for interacting with Artifactory REST API."""
    
    def __init__(self, config: Config):
        self.config = config
        self.headers = {
            "content-type": "text/plain",
            "X-JFrog-Art-Api": config.artifactory_token
        }
    
    def search_artifacts(self, repository: str) -> List[Dict]:
        """
        Search for artifacts in a repository using AQL.
        
        Args:
            repository: Repository name to search in
            
        Returns:
            List of artifact metadata dictionaries
        """
        query = (
            f'items.find({{"repo":"{repository}"}}).'
            'include("name", "path", "created", "stat.downloaded", "stat.downloads")'
        )
        
        try:
            response = requests.post(
                f"{self.config.artifactory_url}/api/search/aql",
                data=query,
                headers=self.headers
            )
            response.raise_for_status()
            return response.json().get("results", [])
        except requests.RequestException as e:
            logger.error(f"Failed to search artifacts in {repository}: {e}")
            raise
    
    def move_artifact(self, src_repo: str, path: str, name: str, dest_repo: str, dry_run: bool = True) -> bool:
        """
        Move an artifact from source to destination repository.
        
        Args:
            src_repo: Source repository name
            path: Artifact path within repository
            name: Artifact filename
            dest_repo: Destination repository name
            dry_run: If True, log the operation without executing
            
        Returns:
            True if move was successful, False otherwise
        """
        # Construct source path
        if path == "." or not path:
            src_path = f"{src_repo}/{name}"
        else:
            src_path = f"{src_repo}/{path}/{name}"
        
        dest_path = src_path.replace(src_repo, dest_repo)
        move_url = f"{self.config.artifactory_url}/api/move/{src_path}?to=/{dest_path}"
        
        if dry_run:
            logger.info(f"DRY RUN: Would move {src_path} to {dest_path}")
            return True
        
        try:
            response = requests.post(move_url, headers=self.headers)
            if response.status_code == 200:
                logger.info(f"Successfully moved {src_path} to {dest_path}")
                return True
            else:
                logger.error(f"Failed to move {src_path}: {response.status_code} - {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Error moving {src_path}: {e}")
            return False
    
    def delete_artifact(self, repo: str, path: str, name: str, dry_run: bool = True) -> bool:
        """
        Delete an artifact from a repository.
        
        Args:
            repo: Repository name
            path: Artifact path within repository
            name: Artifact filename
            dry_run: If True, log the operation without executing
            
        Returns:
            True if deletion was successful, False otherwise
        """
        # Construct artifact path
        if path == "." or not path:
            artifact_path = f"{repo}/{name}"
        else:
            artifact_path = f"{repo}/{path}/{name}"
        
        delete_url = f"{self.config.artifactory_url}/{artifact_path}"
        
        if dry_run:
            logger.info(f"DRY RUN: Would delete {artifact_path}")
            return True
        
        try:
            response = requests.delete(delete_url, headers=self.headers)
            if response.status_code == 204:
                logger.info(f"Successfully deleted {artifact_path}")
                return True
            else:
                logger.error(f"Failed to delete {artifact_path}: {response.status_code} - {response.text}")
                return False
        except requests.RequestException as e:
            logger.error(f"Error deleting {artifact_path}: {e}")
            return False

class ArtifactoryOperation(ABC):
    """Abstract base class for Artifactory operations."""
    
    def __init__(self, name: str, days: int, dry_run: bool = True):
        self.name = name
        self.cutoff_days = days
        self.cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        self.dry_run = dry_run
        self.config = Config()
        self.client = ArtifactoryClient(self.config)
        self.parser = NuGetPackageParser()
    
    @abstractmethod
    def execute(self) -> None:
        """Execute the operation."""
        pass
    
    def log(self, message: str, level: str = "info") -> None:
        """Log a message with operation context."""
        getattr(logger, level)(f"[{self.name}] {message}")

class ArchiveOperation(ArtifactoryOperation):
    """Operation to archive old NuGet packages from release to archive repository."""
    
    def __init__(self, days: int, dry_run: bool = True):
        super().__init__("ARCHIVE", days, dry_run)
        self.source_repo = self.config.nuget_release
        self.target_repo = self.config.nuget_archive
    
    def execute(self) -> None:
        """Execute the archive operation."""
        self.log(f"Starting archive from {self.source_repo} to {self.target_repo}")
        self.log(f"Archiving artifacts older than {self.cutoff_days} days")
        self.log(f"Dry run mode: {self.dry_run}")
        
        try:
            # Get all artifacts from source repository
            artifacts = self.client.search_artifacts(self.source_repo)
            self.log(f"Found {len(artifacts)} total artifacts")
            
            # Filter artifacts that should be archived
            artifacts_to_archive = self._filter_artifacts_for_archive(artifacts)
            
            if artifacts_to_archive:
                self.log(f"Found {len(artifacts_to_archive)} artifacts to archive")
                self._archive_artifacts_concurrent(artifacts_to_archive)
            else:
                self.log("No artifacts found for archiving")
                
        except Exception as e:
            self.log(f"Archive operation failed: {e}", "error")
            raise
    
    def _filter_artifacts_for_archive(self, artifacts: List[Dict]) -> List[Dict]:
        """
        Filter artifacts that should be archived based on age and download activity.
        
        Strategy:
        - Group artifacts by package name
        - For each package, keep the most recently downloaded/created version
        - Archive older versions that haven't been downloaded recently
        
        Args:
            artifacts: List of artifact metadata
            
        Returns:
            List of artifacts to archive
        """
        # Parse package information for each artifact
        for artifact in artifacts:
            package_info = self.parser.parse_package_name(artifact["name"])
            artifact.update(package_info)
        
        # Group artifacts by package name
        packages = defaultdict(list)
        for artifact in artifacts:
            packages[artifact["package"]].append(artifact)
        
        artifacts_to_archive = []
        
        for package_name, versions in packages.items():
            if len(versions) <= 1:
                self.log(f"Skipping {package_name}: only one version available")
                continue
            
            # Sort versions by download activity (most recent first)
            versions.sort(key=self._get_sort_key, reverse=True)
            
            # Categorize versions as recent or old
            recent_versions, old_versions = self._categorize_versions(versions)
            
            if recent_versions:
                # Keep recent versions, archive all old ones
                artifacts_to_archive.extend(old_versions)
                self.log(f"{package_name}: Keeping {len(recent_versions)} recent, archiving {len(old_versions)} old")
            elif len(old_versions) > 1:
                # No recent activity, but keep the newest old version
                artifacts_to_archive.extend(old_versions[1:])
                self.log(f"{package_name}: No recent activity, keeping newest, archiving {len(old_versions)-1} old")
        
        return artifacts_to_archive
    
    def _categorize_versions(self, versions: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Categorize versions as recent or old based on download activity."""
        recent_versions = []
        old_versions = []
        
        for version in versions:
            last_activity = self._get_last_activity_timestamp(version)
            if last_activity and last_activity >= self.cutoff:
                recent_versions.append(version)
            else:
                old_versions.append(version)
        
        return recent_versions, old_versions
    
    def _get_last_activity_timestamp(self, artifact: Dict) -> Optional[datetime]:
        """Get the most recent activity timestamp (download or creation)."""
        # Check download timestamp first
        stats = artifact.get("stats", [])
        if stats:
            downloaded_str = stats[0].get("downloaded")
            if downloaded_str:
                download_ts = self.parser.parse_timestamp(downloaded_str)
                if download_ts:
                    return download_ts
        
        # Fall back to creation timestamp
        created_str = artifact.get("created")
        if created_str:
            return self.parser.parse_timestamp(created_str)
        
        return None
    
    def _get_sort_key(self, artifact: Dict) -> Tuple[datetime, datetime]:
        """
        Generate sort key for artifacts (newest first).
        
        Returns tuple of (last_download_time, creation_time) with epoch fallback
        """
        epoch = datetime.fromtimestamp(0, tz=timezone.utc)
        
        last_activity = self._get_last_activity_timestamp(artifact)
        created = self.parser.parse_timestamp(artifact.get("created"))
        
        return (
            last_activity or epoch,
            created or epoch
        )
    
    def _archive_artifacts_concurrent(self, artifacts: List[Dict]) -> None:
        """Archive artifacts using concurrent execution."""
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(
                    self.client.move_artifact,
                    self.source_repo,
                    artifact["path"],
                    artifact["name"],
                    self.target_repo,
                    self.dry_run
                )
                for artifact in artifacts
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        successful = results.count(True)
        failed = results.count(False)
        self.log(f"Archive completed: {successful} successful, {failed} failed")

class CleanupOperation(ArtifactoryOperation):
    """Operation to delete old NuGet packages from snapshot repository."""
    
    def __init__(self, days: int, dry_run: bool = True):
        super().__init__("CLEANUP", days, dry_run)
        self.target_repo = self.config.nuget_snapshot
    
    def execute(self) -> None:
        """Execute the cleanup operation."""
        self.log(f"Starting cleanup of {self.target_repo}")
        self.log(f"Deleting artifacts older than {self.cutoff_days} days")
        self.log(f"Dry run mode: {self.dry_run}")
        
        try:
            # Get all artifacts from target repository
            artifacts = self.client.search_artifacts(self.target_repo)
            self.log(f"Found {len(artifacts)} total artifacts")
            
            # Filter artifacts older than cutoff date
            old_artifacts = self._filter_old_artifacts(artifacts)
            
            if old_artifacts:
                self.log(f"Found {len(old_artifacts)} artifacts to delete")
                self._delete_artifacts_concurrent(old_artifacts)
            else:
                self.log("No old artifacts found for deletion")
                
        except Exception as e:
            self.log(f"Cleanup operation failed: {e}", "error")
            raise
    
    def _filter_old_artifacts(self, artifacts: List[Dict]) -> List[Dict]:
        """
        Filter artifacts that are older than the cutoff date.
        
        Args:
            artifacts: List of artifact metadata
            
        Returns:
            List of artifacts to delete
        """
        old_artifacts = []
        
        for artifact in artifacts:
            # Use creation date as the primary filter criteria
            created_str = artifact.get("created")
            if not created_str:
                self.log(f"No creation date for {artifact.get('name', 'unknown')}, skipping")
                continue
            
            created_date = self.parser.parse_timestamp(created_str)
            if created_date and created_date < self.cutoff:
                old_artifacts.append(artifact)
        
        return old_artifacts
    
    def _delete_artifacts_concurrent(self, artifacts: List[Dict]) -> None:
        """Delete artifacts using concurrent execution."""
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(
                    self.client.delete_artifact,
                    self.target_repo,
                    artifact["path"],
                    artifact["name"],
                    self.dry_run
                )
                for artifact in artifacts
            ]
            
            results = [future.result() for future in as_completed(futures)]
        
        successful = results.count(True)
        failed = results.count(False)
        self.log(f"Cleanup completed: {successful} successful, {failed} failed")

def parse_time_string(time_str: str) -> int:
    """
    Parse time string to days.
    
    Supports formats like: '4w' (4 weeks), '30d' (30 days), '2m' (2 months)
    
    Args:
        time_str: Time string to parse
        
    Returns:
        Number of days
    """
    if not time_str:
        return 30  # Default to 30 days
    
    time_str = time_str.lower().strip()
    
    # Extract number and unit
    if time_str[-1] in ['d', 'w', 'm']:
        try:
            number = int(time_str[:-1])
            unit = time_str[-1]
            
            if unit == 'd':  # days
                return number
            elif unit == 'w':  # weeks
                return number * 7
            elif unit == 'm':  # months (approximate)
                return number * 30
        except ValueError:
            pass
    
    # Try parsing as plain number (assume days)
    try:
        return int(time_str)
    except ValueError:
        logger.warning(f"Could not parse time string '{time_str}', defaulting to 30 days")
        return 30

def main():
    """Main entry point for the archive operation."""
    # Archive artifacts older than 1 day (can be configured)
    archive_days = int(os.getenv("ARCHIVE_DAYS", "1"))
    dry_run = os.getenv("DRY_RUN", "true").lower() == "true"
    
    # Parse cleanup time from TIME environment variable
    time_str = os.getenv("TIME", "4w")
    cleanup_days = parse_time_string(time_str)
    
    operation_type = os.getenv("OPERATION", "archive").lower()
    
    try:
        if operation_type == "archive":
            operation = ArchiveOperation(days=archive_days, dry_run=dry_run)
            operation.execute()
        elif operation_type == "cleanup":
            operation = CleanupOperation(days=cleanup_days, dry_run=dry_run)
            operation.execute()
        elif operation_type == "both":
            # Run archive first, then cleanup
            archive_op = ArchiveOperation(days=archive_days, dry_run=dry_run)
            archive_op.execute()
            
            cleanup_op = CleanupOperation(days=cleanup_days, dry_run=dry_run)
            cleanup_op.execute()
        else:
            logger.error(f"Unknown operation type: {operation_type}. Use 'archive', 'cleanup', or 'both'")
            raise ValueError(f"Invalid operation type: {operation_type}")
            
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        raise

if __name__ == "__main__":
    main()
