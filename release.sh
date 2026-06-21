#!/usr/bin/env bash
# Cut a Maven Central release.
#
# Idempotent: if pom.xml is already at $VERSION (e.g. the bump was committed in a
# PR before merging), the script skips the bump/commit step and only tags + pushes.
#
# Usage: ./release.sh <version>
#   ./release.sh 0.3.0
set -euo pipefail

VERSION=${1:-}
if [[ -z "$VERSION" ]]; then
  echo "Usage: ./release.sh <version>"
  echo "Example: ./release.sh 0.3.0"
  exit 1
fi

# Reject leading 'v' — VERSION is the semver, TAG gets the prefix
if [[ "$VERSION" == v* ]]; then
  echo "Error: pass the version without the leading 'v' (got '${VERSION}'). Example: ./release.sh 0.3.0"
  exit 1
fi

TAG="v${VERSION}"

# Refuse if the working tree has uncommitted changes — they could leak into the release commit
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: working tree has uncommitted changes. Commit or stash before releasing."
  git status --short
  exit 1
fi

# Ensure we're on main and up to date
git checkout main
git pull --ff-only origin main

# Refuse if the tag already exists (locally or remotely) — release would be ambiguous
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "Error: tag ${TAG} already exists locally. Delete it first if you really want to re-release: git tag -d ${TAG}"
  exit 1
fi
if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "Error: tag ${TAG} already exists on origin. Pick a new version."
  exit 1
fi

# Read current pom version (suppress Maven download/info noise; keep only the version line)
CURRENT_VERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout)

if [[ "${CURRENT_VERSION}" == "${VERSION}" ]]; then
  echo "Version is already ${VERSION} on main — skipping bump, going straight to tag."
else
  echo "Bumping ${CURRENT_VERSION} -> ${VERSION}"

  # Bump all pom.xml files atomically
  mvn versions:set -DnewVersion="${VERSION}" -DgenerateBackupPoms=false -q

  # Keep README in sync (lines like '<version>X.Y.Z</version>' inside the install snippets).
  # Only rewrites the exact CURRENT_VERSION → VERSION mapping to avoid touching unrelated text.
  if [[ -f README.md ]]; then
    # macOS sed needs '' after -i; this form works on both BSD and GNU sed
    sed -i.bak "s|<version>${CURRENT_VERSION}</version>|<version>${VERSION}</version>|g" README.md
    rm -f README.md.bak
  fi

  git add pom.xml lnurl-java-core/pom.xml lnurl-java-spring-boot-starter/pom.xml lnurl-java-examples/pom.xml README.md

  # Guard against the "nothing staged" case (e.g. all files happened to already be at VERSION)
  if git diff --cached --quiet; then
    echo "No file changes staged after bump — already in sync. Skipping commit."
  else
    git commit -m "chore: bump version to ${TAG}"
  fi
fi

# Tag and push
git tag "${TAG}"
git push origin main
git push origin "${TAG}"

echo "Released ${TAG} — CI is publishing to Maven Central"
echo "https://github.com/AskAHumanOnline/lnurl-java/actions"
