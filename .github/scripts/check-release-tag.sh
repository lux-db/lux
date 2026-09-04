#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <engine|cli|sdk> <tag> <commit>" >&2
  exit 2
fi

component=$1
tag=$2
commit=$3

case "$component" in
  engine)
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
    expected="v$version"
    ;;
  cli)
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' cli/Cargo.toml | head -n 1)
    expected="cli-v$version"
    ;;
  sdk)
    version=$(jq -er '.version' sdk/package.json)
    expected="sdk-v$version"
    ;;
  *)
    echo "unknown release component: $component" >&2
    exit 2
    ;;
esac

if [[ -z "$version" || "$tag" != "$expected" ]]; then
  echo "$component release tag must be $expected; received $tag" >&2
  exit 1
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "release version must be SemVer without build metadata: $version" >&2
  exit 1
fi

if ! git cat-file -e "$commit^{commit}"; then
  echo "release commit does not exist: $commit" >&2
  exit 1
fi

git fetch --no-tags origin \
  '+refs/heads/main:refs/remotes/origin/main' \
  '+refs/heads/release/*:refs/remotes/origin/release/*'

allowed_ref=$(git for-each-ref \
  --contains="$commit" \
  --format='%(refname:short)' \
  refs/remotes/origin/main \
  refs/remotes/origin/release/ | head -n 1)

if [[ -z "$allowed_ref" ]]; then
  echo "release commit must be contained in main or a release/* branch: $commit" >&2
  exit 1
fi

echo "$tag matches $component $version at $commit ($allowed_ref)"
