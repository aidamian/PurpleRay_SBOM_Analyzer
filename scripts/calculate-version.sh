#!/usr/bin/env bash
# Optional legacy version-suggestion helper. GitHub Actions does not invoke this
# script, it never changes VERSION, and its output is not authoritative.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 release|development|rebuild COMMIT OUTPUT_FILE" >&2
  exit 2
fi

mode=$1
commit=$2
output_file=$3
version_tag_pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

if [[ $mode != release && $mode != development && $mode != rebuild ]]; then
  echo "invalid version mode: $mode" >&2
  exit 2
fi
if ! git cat-file -e "${commit}^{commit}"; then
  echo "commit is not available in the local Git history: $commit" >&2
  exit 2
fi

mapfile -t reachable_tags < <(
  git tag --merged "$commit" --list 'v*' --sort=-v:refname |
    grep -E "$version_tag_pattern" || true
)
mapfile -t exact_tags < <(
  git tag --points-at "$commit" --list 'v*' --sort=-v:refname |
    grep -E "$version_tag_pattern" || true
)

latest_tag=${reachable_tags[0]:-}
exact_tag=${exact_tags[0]:-}
short_commit=$(git rev-parse --short=8 "$commit")
base_version=${latest_tag#v}
base_version=${base_version:-0.0.0}
previous_tag=$latest_tag

if [[ $mode == development ]]; then
  version="${base_version}-dev.${short_commit}"
  tag=""
  is_release=false
elif [[ $mode == rebuild && -n $exact_tag ]]; then
  version=${exact_tag#v}
  tag=$exact_tag
  is_release=false
else
  if [[ $mode == rebuild ]]; then
    version="${base_version}-dev.${short_commit}"
    tag=""
    is_release=false
  elif [[ -n $exact_tag ]]; then
    version=${exact_tag#v}
    tag=$exact_tag
    is_release=true
    previous_tag=""
    for candidate in "${reachable_tags[@]}"; do
      if [[ $candidate != "$exact_tag" ]]; then
        previous_tag=$candidate
        break
      fi
    done
  else
    if [[ -n $latest_tag ]]; then
      range="${latest_tag}..${commit}"
    else
      range=$commit
    fi
    subjects=$(git log --format=%s "$range")
    messages=$(git log --format=%B "$range")
    bump='patch'
    if grep -Eq '^(feat|fix)(\([^)]*\))?!:' <<< "$subjects" ||
      grep -Eq '^BREAKING CHANGE:' <<< "$messages"; then
      bump=major
    elif grep -Eq '^feat(\([^)]*\))?:' <<< "$subjects"; then
      bump=minor
    fi

    IFS=. read -r major minor patch <<< "$base_version"
    case $bump in
      major)
        ((major += 1))
        minor=0
        patch=0
        ;;
      minor)
        ((minor += 1))
        patch=0
        ;;
      patch)
        ((patch += 1))
        ;;
    esac
    version="${major}.${minor}.${patch}"
    tag="v${version}"
    is_release=true
  fi
fi

{
  echo "version=$version"
  echo "tag=$tag"
  echo "previous_tag=$previous_tag"
  echo "short_commit=$short_commit"
  echo "is_release=$is_release"
} >> "$output_file"
