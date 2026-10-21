#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/changelog-section.sh [--file <path>] <version>
       scripts/changelog-section.sh [--file <path>] --check [<version>]

Prints the body of the "## [<version>]" section of CHANGELOG.md without its
heading. Fails when the section is missing or has no entries.

--check checks the file instead: an "## [Unreleased]" heading, a date on every
release heading ("## [x.y.z] - YYYY-MM-DD"), a link reference for every
heading, and either a section for <version> (default: the workspace version)
or entries under Unreleased. It warns about ** and backticks in those sections,
because the update prompt shows notes as plain text.
EOF
}

AWK_LIB='
  { sub(/\r$/, "") }
  function label(line,  rest, i) {
    rest = substr(line, 5)
    i = index(rest, "]")
    return i ? substr(rest, 1, i - 1) : ""
  }
  function entry(line) {
    return line ~ /[^[:space:]]/ && line !~ /^#/ && line !~ /^<!--/
  }
  function trim_end(text) {
    sub(/[[:space:]]+$/, "", text)
    return text
  }
'

has_entries() {
  awk "$AWK_LIB"' entry($0) { found = 1 } END { exit found ? 0 : 1 }'
}

section() {
  awk -v want="$1" "$AWK_LIB"'
    /^## / {
      if (inside) exit
      if (substr($0, 1, 4) == "## [" && label($0) == want) { inside = 1; found = 1 }
      next
    }
    /^\[[^]]*\]:/ { if (inside) exit }
    inside { line[++n] = $0 }
    END {
      if (!found) exit 3
      first = 1
      while (first <= n && line[first] !~ /[^[:space:]]/) first++
      last = n
      while (last >= first && line[last] !~ /[^[:space:]]/) last--
      for (i = first; i <= last; i++) print line[i]
    }
  ' <"$FILE"
}

problems() {
  awk -v version="$1" "$AWK_LIB"'
    /^## / {
      l = label($0)
      current = l
      if (substr($0, 1, 4) != "## [" || l == "") { print "not a version heading: " $0; next }
      rest = trim_end(substr($0, length(l) + 6))
      if (l in seen) print "duplicate heading [" l "]"
      seen[l] = 1
      order[++n] = l
      if (l == "Unreleased") {
        if (rest != "") print "[Unreleased] heading has extra text: " $0
      } else if (l !~ /^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$/) {
        print "not a semver version: [" l "]"
      } else if (rest !~ /^ - [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) {
        print "[" l "] needs a date: ## [" l "] - YYYY-MM-DD"
      }
      next
    }
    /^\[[^]]*\]:/ { refs[substr($0, 2, index($0, "]") - 2)] = 1; current = ""; next }
    current == "Unreleased" && entry($0) { unreleased = 1 }
    END {
      if (!("Unreleased" in seen)) print "no ## [Unreleased] heading"
      for (i = 1; i <= n; i++) if (!(order[i] in refs)) print "no link reference for [" order[i] "]"
      if (!(version in seen) && !unreleased) print "no [" version "] section and no entries under [Unreleased]"
    }
  ' <"$FILE"
}

markup() {
  awk -v version="$1" "$AWK_LIB"'
    /^## / { current = label($0); next }
    /^\[[^]]*\]:/ { current = ""; next }
    (current == "Unreleased" || current == version) && entry($0) && /[*][*]|`/ {
      print "line " NR " [" current "]: " $0
    }
  ' <"$FILE"
}

FILE="$ROOT/CHANGELOG.md" CHECK=false
while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="${2:?--file needs a value}"; shift 2 ;;
    --check) CHECK=true; shift ;;
    -h | --help) usage; exit 0 ;;
    -*) usage; exit 2 ;;
    *) break ;;
  esac
done
[ -f "$FILE" ] || die "no such file: $FILE"

if $CHECK; then
  [ $# -le 1 ] || { usage; exit 2; }
  version="${1:-$(workspace_version)}"
  found="$(problems "$version")"
  [ -z "$found" ] || die "$FILE: $(printf '%s' "$found" | paste -sd ';' - | sed 's/;/; /g')"
  markup "$version" | while IFS= read -r line; do
    warn "$FILE: the update prompt shows notes as plain text; ** and backticks stay as typed: $line"
  done
  say "$FILE is valid"
  exit 0
fi

[ $# -eq 1 ] || { usage; exit 2; }
rc=0
body="$(section "$1")" || rc=$?
[ "$rc" != 3 ] || die "no [$1] section in $FILE"
[ "$rc" = 0 ] || die "could not read $FILE"
printf '%s\n' "$body" | has_entries || die "the [$1] section in $FILE has no entries"
printf '%s\n' "$body"
