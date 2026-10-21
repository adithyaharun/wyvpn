#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

unset GITHUB_ACTIONS
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILED=0
SCRIPT="$ROOT/scripts/changelog-section.sh"

pass() { printf 'ok   %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; FAILED=1; }
check() {
  local name="$1"
  shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

changelog() {
  printf '%s\n' "$@" >"$WORK/CHANGELOG.md"
}
run() {
  "$SCRIPT" --file "$WORK/CHANGELOG.md" "$@" >"$WORK/out" 2>"$WORK/err"
}
refused() {
  ! run "$@"
}
says() {
  grep -qF -- "$1" "$WORK/err"
}

base=(
  "# Changelog"
  ""
  "## [Unreleased]"
  ""
  "### Added"
  ""
  "- Next thing."
  ""
  "## [1.2.0] - 2026-01-02"
  ""
  "### Fixed"
  ""
  "- A fix."
  "- Another fix."
  ""
  "## [1.1.0] - 2026-01-01"
  ""
  "- First."
  ""
  "[Unreleased]: https://example.test/compare/v1.2.0...HEAD"
  "[1.2.0]: https://example.test/compare/v1.1.0...v1.2.0"
  "[1.1.0]: https://example.test/releases/tag/v1.1.0"
)

changelog "${base[@]}"
check "a released section is printed" run 1.2.0
check "the section has no heading and no surrounding blank lines" \
  [ "$(cat "$WORK/out")" = "$(printf '%s\n' '### Fixed' '' '- A fix.' '- Another fix.')" ]
run 1.1.0
check "the last section stops at the link references" [ "$(cat "$WORK/out")" = "- First." ]
run Unreleased
check "Unreleased can be printed" [ "$(cat "$WORK/out")" = "$(printf '%s\n' '### Added' '' '- Next thing.')" ]
check "a version prefix does not match" refused 1.2
check "a missing section fails" refused 9.9.9
check "a missing section is named" says "no [9.9.9] section"

changelog "## [Unreleased]" "" "## [2.0.0] - 2026-02-01" "" "### Added" "" "## [1.0.0] - 2026-01-01" "" "- x" \
  "[Unreleased]: u" "[2.0.0]: u" "[1.0.0]: u"
check "a section with only headings fails" refused 2.0.0
check "an empty section is named" says "the [2.0.0] section"
check "an empty Unreleased fails" refused Unreleased

printf '## [Unreleased]\r\n\r\n## [1.0.0] - 2026-01-01\r\n\r\n- x\r\n\r\n[Unreleased]: u\r\n[1.0.0]: u\r\n' >"$WORK/CHANGELOG.md"
run 1.0.0
check "CRLF line endings are stripped" [ "$(cat "$WORK/out")" = "- x" ]
check "CRLF passes the check" run --check 1.0.0

changelog "${base[@]}"
check "a valid changelog passes the check" run --check 1.2.0
check "an unreleased version passes while Unreleased has entries" run --check 1.3.0

changelog "${base[@]/\#\# \[Unreleased\]/## [Next]}"
check "a missing Unreleased heading fails" refused --check 1.2.0
check "a missing Unreleased heading is named" says "no ## [Unreleased] heading"

changelog "${base[@]/\#\# \[1.2.0\] - 2026-01-02/## [1.2.0]}"
check "a release heading without a date fails" refused --check 1.2.0
check "the undated heading is named" says "[1.2.0] needs a date"

changelog "${base[@]/\#\# \[1.2.0\] - 2026-01-02/## [1.2.0] - Jan 2}"
check "a malformed date fails" refused --check 1.2.0

changelog "${base[@]/\[1.1.0\]: */}"
check "a heading without a link reference fails" refused --check 1.2.0
check "the missing link reference is named" says "no link reference for [1.1.0]"

changelog "${base[@]/\#\# \[1.2.0\]/## [1.2]}"
check "a non-semver heading fails" refused --check 1.1.0
check "the non-semver heading is named" says "not a semver version: [1.2]"

changelog "${base[@]/\#\# \[1.1.0\]/## [1.2.0]}"
check "a duplicate heading fails" refused --check 1.2.0
check "the duplicate heading is named" says "duplicate heading [1.2.0]"

changelog "${base[@]:0:8}" "## Notes" "" "${base[@]:8}"
check "a heading that is not a version fails" refused --check 1.2.0
check "the non-version heading is named" says "not a version heading: ## Notes"

changelog "${base[@]/\#\# \[Unreleased\]/## [Unreleased] - 2026-01-03}"
check "an Unreleased heading with extra text fails" refused --check 1.2.0
check "the extra text is named" says "[Unreleased] heading has extra text"

changelog "${base[@]/\[Unreleased\]: */}"
check "a missing Unreleased link reference fails" refused --check 1.2.0
check "the missing Unreleased link reference is named" says "no link reference for [Unreleased]"

changelog "${base[@]/\[1.1.0\]: /[1.1.0]:}"
check "a link reference without a space counts" run --check 1.2.0
run 1.1.0
check "a link reference without a space ends the section" [ "$(cat "$WORK/out")" = "- First." ]

changelog "${base[@]/\#\# \[1.2.0\] - 2026-01-02/## [1.2.0] - 2026-01-02  }"
check "trailing spaces after the date pass the check" run --check 1.2.0

changelog "## [Unreleased]" "" "<!-- nothing yet -->" "" "## [1.0.0] - 2026-01-01" "" "<!-- todo -->" "" \
  "[Unreleased]: u" "[1.0.0]: u"
check "a section with only an HTML comment has no entries" refused 1.0.0
check "an HTML comment is not an Unreleased entry" refused --check 1.1.0

changelog "${base[@]/- Next thing./- Next **bold** \`code\`}" "" "## [1.0.0] - 2025-01-01" "" "- Old \`code\`." "[1.0.0]: u"
check "markup in Unreleased only warns" run --check 1.2.0
check "the markup warning names the Unreleased line" says "[Unreleased]: - Next **bold**"
silent() {
  ! says "$1"
}
check "markup in older sections is not reported" silent "[1.0.0]: - Old"

changelog "${base[@]/- Next thing./}"
check "a released workspace version passes with an empty Unreleased" run --check 1.2.0
check "an unreleased version fails when Unreleased is empty" refused --check 1.3.0
check "the version without entries is named" says "no [1.3.0] section"

committed_ok() {
  "$SCRIPT" --check 2>"$WORK/err" || { cat "$WORK/err" >&2; return 1; }
}
check "the committed changelog passes the check for the workspace version" committed_ok
RELEASE_YML="$ROOT/.github/workflows/release.yml"
job_lines() {
  awk -v job="$1" '/^  [A-Za-z0-9_-]+:$/ { inside = ($0 == "  " job ":"); next } inside' "$RELEASE_YML"
}
release_notes_wired() {
  local job
  job="$(job_lines release)"
  grep -q 'scripts/changelog-section.sh' <<<"$job" \
    && grep -qF "updater-manifest.sh --notes \"\$(cat \"\$RUNNER_TEMP/notes.md\")\"" <<<"$job" \
    && grep -qF -- "--notes-file \"\$body\"" <<<"$job"
}
check "the release job uses the section for the manifest and the draft" release_notes_wired
tag_only() {
  job_lines "$1" | grep -qx "    if: startsWith(github.ref, 'refs/tags/v')"
}
for job in updater-sign release; do
  check "the $job job runs only for tags" tag_only "$job"
done
preflight_checks() {
  local job
  job="$(job_lines preflight)"
  grep -q "startsWith(github.ref, 'refs/tags/v')" <<<"$job" \
    && grep -q 'persist-credentials: false' <<<"$job" \
    && grep -q '/CHANGELOG.md' <<<"$job" \
    && grep -q 'check_tag_version' <<<"$job" \
    && grep -q 'scripts/changelog-section.sh' <<<"$job"
}
check "the preflight job checks the tag and the changelog section" preflight_checks
build_gated() {
  local job
  job="$(job_lines "$1")"
  grep -qx '    needs: preflight' <<<"$job" \
    && grep -qF "!cancelled() && (needs.preflight.result == 'success' || needs.preflight.result == 'skipped')" <<<"$job"
}
for job in macos windows linux; do
  check "the $job build waits for preflight and still runs when it is skipped" build_gated "$job"
done

[ "$FAILED" = 0 ] || die "changelog script tests failed"
say "all changelog script tests passed"
