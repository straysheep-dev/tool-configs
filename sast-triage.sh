#!/bin/bash

# SPDX-License-Identifier: MIT
# Assisted-by: Claude:claude-sonnet-5
# Assisted-by: Claude:claude-opus-5
# version=0.9

# sast-triage - bash commands to orchestrate source code review.
#
# This script can be executed repeatedly without re-running tools if the report files exist.
# Everything is written to ~/src/sast-review-YYYY-mm-dd/. A summary JSONL file is built and
# a TSV summary renders at the end.
#
# It reads a tsv under ~/src/repos.tsv to determine what repos to clone and operate on:
# TSV format: project<TAB>repo_url<TAB>sha1-commit
# Example: some_project  https://github.com/some_author/some_project.git  abcdef1234567890abcdef1234567890abcdef12

set -uo pipefail
export LC_ALL=C  # Consistent locality for language sorting and character encoding.
export TZ=UTC    # Set UTC for forensics.

# RAM detection, titus explore can crash without enough memory.
mem_total_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
mem_total_mb=$(( mem_total_kb / 1024 ))
if [ "$mem_total_mb" -lt 12288 ]; then
	echo "[WARN] System has ${mem_total_mb}MB RAM (recommended: 12288MB+)" >&2
fi

# Disk space detection, titus datastores and scanner output can be large.
disk_avail_mb=$(df -Pm "${HOME}" | awk 'NR==2 {print $4}')  # Use MB for the value comparison
if [ "$disk_avail_mb" -lt 10240 ]; then
	echo "[WARN] ${HOME} has ${disk_avail_mb}MB free (recommended: 10240MB+)" >&2
fi

src_dir="${HOME}/src"
repos_file="${HOME}/src/repos.tsv"

mkdir -p "${src_dir}"

if [ ! -f "${repos_file}" ]; then
	echo "No repos file at ${repos_file}, nothing to review." >&2
	exit 1
fi

echo "[$(date -Iseconds)] Starting $0..."

results_dir="${HOME}/src/sast-review-$(date +%F)"
mkdir -p "${results_dir}"
cd "${results_dir}" || exit 1

# Truncate these files to avoid growing lists of duplicates.
: > "${results_dir}/commits.txt"
: > "${results_dir}/binaries.list"
: > "${results_dir}/ecosystems.txt"
: > "${results_dir}/guarddog-skipped.txt"
: > "${results_dir}/guarddog-scores.tsv"

max_jobs=8        # Cap concurrent scanners due to memory utilization.
titus_pids=()     # Prepare to run titus in the background, async.
osv_pids=()       # osv-scanner was chosen over pip-audit, or other language-specific scanners
semgrep_pids=()   # Prepare to run semgrep in the background, async.
guarddog_pids=()  # Prepare to run guarddog in the background, async.
bandit_pids=()    # Prepare to run bandit in the background, async.

skip_titus=false
if [ -e "${results_dir}/titus.ds" ]; then
	echo "[$(date -Iseconds)] titus.ds already exists in ${results_dir}, skipping titus scans."
	skip_titus=true
fi

# Stage 1, run titus against all source code.
while IFS=$'\t' read -r project url commit; do
	[ -z "$project" ] && continue
	[[ "$project" == \#* ]] && continue  # Ignore comments in repos.tsv

	proj_dir="${src_dir}/${project}"

	if [ ! -d "${proj_dir}/.git" ]; then
		echo "[$(date -Iseconds)] Cloning missing project: ${project}"
		git clone --quiet "$url" "$proj_dir"
	fi
	git -C "$proj_dir" fetch --quiet origin "$commit" 2>/dev/null
	git -C "$proj_dir" checkout --quiet "$commit"
    # Verify we actually cloned and checked out the pinned commit.
	actual="$(git -C "$proj_dir" rev-parse HEAD)"
	if [ "$actual" != "$commit" ]; then
		echo "[WARN] ${project}: requested ${commit}, got ${actual}" >&2
	fi
	printf '%s\t%s\n' "$project" "$actual" >> "${results_dir}/commits.txt"

	# Enumerate the package ecosystem from manifest files.
	ecosystem=""
	if compgen -G "${proj_dir}/setup.py" >/dev/null 2>&1 || \
	   compgen -G "${proj_dir}/pyproject.toml" >/dev/null 2>&1 || \
	   compgen -G "${proj_dir}/requirements*.txt" >/dev/null 2>&1; then
		ecosystem="pypi"
	elif [ -e "${proj_dir}/package.json" ]; then
		ecosystem="npm"
	elif [ -e "${proj_dir}/go.mod" ]; then
		ecosystem="go"
	elif [ -e "${proj_dir}/Cargo.toml" ]; then
		ecosystem="crates"
	elif [ -e "${proj_dir}/Gemfile" ] || compgen -G "${proj_dir}/*.gemspec" >/dev/null 2>&1; then
		ecosystem="rubygems"
	elif [ -e "${proj_dir}/composer.json" ]; then
		ecosystem="packagist"
	fi

	# Enumerate which languages actually have source files present.
	has_py=false
	has_go=false
	has_rs=false
	has_rb=false
	has_js=false
	has_c=false
	while IFS= read -r f; do
		case "$f" in
			*.py)                     has_py=true ;;
			*.go)                     has_go=true ;;
			*.rs)                     has_rs=true ;;
			*.rb)                     has_rb=true ;;
			*.js|*.ts)                has_js=true ;;
			*.c|*.h|*.cpp|*.hpp|*.cc) has_c=true ;;
		esac
	done < <(git -C "$proj_dir" ls-files)

	printf '%s\t%s\tpy=%s go=%s rs=%s rb=%s js=%s c=%s\n' \
		"$project" "${ecosystem:-none}" \
		"$has_py" "$has_go" "$has_rs" "$has_rb" "$has_js" "$has_c" \
		>> "${results_dir}/ecosystems.txt"

	# Never cd out of results_dir for titus, absolute scan path means
	# titus.ds accumulates findings from every project into one datastore.
	if [ "$skip_titus" = false ]; then
		(
			scan_start=$(date +%s)
			titus scan "${proj_dir}" --rules "${HOME}/src/tool-configs/titus/" --git \
				-q >> titus.log 2>&1
			scan_status=$?
			scan_runtime=$(( $(date +%s) - scan_start ))
			echo "[$(date -Iseconds)] titus finished: ${project} (exit ${scan_status}, ${scan_runtime}s)"
		) &
		titus_pids+=($!)
	fi

	if [ ! -e "${results_dir}/${project}-osv.json" ]; then
		(
			# We run with all call analysis enabled except for rust, due to RCE concerns.
			# https://google.github.io/osv-scanner/usage/scan-source#call-analysis-in-rust
			scan_start=$(date +%s)
			osv-scanner scan source -r "${proj_dir}" \
				--call-analysis=all --no-call-analysis=rust \
				--format json --output "${results_dir}/${project}-osv.json" \
				>> osv.log 2>&1
			json_status=$?  # osv-scanner exits non-zero if it has any findings.
            osv-scanner scan source -r "${proj_dir}" \
				--call-analysis=all --no-call-analysis=rust \
				--format html --output "${results_dir}/${project}-osv.html" \
				>> osv.log 2>&1
			html_status=$?  # osv-scanner exits non-zero if it has any findings.
			scan_runtime=$(( $(date +%s) - scan_start ))
            echo "[$(date -Iseconds)] osv-scanner finished: ${project} (json ${json_status}, html ${html_status}, ${scan_runtime}s)"
		) &
		osv_pids+=($!)
	fi

	if [ ! -e "${results_dir}/${project}-semgrep.json" ]; then
		(
			scan_start=$(date +%s)
			semgrep scan "${proj_dir}" \
                --config p/default \
				--config "${HOME}/src/tool-configs/semgrep/" \
				--json --output "${results_dir}/${project}-semgrep.json" \
				>> semgrep.log 2>&1
			scan_status=$?
			scan_runtime=$(( $(date +%s) - scan_start ))
			echo "[$(date -Iseconds)] semgrep finished: ${project} (exit ${scan_status}, ${scan_runtime}s)"
		) &
		semgrep_pids+=($!)
	fi

	if [ -z "$ecosystem" ]; then
		printf '%s\tno-ecosystem\n' "$project" >> "${results_dir}/guarddog-skipped.txt"
		echo "[$(date -Iseconds)] guarddog: no supported ecosystem for ${project}, skipping"
	elif [ ! -e "${results_dir}/${project}-guarddog.json" ]; then
		(
			scan_start=$(date +%s)
			guarddog "${ecosystem}" scan "${proj_dir}" \
				--output-format json \
				> "${results_dir}/${project}-guarddog.json" \
				2>> guarddog.log
			scan_status=$?
			scan_runtime=$(( $(date +%s) - scan_start ))
			echo "[$(date -Iseconds)] guarddog finished: ${project} (${ecosystem}, exit ${scan_status}, ${scan_runtime}s)"
		) &
		guarddog_pids+=($!)
	fi

	if [ "$has_py" = true ] && [ ! -e "${results_dir}/${project}-bandit.json" ]; then
		(
			# -ll = MEDIUM severity and above, all confidence levels.
			# --ignore-nosec so developer-suppressed findings still surface.
			scan_start=$(date +%s)
			bandit -r "${proj_dir}" -ll -q --ignore-nosec \
				--format json --output "${results_dir}/${project}-bandit.json.part" \
				>> bandit.log 2>&1
			json_status=$?  # bandit exits non-zero if it has any findings.
			mv "${results_dir}/${project}-bandit.json.part" \
			   "${results_dir}/${project}-bandit.json"

			bandit -r "${proj_dir}" -ll -q --ignore-nosec \
				--format html --output "${results_dir}/${project}-bandit.html" \
				>> bandit.log 2>&1
			html_status=$?  # bandit exits non-zero if it has any findings.
			scan_runtime=$(( $(date +%s) - scan_start ))
			echo "[$(date -Iseconds)] bandit finished: ${project} (json ${json_status}, html ${html_status}, ${scan_runtime}s)"
		) &
		bandit_pids+=($!)
	fi

	# git ls-files needs to cd, and make sure each line has the full path
	# name as we go rather than reconstructing it later.
	( cd "${proj_dir}" && \
	  git ls-files -z --others --exclude-standard --cached | \
	  while IFS= read -r -d '' f
	  do
		[ -f "$f" ] || continue                             # Ignore directories (missing submodules)
		mime_encoding=$(file -bL --mime-encoding -- "$f")   # Determine encoding type
		mime_type=$(file -bL --mime-type -- "$f")           # Determine mime type
		[ "$mime_encoding" = "binary" ] && [ "$mime_type" != "inode/x-empty" ] && \
			printf '%s\t%s\t%s\n' "$project" "$(realpath -s "$f")" "$mime_type"
	  done ) >> "${results_dir}/binaries.list"

	# Manage concurrent processes to avoid memory exhaustion.
	while [ "$(jobs -rp | wc -l)" -ge "$max_jobs" ]; do
		sleep 2
	done

done < "${repos_file}"

# Titus
echo "[$(date -Iseconds)] Waiting on ${#titus_pids[@]} titus scans..."
wait "${titus_pids[@]}"
echo "[$(date -Iseconds)] All titus scans complete."
if [ ! -e "${results_dir}/titus.ds.json" ]; then
	echo "[$(date -Iseconds)] Writing titus findings to ${results_dir}/titus.ds.json..."
	titus report --datastore "${results_dir}/titus.ds" --format json > "${results_dir}/titus.ds.json"
	echo "[$(date -Iseconds)] Wrote titus JSON report."
fi

# osv-scanner
echo "[$(date -Iseconds)] Waiting on ${#osv_pids[@]} osv-scanner runs..."
wait "${osv_pids[@]}" 2>/dev/null
echo "[$(date -Iseconds)] All osv-scanner runs complete."

# semgrep
echo "[$(date -Iseconds)] Waiting on ${#semgrep_pids[@]} semgrep scans..."
wait "${semgrep_pids[@]}" 2>/dev/null
echo "[$(date -Iseconds)] All semgrep scans complete."

# guarddog
echo "[$(date -Iseconds)] Waiting on ${#guarddog_pids[@]} guarddog scans..."
wait "${guarddog_pids[@]}" 2>/dev/null
echo "[$(date -Iseconds)] All guarddog scans complete."

# bandit
echo "[$(date -Iseconds)] Waiting on ${#bandit_pids[@]} bandit scans..."
wait "${bandit_pids[@]}" 2>/dev/null
echo "[$(date -Iseconds)] All bandit scans complete."

# Stage 2, run YARA-X and or FLOSS on all binary files discovered.
while IFS=$'\t' read -r project bin mime; do
	proj_dir="${src_dir}/${project}"
	rel="${bin#"${proj_dir}"/}"
	safe_name="${rel//\//_}"

    if [ ! -e "${project}-${safe_name}.floss.txt" ]; then
        echo "[$(date -Iseconds)] Running FLOSS on ${bin} (${mime})..."
        floss -n 10 --color never -v -- "$bin" \
            > "${project}-${safe_name}.floss.txt" \
            2> "${project}-${safe_name}.floss.stderr"
        floss_rc=$?

        if grep -q "FLOSS currently supports the following formats" "${project}-${safe_name}.floss.stderr"; then
            echo "[$(date -Iseconds)] ${bin} is not PE/ELF, retrying with --only static..."
            floss -n 10 --color never -v --only static -- "$bin" \
                > "${project}-${safe_name}.floss.txt" \
                2> "${project}-${safe_name}.floss.stderr"
            floss_rc=$?
        fi

        if [ "$floss_rc" -ne 0 ]; then
            echo "[$(date -Iseconds)] FLOSS exited ${floss_rc} on ${bin}, see ${project}-${safe_name}.floss.stderr" >&2
        else
            rm -f "${project}-${safe_name}.floss.stderr"
        fi
    fi

    # TODO: Once we build and test the yara rules, enable this block.
	# yr scan "${HOME}/src/tool-configs/yara/" "$bin" | \
	# 	tee "${project}-${safe_name}.yara.txt" >/dev/null
done < "${results_dir}/binaries.list"

# Stage 3: Merge and normalize all findings as a JSONL file.
# Titus, FLOSS, and YARA output is absent here; this is only for SAST reports
# so we can 1) have a summary of the results and 2) compare and investigate
# in Titus as needed.
merge_findings() {
	local out="${results_dir}/findings.jsonl"
	local f project

	if ! command -v jq >/dev/null 2>&1; then
		echo "[!] jq not found, skipping merge" >&2
		return 1
	fi

    # Clear a previous merge in case we need to run again.
	: > "$out"

	# bandit: .results[], severity is LOW/MEDIUM/HIGH already.
	for f in "${results_dir}"/*-bandit.json; do
		[ -e "$f" ] || continue
		project="$(basename "$f" -bandit.json)"
		jq -c --arg project "$project" --arg strip "${src_dir}/" '
			.results[]? | {
				project: $project,
				tool: "bandit",
				rule: .test_id,
				severity: .issue_severity,
				path: (.filename | sub("^" + $strip; "")),
				line: .line_number,
				message: .issue_text
			}' "$f" >> "$out" 2>> merge.log  # merge.log will record JSON schema errors.
	done

	# semgrep: .results[], severity is INFO/WARNING/ERROR.
	for f in "${results_dir}"/*-semgrep.json; do
		[ -e "$f" ] || continue
		project="$(basename "$f" -semgrep.json)"
		jq -c --arg project "$project" --arg strip "${src_dir}/" '
			.results[]? | {
				project: $project,
				tool: "semgrep",
				rule: .check_id,
				severity: ({"ERROR":"HIGH","WARNING":"MEDIUM","INFO":"LOW"}[.extra.severity] // "UNKNOWN"),
				path: (.path | sub("^" + $strip; "")),
				line: .start.line,
				message: .extra.message
			}' "$f" >> "$out" 2>> merge.log  # merge.log will record JSON schema errors.
	done

	# osv-scanner: nested results[] > packages[] > vulnerabilities[].
	# MODERATE is normalized to MEDIUM; line is always 0 (manifest-level finding).
	for f in "${results_dir}"/*-osv.json; do
		[ -e "$f" ] || continue
		project="$(basename "$f" -osv.json)"
		jq -c --arg project "$project" '
			.results[]? as $r
			| $r.packages[]? as $pkg
			| $pkg.vulnerabilities[]?
			| {
				project: $project,
				tool: "osv",
				rule: .id,
				severity: ((.database_specific.severity // "UNKNOWN")
				           | ascii_upcase
				           | if . == "MODERATE" then "MEDIUM" else . end),
				path: $r.source.path,
				line: 0,
				message: "\($pkg.package.name)@\($pkg.package.version) \(.summary // "")"
			}' "$f" >> "$out" 2>> merge.log  # merge.log will record JSON schema errors.
	done

	# guarddog: .results is keyed by rule id; non-hits are empty objects.
	# No severity field, so threat-* maps to HIGH and capability-* to LOW.
	# Paths are already relative to the package root.
	for f in "${results_dir}"/*-guarddog.json; do
		[ -e "$f" ] || continue
		project="$(basename "$f" -guarddog.json)"
		jq -c --arg project "$project" '
			.results
			| to_entries[]
			| select(.value | type == "array")
			| .key as $rule
			| .value[]
			| {
				project: $project,
				tool: "guarddog",
				rule: $rule,
				severity: (if ($rule | startswith("threat-")) then "HIGH" else "LOW" end),
				path: ($project + "/" + (.location | split(":")[0])),
				line: (.location | split(":")[1] | tonumber? // 0),
				message: "\(.message) [match: \(.match)]"
			}' "$f" >> "$out" 2>> merge.log  # merge.log will record JSON schema errors.

		jq -r --arg project "$project" \
			'[$project, .risk_score.label, (.issues|tostring)] | @tsv' \
			"$f" >> "${results_dir}/guarddog-scores.tsv" 2>> merge.log
	done

	echo "[$(date -Iseconds)] merged $(wc -l < "$out") findings -> ${out}"
	sha256sum "$out" | tee "${out}.sha256"
}

# Run the merge function above to generate the findings.jsonl file.
merge_findings

echo "[$(date -Iseconds)] Printing summary.tsv to terminal:"
echo ""

# This summary TSV is printed to terminal, to help point the operator in the right directions.
{
    printf 'COUNT\tPROJECT\tTOOL\tSEVERITY\n'
    jq -r '[.project, .tool, .severity] | @tsv' findings.jsonl | sort | uniq -c | sort -k4
} | column -t | tee "${results_dir}/summary.tsv"

echo ""

# This will parse file paths and line numbers across the SAST and pattern matching tools, to
# create a list showing shared matches across them both. Use this list along with the summary
# above to prioritize review.
# The caveat is Titus does not report full paths in JSON; so matches for "requirements.txt"
# can be vague if you have 5 projects that each have a requirements file.
# TODO: Find a way to determine repo path, or get that information into the Titus JSON.
if [ ! -e "${results_dir}/cross-examine.list" ]; then
    echo "[$(date -Iseconds)] Comparing output files for shared matches on file:line to create cross-examine.list..."
    jq -r '.[] | .Matches[] | "\(.file_path):\(.Location.Source.Start.Line)"' \
        titus.ds.json | LC_ALL=C sort -u > "${results_dir}/titus-matches.txt"

    jq -r 'select(.line > 0) | "\(.path):\(.line)"' \
        findings.jsonl | sed 's|^[^/]*/||' | LC_ALL=C sort -u > "${results_dir}/sast-matches.txt"

    comm -12 "${results_dir}/titus-matches.txt" "${results_dir}/sast-matches.txt" > "${results_dir}/cross-examine.list"

    echo "[$(date -Iseconds)] Coverage stats:"
    printf '  %-40s %s\n' \
        "SAST findings (findings.jsonl):"    "$(wc -l < "${results_dir}/findings.jsonl")" \
        "Titus match locations:"             "$(wc -l < "${results_dir}/titus-matches.txt")" \
        "Shared matches (cross-examine):"    "$(wc -l < "${results_dir}/cross-examine.list")"

else
    echo "[$(date -Iseconds)] cross-examine.list already exists in ${results_dir}."
fi

echo ""
echo "[$(date -Iseconds)] $0 done."
