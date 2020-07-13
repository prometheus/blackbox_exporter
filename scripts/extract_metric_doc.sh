#!/bin/bash
set -e

cursection=

function header() {
   section="$1"
   echo
   echo "## ${section^} metrics"
   echo
}

function table_header() {
   echo "| metric name | doc                                              |"
   echo "|-------------|--------------------------------------------------|"
}

# Align column of markdown table saved in "$tmpfile"
function beautify_section() {
   column -t -s'|' -o '|' < "$tmpfile" | sed '/^|----/s/ /-/g'
}

tmpfile=$(mktemp /tmp/extract-metric.XXXXXX)
trap 'rm "$tmpfile"' INT ABRT EXIT

cat <<EOF
# Blackbox Exporter Metric Documentation

*Those tables are automatically extracted from source code. Do not modify
manually!*

EOF

grep '^\s*\<\(Name\|Help\):\s*"\(.*\)"' $* | \
   sed -e 's#^./\(vendor\|main\|config\|prober/utils\).*go:#!General!#' \
   -e 's#^./prober/\([^.]*\)\.go:#!\1!#' \
   -e 's#^.*Help: *"##' \
   -e 's#!\s*Name: *"#! #' \
| sed -e 'N;s/\n/ /' \
   -e 's#",\s*$##' \
   -e 's#",\s*# | #' \
| sort \
| while read -r line ;
do
   section=$(echo "$line" | sed 's/^!\([^!]*\)!.*/\1/')
   doc=${line:$((${#section}+2))}
   if [[ $section != "$cursection" ]]
   then
      cursection="$section"
      beautify_section
      header "$section"  
      table_header > "$tmpfile"
   fi
   echo "|$doc|" >> "$tmpfile"
done
beautify_section


