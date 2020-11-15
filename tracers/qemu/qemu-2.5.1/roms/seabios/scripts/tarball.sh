#!/bin/sh
#
# Script to create seabios release and snapshot tarballs.
# Accepts conmmit (hash, tag, branch, ...) as first argument,
# uses HEAD if unspecified.
#

commit="${1-HEAD}"

# figure name for the tarball
reltag="$(git describe --tags --match 'rel-*' --exact $commit 2>/dev/null)"
if test "$reltag" != ""; then
	# release
	name="${reltag#rel-}"
else
	# snapshot
	reltag="$(git describe --tags --match 'rel-*' $commit 2>/dev/null)"
	name="snap-${reltag#rel-}"
fi

# export tarball archive from git
prefix="seabios-${name}/"
output="seabios-${name}.tar"
echo "# commit $commit  ->  tarball: ${output}.gz"
rm -f "$output" "${output}.gz"
git archive --format=tar --prefix="$prefix" "$commit" > "$output"

# add .version file to tarball
dotver="$(mktemp dotver.XXXXXX)"
echo "$name" > "$dotver"
tar --append --file="$output" --owner=root --group=root --mode=0664 \
	--transform "s:${dotver}:${prefix}.version:" "$dotver"
rm -f "$dotver"

# finally compress it
gzip "$output"
