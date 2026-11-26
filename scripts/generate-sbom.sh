#!/bin/bash
#
# Copyright 2026 Delphix
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# Write a CycloneDX SBOM listing the JDKs this package ships.
#
# Usage: generate-sbom.sh <jdk-directory> <output-file>
#
# The JDKs are shipped as archives (<jdk-directory>/<platform>/jdk17/jdk.tar.gz
# or jdk.zip), which SBOM scanners do not open, so without this file the
# package's SBOM lists none of them. Each JDK's vendor and version are read
# from the "release" file inside its archive, so the list follows a JDK
# upgrade without being edited.
#

function die() {
	echo "$(basename "$0"): $*" >&2
	exit 1
}

[[ $# -eq 2 ]] || die "Usage: $(basename "$0") <jdk-directory> <output-file>"

JDK_DIR="$1"
OUTPUT="$2"

#
# Print the "release" file at the top level of a JDK archive.
#
function release_file() {
	local archive="$1" member

	case "$archive" in
	*.tar.gz)
		member="$(tar -tzf "$archive" | grep -m1 -E '^(\./)?[^/]+/release$')" ||
			die "no release file in '$archive'"
		tar -xzOf "$archive" "$member"
		;;
	*.zip)
		member="$(unzip -Z1 "$archive" | grep -m1 -E '^[^/]+/release$')" ||
			die "no release file in '$archive'"
		unzip -p "$archive" "$member"
		;;
	*)
		die "unknown archive type '$archive'"
		;;
	esac
}

#
# Print the value of KEY="value" from a release file. The Windows JDK's has
# CRLF line endings.
#
function release_value() {
	tr -d '\r' <<<"$2" | sed -n "s/^$1=\"\\(.*\\)\"\$/\\1/p" | head -1
}

components=()
for archive in "$JDK_DIR"/*/jdk17/jdk.tar.gz "$JDK_DIR"/*/jdk17/jdk.zip; do
	[[ -f "$archive" ]] || continue
	platform="$(basename "$(dirname "$(dirname "$archive")")")"
	release="$(release_file "$archive")" || exit 1

	implementor="$(release_value IMPLEMENTOR "$release")"
	java_version="$(release_value JAVA_VERSION "$release")"
	runtime_version="$(release_value JAVA_RUNTIME_VERSION "$release")"
	[[ -n "$java_version" ]] || die "no JAVA_VERSION in '$archive'"

	#
	# Temurin builds name Eclipse Adoptium as the implementor. The Solaris
	# builds come from the OpenJDK jdk17u sources and name none.
	#
	case "$implementor" in
	"Eclipse Adoptium")
		name="Eclipse Temurin JDK"
		version="$runtime_version"
		purl_name="adoptium/temurin-jdk"
		cpe_product="eclipse:temurin"
		;;
	"N/A" | "")
		name="OpenJDK"
		version="$java_version"
		purl_name="openjdk/jdk"
		cpe_product="oracle:openjdk"
		;;
	*)
		die "unknown JDK implementor '$implementor' in '$archive'"
		;;
	esac

	# Every value below goes into JSON unquoted by any tool.
	for value in "$platform" "$version" "$java_version"; do
		[[ "$value" =~ ^[A-Za-z0-9._+-]+$ ]] ||
			die "unexpected value '$value' in '$archive'"
	done

	sha256="$(sha256sum "$archive" | awk '{print $1}')"
	purl="pkg:generic/$purl_name@${version//+/%2B}?platform=$platform"

	components+=("$(
		cat <<-EOF
			    {
			      "type": "library",
			      "bom-ref": "$purl",
			      "name": "$name",
			      "version": "$version",
			      "purl": "$purl",
			      "cpe": "cpe:2.3:a:$cpe_product:$java_version:*:*:*:*:*:*:*",
			      "hashes": [ { "alg": "SHA-256", "content": "$sha256" } ],
			      "licenses": [ { "license": { "name": "GPL-2.0-only WITH Classpath-exception-2.0" } } ],
			      "properties": [ { "name": "delphix:host-jdks:platform", "value": "$platform" } ]
			    }
		EOF
	)")
done

[[ ${#components[@]} -gt 0 ]] || die "no JDK archives found in '$JDK_DIR'"

mkdir -p "$(dirname "$OUTPUT")" || die "failed to create output directory"
{
	cat <<-EOF
		{
		  "bomFormat": "CycloneDX",
		  "specVersion": "1.6",
		  "version": 1,
		  "metadata": {
		    "component": { "type": "application", "name": "host-jdks" }
		  },
		  "components": [
	EOF
	for i in "${!components[@]}"; do
		[[ $i -gt 0 ]] && echo ","
		printf '%s' "${components[$i]}"
	done
	printf '\n  ]\n}\n'
} >"$OUTPUT" || die "failed to write '$OUTPUT'"
