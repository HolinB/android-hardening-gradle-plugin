#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
checksum_file="$repository_root/gradle/wrapper/gradle-wrapper.jar.sha256"
wrapper_jar="$repository_root/gradle/wrapper/gradle-wrapper.jar"

expected=$(awk '$2 == "gradle/wrapper/gradle-wrapper.jar" { print $1 }' "$checksum_file")
if [ "$(wc -l < "$checksum_file" | tr -d ' ')" != "1" ] ||
    [ "${#expected}" != "64" ]; then
    echo "Invalid Gradle wrapper JAR checksum contract" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$wrapper_jar" | awk '{ print $1 }')
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$wrapper_jar" | awk '{ print $1 }')
else
    echo "No SHA-256 tool is available" >&2
    exit 1
fi

if [ "$actual" != "$expected" ]; then
    echo "Gradle wrapper JAR checksum mismatch" >&2
    exit 1
fi

echo "Gradle wrapper JAR checksum verified: $actual"
