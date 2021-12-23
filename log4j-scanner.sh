#!/bin/bash

#
# Bash script to scan a directory or all local file systems for log4j.
# Requires packages bash (v3), unzip
#


# When passed no argument, scans all local filesystems, otherwise only the given path is scanned
scanDir=$1

if [[ "$scanDir" =~ ^-h|^--h ]]
then
  echo "Scan local file system or directory tree for log4j"
  echo ""
  echo "USAGE: log4j-scanner.sh [directory]"
  echo ""
  echo "directory  [optional] Directory tree to scan. If not given all local file systems are scanned"
  exit 0
fi

searchClass="org/apache/logging/log4j/core/lookup/JndiLookup.class"
tempDir=$(mktemp -d /tmp/log4j-scan.XXXX)
outFile=$(mktemp /tmp/CVE-2021-44228.XXXX)
vulnerabilities_found=0
ansi_yellow='\033[1;33m'
ansi_green='\033[0;32m'
ansi_nocolor='\033[0m'
analysed_files=0

rm "${outFile}" >/dev/null 2>&1

# Check for requirements
if ! command -v unzip &> /dev/null
then
  echo "ERROR: this script requires unzip to be installed on your system."
  echo "Please install unzip and try again."
  exit 2
fi

# Detects if the class exist inside a jar, ear or war file.
function findClass {
  local jarFile=$1
  local prefix=$2
  analysed_files=$((analysed_files+1))
  if /usr/bin/unzip -l "${jarFile}" | grep -q "${searchClass}"
  then

    if [ -n "$prefix" ]
    then
      filename="${jarFile#"$tempDir/$(basename "$prefix")"}"
      prefix="${prefix}->"
    else
      filename="${jarFile}"
    fi
    echo "${prefix}${filename}" >> "${outFile}"
    vulnerabilities_found=1
  fi
}

# Check if there are nested jars, wars or ears
function searchNestedJars {
  local jarFile=$1
  local dir
  local nested_files
  dir="${tempDir}/$(basename "${jarFile}")/"

  unzip -qq -o -d "$dir" "$jarFile" '*.jar' '*.war' '*.ear' >/dev/null 2>&1

  nested_files=$(find "$dir" -type f -iname "*.[ejw]ar")
  if [ "$nested_files" != '' ]; then
    while IFS= read -r file
    do
      findClass "$file" "$jarFile"

      if /usr/bin/unzip -l "$file" | tail  -n +2 | grep -q -i '\.jar\|\.war\|\.ear'
      then
        searchNestedJars "$file"
      fi
    done < <(printf '%s\n' "$nested_files")
  fi

}

if [ -z "$scanDir" ]
then
  # Get a list of all file systems
  file_systems=$(df -l -P | tail -n +2 | awk '{print $6}' | tr '\n' ' ')
else
  # Look only for the folder passed as a parameter
  file_systems=$scanDir
fi

printf "%bINFO: Searching for jar, war or ear files on %s%b\n" "${ansi_green}" "$file_systems" "${ansi_nocolor}"


# Find all jar, ear or war on the system
jars_found=$(find $file_systems -xdev -type f -iname "*.[ejw]ar" 2> /dev/null)

if [ "$jars_found" != '' ]
then
  # Iterate over the files found
  while IFS= read -r jar_fullpath
  do

    findClass "$jar_fullpath"

    if /usr/bin/unzip -l "$jar_fullpath" | tail  -n +2 | grep -q -i '\.jar\|\.war\|\.ear'
    then
      searchNestedJars "$jar_fullpath"
    fi

  done < <(printf '%s\n' "$jars_found")

else
  printf "%bINFO: No jar, ear or war files found on this machine.%b\n" "${ansi_green}" "${ansi_nocolor}"
fi

printf "%bINFO: %s files analyzed%b\n" "${ansi_green}" "$analysed_files" "${ansi_nocolor}"

if [ "$vulnerabilities_found" == "1" ]
then
  printf "%b\nWARNING: Found files containing %s%b\n\n" "${ansi_yellow}" "$searchClass" "${ansi_nocolor}"
  printf "Vulnerable files: \n\n"
  cat "$outFile"
else
  printf "%bINFO: No files containing %s found%b\n" "${ansi_green}" "$searchClass" "${ansi_nocolor}"
fi

rm -f "$outFile"
rm -rf "$tempDir"

exit $vulnerabilities_found
