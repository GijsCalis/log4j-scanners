#!/bin/bash

#
# Bash script to scan a directory or all local file systems for log4j.
# Requires packages bash (v3), unzip and zip
#


# When passed no argument, scans all local filesystems, otherwise only the given path is scanned
scanDir=$1

if [[ "$scanDir" =~ ^-h|^--h ]]; then
  echo "Scan local file system or directory tree for log4j"
  echo ""
  echo "USAGE: log4j-scanner.sh [directory]"
  echo ""
  echo "directory  [optional] Directory tree to scan. If not given all local file systems are scanned"
  exit 0
fi

searchClass="org/apache/logging/log4j/core/lookup/JndiLookup.class"
tempDir=/tmp/log4j-scan
outFile=/tmp/CVE-2021-44228.log
found=0

rm "${outFile}" >/dev/null 2>&1

function findClass {
  local jarFile=$1
  local prefix=$2

  if [ $( zip -sf "${jarFile}" | grep ".*${searchClass}" ) ]; then

    if [[ ! -z "$prefix" ]]; then
#      echo "Tempdir: $tempDir __JarFile: $jarFile ___base: $(basename $prefix)"
      filename=${jarFile#"$tempDir/$(basename $prefix)"}
      prefix="${prefix}->"
    else
      filename="${jarFile}"
    fi
    echo "${prefix}${filename}" | tee -a "${outFile}";
    found=1
  fi;
}

function searchNestedJars {
  local jarFile=$1
  local dir="${tempDir}/$(basename $jarFile)/"

  unzip -qq -o -d "${dir}" "${jarFile}" '*.jar' '*.war' '*.ear' >/dev/null 2>&1

  find "${dir}" -iname "*.[ejw]ar" | while read nestedFile; do
    findClass $nestedFile $jarFile
  done

  if [ $( zip -sf "${jarFile}" | grep -q -P '\.(e|j|w)ar$' ) ]; then
    searchNestedJars $jarFile $jarFile
  fi;

}

mkdir -p "${tempDir}"

if [ -z "$scanDir" ]; then
  echo "Scanning all local file systems"

  for fs in $(mount | awk '/ext|overlay|xfs/ {print $3}'); do
    echo $fs:;
    find $fs/ -xdev -type f -iname "*.[ejw]ar" | while read line; do
      findClass $line

        if [ $( zip -sf "${line}" | grep -q -P '\.(e|j|w)ar$' | wc -l) ]; then
          searchNestedJars $line $line
        fi;
     done;
  done

else
  echo "Scanning directory: ${scanDir}"
  
  find "${scanDir}" -type f -iname "*.[ejw]ar" | while read line; do
    findClass $line
    if [ $( zip -sf "${line}" | grep -q -P '\.(e|j|w)ar$' | wc -l) ]; then
      searchNestedJars $line $line
    fi;
  done;
fi

echo "----------------------------------------------------------"
echo "Do not forget to clean up temporary files at: $tempDir !"
echo "e.g.  rm -rf '$tempDir'"
echo "----------------------------------------------------------"
echo ""

if [ $found ]; then
  echo "WARNING: Found log4j 2, see: less $outFile"
else
  echo "log4j 2 not found."
fi

exit $found
