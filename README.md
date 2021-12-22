# log4j-scanners
Tools and scripts to scan for log4j on file systems

Scripts have seen limited testing, but seem to work.

usage: script-name -h

The scripts search recursively in jar, war and ear files and reports files that contain JndiLookup.class.
Recursively means that jar, war and ear files found inside jar, war and ear files are also scanned.


| Script           | Comments |
|:-----------------|:---------|
|log4j-scanner.sh  | Bash script, scans directory or all local file systems. Reports all files containing JndiLookup.class. No version information |
|log4j-scanner.ps1 | Powershell script, scans directory or all local file systems. Tries to report version numbers and whether a file contains a vulnerable version. Also finds Log4j version 1.|
