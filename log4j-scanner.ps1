<#
    .SYNOPSIS
    log4j-scanner.ps1 scans drives or a directory tree for presence of java archives (jar/war/ear) containing log4j and analyzes the contents of the file to determine if it is vulnerable.

    .PARAMETER  rootDir
    Root directory to start search at. If no directory is given all local disks are scanned.

    .PARAMETER logDir
    Directory to write output csv files with all found files.

    .PARAMETER debug
    Print extra output to the console while searching. Lots of output, useful for debugging.

    .DESCRIPTION
    Review directory treee or all local disks for any presence of log4j jar files, extract the manifest from the file and determine if the version is less than 2.17.
    Also scans nested java archives found; i.e. jar in jar file or war in ear file, etc.
    Output progress to console status and global result at end.
    Record list of all java archiv files with log4j in 'log4j-all-found.csv', all (potentialy) vulnerable files are written to 'log4j-vulnerable.csv'.

    Also works on Linux (Ubuntu 20 tested) with powershell package installed.

    Based on and thanks to : https://github.com/sp4ir/incidentresponse/blob/main/Get-Log4shellVuln.ps1
#>

param (
    $rootDir,
    $logDir=[System.IO.Path]::GetTempPath(),
    [switch]$debug,
    [switch]$help = $false
)

if ($help) {
    Get-Help $MYINVOCATION.InvocationName
    return
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$logFolder               = Resolve-Path "$logDir"
$targetManifestFile      = Join-Path -Path "$logFolder" -ChildPath "log4j-manifest.txt"
$allVulnerableLog4jFiles = Join-Path -Path "$logFolder" -ChildPath "log4j-vulnerable.csv"
$allFilesWithLog4j       = Join-Path -Path "$logFolder" -ChildPath "log4j-all-found.csv"

if ($rootDir) {
    Write-Output "Scanning all files in directory recursively: $rootDir"
    Write-Output "Gathering all java archives (.jar, .war, .ear) ..."
    $jarFiles = Get-ChildItem -Path "$rootDir" -File -Recurse -ErrorAction SilentlyContinue | where {$_.extension -in ".jar",".war",".ear"} | Select-Object -ExpandProperty FullName
} else {
    Write-Output "Scanning all local drives"
    Write-Output "Gathering all java archives (.jar, .war, .ear) ..."
    $jarFiles = Get-PSDrive | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -ErrorAction SilentlyContinue | where {$_.extension -in ".jar",".war",".ear"} | Select-Object -ExpandProperty FullName
}


$global:result = $null

Function Scan-Jar {
    param(
		[Parameter(Mandatory)]
		[string]$fileName,

		[Parameter(Mandatory)]
		[object]$jarFile,

        [string]$prefix=""
	)

    if ($prefix) {
        $outFileName = "$prefix->$fileName"
        $indent = "  "
        $sep = "->"
    } else {
        $outFileName = $fileName
        $indent = ""
        $sep = ""
    }
    
    if ($debug) { Write-Output "$indent Scan-Jar: [$fileName], prefix [$prefix], Entries: [$($jarFile.Entries.count)]"  }

    [bool] $foundSuspectFile = $false
    $log4jVersion = "unknown"
    $clazz = ''

    # First scan nested jar files recursively
    $jarFile.Entries |
    Where-Object { $_.Name -like '*.jar' -or $_.Name -like '*.war' -or $_.Name -like '*.ear'} | ForEach-Object {
        $nestedJar = $_
        $extractedJarName = "$($env:TEMP)\$($nestedJar.Name)"
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($nestedJar, $extractedJarName, $true)

        if ($debug) { Write-Output "$indent Scanning nested Jar: [$fileName -> $($nestedJar.Name)]" }

        try {
            $zipFile = [System.IO.Compression.ZipFile]::Open($extractedJarName, 'Read')

            Scan-Jar -fileName $nestedJar.Name -jarFile $zipFile -prefix "$($prefix)$($sep)$($fileName)"
        } catch [System.IO.InvalidDataException] {
            $message = $_
            Write-Error "Could not open file '$extractedJarName': $message"
        }
        $zipFile.dispose()

        Remove-Item $extractedJarName -ErrorAction SilentlyContinue
    }

    # Scan class files in main jar ($jarFile).
    $jarFile.Entries |
    Where-Object { $_.Name -like 'JndiLookup.class' -or $_.FullName -eq 'org/apache/log4j/Logger.class'} | ForEach-Object {
        $foundSuspectFile = $true
        $clazz = $_.FullName

        if ($_.FullName -eq 'org/apache/log4j/Logger.class') {
            $log4jVersion = '1' 
        }
        $output = "$fileName,$($_.FullName)"

        if ($debug) { Write-Output "$indent Found: $output" }

        $output | Out-File -Append $allFilesWithLog4j
        if ($null -eq $global:result) { $global:result = "Jndi class exists" }
    }

    if ($foundSuspectFile) {

        if ($fileName -like "*log4j-*") {
            
            $jarFile.Entries |
            Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | ForEach-Object {
                # Try to determine version from manifest, although inspecting JndiLookup.class and JndiManager.class would be better.
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $targetManifestFile, $true)

                try {
                    $implementationVersion = (Get-Content $targetManifestFile | Where-Object { $_ -like 'Implementation-Version: *' }).ToString()
                    $log4jVersion = $implementationVersion.Split(":")[1].trim()
                } catch  {
                    $message = $_
                    Write-Warning "Could not determine log4j version for '$outFileName': $message"
                }

                if ($debug) { Write-Output "$indent Log4j version: [$log4jVersion]" }

                Remove-Item $targetManifestFile -ErrorAction SilentlyContinue

                $implementationVersion_ = $log4jVersion.Split('.')
                $majorVersion = $implementationVersion_[0]
                $minorVersion = $implementationVersion_[1]
                $patchVersion = $implementationVersion_[2]

                if ($majorVersion -eq 1) {
                    if ($debug) { Write-Output "$indent Old log4j v1 found" }
                    "$outFileName,$clazz,$log4jVersion" | Out-File -Append $allVulnerableLog4jFiles

                } elseif ($majorVersion -eq 2 -and $minorVersion -eq 12 -and $patchVersion -eq 2) {
                    if ($debug) { Write-Output "$indent Patched version found" }

                } elseif ($majorVersion -eq 2 -and $minorVersion -lt 17 ) {
                    if ($debug) { Write-Output "$indent log4shell vulnerability exists" }
                    "$outFileName,$clazz,$log4jVersion" | Out-File -Append $allVulnerableLog4jFiles

                } elseif ($majorVersion -eq 2 -and $minorVersion -eq 17 ) {
                    if ($debug) { Write-Output "$indent Fixed version found" }

                }
            }
        } else {
            if ($debug) { Write-Output "$indent Could not determine log4j-version for file: $fileName" }

            "$outFileName,$clazz,$log4jVersion" | Out-File -Append $allVulnerableLog4jFiles
        }

        $global:result = "One or more vulnerable files found, see: $allVulnerableLog4jFiles"


    } else {
        if ($debug) { Write-Output "$indent Jndi class not found" }
    }
}

Function Format-FileSize() {
    Param ([int]$size)
    If     ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    ElseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    ElseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    ElseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    ElseIf ($size -gt 0) {[string]::Format("{0:0.00} B", $size)}
    Else {""}
}

echo "file,class,version" | Out-File $allVulnerableLog4jFiles
echo "file,class" | Out-File $allFilesWithLog4j

Write-Output "Found: $($jarFiles.count) jar files"
$i=0
foreach ($jarFile in $jarFiles) {
    $i++
    if ($debug) {
        Write-Output "FILE: $jarFile"
    } else {
        [int]$c=($i/$jarFiles.count*100)
        Write-Progress -Activity "Scanning files" -Status "$c% Complete:" -PercentComplete $c
    }
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
        Scan-Jar -fileName $jarFile -jarFile $zip

    } catch [System.IO.InvalidDataException] {
        $message = $_
        Write-Warning "Could not scan file '$jarFile' (Size: $(Format-FileSize((Get-Item $jarFile).length))), Error: $message "
    }    
    
    if ($debug) { Write-Output "" }
}

$exitCode = 0
if ($null -eq $global:result) {
    $global:result = "no vulnerable files found."
} else {
    $exitCode = 1
}

Write-Output "Result: $global:result"
exit $exitCode
