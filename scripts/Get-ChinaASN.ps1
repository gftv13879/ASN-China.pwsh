<#
.SYNOPSIS
Fetches and saves the latest China ASN list from bgp.he.net using PowerShell Core idioms.

.DESCRIPTION
This script scrapes ASN information for China from the Hurricane Electric BGP toolkit website (bgp.he.net).
It extracts ASN numbers and names, formats them, and saves the list to two files independently:
1. A detailed list (e.g., ASN.China.list) with IP-ASN format.
2. A simple list (e.g., ASN.China.txt) with just AS numbers (ASXXXX).
Failure to write to one file does not prevent attempting to write to the other.
It utilizes PowerShell Core best practices like CmdletBinding, Verbose output, and standard function naming.

.PARAMETER OutputFile
The path to the file where the main ASN list (IP-ASN format) will be saved.
Defaults to 'ASN.China.list' in the current directory. The secondary file ('ASN.China.txt') will be placed in the same directory.

.NOTES
Author: Based on Python script by Vincent Young, adapted for PowerShell Core by AI & User.
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
Requires: PowerShell Core (pwsh) 6+ with internet connectivity.
Generates two files: the one specified by -OutputFile and a secondary file named 'ASN.China.txt' in the same directory.
Version: 2.4 (Fixed path initialization bug when using default OutputFile)

.LINK
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN

.EXAMPLE
.\Get-ChinaASN.ps1
Fetches data and saves it to .\ASN.China.list and .\ASN.China.txt in the current directory.

.EXAMPLE
.\Get-ChinaASN.ps1 -OutputFile /data/ChinaASNs_detail.list
Fetches data and saves the detailed list to /data/ChinaASNs_detail.list, and the simple list to /data/ASN.China.txt.

.EXAMPLE
.\Get-ChinaASN.ps1 -OutputFile ..\output\China_ASN.list
Fetches data and saves the detailed list relative to the parent directory in 'output', and the simple list to ..\output\ASN.China.txt.

.EXAMPLE
.\Get-ChinaASN.ps1 -Verbose
Runs the script with detailed verbose output showing each step.
#>
[CmdletBinding()] # Enables common parameters like -Verbose
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "ASN.China.list"
) # <-- Closing brace for param block

# --- Script Constants ---
$DataSourceUrl = "https://bgp.he.net/country/CN"
$RequestHeaders = @{
    # Standard User-Agent often used in PowerShell scripts
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 PowerShellCore/$(($PSVersionTable.PSVersion).ToString())"
} # <-- Closing brace for Hashtable

# --- START: Path Calculation Modification ---
# Determine the directory of the primary output file for the secondary file
try {
    # Get the *intended* directory based on the input $OutputFile string
    $OutputDirectory = Split-Path -Path $OutputFile -Parent

    # If no directory part was found (e.g., just a filename), use the current directory.
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory = $PWD.Path # Use current working directory
        Write-Verbose "No directory specified for primary output file. Using current directory: $OutputDirectory"
        # --- FIX: Update $OutputFile to include the determined directory ---
        $OutputFile = Join-Path -Path $OutputDirectory -ChildPath (Split-Path -Path $OutputFile -Leaf) # Rebuild $OutputFile with directory
        Write-Verbose "Updated primary OutputFile path to: $OutputFile"
    } else {
        # If a directory was specified, resolve it to handle relative paths (like .. or .)
        # Resolve-Path ensures we have a canonical path to work with
        try {
            $ResolvedDirectory = Resolve-Path -Path $OutputDirectory
            $OutputDirectory = $ResolvedDirectory.Path # Use the resolved path string
            # Rebuild $OutputFile using the fully resolved directory and the original filename part
            $OutputFile = Join-Path -Path $OutputDirectory -ChildPath (Split-Path -Path $OutputFile -Leaf)
            Write-Verbose "Resolved specified output directory to: $OutputDirectory"
            Write-Verbose "Updated primary OutputFile path to: $OutputFile"
        } catch {
            Write-Error "Failed to resolve the specified output directory '$OutputDirectory'. Error: $($_.Exception.Message)"
            throw $_ # Stop script if specified path is invalid
        }
    }
} catch {
    Write-Error "An unexpected error occurred during path calculation for '$OutputFile'. Error: $($_.Exception.Message)"
    throw $_
}

# Construct the path for the secondary file in the *same* determined directory.
$SecondOutputFile = Join-Path -Path $OutputDirectory -ChildPath "ASN.China.txt"
# --- END: Path Calculation Modification ---


# --- Function to Initialize Output File ---
function Initialize-OutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [string]$HeaderText # Allow custom header or no header
    ) # <-- Closing brace for param block

    Write-Verbose "Initializing output file: $FilePath"

    try {
        # Now $FilePath should always have a directory component (or be rooted)
        $Dir = Split-Path -Path $FilePath -Parent
        # Check if $Dir is not null/empty AND the directory doesn't exist
        if (-not [string]::IsNullOrWhiteSpace($Dir) -and -not (Test-Path -Path $Dir -PathType Container)) {
             Write-Verbose "Creating directory: $Dir"
             New-Item -Path $Dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } elseif ([string]::IsNullOrWhiteSpace($Dir)) {
             # This case should ideally not happen with the corrected logic, but added as safety
             Write-Verbose "Target path '$FilePath' appears to be in the root directory. No directory creation needed."
        }

        # Write content to file, overwriting. Use UTF8NoBOM.
        if (-not [string]::IsNullOrEmpty($HeaderText)) {
             Set-Content -Path $FilePath -Value $HeaderText -Encoding UTF8NoBOM -Force -ErrorAction Stop
        } else {
             Set-Content -Path $FilePath -Value $null -Encoding UTF8NoBOM -Force -ErrorAction Stop
        }
        Write-Verbose "Output file initialized successfully: $FilePath"
    } catch {
        Write-Error "FATAL: Failed to initialize output file '$FilePath'. Error: $($_.Exception.Message)"
        throw $_ # Re-throw to halt script execution
    }
} # <-- Closing brace for Initialize-OutputFile function

# --- Main Logic Function ---
function Update-ChinaAsnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile, # Will now receive full path e.g. /workspace/ASN.China.list

        [Parameter(Mandatory = $true)]
        [string]$SecondaryOutputFile, # Will now receive full path e.g. /workspace/ASN.China.txt

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    ) # <-- Closing brace for param block

    # 1. Initialize the output files (overwrites existing, adds header to primary)
    # Get current UTC time
    $utcTime = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss")
    $header = @"
// ASN Information in China. (Source: $DataSourceUrl, Script based on https://github.com/gftv13879/ASN-China.pwsh)
// Last Updated: UTC $utcTime
// PowerShell Core script. Format: IP-ASN,AS_NUMBER // AS_NAME

"@
    # Initialize-OutputFile should now work correctly for both paths
    Initialize-OutputFile -FilePath $DestinationFile -HeaderText $header -Verbose:$VerbosePreference
    Initialize-OutputFile -FilePath $SecondaryOutputFile -HeaderText $null -Verbose:$VerbosePreference # No header

    # 2. Fetch Web Content
    Write-Verbose "Attempting to fetch ASN data from $Url"
    $response = $null
    try {
        $response = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -ErrorAction Stop
        Write-Verbose "Successfully fetched data (Status: $($response.StatusCode)). Content length: $($response.RawContentLength) bytes."
    } catch {
        Write-Error "FATAL: Failed to fetch data from '$Url'. Error: $($_.Exception.Message)"
        throw $_
    } # <-- Closing brace for try/catch

    # 3. Parse Content using Regex
    $htmlContent = $response.Content
    $rowRegex = '(?si)<tr>\s*<td><a.*?href="/AS(\d+?)".*?>AS\1</a></td>\s*<td>(.*?)</td>'
    Write-Verbose "Parsing HTML content using regex pattern: $rowRegex"
    $matches = $htmlContent | Select-String -Pattern $rowRegex -AllMatches

    if ($null -eq $matches -or $matches.Matches.Count -eq 0) {
        Write-Warning "No ASN rows found matching the expected pattern. Website structure might have changed or table is empty."
        Write-Host "Processing complete. No ASN entries found to write."
        return
    } # <-- Closing brace for if

    $matchCount = $matches.Matches.Count
    Write-Verbose "Found $matchCount potential ASN entries."
    Write-Host "Processing $matchCount ASN entries..."

    # 4. Process Matches and Append to Files
    $processedCountPrimary = 0
    $processedCountSecondary = 0
    $skippedValidationCount = 0

    Write-Verbose "Primary output file target: $DestinationFile"
    Write-Verbose "Secondary output file target: $SecondaryOutputFile"

    # --- START: Processing Loop with Independent Writes ---
    foreach ($match in $matches.Matches) {
        if ($match.Groups.Count -ge 3) {
            $asnNumber = $match.Groups[1].Value.Trim()
            $asnNameRaw = $match.Groups[2].Value.Trim()
            $asnNameClean = ($asnNameRaw -replace '<[^>]+>').Trim() # Basic HTML tag removal

            if (-not [string]::IsNullOrWhiteSpace($asnNumber)) {
                # --- Attempt 1: Write to Primary File ---
                $primaryFileInfo = "IP-ASN,{0} // {1}" -f $asnNumber, $asnNameClean
                try {
                    Add-Content -Path $DestinationFile -Value $primaryFileInfo -Encoding UTF8NoBOM -ErrorAction Stop
                    $processedCountPrimary++
                    Write-Verbose "Added to '$DestinationFile': AS$asnNumber"
                } catch {
                    Write-Warning "Failed to write ASN $asnNumber to primary file '$DestinationFile'. Error: $($_.Exception.Message)"
                } # <-- End Try/Catch for Primary File

                # --- Attempt 2: Write to Secondary File (Independent of Attempt 1) ---
                $secondaryFileInfo = "AS$asnNumber"
                try {
                    Add-Content -Path $SecondaryOutputFile -Value $secondaryFileInfo -Encoding UTF8NoBOM -ErrorAction Stop
                    $processedCountSecondary++
                    Write-Verbose "Added to '$SecondaryOutputFile': $secondaryFileInfo"
                } catch {
                    Write-Warning "Failed to write ASN $asnNumber to secondary file '$SecondaryOutputFile'. Error: $($_.Exception.Message)"
                } # <-- End Try/Catch for Secondary File

            } else {
                Write-Warning "Skipping match: Extracted ASN number is blank. Raw Name: '$asnNameRaw'."
                $skippedValidationCount++
            } # <-- End ASN Number Validation
        } else {
            Write-Warning "Skipping match: Did not contain expected groups (found $($match.Groups.Count), need >=3)."
            $skippedValidationCount++
        } # <-- End Group Count Validation
    } # <-- End Foreach Loop
    # --- END: Processing Loop with Independent Writes ---


    # 5. Final Summary
    Write-Host "----------------------------------------"
    Write-Host "ASN Processing Complete."
    $potentialValidEntries = $matchCount - $skippedValidationCount
    Write-Host "Total regex matches found: $matchCount"
    if ($skippedValidationCount -gt 0) {
        Write-Host "Skipped $skippedValidationCount entries due to parsing/validation issues."
    }
    Write-Host "Valid ASN entries attempted: $potentialValidEntries"
    Write-Host " - Successfully wrote $processedCountPrimary entries to primary file '$DestinationFile'."
    Write-Host " - Successfully wrote $processedCountSecondary entries to secondary file '$SecondaryOutputFile'."

    $primaryWriteFailures = $potentialValidEntries - $processedCountPrimary
    $secondaryWriteFailures = $potentialValidEntries - $processedCountSecondary

    if ($primaryWriteFailures -gt 0) {
        Write-Warning "Note: There were $primaryWriteFailures write failures for the primary file (check warnings above)."
    }
    if ($secondaryWriteFailures -gt 0) {
        Write-Warning "Note: There were $secondaryWriteFailures write failures for the secondary file (check warnings above)."
    }
    Write-Host "----------------------------------------"

} # <-- Closing brace for Update-ChinaAsnList function


# --- Execute Main Logic ---
Write-Verbose "Starting script execution..."
# Show the final calculated paths before starting the main process
Write-Verbose "Primary output file will be: $OutputFile"       # Should now show full path if default used
Write-Verbose "Secondary output file will be: $SecondOutputFile" # Should show full path

try {
    Update-ChinaAsnList -DestinationFile $OutputFile -SecondaryOutputFile $SecondOutputFile -Url $DataSourceUrl -Headers $RequestHeaders -Verbose:$VerbosePreference
    Write-Host "Script finished successfully."
} catch {
    # Catch exceptions from Initialize-OutputFile, Invoke-WebRequest, or Path Resolution
    Write-Error "Script execution FAILED."
    exit 1 # Exit with non-zero code for failure
}

# Exit with success code
exit 0
