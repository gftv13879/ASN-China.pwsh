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
Version: 2.3 (Clarified independent writes and path logic)

.LINK
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN

.EXAMPLE
.\Get-ChinaASN.ps1
Fetches data and saves it to .\ASN.China.list and .\ASN.China.txt in the current directory.

.EXAMPLE
.\Get-ChinaASN.ps1 -OutputFile C:\data\ChinaASNs_detail.list
Fetches data and saves the detailed list to C:\data\ChinaASNs_detail.list, and the simple list to C:\data\ASN.China.txt.

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
# Use Resolve-Path on the $OutputFile *first* to handle relative paths correctly upfront.
# If Resolve-Path fails (e.g., path doesn't exist yet but is valid), fall back to Split-Path.
try {
    $resolvedPrimaryPath = Resolve-Path -Path $OutputFile -ErrorAction SilentlyContinue # Try to get full path
    if ($resolvedPrimaryPath) {
        $OutputDirectory = Split-Path -Path $resolvedPrimaryPath.Path -Parent
    } else {
        # If path doesn't exist, Split-Path is needed to get the intended directory
        $OutputDirectory = Split-Path -Path $OutputFile -Parent
    }
} catch {
    # Fallback if Resolve-Path had other issues
     Write-Warning "Could not fully resolve output path '$OutputFile'. Using basic Split-Path."
     $OutputDirectory = Split-Path -Path $OutputFile -Parent
}

# If no directory part was found (e.g., just a filename), use the current directory.
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    # Get the current working directory explicitly for clarity
    $OutputDirectory = $PWD.Path # Or use "." which is equivalent for Join-Path
    Write-Verbose "No directory specified for primary output file. Using current directory: $OutputDirectory"
} else {
     Write-Verbose "Determined output directory: $OutputDirectory"
}

# Construct the path for the secondary file in the *same* directory.
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
        # Ensure the directory exists before writing the file
        $Dir = Split-Path -Path $FilePath -Parent
        if ($null -ne $Dir -and -not (Test-Path -Path $Dir -PathType Container)) {
             Write-Verbose "Creating directory: $Dir"
             New-Item -Path $Dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # Write content to file, overwriting. Use UTF8 encoding without BOM.
        if (-not [string]::IsNullOrEmpty($HeaderText)) {
             Set-Content -Path $FilePath -Value $HeaderText -Encoding UTF8NoBOM -Force -ErrorAction Stop
        } else {
             Set-Content -Path $FilePath -Value $null -Encoding UTF8NoBOM -Force -ErrorAction Stop
        }
        Write-Verbose "Output file initialized successfully: $FilePath"
    } catch {
        Write-Error "FATAL: Failed to initialize output file '$FilePath'. Error: $($_.Exception.Message)"
        # Re-throw the exception to halt script execution as initialization is critical
        throw $_
    }
} # <-- Closing brace for Initialize-OutputFile function

# --- Main Logic Function ---
function Update-ChinaAsnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile,

        [Parameter(Mandatory = $true)]
        [string]$SecondaryOutputFile, # Added parameter for second file

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
        # Optional: Uncomment debug lines if needed
        # Write-Warning "Attempting to dump first 5KB of HTML content for debugging:"
        # try { Write-Host $htmlContent.Substring(0, [System.Math]::Min($htmlContent.Length, 5120)) } catch {}
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
    # This loop attempts to write each valid ASN entry to BOTH files.
    # Failure to write to one file does NOT prevent the attempt to write to the other,
    # thanks to the separate try/catch blocks below.
    foreach ($match in $matches.Matches) {
        if ($match.Groups.Count -ge 3) {
            $asnNumber = $match.Groups[1].Value.Trim()
            $asnNameRaw = $match.Groups[2].Value.Trim()
            # Basic cleaning: Remove HTML tags. Consider [System.Net.WebUtility]::HtmlDecode if needed.
            $asnNameClean = ($asnNameRaw -replace '<[^>]+>').Trim()

            if (-not [string]::IsNullOrWhiteSpace($asnNumber)) {
                # --- Attempt 1: Write to Primary File ---
                $primaryFileInfo = "IP-ASN,{0} // {1}" -f $asnNumber, $asnNameClean
                try {
                    # Use UTF8NoBOM for better compatibility, especially with *nix tools
                    Add-Content -Path $DestinationFile -Value $primaryFileInfo -Encoding UTF8NoBOM -ErrorAction Stop
                    $processedCountPrimary++
                    Write-Verbose "Added to '$DestinationFile': AS$asnNumber"
                } catch {
                    # Log failure for this file but continue to the next attempt
                    Write-Warning "Failed to write ASN $asnNumber to primary file '$DestinationFile'. Error: $($_.Exception.Message)"
                } # <-- End Try/Catch for Primary File

                # --- Attempt 2: Write to Secondary File (Independent of Attempt 1) ---
                $secondaryFileInfo = "AS$asnNumber"
                try {
                    # Use UTF8NoBOM
                    Add-Content -Path $SecondaryOutputFile -Value $secondaryFileInfo -Encoding UTF8NoBOM -ErrorAction Stop
                    $processedCountSecondary++
                    Write-Verbose "Added to '$SecondaryOutputFile': $secondaryFileInfo"
                } catch {
                     # Log failure for this file. Loop will continue to next ASN.
                    Write-Warning "Failed to write ASN $asnNumber to secondary file '$SecondaryOutputFile'. Error: $($_.Exception.Message)"
                } # <-- End Try/Catch for Secondary File

            } else {
                Write-Warning "Skipping match: Extracted ASN number is blank. Raw Name: '$asnNameRaw'. Full Match: '$($match.Value)'"
                $skippedValidationCount++
            } # <-- End ASN Number Validation
        } else {
            Write-Warning "Skipping match: Did not contain expected groups (found $($match.Groups.Count), need >=3). Full match: '$($match.Value)'"
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
Write-Verbose "Primary output file will be: $OutputFile"
Write-Verbose "Secondary output file will be: $SecondOutputFile" # This now uses the refined path logic

try {
    # Pass both file paths to the function
    Update-ChinaAsnList -DestinationFile $OutputFile -SecondaryOutputFile $SecondOutputFile -Url $DataSourceUrl -Headers $RequestHeaders -Verbose:$VerbosePreference
    Write-Host "Script finished successfully."
} catch {
    # Catch exceptions from Initialize-OutputFile or Invoke-WebRequest
    Write-Error "Script execution FAILED."
    exit 1 # Exit with non-zero code for failure
}

# Exit with success code
exit 0
