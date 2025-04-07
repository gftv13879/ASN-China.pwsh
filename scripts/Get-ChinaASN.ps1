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
Defaults to 'ASN.China.list' in the current directory.

.NOTES
Author: Based on Python script by Vincent Young, adapted for PowerShell Core by AI & User.
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
Requires: PowerShell Core (pwsh) 6+ with internet connectivity.
Generates two files: the one specified by -OutputFile and a secondary file named 'ASN.China.txt' in the same directory.
Version: 2.2 (Independent file writes logic)

.LINK
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN

.EXAMPLE
.\Get-ChinaASN.ps1
Fetches data and saves it to .\ASN.China.list and .\ASN.China.txt.

.EXAMPLE
.\Get-ChinaASN.ps1 -OutputFile C:\data\ChinaASNs_detail.list
Fetches data and saves the detailed list to the specified path, and the simple list to C:\data\ASN.China.txt.

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

# Determine the directory of the primary output file for the secondary file
$OutputDirectory = Split-Path -Path $OutputFile -Parent
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = "." # Use current directory if no path specified
}
$SecondOutputFile = Join-Path -Path $OutputDirectory -ChildPath "ASN.China.txt"


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
        # Use Resolve-Path to get the full path for clearer error messages if needed
        $fullPath = Resolve-Path -Path $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $fullPath) {
            Write-Verbose "Output file full path: $($fullPath.Path)"
        } else {
             Write-Verbose "Output path specified: $FilePath"
        }

        # Write content to file, overwriting. Use UTF8 encoding without BOM for better cross-platform compatibility.
        # Only write header if provided
        if (-not [string]::IsNullOrEmpty($HeaderText)) {
             Set-Content -Path $FilePath -Value $HeaderText -Encoding UTF8 -Force -ErrorAction Stop # Make error terminating
        } else {
             # Create an empty file or clear existing content
             Set-Content -Path $FilePath -Value $null -Encoding UTF8 -Force -ErrorAction Stop
        }
        Write-Verbose "Output file initialized successfully."
    } catch {
        # Catch block is triggered if Set-Content fails due to -ErrorAction Stop
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
    Write-Verbose "Initializing primary output file: $DestinationFile"
    # Get current UTC time
    $utcTime = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss")
    # Create header content using a here-string for readability
    $header = @"
// ASN Information in China. (Source: $DataSourceUrl, Script based on https://github.com/gftv13879/ASN-China.pwsh)
// Last Updated: UTC $utcTime
// PowerShell Core script. Format: IP-ASN,AS_NUMBER // AS_NAME

"@ #<-- Closing Here-String delimiter must be at the start of the line
    # Initialize primary file with header
    Initialize-OutputFile -FilePath $DestinationFile -HeaderText $header -Verbose:$VerbosePreference

    # Initialize secondary file (empty)
    Write-Verbose "Initializing secondary output file: $SecondaryOutputFile"
    Initialize-OutputFile -FilePath $SecondaryOutputFile -HeaderText $null -Verbose:$VerbosePreference # No header for second file

    # 2. Fetch Web Content
    Write-Verbose "Attempting to fetch ASN data from $Url"
    $response = $null
    try {
        $response = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -ErrorAction Stop
        Write-Verbose "Successfully fetched data (Status: $($response.StatusCode)). Content length: $($response.RawContentLength) bytes."
    } catch {
        Write-Error "FATAL: Failed to fetch data from '$Url'. Error: $($_.Exception.Message)"
        # Stop script if web request fails
        throw $_
    } # <-- Closing brace for try/catch

    # 3. Parse Content using Regex
    $htmlContent = $response.Content
    # Regex to find table rows (<tr>) and extract ASN number (Group 1) and Name (Group 2)
    # (?si) -> s: dot matches newline; i: case-insensitive (good practice)
    # *? -> non-greedy match
    # Updated Regex to be slightly more robust against whitespace variations and potentially nested tags in name cell
    $rowRegex = '(?si)<tr>\s*<td><a.*?href="/AS(\d+?)".*?>AS\1</a></td>\s*<td>(.*?)</td>'

    Write-Verbose "Parsing HTML content using regex pattern: $rowRegex"
    # Use Select-String to find all matches in the content
    $matches = $htmlContent | Select-String -Pattern $rowRegex -AllMatches

    if ($null -eq $matches -or $matches.Matches.Count -eq 0) {
        Write-Warning "No ASN rows found matching the expected pattern. The website structure might have changed, or the table is empty."

        # --- START DEBUG OUTPUT ---
        # Uncomment below lines if you need to debug the HTML content when no matches are found
        # Write-Warning "Attempting to dump first 5KB of HTML content for debugging:"
        # Write-Host "===== HTML Start (First 5KB) ====="
        # Write-Host $htmlContent.Substring(0, [System.Math]::Min($htmlContent.Length, 5120))
        # Write-Host "===== HTML End ====="
        # --- END DEBUG OUTPUT ---

        # Even if no data, script technically completed its task (fetching and checking)
        Write-Host "Processing complete. No ASN entries found to write."
        return # Continue to finish "successfully" but without data
    } # <-- Closing brace for if

    $matchCount = $matches.Matches.Count
    Write-Verbose "Found $matchCount potential ASN entries."
    Write-Host "Processing $matchCount ASN entries..."

    # 4. Process Matches and Append to Files
    # --- Start of the Modified Processing Block ---
    $processedCountPrimary = 0
    $processedCountSecondary = 0
    $skippedValidationCount = 0 # Counter specifically for validation skips

    Write-Verbose "Primary output file: $DestinationFile"
    Write-Verbose "Secondary output file: $SecondaryOutputFile"

    # --- Processing Loop ---
    foreach ($match in $matches.Matches) {
        # Check if the match has the expected number of capture groups
        if ($match.Groups.Count -ge 3) {
            # Extract and trim ASN number and name
            $asnNumber = $match.Groups[1].Value.Trim()
            $asnNameRaw = $match.Groups[2].Value.Trim()
            $asnNameClean = $asnNameRaw -replace '<[^>]+>'
            # Optional: Decode HTML entities
            # try { $asnNameClean = [System.Net.WebUtility]::HtmlDecode($asnNameClean) } catch { Write-Warning "Could not HTML decode name: $asnNameClean" }

            # Validate ASN number is not empty after trimming
            if (-not [string]::IsNullOrWhiteSpace($asnNumber)) {

                # --- Attempt to Write to the First File ---
                $primaryFileInfo = "IP-ASN,{0} // {1}" -f $asnNumber, $asnNameClean
                try {
                    Add-Content -Path $DestinationFile -Value $primaryFileInfo -Encoding UTF8 -ErrorAction Stop
                    $processedCountPrimary++ # Increment success count for primary file
                    Write-Verbose "Added to '$DestinationFile': $primaryFileInfo"
                } catch {
                    # Log error for primary file, but DO NOT stop or skip secondary write attempt
                    Write-Warning "Failed to write ASN $asnNumber to primary file '$DestinationFile'. Error: $($_.Exception.Message)"
                    # Note: $processedCountPrimary is NOT incremented on failure.
                } # <-- Closing brace for inner try/catch

                # --- Attempt to Write to the Second File (Independently) ---
                $secondaryFileInfo = "AS$asnNumber"
                try {
                    Add-Content -Path $SecondaryOutputFile -Value $secondaryFileInfo -Encoding UTF8 -ErrorAction Stop
                    $processedCountSecondary++ # Increment success count for secondary file
                    Write-Verbose "Added to '$SecondaryOutputFile': $secondaryFileInfo"
                } catch {
                    # Log error for secondary file
                    Write-Warning "Failed to write ASN $asnNumber to secondary file '$SecondaryOutputFile'. Error: $($_.Exception.Message)"
                    # Note: $processedCountSecondary is NOT incremented on failure.
                } # <-- Closing brace for inner try/catch
                # Both write attempts are now complete for this ASN, regardless of individual success/failure.

            } else {
                # ASN number was blank or whitespace after trimming
                Write-Warning "Skipping match because the extracted ASN number is blank or whitespace. Raw Name: '$asnNameRaw'. Full Match: '$($match.Value)'"
                $skippedValidationCount++ # Increment validation skip count
            } # <-- Closing brace for inner if
        } else {
            # Regex match didn't have enough capture groups
            Write-Warning "Skipping match because it did not contain the expected number of groups (found $($match.Groups.Count), expected at least 3). Full match: '$($match.Value)'"
            $skippedValidationCount++ # Increment validation skip count
        } # <-- Closing brace for outer if
    } # <-- Closing brace for foreach loop

    # --- Final Summary ---
    Write-Host "----------------------------------------"
    Write-Host "ASN Processing Complete."
    Write-Host "Total regex matches found: $matchCount"
    Write-Host "Successfully wrote $processedCountPrimary entries to primary file '$DestinationFile'."
    Write-Host "Successfully wrote $processedCountSecondary entries to secondary file '$SecondaryOutputFile'."

    if ($skippedValidationCount -gt 0) {
        Write-Host "Skipped $skippedValidationCount entries due to validation errors (missing data or insufficient groups)."
    } # <-- Closing brace for if

    # Calculate potential write failures based on processed counts vs. valid matches
    $potentialValidEntries = $matchCount - $skippedValidationCount
    $primaryWriteFailures = $potentialValidEntries - $processedCountPrimary
    $secondaryWriteFailures = $potentialValidEntries - $processedCountSecondary

    if ($primaryWriteFailures -gt 0) {
        Write-Warning "Note: There were $primaryWriteFailures potential write failures for the primary file (check warnings above)."
    } # <-- Closing brace for if
    if ($secondaryWriteFailures -gt 0) {
        Write-Warning "Note: There were $secondaryWriteFailures potential write failures for the secondary file (check warnings above)."
    } # <-- Closing brace for if

    Write-Host "----------------------------------------"
    # --- End of the Modified Processing Block ---

} # <-- Closing brace for Update-ChinaAsnList function


# --- Execute Main Logic ---
Write-Verbose "Starting script execution..."
Write-Verbose "Primary output file will be: $OutputFile"
Write-Verbose "Secondary output file will be: $SecondOutputFile"
try {
    # Pass both file paths to the function
    Update-ChinaAsnList -DestinationFile $OutputFile -SecondaryOutputFile $SecondOutputFile -Url $DataSourceUrl -Headers $RequestHeaders -Verbose:$VerbosePreference
    Write-Host "Script finished successfully." # Moved here to indicate completion after processing
} catch {
    # Catch any exceptions thrown from Update-ChinaAsnList or Initialize-OutputFile
    Write-Error "Script execution FAILED."
    # Error details should have been written by the function that threw the exception.
    # Exit with a non-zero code to indicate failure, useful for automation.
    exit 1
} # <-- Closing brace for try/catch

# Exit with success code
exit 0