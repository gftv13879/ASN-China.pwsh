<#
.SYNOPSIS
Fetches and saves the latest China ASN list from bgp.he.net using PowerShell Core idioms.

.DESCRIPTION
This script scrapes ASN information for China from the Hurricane Electric BGP toolkit website (bgp.he.net).
It extracts ASN numbers and names, formats them, and saves the list to a specified file.
It utilizes PowerShell Core best practices like CmdletBinding, Verbose output, and standard function naming.

.PARAMETER OutputFile
The path to the file where the ASN list will be saved. Defaults to 'ASN.China.list' in the current directory.

.EXAMPLE
.\Update-ChinaAsnList.ps1
Fetches data and saves it to .\ASN.China.list.

.EXAMPLE
.\Update-ChinaAsnList.ps1 -OutputFile C:\data\ChinaASNs.txt
Fetches data and saves it to the specified path.

.EXAMPLE
.\Update-ChinaAsnList.ps1 -Verbose
Runs the script with detailed verbose output showing each step.

.NOTES
Author: Based on Python script by Vincent Young, adapted for PowerShell Core by AI.
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
Requires: PowerShell Core (pwsh) 6+ with internet connectivity.
Version: 2.0 (PowerShell Core rewrite)

.LINK
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
#>
[CmdletBinding()] # Enables common parameters like -Verbose
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "ASN.China.list"
)

# --- Script Constants ---
$DataSourceUrl = "https://bgp.he.net/country/CN"
$RequestHeaders = @{
    # Standard User-Agent often used in PowerShell scripts
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 PowerShellCore/$(($PSVersionTable.PSVersion).ToString())"
}

# --- Function to Initialize Output File ---
function Initialize-OutputFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    Write-Verbose "Initializing output file: $FilePath"
    # Get current UTC time
    $utcTime = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss")


    # Create header content using a here-string for readability
    $header = @"
// ASN Information in China. (Source: $DataSourceUrl, Script based on https://github.com/gftv13879/ASN-China.pwsh)
// Last Updated: UTC $utcTime
// PowerShell Core script. Format: IP-ASN,AS_NUMBER // AS_NAME

"@

    try {
        # Use Resolve-Path to get the full path for clearer error messages if needed
        $fullPath = Resolve-Path -Path $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $fullPath) {
            Write-Verbose "Output file full path: $($fullPath.Path)"
        } else {
             Write-Verbose "Output path specified: $FilePath"
        }
        
        # Write header to file, overwriting. Use UTF8 encoding without BOM for better cross-platform compatibility.
        Set-Content -Path $FilePath -Value $header -Encoding UTF8 -Force -ErrorAction Stop # Make error terminating
        Write-Verbose "Output file initialized successfully."
    } catch {
        # Catch block is triggered if Set-Content fails due to -ErrorAction Stop
        Write-Error "FATAL: Failed to initialize output file '$FilePath'. Error: $($_.Exception.Message)"
        # Re-throw the exception to halt script execution as initialization is critical
        throw $_
    }
}

# --- Main Logic Function ---
function Update-ChinaAsnList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile,

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $SecondOutputFile = "ASN.China.txt"

    

    # 1. Initialize the output file (overwrites existing, adds header)
    # If Initialize-OutputFile fails, it will throw an exception halting this function.
    Initialize-OutputFile -FilePath $DestinationFile -Verbose:$VerbosePreference

        Write-Verbose "Initializing secondary output file: $SecondOutputFile"
    try {
        Set-Content -Path $SecondOutputFile -Value "" -Encoding UTF8 -Force -ErrorAction Stop
        Write-Verbose "Secondary output file initialized successfully."
    } catch {
        Write-Error "FATAL: Failed to initialize secondary output file '$SecondOutputFile'. Error: $($_.Exception.Message)"
        throw $_
    }

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
    }

    # 3. Parse Content using Regex
    $htmlContent = $response.Content
    # Regex to find table rows (<tr>) and extract ASN number (Group 1) and Name (Group 2)
    # (?si) -> s: dot matches newline; i: case-insensitive (good practice)
    # *? -> non-greedy match
    $rowRegex = '(?si)<tr>\s*<td><a.*?href="/AS\d+?".*?>AS(\d+?)</a></td>\s*<td>(.*?)</td>'

    Write-Verbose "Parsing HTML content using regex pattern: $rowRegex"
    # Use Select-String to find all matches in the content
    $matches = $htmlContent | Select-String -Pattern $rowRegex -AllMatches

    # if ($null -eq $matches -or $matches.Matches.Count -eq 0) {
    #     Write-Warning "No ASN rows found matching the expected pattern. The website structure might have changed, or the table is empty."
    #     # Continue script completion, but the file will only contain the header.
    #     return
    # }
    if ($null -eq $matches -or $matches.Matches.Count -eq 0) {
        Write-Warning "No ASN rows found matching the expected pattern. The website structure might have changed, or the table is empty."
    
        # --- START DEBUG OUTPUT ---
        Write-Warning "Attempting to dump first 5KB and last 1KB of HTML content for debugging:"
        Write-Host "===== HTML Start  ====="
        Write-Host $htmlContent
        Write-Host "===== HTML End  ====="

        # --- END DEBUG OUTPUT ---
    
        return # Continue to finish "successfully" but without data
    }
    $matchCount = $matches.Matches.Count
    Write-Verbose "Found $matchCount potential ASN entries."
    Write-Host "Processing $matchCount ASN entries..."
    $processedCount = 0
    $processedCountSecondFile = 0

    # 4. Process Matches and Append to File
# Assume the following variables are defined before this block:
# $matches:          The result object from Select-String or a similar regex operation,
#                    containing a .Matches property (a collection of Match objects).
# $DestinationFile:  The path for the first output file (e.g., "ASN.China.list").
# $SecondOutputFile: The path for the second output file (e.g., "ASN.China.txt").

# --- Initialization ---
# Validate required variables (optional but good practice)
if ($null -eq $matches -or $null -eq $matches.Matches) {
    Write-Error "Input variable `$matches or `$matches.Matches` is null. Cannot proceed."
    # Consider stopping script execution here if appropriate (e.g., throw or return)
    # For example: throw "Input matches collection is missing."
    # Or if in a function: return
} elseif ([string]::IsNullOrWhiteSpace($DestinationFile)) {
    Write-Error "Variable `$DestinationFile` (path for primary output) is not set."
    # throw "DestinationFile path is missing."
} elseif ([string]::IsNullOrWhiteSpace($SecondOutputFile)) {
    Write-Error "Variable `$SecondOutputFile` (path for secondary output) is not set."
    # throw "SecondOutputFile path is missing."
} else {
    # Initialize counters
    $processedCountPrimary = 0
    $processedCountSecondary = 0
    $skippedCount = 0
    $totalMatches = $matches.Matches.Count

    Write-Host "Starting ASN processing..."
    Write-Verbose "Found $totalMatches potential matches from input."
    Write-Verbose "Primary output file: $DestinationFile"
    Write-Verbose "Secondary output file: $SecondOutputFile"

    # --- Processing Loop ---
    foreach ($match in $matches.Matches) {
        # Check if the match has the expected number of capture groups
        # Group 0: Full match
        # Group 1: Expected ASN Number
        # Group 2: Expected ASN Name
        if ($match.Groups.Count -ge 3) {
            # Extract and trim ASN number and name
            $asnNumber = $match.Groups[1].Value.Trim()
            $asnNameRaw = $match.Groups[2].Value.Trim() # Keep raw name for potential debugging

            # Clean the ASN Name: Remove potential HTML tags (basic removal)
            $asnNameClean = $asnNameRaw -replace '<[^>]+>'
            # Optional: Decode HTML entities like & -> & if needed
            # try { $asnNameClean = [System.Net.WebUtility]::HtmlDecode($asnNameClean) } catch { Write-Warning "Could not HTML decode name: $asnNameClean" }

            # Validate ASN number is not empty after trimming
            if (-not [string]::IsNullOrWhiteSpace($asnNumber)) {

                # --- Write to the first file (e.g., ASN.China.list format) ---
                $primaryFileInfo = "IP-ASN,{0} // {1}" -f $asnNumber, $asnNameClean
                $writePrimarySuccess = $false
                try {
                    Add-Content -Path $DestinationFile -Value $primaryFileInfo -Encoding UTF8 -ErrorAction Stop
                    $processedCountPrimary++
                    $writePrimarySuccess = $true # Mark primary write as successful
                    Write-Verbose "Added to '$DestinationFile': $primaryFileInfo"
                } catch {
                    Write-Warning "Failed to write ASN $asnNumber to primary file '$DestinationFile'. Error: $($_.Exception.Message)"
                    # Option 1 (Default): Skip this ASN entirely and continue with the next match
                    Write-Warning "Skipping all writes for ASN $asnNumber due to primary file write error."
                    $skippedCount++
                    continue # Move to the next $match in the foreach loop
                    # Option 2: Stop the entire script if the primary file write fails (uncomment below)
                    # Write-Error "Critical error writing to primary file '$DestinationFile'. Stopping script."
                    # throw $_ # Re-throws the caught exception, stopping the script
                }

                # --- Write to the second file (e.g., ASN.China.txt format) ---
                # This block only executes if the write to the *first* file was successful
                if ($writePrimarySuccess) {
                    $secondaryFileInfo = "AS$asnNumber"
                    try {
                        Add-Content -Path $SecondOutputFile -Value $secondaryFileInfo -Encoding UTF8 -ErrorAction Stop
                        $processedCountSecondary++
                        Write-Verbose "Added to '$SecondOutputFile': $secondaryFileInfo"
                    } catch {
                        # Writing to the secondary file might be less critical.
                        # Log a warning but allow processing to continue for other ASNs.
                        Write-Warning "Failed to write ASN $asnNumber to secondary file '$SecondOutputFile'. Error: $($_.Exception.Message)"
                        # Note: $processedCountSecondary will not be incremented for this ASN.
                        # Script continues to the next $match regardless of this specific error.
                    }
                }

            } else {
                # ASN number was blank or whitespace after trimming
                Write-Warning "Skipping match because the extracted ASN number is blank or whitespace. Raw Name: '$asnNameRaw'. Full Match: '$($match.Value)'"
                $skippedCount++
            }
        } else {
            # Regex match didn't have enough capture groups
            Write-Warning "Skipping match because it did not contain the expected number of groups (found $($match.Groups.Count), expected at least 3). Full match: '$($match.Value)'"
            $skippedCount++
        }
    } # End foreach loop

    # --- Final Summary ---
    Write-Host "----------------------------------------"
    Write-Host "ASN Processing Complete."
    Write-Host "Total regex matches processed: $totalMatches"
    Write-Host "Successfully wrote $processedCountPrimary entries to primary file '$DestinationFile'."
    Write-Host "Successfully wrote $processedCountSecondary entries to secondary file '$SecondOutputFile'."
    if ($skippedCount -gt 0) {
        Write-Host "Skipped $skippedCount entries due to missing data, insufficient groups, or primary write errors."
    }
    if ($processedCountPrimary -ne $processedCountSecondary) {
         Write-Warning "Note: The number of entries written to the two files differs. This is expected if there were errors writing ONLY to the secondary file."
    }
    Write-Host "----------------------------------------"
} # End initial validation else block


# --- Execute Main Logic ---
Write-Verbose "Starting script execution..."
try {
    Update-ChinaAsnList -DestinationFile $OutputFile -Url $DataSourceUrl -Headers $RequestHeaders -Verbose:$VerbosePreference
    Write-Verbose "Script finished successfully."
} catch {
    # Catch any exceptions thrown from Update-ChinaAsnList or Initialize-OutputFile
    Write-Error "Script execution failed."
    # Error details should have been written by the function that threw the exception.
    # Exit with a non-zero code to indicate failure, useful for automation.
    exit 1
}

# Exit with success code
exit 0
