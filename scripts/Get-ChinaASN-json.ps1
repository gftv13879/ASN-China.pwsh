<#
.SYNOPSIS
Fetches and saves the latest China ASN list from bgp.he.net as a JSON file using PowerShell Core idioms.

.DESCRIPTION
This script scrapes ASN information for China from the Hurricane Electric BGP toolkit website (bgp.he.net).
It extracts ASN numbers and names, structures them into a PowerShell object along with metadata,
and saves the final object as a JSON file.
It utilizes PowerShell Core best practices like CmdletBinding, Verbose output, and standard function naming.

.PARAMETER OutputFile
The path to the file where the ASN JSON list will be saved. Defaults to 'ASN.China.list.json' in the current directory.

.EXAMPLE
.\Update-ChinaAsnListJson.ps1
Fetches data and saves it to .\ASN.China.list.json.

.EXAMPLE
.\Update-ChinaAsnListJson.ps1 -OutputFile C:\data\ChinaASNs.json
Fetches data and saves it to the specified path.

.EXAMPLE
.\Update-ChinaAsnListJson.ps1 -Verbose
Runs the script with detailed verbose output showing each step.

.NOTES
Author: Based on Python script by Vincent Young, adapted for PowerShell Core by AI, modified for JSON output.
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
Requires: PowerShell Core (pwsh) 6+ with internet connectivity.
Version: 3.0 (PowerShell Core rewrite with JSON output)

.LINK
Original Python Project: https://github.com/gftv13879/ASN-China.pwsh
Data Source: https://bgp.he.net/country/CN
#>
[CmdletBinding()] # Enables common parameters like -Verbose
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile = "ASN.China.list.json" # Default changed to .json
)

# --- Script Constants ---
$DataSourceUrl = "https://bgp.he.net/country/CN"
$RequestHeaders = @{
    # Standard User-Agent often used in PowerShell scripts
    "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 PowerShellCore/$(($PSVersionTable.PSVersion).ToString())"
}
$ScriptInfo = "PowerShell Core script based on https://github.com/gftv13879/ASN-China.pwsh"

# --- Main Logic Function ---
function Update-ChinaAsnListToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile,

        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [string]$ScriptSourceInfo
    )

    # 1. Fetch Web Content
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

    # 2. Parse Content using Regex
    $htmlContent = $response.Content
    # Regex to find table rows (<tr>) and extract ASN number (Group 1) and Name (Group 2)
    # (?si) -> s: dot matches newline; i: case-insensitive (good practice)
    # *? -> non-greedy match
    $rowRegex = '(?si)<tr>\s*<td><a.*?href="/AS\d+?".*?>AS(\d+?)</a></td>\s*<td>(.*?)</td>'

    Write-Verbose "Parsing HTML content using regex pattern: $rowRegex"
    # Use Select-String to find all matches in the content
    $matches = $htmlContent | Select-String -Pattern $rowRegex -AllMatches

    # Initialize an array to hold ASN objects
    $asnObjectList = [System.Collections.Generic.List[PSCustomObject]]::new()
    $matchCount = 0
    if ($null -ne $matches) {
        $matchCount = $matches.Matches.Count
    }

    if ($matchCount -eq 0) {
        Write-Warning "No ASN rows found matching the expected pattern. The website structure might have changed, or the table is empty."

        # --- START DEBUG OUTPUT ---
        Write-Warning "Attempting to dump first 5KB and last 1KB of HTML content for debugging:"
        Write-Host "===== HTML Start (First 5KB) ====="
        Write-Host $htmlContent.Substring(0, [System.Math]::Min($htmlContent.Length, 5120))
        Write-Host "===== HTML End (Last 1KB) ====="
        if ($htmlContent.Length -gt 1024) {
            Write-Host $htmlContent.Substring($htmlContent.Length - 1024)
        } else {
            Write-Host $htmlContent
        }
        Write-Host "===== End of Debug Dump ====="
        # --- END DEBUG OUTPUT ---

        # Continue, but the JSON 'asns' array will be empty
    } else {
        Write-Verbose "Found $matchCount potential ASN entries."
        Write-Host "Processing $matchCount ASN entries..."

        # 3. Process Matches and Build Object List
        foreach ($match in $matches.Matches) {
            # Groups[0] is the full match, Groups[1] is the first capture group, etc.
            if ($match.Groups.Count -ge 3) {
                $asnNumberStr = $match.Groups[1].Value.Trim()
                $asnName = $match.Groups[2].Value.Trim()

                # Basic cleanup: remove potential HTML tags from name (simple version)
                $asnNameClean = $asnName -replace '<[^>]+>'
                # Optional: Decode HTML entities if needed (e.g., &amp; -> &)
                # $asnNameClean = [System.Net.WebUtility]::HtmlDecode($asnNameClean) # Uncomment if needed

                if (-not [string]::IsNullOrWhiteSpace($asnNumberStr) -and $asnNumberStr -match '^\d+$') {
                    # Try converting ASN to integer for cleaner JSON, keep as string if huge or fails
                    try {
                        $asnNumber = [int]$asnNumberStr
                    } catch {
                        Write-Warning "Could not convert ASN '$asnNumberStr' to integer, keeping as string."
                        $asnNumber = $asnNumberStr
                    }

                    # Create a PSCustomObject for this ASN
                    $asnObject = [PSCustomObject]@{
                        asn_number = $asnNumber
                        asn_name   = $asnNameClean
                    }
                    $asnObjectList.Add($asnObject)
                    Write-Verbose "Processed: ASN $($asnObject.asn_number) - $($asnObject.asn_name)"
                } else {
                    Write-Warning "Skipping row due to missing or invalid ASN number: '$asnNumberStr'. Original row data might be incomplete or malformed."
                }
            } else {
                 Write-Warning "Regex match did not contain expected groups. Skipping."
            }
        } # End foreach loop
        Write-Host "Successfully processed $asnObjectList.Count ASN entries."
    } # End if matches found

    # 4. Construct the final JSON structure with metadata
    $utcTime = ((Get-Date).ToUniversalTime()).ToString("yyyy-MM-dd HH:mm:ss")
    $jsonData = [PSCustomObject]@{
        metadata = [PSCustomObject]@{
            source_url       = $Url
            last_updated_utc = $utcTime
            script_info      = $ScriptSourceInfo
            entry_count      = $asnObjectList.Count # Add count to metadata
        }
        asns = $asnObjectList # Add the list/array of ASN objects
    }

    # 5. Convert to JSON and Save to File
    Write-Verbose "Converting data structure to JSON format."
    # Use -Depth 5 or higher to ensure nested objects (metadata, asns array) are fully converted
    $jsonOutput = $jsonData | ConvertTo-Json -Depth 5

    Write-Verbose "Attempting to write JSON data to: $DestinationFile"
    try {
        # Use Resolve-Path to get the full path for clearer messages
        $fullPath = Resolve-Path -Path $DestinationFile -ErrorAction SilentlyContinue
        if ($null -ne $fullPath) {
            Write-Verbose "Output file full path: $($fullPath.Path)"
        } else {
             Write-Verbose "Output path specified: $DestinationFile"
        }

        # Write JSON string to file, overwriting. Use UTF8 encoding without BOM.
        Set-Content -Path $DestinationFile -Value $jsonOutput -Encoding UTF8 -Force -ErrorAction Stop
        Write-Host "Successfully wrote $($asnObjectList.Count) ASN entries to '$DestinationFile'."
    } catch {
        # Catch block is triggered if Set-Content fails due to -ErrorAction Stop
        Write-Error "FATAL: Failed to write JSON output file '$DestinationFile'. Error: $($_.Exception.Message)"
        # Re-throw the exception to halt script execution as saving is critical
        throw $_
    }
}

# --- Execute Main Logic ---
Write-Verbose "Starting script execution..."
try {
    # Call the main function
    Update-ChinaAsnListToJson -DestinationFile $OutputFile -Url $DataSourceUrl -Headers $RequestHeaders -ScriptSourceInfo $ScriptInfo -Verbose:$VerbosePreference
    Write-Verbose "Script finished successfully."
} catch {
    # Catch any exceptions thrown from Update-ChinaAsnListToJson
    Write-Error "Script execution failed."
    # Error details should have been written by the function that threw the exception.
    # Exit with a non-zero code to indicate failure, useful for automation.
    exit 1
}

# Exit with success code
exit 0
