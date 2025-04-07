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
    $utcTime = (Get-Date).ToUniversalTime() -Format "yyyy-MM-dd HH:mm:ss"

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

    # 1. Initialize the output file (overwrites existing, adds header)
    # If Initialize-OutputFile fails, it will throw an exception halting this function.
    Initialize-OutputFile -FilePath $DestinationFile -Verbose:$VerbosePreference

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
    $rowRegex = '(?si)<tr>\s*<td><a href="/AS\d+?">AS(\d+?)</a></td>\s*<td>(.*?)</td>'

    Write-Verbose "Parsing HTML content using regex pattern: $rowRegex"
    # Use Select-String to find all matches in the content
    $matches = $htmlContent | Select-String -Pattern $rowRegex -AllMatches

    if ($null -eq $matches -or $matches.Matches.Count -eq 0) {
        Write-Warning "No ASN rows found matching the expected pattern. The website structure might have changed, or the table is empty."
        # Continue script completion, but the file will only contain the header.
        return
    }

    $matchCount = $matches.Matches.Count
    Write-Verbose "Found $matchCount potential ASN entries."
    Write-Host "Processing $matchCount ASN entries..."
    $processedCount = 0

    # 4. Process Matches and Append to File
    foreach ($match in $matches.Matches) {
        # Groups[0] is the full match, Groups[1] is the first capture group, etc.
        if ($match.Groups.Count -ge 3) {
            $asnNumber = $match.Groups[1].Value.Trim()
            $asnName = $match.Groups[2].Value.Trim()

            # Basic cleanup: remove potential HTML tags from name (simple version)
            $asnNameClean = $asnName -replace '<[^>]+>'
            # Optional: Decode HTML entities if needed (e.g., &amp; -> &) - requires more complex handling
            # $asnNameClean = [System.Net.WebUtility]::HtmlDecode($asnNameClean) # Uncomment if needed

            if (-not [string]::IsNullOrWhiteSpace($asnNumber)) {
                # Format the output line
                $asnInfo = "IP-ASN,{0} // {1}" -f $asnNumber, $asnNameClean
                try {
                    # Append the formatted line using UTF8 encoding without BOM
                    Add-Content -Path $DestinationFile -Value $asnInfo -Encoding UTF8 -ErrorAction Stop
                    $processedCount++
                    Write-Verbose "Added: $asnInfo"
                } catch {
                    Write-Warning "Failed to write ASN $asnNumber to file '$DestinationFile'. Error: $($_.Exception.Message)"
                    # Decide whether to continue or stop on write errors
                    # continue # Skip to next ASN
                    # throw $_ # Stop the entire script
                }
            } else {
                Write-Warning "Skipping row due to missing ASN number. Original row data might be incomplete or malformed."
            }
        } else {
             Write-Warning "Regex match did not contain expected groups. Skipping."
        }
    } # End foreach loop

    Write-Host "Successfully processed and wrote $processedCount out of $matchCount found entries to '$DestinationFile'."
}

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
