<#
.SYNOPSIS
  使用流式处理方式，低内存占用地获取 RIPE RISwhois 和 CAIDA RouteViews 数据，
  解析并聚合成 ASN 到 IP 前缀的映射，并根据提供的 JSON 文件过滤输出为 JSON 格式。

.DESCRIPTION
  此脚本通过流式处理下载和解压数据，避免将整个大文件加载到内存中。
  1. 流式下载和解压 RIPE RISwhois dumps (IPv4 & IPv6)。
  2. 下载 CAIDA pfx2as 创建日志，找到最新的 pfx2as 文件。
  3. 流式下载和解压最新的 CAIDA pfx2as 文件 (IPv4 & IPv6)。
  4. 逐行解析 RIPE 和 CAIDA 数据，聚合到内存哈希表。
  5. 读取指定的 JSON 文件，获取要过滤的 ASN 列表。
  6. 仅筛选出 JSON 文件中列出的 ASN 的前缀映射。
  7. 将过滤后的映射构建成 PowerShell 对象。
  8. 将该对象转换为 JSON 格式并写入输出文件。

.NOTES
  - 需要 PowerShell (pwsh) 运行环境。
  - 脚本执行期间需要稳定的网络连接。
  - 输出 JSON 文件会覆盖同名旧文件。
  - 输入的 JSON 文件应具有 'asns' 数组，其中每个对象包含 'asn_number' 字段。
  - **重要**: 默认路径是相对于脚本的 *工作目录*。在 GitHub Actions 中，工作目录通常是仓库的根目录 (`/workspace` in container).

.PARAMETER AsnFilterFile
  包含要过滤的 ASN 列表的 JSON 文件的路径。
  JSON 结构应为: {..., "asns": [ { "asn_number": 123,... },... ] }
  默认为工作目录下的 './ASN.China.list.json'。

.PARAMETER OutputFile
  输出 JSON 文件的路径和名称。
  默认为工作目录下的 './IP.China.list.json'。

.EXAMPLE
  # 在仓库根目录运行 (或工作目录是仓库根目录时)
  pwsh ./scripts/Convert_Asn2IP.ps1

.EXAMPLE
  # 指定不同的 JSON 过滤文件和 JSON 输出文件 (相对于当前工作目录)
  pwsh ./scripts/Convert_Asn2IP.ps1 -AsnFilterFile ./config/my_asn_list.json -OutputFile ./output/my_filtered_output.json
#>

param(
    # 包含要过滤的 ASN 列表的 JSON 文件的路径
    # 默认指向相对于 *工作目录* 的文件 (即 /workspace/ASN.China.list.json in action)
    [string]$AsnFilterFile = './ASN.China.list.json',

    # 输出 JSON 文件的路径和名称
    # 默认指向相对于 *工作目录* 的文件 (即 /workspace/IP.China.list.json in action)
    [string]$OutputFile = "./IP.China.list.json" # <<< 注意：您已更改此默认输出文件名
)

# --- Configuration ---
$ErrorActionPreference = 'Stop' # 在发生错误时退出脚本
$VerbosePreference = 'Continue' # 显示详细进度

# --- Data Structure ---
# 使用 ConcurrentDictionary 保证线程安全
$asnToPrefixMap = [System.Collections.Concurrent.ConcurrentDictionary[string, System.Collections.Generic.List[string]]]::new()

# --- Helper Function to Add to Map (线程安全版本 - 使用 Monitor) ---
function Add-PrefixToMap {
    param(
        [string]$Asn,
        [string]$Prefix
    )
    if ($Asn -notmatch '^\d+$') { Write-Warning "为前缀 '$Prefix' 跳过无效的 ASN 格式 '$Asn'"; return }
    if ($Prefix -notmatch '^[0-9a-fA-F:.]+/\d{1,3}$') { Write-Warning "为 ASN '$Asn' 跳过无效的前缀格式 '$Prefix'"; return }
    $prefixList = $asnToPrefixMap.GetOrAdd($Asn, { [System.Collections.Generic.List[string]]::new() })
    [System.Threading.Monitor]::Enter($prefixList)
    try { if (-not $prefixList.Contains($Prefix)) { $prefixList.Add($Prefix) } }
    finally { [System.Threading.Monitor]::Exit($prefixList) }
}

# --- Helper Function: 下载、流式解压并逐行处理 Gzip URL 内容 ---
function Process-GzippedUrlStreamLineByLine {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][scriptblock]$LineProcessor
    )
    Write-Verbose "开始流式处理 URL: $Url"
    $webResponse = $null; $responseStream = $null; $gzipStream = $null; $streamReader = $null; $linesProcessed = 0
    try {
        $webRequest = [System.Net.WebRequest]::Create($Url); $webRequest.Timeout = 300000
        $webRequest.Headers.Add([System.Net.HttpRequestHeader]::AcceptEncoding, "gzip, deflate")
        $webResponse = $webRequest.GetResponse()
        if ($webResponse -isnot [System.Net.HttpWebResponse] -or $webResponse.StatusCode -ne [System.Net.HttpStatusCode]::OK) { throw "下载失败，URL: '$Url'，HTTP 状态码: $($webResponse.StatusCode)" }
        $responseStream = $webResponse.GetResponseStream()
        $contentEncoding = $webResponse.Headers["Content-Encoding"]
        if ($contentEncoding -ne $null -and $contentEncoding.ToLowerInvariant().Contains("gzip")) {
            Write-Verbose "使用 GzipStream 解压来自 $Url 的流..."; $gzipStream = [System.IO.Compression.GzipStream]::new($responseStream, [System.IO.Compression.CompressionMode]::Decompress); $streamReader = [System.IO.StreamReader]::new($gzipStream, [System.Text.Encoding]::UTF8)
        } else { Write-Verbose "直接读取来自 $Url 的响应流 (非 Gzip)..."; $streamReader = [System.IO.StreamReader]::new($responseStream, [System.Text.Encoding]::UTF8) }
        Write-Verbose "开始逐行读取和处理 $Url 的数据..."
        while (($line = $streamReader.ReadLine()) -ne $null) { & $LineProcessor $line; $linesProcessed++ }
        Write-Verbose "成功完成 $Url 的流式处理，共处理 $linesProcessed 行."; return $true
    } catch { throw "处理 URL '$Url' 的流时出错: $($_.Exception.ToString())" }
    finally {
        if ($streamReader -ne $null) { $streamReader.Dispose() }
        if ($gzipStream -ne $null) { $gzipStream.Dispose() }
        if ($responseStream -ne $null) { $responseStream.Close() }
        if ($webResponse -ne $null) { $webResponse.Close() }
        Write-Verbose "已清理 $Url 的流资源."
    }
}

# --- Helper Function to Download Text URL Content In Memory ---
function Get-UrlContentText {
    param( [string]$Url )
    Write-Verbose "正在下载文本内容 (内存中): $Url..."
    try {
        $webRequest = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 120
        if ($webRequest.StatusCode -eq 200) {
            Write-Verbose "成功从 $Url 下载了文本内容."; $content = $webRequest.Content
            # Removed BOM check - relying on defaults
            return $content -split '\r?\n'
        } else { throw "下载失败，URL '$Url'，HTTP 状态码: $($webRequest.StatusCode)" }
    } catch { Write-Error "下载文本 URL '$Url' 时出错: $($_.Exception.Message)"; return $null }
}

# --- Main Script Logic ---
Write-Host "--- 开始 ASN 到 IP 前缀映射生成 (过滤流式处理, 输出 JSON) ---"
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# --- 1. 定义 RIPE 行处理逻辑 ---
$ripeLineProcessor = { param($line) if ($line.StartsWith('%') -or [string]::IsNullOrWhiteSpace($line)) { return }; $parts = $line -split '\t+'; if ($parts.Count -ge 2) { $asn = $parts[0].Trim(); $prefix = $parts[1].Trim(); Add-PrefixToMap -Asn $asn -Prefix $prefix } }

# --- 2. 处理 RIPE RISwhois Dumps ---
Write-Host "`n--- 处理 RIPE RISwhois (流式) ---"
$ripeUrls = @{ IPv4 = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz"; IPv6 = "https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz" }
foreach ($ipVersion in $ripeUrls.Keys) { $url = $ripeUrls[$ipVersion]; Write-Host "开始处理 RIPE $ipVersion 数据源: $url"; try { Process-GzippedUrlStreamLineByLine -Url $url -LineProcessor $ripeLineProcessor; Write-Host "完成处理 RIPE $ipVersion 数据源." } catch { Write-Warning "处理 RIPE $ipVersion 数据源 $url 时遇到错误: $($_.Exception.Message)" } }

# --- 3. 定义 CAIDA 行处理逻辑 ---
$caidaLineProcessor = { param($line) if ($line.StartsWith('#') -or [string]::IsNullOrWhiteSpace($line)) { return }; $parts = $line -split '\t+'; if ($parts.Count -eq 3) { $prefixIp = $parts[0].Trim(); $prefixLen = $parts[1].Trim(); $asString = $parts[2].Trim(); if (($prefixLen -match '^\d{1,3}$') -and ($prefixIp -match '^[0-9a-fA-F:.]+$')) { $fullPrefix = "$prefixIp/$prefixLen"; $individualASNs = $asString -split '[_,]' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }; if ($individualASNs) { foreach ($asn in $individualASNs) { Add-PrefixToMap -Asn $asn -Prefix $fullPrefix } } else { Write-Warning "在前缀 '$fullPrefix' 的行中未找到有效的 ASN: '$asString'" } } else { Write-Warning "跳过无效的 CAIDA 行格式 (IP/Length): '$line'" } } else { Write-Warning "跳过无效的 CAIDA 行格式 (Parts Count): '$line'" } }

# --- 4. 处理 CAIDA RouteViews pfx2as ---
Write-Host "`n--- 处理 CAIDA RouteViews pfx2as (流式) ---"
$caidaSources = @{ IPv4 = @{ LogUrl = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log"; BaseUrl = "https://publicdata.caida.org/datasets/routing/routeviews-prefix2as/" }; IPv6 = @{ LogUrl = "https://publicdata.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log"; BaseUrl = "https://publicdata.caida.org/datasets/routing/routeviews6-prefix2as/" } }
foreach ($ipVersion in $caidaSources.Keys) {
    $sourceInfo = $caidaSources[$ipVersion]; $logUrl = $sourceInfo.LogUrl; $baseUrl = $sourceInfo.BaseUrl.TrimEnd('/')
    Write-Host "获取 CAIDA $ipVersion 日志: $logUrl..."; $logLines = Get-UrlContentText -Url $logUrl
    if ($logLines -eq $null) { Write-Warning "未能下载或处理 CAIDA $ipVersion 日志，跳过 CAIDA $ipVersion 数据源."; continue }
    $latestSeqNum = -1L; $latestPath = $null
    foreach($logLine in $logLines) { if ($logLine.StartsWith('#') -or [string]::IsNullOrWhiteSpace($logLine)) { continue }; $logParts = $logLine -split '\t+'; if ($logParts.Count -ge 3) { $seqNumStr = $logParts[0].Trim(); $seqNum = 0L; if ([long]::TryParse($seqNumStr, [ref]$seqNum)) { if ($seqNum -gt $latestSeqNum) { $latestSeqNum = $seqNum; $latestPath = $logParts[2].Trim() } } } }
    if (-not $latestPath) { Write-Warning "无法从 CAIDA $ipVersion 日志 '$logUrl' 确定最新路径，跳过."; continue }
    Write-Host "找到最新的 CAIDA $ipVersion 路径: $latestPath (Seq: $latestSeqNum)"; $dataUrl = if ($latestPath.StartsWith('/')) { "$baseUrl$latestPath" } else { "$baseUrl/$latestPath" }
    Write-Host "开始处理 CAIDA $ipVersion 数据源: $dataUrl"; try { Process-GzippedUrlStreamLineByLine -Url $dataUrl -LineProcessor $caidaLineProcessor; Write-Host "完成处理 CAIDA $ipVersion 数据源." } catch { Write-Warning "处理 CAIDA $ipVersion 数据源 $dataUrl 时遇到错误: $($_.Exception.Message)" }
}

# --- 5. 读取并解析 ASN 过滤文件 ---
Write-Host "`n--- 读取 ASN 过滤文件 ---"
# --- Logging Start ---
$currentWorkingDirectory = Get-Location | Select-Object -ExpandProperty Path
Write-Host "当前工作目录 (Current Working Directory): $currentWorkingDirectory"
Write-Host "使用的过滤器文件参数 (AsnFilterFile Parameter): $AsnFilterFile"
# --- Logging End ---

try {
    # Resolve the path relative to the current working directory ($PWD or Get-Location)
    $resolvedAsnFilterFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AsnFilterFile)
    Write-Host "解析后的过滤器文件绝对路径 (Resolved Filter File Path): $resolvedAsnFilterFile"
} catch {
    Write-Error "无法解析 ASN 过滤文件路径 '$AsnFilterFile' (相对于工作目录 '$currentWorkingDirectory'): $($_.Exception.Message)"
    exit 1
}

# Check if the resolved path exists
$filterFileExists = Test-Path -Path $resolvedAsnFilterFile -PathType Leaf
if (-not $filterFileExists) {
    # More detailed error message
    Write-Error "指定的 ASN 过滤文件未找到!"
    Write-Error "  - 检查路径: '$resolvedAsnFilterFile'"
    Write-Error "  - (该路径是根据参数 '$AsnFilterFile' 相对于工作目录 '$currentWorkingDirectory' 解析得到的)"
    Write-Error "  - 请确保文件 'ASN.China.list.json' 存在于仓库根目录 (即 '$currentWorkingDirectory')。"
    Write-Error "脚本将退出。"
    exit 1
}

# Proceed only if file exists
$asnFilterSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
try {
    Write-Verbose "正在读取并解析 JSON 文件: $resolvedAsnFilterFile"
    $jsonContent = Get-Content -Path $resolvedAsnFilterFile -Raw | ConvertFrom-Json
    if ($null -eq $jsonContent.asns -or $jsonContent.asns -isnot [array]) { throw "JSON 文件 '$resolvedAsnFilterFile' 缺少 'asns' 数组或格式不正确。" }
    $asnProcessedFromJson = 0; $asnAddedToFilter = 0
    foreach ($asnEntry in $jsonContent.asns) {
        $asnProcessedFromJson++; if ($null -ne $asnEntry.asn_number) { $asnString = $asnEntry.asn_number.ToString().Trim(); if ($asnString -match '^\d+$') { if ($asnFilterSet.Add($asnString)) { $asnAddedToFilter++ } } else { Write-Warning "在 JSON 文件中跳过无效的 asn_number (非数字): '$($asnEntry.asn_number)'" } } else { Write-Warning "在 JSON 文件中找到空的或缺失的 'asn_number' 条目。" }
    }
    Write-Host "从 '$resolvedAsnFilterFile' (共 $asnProcessedFromJson 条记录) 加载了 $asnAddedToFilter 个唯一的有效 ASN 用于过滤。"
    if ($asnAddedToFilter -lt $asnProcessedFromJson) { Write-Warning "JSON 文件中包含 $($asnProcessedFromJson - $asnAddedToFilter) 个重复、无效或缺失的 ASN 条目。" }
    if ($asnAddedToFilter -eq 0) { Write-Warning "目标 ASN 过滤器为空，输出将为空。" }
} catch { Write-Error "读取或解析 ASN 过滤文件 '$resolvedAsnFilterFile' 时出错: $($_.Exception.ToString())"; exit 1 }


# --- 6. 生成过滤后的输出 (JSON 格式) ---
Write-Host "`n--- 生成过滤后的 JSON 输出文件 ---"
try {
    $resolvedOutputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputFile)
    Write-Host "解析后的输出文件绝对路径 (Resolved Output File Path): $resolvedOutputFile"
} catch { Write-Error "无法解析输出文件路径 '$OutputFile': $($_.Exception.Message)"; exit 1 }

$filteredOutputList = [System.Collections.Generic.List[PSCustomObject]]::new()
$totalFilteredPrefixMappingCount = 0; $asnsFoundInMap = 0
Write-Host "正在根据过滤列表构建 JSON 输出结构..."
$sortedFilteredAsns = $asnFilterSet | Sort-Object { [int64]$_ }

foreach ($asnToFilter in $sortedFilteredAsns) {
    $prefixListData = $null
    if ($asnToPrefixMap.TryGetValue($asnToFilter, [ref]$prefixListData)) {
        $asnsFoundInMap++; $sortedPrefixes = $prefixListData | Sort-Object; $totalFilteredPrefixMappingCount += $sortedPrefixes.Count
        $asnObject = [PSCustomObject]@{ asn_number = $asnToFilter; prefixes = $sortedPrefixes }; $filteredOutputList.Add($asnObject)
    }
}

$finalOutputObject = [PSCustomObject]@{
    metadata = [PSCustomObject]@{ generation_timestamp_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); data_sources = @("RIPE RISwhois Dumps", "CAIDA RouteViews pfx2as"); filter_file = $resolvedAsnFilterFile; filtered_asn_count_in_file = $asnFilterSet.Count; filtered_asn_count_found_in_data = $asnsFoundInMap; total_prefix_mappings_output = $totalFilteredPrefixMappingCount }
    asn_prefix_map = $filteredOutputList
}

try {
    Write-Host "正在将构建的对象转换为 JSON 并写入输出文件: $resolvedOutputFile ..."
    $jsonOutput = $finalOutputObject | ConvertTo-Json -Depth 5 #-Compress
    $outputDirectory = Split-Path -Path $resolvedOutputFile -Parent
    if (-not (Test-Path -Path $outputDirectory -PathType Container)) { Write-Verbose "创建输出目录: $outputDirectory"; New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null }
    $streamWriter = [System.IO.StreamWriter]::new($resolvedOutputFile, $false, [System.Text.UTF8Encoding]::new($false)) # Overwrite, No BOM
    $streamWriter.Write($jsonOutput); $streamWriter.Close()
    Write-Host "成功将 $totalFilteredPrefixMappingCount 条过滤后的 ASN 到 IP 前缀映射以 JSON 格式写入到: $resolvedOutputFile"
    if ($asnsFoundInMap -lt $asnFilterSet.Count) { Write-Warning "注意: 过滤列表中的 $($asnFilterSet.Count - $asnsFoundInMap) 个 ASN 在 RIPE/CAIDA 数据中未找到对应的前缀。" }
} catch { Write-Error "转换 JSON 或写入输出文件 '$resolvedOutputFile' 失败: $($_.Exception.ToString())"; exit 1 }

$stopwatch.Stop()
Write-Host "脚本执行完毕。总耗时: $($stopwatch.Elapsed.ToString())"
