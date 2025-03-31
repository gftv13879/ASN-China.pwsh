<#
.SYNOPSIS
# 脚本简介：从指定的输入文件读取 ASN 列表，查询 RIPEStat API 获取宣告的前缀，
# 并将唯一的 CIDR 前缀输出到指定的文件（支持纯列表格式）。
# 设计用于纯 PowerShell 环境，例如 GitHub Actions。

.DESCRIPTION
# 脚本描述：
# 1. 从 -InputAsnFilePath 参数指定的文件读取 ASN。
# 2. 提取唯一的 ASN 号码。
# 3. 对每个唯一的 ASN，使用 Invoke-RestMethod 查询 RIPEStat 'announced-prefixes' API 端点。
# 4. 收集 API 返回的所有宣告的前缀 (IPv4 和 IPv6)。
# 5. 移除重复的前缀。
# 6. 如果指定了 -RawOutput，则将唯一前缀直接写入 -OutputFilePath 指定的文件，每行一个，无标题。
# 7. 否则（默认），将唯一前缀作为带标题的 CSV 写入 -OutputFilePath 指定的文件。

.PARAMETER InputAsnFilePath
# 参数 InputAsnFilePath：【必需】包含 ASN 列表的文本文件的路径。
# (文件内格式可以是 'IP-ASN,12345 // Comment' 或每行一个 ASN 数字)。

.PARAMETER OutputFilePath
# 参数 OutputFilePath：【必需】指定结果文件的完整保存路径。
# 输出格式由 -RawOutput 参数决定。

.PARAMETER RawOutput
# 参数 RawOutput：【可选开关】如果指定此参数，输出文件将只包含 CIDR 列表，每行一个，没有 CSV 标题。
# 如果不指定，则输出为标准的单列 CSV 文件（带 "Prefix" 标题）。

.EXAMPLE
# 示例 1：从 ASN.China.list 读取，输出为纯列表到 IP.China.list
./Get-AsnPrefixes.ps1 -InputAsnFilePath ./ASN.China.list -OutputFilePath ./IP.China.list -RawOutput

.EXAMPLE
# 示例 2：从另一个文件读取，输出为 CSV 文件
./Get-AsnPrefixes.ps1 -InputAsnFilePath ./other_asns.txt -OutputFilePath ./other_prefixes.csv

.NOTES
# 注意事项：
# - 容器需要有效的互联网连接以查询 RIPEStat API。
# - 使用公共 RIPEStat API - 请求间有短暂延迟。
# - ErrorActionPreference 设置为 Stop。
# - 使用 Write-Host/Write-Error 输出日志。
# - 关键错误时以退出码 1 退出。
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$InputAsnFilePath,

    [Parameter(Mandatory=$true)]
    [string]$OutputFilePath,

    [Parameter(Mandatory=$false)]
    [switch]$RawOutput # 添加开关参数控制输出格式
)

# --- 全局错误处理设置 ---
$ErrorActionPreference = 'Stop'

# --- 函数：从单行文本中解析 ASN ---
function Parse-AsnFromLine {
    param([string]$Line)
    if ($Line -match 'IP-ASN,(\d+)') {
        return $Matches[1]
    } elseif ($Line -match '^\s*(\d+)\s*$') {
        return $Matches[1]
    }
    return $null
}

# --- 读取和解析输入文件 ---
Write-Host "正在从文件处理 ASN 列表: $InputAsnFilePath"
if (-not (Test-Path $InputAsnFilePath)) {
    Write-Error "输入文件未找到: $InputAsnFilePath"
    exit 1
}

$asnSet = [System.Collections.Generic.HashSet[string]]::new()
try {
    Get-Content $InputAsnFilePath | ForEach-Object {
        $asn = Parse-AsnFromLine -Line $_
        if ($asn) {
            [void]$asnSet.Add($asn)
        }
    }
} catch {
    Write-Error "读取或解析输入文件 '$InputAsnFilePath' 时出错: $($_.Exception.Message)"
    exit 1
}

if ($asnSet.Count -eq 0) {
    Write-Error "在输入文件 '$InputAsnFilePath' 中未找到有效的 ASN 号码。"
    # 如果没找到 ASN，根据输出模式处理
    Write-Host "在 $OutputFilePath 创建空文件。"
    if ($RawOutput) {
        Set-Content -Path $OutputFilePath -Value $null -Encoding UTF8 -ErrorAction Stop
    } else {
         # 创建带标题的空 CSV
         New-Object PSObject | Add-Member -MemberType NoteProperty -Name Prefix -Value $null | Select-Object Prefix | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    }
    exit 0 # 没找到 ASN 不算失败，只是没有结果
}

Write-Host "找到 $($asnSet.Count) 个唯一的 ASN 进行查询。"

# --- 查询 RIPEStat API ---
# (这部分代码与上一个版本相同，只是日志和错误处理)
$allPrefixes = [System.Collections.Generic.List[string]]::new()
$ripeStatUrlTemplate = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{0}"
$totalAsns = $asnSet.Count
$currentAsnCount = 0

Write-Host "正在查询 RIPEStat API 获取宣告的前缀..."

foreach ($asn in ($asnSet | Sort-Object {[int]$_})) {
    $currentAsnCount++
    $apiUrl = $ripeStatUrlTemplate -f $asn
    Write-Host "[$currentAsnCount/$totalAsns] 正在查询 AS$asn ..."

    try {
        $headers = @{ "User-Agent" = "GitHubAction-PowerShell-AsnToCidr/1.1" }
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -UseBasicParsing -Headers $headers -ErrorAction Stop -TimeoutSec 120

        if ($null -ne $response -and $response.PSObject.Properties['data'] -ne $null -and $response.data.PSObject.Properties['prefixes'] -ne $null) {
            $prefixesFound = $response.data.prefixes.Count
            Write-Host "  为 AS$asn 找到 $prefixesFound 个前缀。"
            foreach ($prefixInfo in $response.data.prefixes) {
                if ($prefixInfo.prefix) {
                    $allPrefixes.Add($prefixInfo.prefix)
                }
            }
        } else {
             Write-Warning "  未找到 AS$asn 的前缀数据数组或数组为空。API 状态: $($response.status)"
        }
        Start-Sleep -Seconds 1
    } catch [System.Net.WebException] {
        $statusCode = 0
        if($_.Exception.Response -ne $null) { $statusCode = [int]$_.Exception.Response.StatusCode }
        $errorMessage = $_.Exception.Message
        Write-Warning "查询 AS$asn 时发生 API 错误 (状态码: $statusCode): $errorMessage"
        continue
    } catch {
        Write-Warning "查询 AS$asn 时发生意外错误: $($_.Exception.Message)"
        continue
    }
}

# --- 处理并导出结果 ---
# 确保输出目录存在
try {
    $outputDirectory = Split-Path -Path $OutputFilePath -Parent
    if ($outputDirectory -and (-not (Test-Path $outputDirectory))) {
        Write-Host "正在创建输出目录: $outputDirectory"
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
} catch {
     Write-Error "无法创建输出目录 '$outputDirectory': $($_.Exception.Message)"
     exit 1
}

if ($allPrefixes.Count -eq 0) {
    Write-Warning "未能从 API 收集到给定 ASN 的任何前缀。"
    Write-Host "在 $OutputFilePath 创建空文件。"
    if ($RawOutput) {
        Set-Content -Path $OutputFilePath -Value $null -Encoding UTF8 -ErrorAction Stop
    } else {
         New-Object PSObject | Add-Member -MemberType NoteProperty -Name Prefix -Value $null | Select-Object Prefix | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    }
} else {
    Write-Host "总共收集到 $($allPrefixes.Count) 个前缀（包含重复项）。"
    Write-Host "正在筛选唯一前缀..."

    # 获取唯一的 IP 前缀列表 (字符串)
    $uniquePrefixes = $allPrefixes | Select-Object -Unique

    $uniqueCount = $uniquePrefixes.Count
    Write-Host "找到 $uniqueCount 个唯一前缀。"

    # --- 根据 -RawOutput 参数决定输出格式 ---
    if ($RawOutput) {
        Write-Host "正在将 $uniqueCount 个唯一前缀（纯列表格式）导出到 $OutputFilePath ..."
        try {
            # 直接将字符串列表写入文件，每行一个，使用 UTF8 编码
            Set-Content -Path $OutputFilePath -Value $uniquePrefixes -Encoding UTF8 -ErrorAction Stop
            Write-Host "成功将纯列表格式的前缀导出到 $OutputFilePath"
        } catch {
             Write-Error "导出纯列表文件 '$OutputFilePath' 失败: $($_.Exception.Message)"
             exit 1
        }
    } else {
        # --- 输出为 CSV (默认行为) ---
        Write-Host "正在将 $uniqueCount 个唯一前缀（CSV 格式）导出到 $OutputFilePath ..."
        try {
            # 转换成对象再导出
            $uniquePrefixObjects = $uniquePrefixes | ForEach-Object { [PSCustomObject]@{ Prefix = $_ } }
            $uniquePrefixObjects | Export-Csv -Path $OutputFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Host "成功将 CSV 格式的前缀导出到 $OutputFilePath"
        } catch {
            Write-Error "导出 CSV 文件 '$OutputFilePath' 失败: $($_.Exception.Message)"
            exit 1
        }
    }
}

Write-Host "脚本成功完成。"
exit 0
