# ==============================
# ANY.RUN IOC Scraper with CSV/JSON Export Options
# ==============================

# 🔧 Configuration
$exports = "C:\Temp"
$exportCsv = $true     # Enable/disable CSV export
$exportJson = $true     # Enable/disable JSON export

# Check if at least one export option is enabled
if (-not ($exportCsv -or $exportJson)) {
    Write-Host "No export option enabled! Please set at least one variable (`$exportCsv` or `$exportJson`) to `$true`." -ForegroundColor Red
    exit
}

# ==============================
# Main Routine
# ==============================
$anyrunURLs = (Invoke-WebRequest -UseBasicParsing -Uri "https://any.run/malware-trends/").Links |
Where-Object { $_.href -like "/malware-trends/*" } |
Select-Object href

$staticURLPart = "https://any.run"
$csvData = @()

ForEach ($url in $anyrunURLs.href) {

    Write-Host "Processing URL: $url" -ForegroundColor White
     
    # Get the content of the trend page
    $content = Invoke-WebRequest -UseBasicParsing -Uri "$staticURLPart$url"
    $htmlContent = $content.Content

    # Reset variables for each page
    $malwareType = $null
    $malwareName = $null
    $origin = $null
    $firstSeen = $null
    $lastSeen = $null

    # Extract malware name
    $namePattern = '<h1 class="title dot-(?:success|warning|danger)">(.*?)</h1>'
    if ($htmlContent -match $namePattern) { $malwareName = $Matches[1].Trim() } 

    # Extract malware type
    $typePattern = '<i class="fas fa-puzzle-piece"></i>\s*(.*?)\s*</div>'
    if ($htmlContent -match $typePattern) { $malwareType = $Matches[1].Trim() } 
     
    # Extract origin (country)
    $originPattern = '<i class="fas fa-map-marker-alt"></i>\s*(.*?)\s*</div>'
    if ($htmlContent -match $originPattern) { $origin = $Matches[1].Trim() }

    # Extract and convert "First Seen" date
    $firstSeenPattern = '<i class="fas fa-calendar-alt"></i>\s*(.*?)\s*</div>'
    if ($htmlContent -match $firstSeenPattern) {
        $dateString = $Matches[1].Trim()
        $inputFormat = "d MMMM, yyyy"
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US') 
        $outputFormat = "dd.MM.yyyy"
        try {
            $dateObject = [datetime]::ParseExact($dateString, $inputFormat, $culture)
            $firstSeen = $dateObject.ToString($outputFormat)
        }
        catch { $firstSeen = $dateString }
    }

    # Extract and convert "Last Seen" date
    $lastSeenPattern = '<i class="fas fa-clock"></i>\s*(.*?)\s*</div>'
    if ($htmlContent -match $lastSeenPattern) {
        $dateString = $Matches[1].Trim()
        $inputFormat = "d MMMM, yyyy"
        $culture = [System.Globalization.CultureInfo]::GetCultureInfo('en-US') 
        $outputFormat = "dd.MM.yyyy"
        try {
            $dateObject = [datetime]::ParseExact($dateString, $inputFormat, $culture)
            $lastSeen = $dateObject.ToString($outputFormat)
        }
        catch { $lastSeen = $dateString }
    }

    # Collect IOC data
    $currentIpData = @()
    $currentHashData = @()
    $currentDomainData = @()
    $currentUrlData = @()
    $DataName = ""

    ForEach ($Line in $htmlContent -split "`n") { 
        If ($Line -like "*ipData*") { $DataName = "ipData" } 
        ElseIf ($Line -like "*hashData*") { $DataName = "hashData" } 
        ElseIf ($Line -like "*domainData*") { $DataName = "domainData" } 
        ElseIf ($Line -like "*urlData*") { $DataName = "urlData" } 
        ElseIf ($Line -like "*list__item*") { 
            $DataValue = $Line.Replace('<div class="list__item">', '').Replace('</div>', '').Trim() 
             
            if ($DataValue -notin @("No IP addresses found", "No hashes found", "No Domain found", "No URLs found")) {
                switch ($DataName) { 
                    "ipData" { $currentIpData += $DataValue } 
                    "hashData" { $currentHashData += $DataValue } 
                    "domainData" { $currentDomainData += $DataValue } 
                    "urlData" { $currentUrlData += $DataValue.Replace("http://", "").Replace("https://", "") }
                }
            }
        } 
    } 
     
    # Build structured data for CSV/JSON
    $iocCollections = @{
        "IP"     = $currentIpData
        "HASH"   = $currentHashData
        "DOMAIN" = $currentDomainData
        "URL"    = $currentUrlData
    }

    foreach ($iocType in $iocCollections.Keys) {
        foreach ($iocValue in $iocCollections[$iocType]) {
            $csvData += [PSCustomObject]@{
                'IOC_Typ'      = $iocType
                'IOC_Wert'     = $iocValue
                'Malware_Name' = $malwareName
                'Malware_Typ'  = $malwareType
                'Origin'       = $origin
                'FirstSeen'    = $firstSeen
                'LastSeen'     = $lastSeen
            }
        }
    }
     
    Write-Host "Processed: $url. Total IOCs collected so far: $($csvData.Count)"
}

# ==============================
# Export Logic
# ==============================

if ($exportCsv) {
    $exportCsvPath = Join-Path $exports "anyrun_iocs.csv"
    $csvData | Export-Csv -Path $exportCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "📁 CSV exported to: $exportCsvPath" -ForegroundColor Cyan
}

if ($exportJson) {
    $exportJsonPath = Join-Path $exports "anyrun_iocs.json"
    $csvData | ConvertTo-Json -Depth 5 | Out-File -FilePath $exportJsonPath -Encoding UTF8
    Write-Host "📁 JSON exported to: $exportJsonPath" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Data export completed." -ForegroundColor Green
Write-Host "Total number of exported IOCs: $($csvData.Count)" -ForegroundColor Green
