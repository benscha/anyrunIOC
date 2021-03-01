#Get Top Malware Links

Clear-Variable -Name ips, malfilehash, urls

$anyrunURLs = ((Invoke-WebRequest –Uri ‘https://any.run/malware-trends/’).Links | Where-Object {$_.href -like “/malware-trends/*”})
$staticURLPart = "https://any.run"

ForEach ($url in $anyrunURLs.href ) 
    {

    $MalwareInfo = (Invoke-WebRequest –Uri $staticURLPart$url)

    #IPData
    $ContentIP = ($MalwareInfo.ParsedHTML.getElementById('ipData')).OuterText
    #MalwareFileHash
    $ContentHash = ($MalwareInfo.ParsedHTML.getElementById('hashData')).OuterText
    #DomainData
    $ContentDomain = ($MalwareInfo.ParsedHTML.getElementById('domainData')).OuterText

    $urlTxt = $url.Replace("/malware-trends/","`n#") 
    $urlTxt += "`n"

    $ips += $urlTxt
    $ips += $ContentIP
    $malfilehash += $urlTxt
    $malfilehash += $ContentHash
    $urls += $urlTxt
    $urls += $ContentDomain

    }


    #Output all ips
    $ips = $ips.Replace("No IP adresses found","").Replace("`n`n","")

    #Output all urls
    $urls = $urls.Replace("No hashes found","").Replace("`n`n","")

    #Output all malware file hashes
    $malfilehash = $malfilehash.Replace("No hashes found","").Replace("`n`n","")
