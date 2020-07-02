# Connect to o365
Connect-MsolService

# Gets all domains in o365
$MSOL_Domains = Get-MsolDomain

Function GettingSPFDKIMDMARC_Records {
    
    $SPFResultes = Resolve-DnsName -Type TXT -Name $AbbriviatedName -erroraction 'silentlycontinue'
        If ($SPFResultes -eq $Null){
            Write-Host "No SPF Setting Found"
        } Else {
            $SPFResultes | Select Name, Strings | fl
        }
    $DKIM1Resultes = Resolve-DnsName -Type CNAME -Name selector1._domainkey.$AbbriviatedName -erroraction 'silentlycontinue'
        If ($DKIM1Resultes -eq $Null){
            Write-Host "No DKIM1 Setting Found"
        } Else {
            $DKIM1Resultes | Select Name, NameHost | fl
        }
    $DKIM2Resultes = Resolve-DnsName -Type CNAME -Name selector2._domainkey.$AbbriviatedName -erroraction 'silentlycontinue'
        If ($DKIM2Resultes -eq $Null){
            Write-Host "No DKIM2 Setting Found"
        } Else {
            $DKIM2Resultes | Select Name, NameHost | fl
        }
    $DMARCResultes = Resolve-DnsName -Type Txt -Name _dmarc.$AbbriviatedName -erroraction 'silentlycontinue'
        If ($DMARCResultes -eq $Null){
            Write-Host "No DMARC Setting Found"
        } Else {
            $DMARCResultes | Select Name, Strings | fl
        }
}

Function SPFCheck {

    $CheckResultes = Resolve-DnsName -Type TXT -Name $AbbriviatedName -erroraction 'silentlycontinue' | ? Strings -Match "spf1"
        
    # Checking Hard or Soft Fail
    $SoftFail = $CheckResultes.Strings -Match "~all"
    $HardFail = $CheckResultes.Strings -Match "-all"
        If ($SoftFail -eq $False -and $HardFail -eq $False) {
            Write-Host 'SPF Record Not Detected' -ForegroundColor Red
        } Else {
            If ($SoftFail -ne $Null){
                Write-Host 'SPF Set to Soft Fail' -foregroundColor Yellow
            }
            If ($HardFail -ne $Null){
                Write-Host 'SPF Set to Hard Fail' -ForegroundColor Green
            }
        }

    # Spliting SPF to get Include Count
    $split = $CheckResultes.Strings
    $split = $split -replace '(v=spf1 )'
    $split = $split -replace '( -all)'
    $split = $split -replace '( ~all)'
    $split = $split -split " "

    #put a check here if the SPF is not found then dont do this

    If ($split.count -ge 10) {
        Write-host 'Includes may be to many:' $split.Count -ForegroundColor Yellow
    } 
    If ($split.count -le 0) {
        Write-host 'Includes may be to few:' $split.Count -ForegroundColor Yellow
    } Else { 
        Write-Host 'Includes appear to be ok:' $split.Count -ForegroundColor Green
    }
}


# Runs for each domain in domains. Only returns if one exists
ForEach ($MSOLDomainName in $MSOL_Domains) {
    $AbbriviatedName = $MSOLDomainName.Name
    Write-Host " ------------------------------------------------"
    Write-Host "Domain:"$AbbriviatedName
    GettingSPFDKIMDMARC_Records # Calls Function to get all records
    SPFCheck
}