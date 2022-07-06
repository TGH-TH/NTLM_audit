#### NTLM auditing script
#### Read Only - will make no changes just gather info
#### v0.1 TGH
#### Tier0 workstream


$results=@() # create empty array for the results to go in
$onlineDCs=@() # create empty array for the online Domain Controllers to go in
$now=Get-Date # set todays date as a varible - will be used to create the timespan for the 'days ago' attribute
$DomainControllers=Get-ADDomainController -filter * # get all domain controllers in the local AD domain
$ADdomain=Get-ADDomain # get local AD domain details
$TimeinPasttoGetLogs=new-timespan -Minutes 20 # How far back in time to get logs - large figures here may slow the script down too much

# Regexs to parse the message field of the event logs for various data

$regex='[\n\r][ \t].*Logon Process:[ \t]*([^\n\r]*)'
$regexAccount='[\n\r][ \t].*Security ID:[ \t]*([^\n\r]*)'
$regexPackageName='[\n\r][ \t].*Package Name \(NTLM only\):[ \t]*([^\n\r]*)'
$regexKeyLength='[\n\r][ \t].*Key Length:[ \t]*([^\n\r]*)'
$regexWorkStationName='[\n\r][ \t].*Workstation Name:[ \t]*([^\n\r]*)'
$regexWorkStationIP='[\n\r][ \t].*Source Network Address:[ \t]*([^\n\r]*)'

# event log data in filterXML format

$filterXML=@"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= $($TimeinPasttoGetLogs.TotalMilliseconds)]]]</Select>
  </Query>
</QueryList>
"@


Clear-Host
# writing script information to the screen
write-host -ForegroundColor Gray "Analysing Domain controllers in the " -NoNewline; write-host -ForegroundColor Yellow $ADdomain.dnsroot -NoNewline; Write-Host -ForegroundColor Gray " Active Directory domain"
Write-Host -ForegroundColor Yellow $DomainControllers.count -NoNewline; write-host -ForegroundColor Gray " Domain Controllers discovered"
Write-Host -ForegroundColor Gray "Checking for online domain controllers analyse for NTLM authentications"


foreach($DomainController in $DomainControllers)
{
write-host -ForegroundColor Gray "Checking if " -NoNewline; Write-Host -ForegroundColor Yellow $DomainController.HostName -NoNewline; Write-Host -ForegroundColor Gray " is online - " -NoNewline
if(Test-Connection -ComputerName $DomainController.hostname -Quiet)
{
$onlineDCs += $DomainController
Write-Host -ForegroundColor Green "Success"
}else
{
Write-Host -ForegroundColor Red "Failure - this DC will not be included in this audit"
}
}

write-host ""


foreach($onlineDC in $onlineDCs)
{
$NTLMevents=0
write-host ""
Write-Host -ForegroundColor Gray "Getting events on Domain Controller " -NoNewline; Write-Host -ForegroundColor Yellow "$($onlineDC.Hostname)"
$events=get-winevent -ComputerName $onlineDC.Hostname -FilterXml $filterXML
$count=$events.count
Write-Host -ForegroundColor Gray "Parsing " -NoNewline;Write-Host -ForegroundColor Yellow $count -NoNewline;Write-Host -ForegroundColor Gray " filtered events" -NoNewline
foreach($event in $events)
{
if($event.message -match $regex)
{
if($Matches[1] -eq "NtLmSsp ")
{
$NTLMevents++
$protocol=$Matches[1]
$account=(get-aduser ($event.Message | Select-String $regexAccount -AllMatches | %{$_.matches} | %{$_.groups[1].value} | Select-Object -Last 1)).SamAccountName
$PackageName=$event.Message | Select-String $regexPackageName -AllMatches | %{$_.matches} | %{$_.groups[1].value}
$KeyLength=$event.Message | Select-String $regexKeyLength -AllMatches | %{$_.matches} | %{$_.groups[1].value}
$WorkstationName=$event.Message | Select-String $regexWorkStationName -AllMatches | %{$_.matches} | %{$_.groups[1].value}
$WorkStationIP=$event.Message | Select-String $regexWorkStationIP -AllMatches | %{$_.matches} | %{$_.groups[1].value}

$result=New-Object PSobject
$result | Add-Member -MemberType NoteProperty -Name "Time" -value $event.TimeCreated
$result | Add-Member -MemberType NoteProperty -Name "Protocol" -value $protocol
$result | Add-Member -MemberType NoteProperty -Name "Originating_DC" -value $onlineDC.HostName
$result | Add-Member -MemberType NoteProperty -Name "User_Account" -value $account
$result | Add-Member -MemberType NoteProperty -Name "NTLM_Package" -value $PackageName
$result | Add-Member -MemberType NoteProperty -Name "NTLM_Key_Length" -value $KeyLength
$result | Add-Member -MemberType NoteProperty -Name "Workstation_name" -value $WorkstationName
$result | Add-Member -MemberType NoteProperty -Name "Workstation_IP" -value $WorkStationIP

$results=$results+$result
}
}

}
write-host -ForegroundColor Gray " - NTLM event log entires on $onlineDC - " -NoNewline; Write-Host -ForegroundColor Green $NTLMevents
}


$results | Out-GridView -Title "NTLM usage in the $($ADdomain.dnsroot) domain" # visually output data
if(!(test-path -Path $env:TEMP\TIER0)){New-Item -Path $env:TEMP\TIER0 -ItemType Directory}  # create a tmp folder for the csv export
$results | Export-Csv -Path $env:TEMP\TIER0\$($ADdomain.DNSRoot)_NTLM_usage_report.csv -NoTypeInformation # create the csv export
ii $env:TEMP\TIER0 # open the folder containing the CSV export for convenience