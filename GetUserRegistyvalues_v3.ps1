<#Defining Variables for testing.
$env:DesiredScreenSaveTimeOut = "600"
$env:DesiredSCRNSAVEEXE
$env:AEMDevelopment = $true
#>

$DesiredScreenSaveTimeOut = $env:DesiredScreenSaveTimeOut
$DesiredSCRNSAVEEXE = $env:DesiredSCRNSAVEEXE



function Exit-AEM {
        Param(
        [string]$Result,
        $DiagnosticData,
        [int]$ExitCode
        )

    '<-Start Result->'
    "ExitCode=$ExitCode"
    "Mon_Result=$Result"
    '<-End Result->'
    if($DiagnosticData){
        '<-Start Diagnostic->'
        $DiagnosticData
        '<-End Diagnostic->'
        }
    if ($env:AEMDevelopment -eq $true){"Exitcode:$exitcode";continue}
    #return $ExitCode
    }

Function Get-ActiveSessions{
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [string]$Name='localhost'
        ,
        [switch]$Quiet
    )
    Begin{
        $return = @()
    }
    Process{
        If(!(Test-Connection $Name -Quiet -Count 1)){
            Write-Error -Message "Unable to contact $Name. Please verify its network connectivity and try again." -Category ObjectNotFound -TargetObject $Name
            Return
        }
        If([bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")){ #check if user is admin, otherwise no registry work can be done
            #the following registry key is necessary to avoid the error 5 access is denied error
            $LMtype = [Microsoft.Win32.RegistryHive]::LocalMachine
            $LMkey = "SYSTEM\CurrentControlSet\Control\Terminal Server"
            $LMRegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($LMtype,$Name)
            $regKey = $LMRegKey.OpenSubKey($LMkey,$true)
            If($regKey.GetValue("AllowRemoteRPC") -ne 1){
                $regKey.SetValue("AllowRemoteRPC",1)
                Start-Sleep -Seconds 1
            }
            $regKey.Dispose()
            $LMRegKey.Dispose()
        }
        $result = qwinsta /server:$Name
        If($result){
            ForEach($line in $result[1..$result.count]){ #avoiding the line 0, don't want the headers
                $tmp = $line.split(" ") | ?{$_.length -gt 0}
                If(($line[19] -ne " ")){ #username starts at char 19
                    If($line[48] -eq "A"){ #means the session is active ("A" for active)
                        $return += New-Object PSObject -Property @{
                            "ComputerName" = $Name
                            "SessionName" = $tmp[0]
                            "UserName" = $tmp[1]
                            "ID" = $tmp[2]
                            "State" = $tmp[3]
                            "Type" = $tmp[4]
                        }
                    }Else{
                        $return += New-Object PSObject -Property @{
                            "ComputerName" = $Name
                            "SessionName" = $null
                            "UserName" = $tmp[0]
                            "ID" = $tmp[1]
                            "State" = $tmp[2]
                            "Type" = $null
                        }
                    }
                }
            }
        }Else{
            Write-Error "Unknown error, cannot retrieve logged on users"
        }
    }
    End{
        If($return){
            If($Quiet){
                Return $true
            }
            Else{
                Return $return
            }
        }Else{
            If(!($Quiet)){
                Write-Host "No active sessions."
            }
            Return $false
        }
    }
}


function TranslateSID ($user)
{
    $AdObj = New-Object System.Security.Principal.NTAccount($user)
    $strSID=$null
    $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
    
    return $strSID
}

<#This is unnecessary because it is not desired to output to a file. It was only done because we couldn't get around it in previous iterations.
$UserPath = "C:\BLTSUserChecks"
if (!(Test-Path "$UserPath")) {New-Item -Path "C:\BLTSUserChecks" -ItemType Directory}
Set-Location $UserPath
#>

<#$CheckName = [Environment]::GetEnvironmentVariable("CheckName", "Process") #Unique name for the value stored in the UserPath for this check

$HKCUKey = [Environment]::GetEnvironmentVariable("HKCUKey", "Process") #Key in HKCU that contains value of concern
$HKCUValue = [Environment]::GetEnvironmentVariable("HKCUValue", "Process") #Value under the key of concern
#>

#$UserChecksInput = [Environment]::GetEnvironmentVariable("UserChecksInput", "Process")
$UserChecksInput = "ScreenSaveActive,HKCU:\Control Panel\Desktop,ScreenSaveActive;ScreenSaverIsSecure,HKCU:\Control Panel\Desktop,ScreenSaverIsSecure;ScreenSaveTimeOut,HKCU:\Control Panel\Desktop,ScreenSaveTimeOut;SCRNSAVE.EXE,HKCU:\Control Panel\Desktop,SCRNSAVE.EXE"
<#All of the entries to be checked will be populated as one string. Groups, in order, will consist of
the checkname, the HKCUKey, and the HKCUValue, separated by commas. Multiple Groups can be specified by separating them by semicolons.#>

$UserChecksArray = $UserChecksInput -split (';')

#get username that has active session
$users = (Get-ActiveSessions -ErrorAction SilentlyContinue | ? state -eq active).Username
    if (!$users) {Exit-AEM -Result "No Users Logged In" -ExitCode 0}

#Get-WmiObject win32_useraccount # this is old way, use carefully
#get SID of user that has active session
<#
$SIDs = @{}
$users | ForEach-Object {
$AdObj = New-Object System.Security.Principal.NTAccount($_)
$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
$SIDs.Add($_,$strSID.Value)
}
#>

$SIDs = @{}
$users | ForEach-Object {
    $user = $_
    $SID = TranslateSID $user

    if (!($SID))
    {
        Write-output "Getting SID from local or AD user failed, trying Azure AD"
        $user = "AZUREAD\$user@$env:USERDNSDOMAIN"
        $SID = TranslateSID $user
        if ($SID)
        {
            Write-Output "SID found for AZURE AD user: $user, $($SID.Value)"   
        }
        else
        {
            Write-Output "SID found for AZURE AD user $user"   
        }
    }

    $SIDs.Add($_,$SID.Value)
}
#create a new PSDrive to access HCU values
if (!(Test-Path HKU:\))
{
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS| Out-Null
}



#Iterate via each user
$SIDs.Keys | ForEach-Object {
$username=$_
$SID = $SIDs.Item($_)

    foreach ($feinput in $UserChecksArray){
        $checkset = $feinput -split (',')
        $CheckName = $checkset[0]
        $HKCUKey = $checkset[1]
        $HKCUValue = $checkset[2]

        #$CheckFileName=$CheckName+$username
        #Removed appendage since it is unnecessary and disrupts consistency.
        #$CheckName=$CheckName+"-"+$username
    
        <#Remove files that might be present from previous checks
        if (test-path "$CheckName.txt")
        {
            Write-Host "Removing old file $CheckName.txt" -ForegroundColor Cyan
            Remove-Item "$CheckName.txt"
        }#>
    
        #Replace HKCU string with new PSDrive value
        $HKCUKey=$HKCUKey.Replace("HKCU:","HKU:\$SID")
        #$data = Get-ItemProperty $HKCUKey | select -ExpandProperty $HKCUValue

        #Test if value exist

        $TestValue = (Get-ItemProperty $HKCUKey).PSObject.Properties.Name -contains $HKCUValue


    
        if ($TestValue)
        {
            #If value exist fetch data and save it to a file
            $data = Get-ItemProperty $HKCUKey | select -ExpandProperty $HKCUValue
            #Write-Host "Writing data for $checkname and $HKCUKey" -ForegroundColor Cyan
            #$data | Out-File "$CheckName.txt" -Force
            #Set-Content -Path "$CheckName.txt" -Value $data 
            #Prepending "Monitor" prevent interference with an existing variable
            
            if (!(Get-Variable -Name ("Monitor" + $CheckName) -ErrorAction SilentlyContinue | Out-Null))
            {
                New-Variable -Name ("Monitor" + $CheckName) -Value $data
                    
            }
            #$data
        }
        <#
        else
        {
            Write-Host "$($CheckName): No data"
        }
        #>

    }

    #Testing for failure
    if ($MonitorScreenSaveActive -ne 1) {Exit-AEM -Result "Screensaver is not active for user $username" -ExitCode 1}
    if ($MonitorScreenSaverIsSecure -ne 1) {Exit-AEM -Result "Screensaver is not secure for user $username" -ExitCode 2}
    if ($MonitorScreenSaveTimeOut -gt $DesiredScreenSaveTimeOut) {Exit-AEM -Result "Screensaver time out is $MonitorScreenSaveTimeOut for user $username, limit is $DesiredScreenSaveTimeOut" -ExitCode 4}
    if (${MonitorSCRNSAVE.EXE} -ne $DesiredSCRNSAVEEXE) {Exit-AEM -Result "Screensaver path is not $DesiredSCRNSAVEEXE $username" -ExitCode 8}
    
    #Clean up variables for next round
    Get-Variable | ?{$_.name -like "monitor*"} | Remove-Variable

}

#Clean up
Remove-PSDrive -Name HKU

Exit-AEM -Result "Screen Saver set as desired" -ExitCode 0