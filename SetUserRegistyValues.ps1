#Update your default value
param ($timeoutinseconds = 300)

#Add more below keeping the format
$UserChecksInput =   "`
HKCU:\Control Panel\Desktop,SCRNSAVE.EXE,REG_SZ,C:\Windows\system32\scrnsave.scr;`
HKCU:\Control Panel\Desktop,ScreenSaveTimeOut,REG_SZ,$timeoutinseconds;`
HKCU:\Control Panel\Desktop,ScreenSaveActive,REG_SZ,1;`
HKCU:\Control Panel\Desktop,ScreenSaverIsSecure,REG_SZ,1`
"

$UserChecksArray = $UserChecksInput.replace("`n",[System.String]::Empty).replace("`r",[System.String]::Empty) -split (";")

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

function Add-RegistyValues ($path, $val, $type, $f)
{
    If (Get-ItemProperty -Path $path -Name $val -ErrorAction SilentlyContinue) {

        $v = Get-ItemPropertyValue -Path $path -Name $val
        #Write-Verbose "Registry $val exists in $path with value $v" -Verbose
        if ($v -eq $f)
        {
            Write-Output "Required registy ($val) already added in ($path) with value ($f)"
        }
        else
        {
            try
            {
                Write-Output "Updating registry name $val to $path with value $f from $v"
                Set-ItemProperty -Path $path -Name $val -Value $f
            }
            catch 
            {
                Write-Error "Error adding registry." -Verbose
            }
        }
    } 
    Else 
    {
        #Write-Output "Value $val DOES NOT exist in $path"
        try
        {
            Write-Output "Adding registry name $val to $path with value $f"
            Set-ItemProperty -Path $path -Name $val -Value $f
        }
        catch 
        {
            Write-Error "Error adding registry." -Verbose
        }
    }
}

$users = (Get-ActiveSessions -ErrorAction SilentlyContinue | ? state -eq active).Username
if (!$users) {Write-Output "No users logged."}

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
    try
    {
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS| Out-Null
    }
    catch
    {
        Write-Error "Error creating HKU drive." -Verbose
        break
    }
}

$SIDs.Keys | ForEach-Object {
    $username=$_
    $SID = $SIDs.Item($_)
    $UserChecksArray | ForEach-Object {
        $checkset = $_ -split (",")
        $reg_path = $checkset[0].Replace("HKCU:","HKU:\$SID")
        $reg_val = $checkset[1]
        $reg_type = $checkset[2]
        $reg_f = $checkset[3]
        Add-RegistyValues $reg_path $reg_val $reg_type $reg_f
    }
}

if (Test-Path HKU:\)
{
    Remove-PSDrive -Name HKU
}