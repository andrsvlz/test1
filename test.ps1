if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
    $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
    "@
        Add-Type $certCallback
     }
    [ServerCertificateValidationCallback]::Ignore()

function Get-LoggedOnUser {
$ExplorerProcess = Get-WmiObject -class win32_process  | where name -Match explorer
if($ExplorerProcess -eq $null) {
    $LoggedOnUser = "No current user"
}else{
    $LoggedOnUser = $ExplorerProcess.getowner().user
}
return $LoggedOnUser[0]
}
Function Write-Log($message, $level="INFO") {
    # Poor man's implementation of Log4Net
    $date_stamp = Get-Date -Format s
    $log_entry = "$date_stamp - $level - $message"
    $log_file = "c:\temp\upgrade_SAPBI.log"
    Write-Verbose -Message $log_entry
    Add-Content -Path $log_file -Value $log_entry
}
Function Run-Process($executable, $arguments) {
    $executable
    $arguments
    $process = New-Object -TypeName System.Diagnostics.Process
    $psi = $process.StartInfo
    $psi.FileName = $executable
    $psi.Arguments = $arguments
    Write-log -message "starting new process '$executable $arguments'"
    $process.Start() | Out-Null
    
    $process.WaitForExit() | Out-Null
    $exit_code = $process.ExitCode
    Write-Log -message "process completed with exit code '$exit_code'"

    return $exit_code
}
Function Download-File($url, $path) {
    Write-Log -message "downloading url '$url' to '$path'"
    Invoke-RestMethod -Uri $url -OutFile $path
    }
function Get-Software{
    <#
        .SYNOPSIS
        Reads installed software from registry

        .PARAMETER DisplayName
        Name or part of name of the software you are looking for

        .EXAMPLE
        Get-Software -DisplayName *Office*
        returns all software with "Office" anywhere in its name
    #>

    param
    (
    # emit only software that matches the value you submit:
    [string]
    $DisplayName = '*'
    )


    #region define friendly texts:
    $Scopes = @{
        HKLM = 'All Users'
        HKCU = 'Current User'
    }

    $Architectures = @{
        $true = '32-Bit'
        $false = '64-Bit'
    }
    #endregion

    #region define calculated custom properties:
        # add the scope of the software based on whether the key is located
        # in HKLM: or HKCU:
        $Scope = @{
            Name = 'Scope'
            Expression = {
            $Scopes[$_.PSDrive.Name]
            }
        }

        # add architecture (32- or 64-bit) based on whether the registry key 
        # contains the parent key WOW6432Node:
        $Architecture = @{
        Name = 'Architecture'
        Expression = {$Architectures[$_.PSParentPath -like '*\WOW6432Node\*']}
        }
    #endregion

    #region define the properties (registry values) we are after
        # define the registry values that you want to include into the result:
        $Values = 'AuthorizedCDFPrefix',
                    'Comments',
                    'Contact',
                    'DisplayName',
                    'DisplayVersion',
                    'EstimatedSize',
                    'HelpLink',
                    'HelpTelephone',
                    'InstallDate',
                    'InstallLocation',
                    'InstallSource',
                    'Language',
                    'ModifyPath',
                    'NoModify',
                    'PSChildName',
                    'PSDrive',
                    'PSParentPath',
                    'PSPath',
                    'PSProvider',
                    'Publisher',
                    'Readme',
                    'Size',
                    'SystemComponent',
                    'UninstallString',
                    'URLInfoAbout',
                    'URLUpdateInfo',
                    'Version',
                    'VersionMajor',
                    'VersionMinor',
                    'WindowsInstaller',
                    'Scope',
                    'Architecture'
    #endregion

    #region Define the VISIBLE properties
        # define the properties that should be visible by default
        # keep this below 5 to produce table output:
        [string[]]$visible = 'DisplayName','DisplayVersion','Scope','Architecture'
        [Management.Automation.PSMemberInfo[]]$visibleProperties = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',$visible)
    #endregion

    #region read software from all four keys in Windows Registry:
        # read all four locations where software can be registered, and ignore non-existing keys:
        Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                            'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Ignore |
        # exclude items with no DisplayName:
        Where-Object DisplayName |
        # include only items that match the user filter:
        Where-Object { $_.DisplayName -like $DisplayName } |
        # add the two calculated properties defined earlier:
        Select-Object -Property *, $Scope, $Architecture |
        # create final objects with all properties we want:
        Select-Object -Property $values |
        # sort by name, then scope, then architecture:
        Sort-Object -Property DisplayName, Scope, Architecture |
        # add the property PSStandardMembers so PowerShell knows which properties to
        # display by default:
        Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $visibleProperties -PassThru
    #endregion 
}


$user=Get-LoggedOnUser
$tmp_dir="C:\temp"
if (-not (Test-Path -Path $tmp_dir)) {
New-Item -Path $tmp_dir -ItemType Directory > $null}
$folder=$tmp_dir
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($architecture -eq "AMD64") {
$folder=$folder+"\x64\"
$arq="\x64\"
$arc="x64"
} else {
$folder=$folder+"\x86\"
$arq="\x86\"
$arc="x86"
}
if ($(dotnet --list-sdks) -match "5.0.407"){
echo "si"
}
else{
$file = $null
$url = $null
$url="https://mosaicoweb.colombina.com/corona_complementos/$arc/dotnet.exe"#poner
if ($file -eq $null) {
$filename = "dotnet.exe"
$file = "$folder\$filename"

if ($url -ne $null) {
Download-File -url $url -path $file
}
$exit_code = Run-Process -executable $folder"dotnet.exe" -arguments "/quiet /norestart"}
 if ($exit_code -ne 0 -and $exit_code -ne 3010) {
        $log_msg = "$($error_msg): exit code $exit_code"
        Write-Log -message $log_msg -level "ERROR"
        throw $log_msg
    }
}



$architecture = $env:PROCESSOR_ARCHITECTURE
if ($architecture -eq "AMD64") {
 if (Get-ItemProperty -Path "HKLM:\SOFTWARE\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}") 
 {
instalado}
else{
$file = $null
$url = $null
$url="https://mosaicoweb.colombina.com/corona_complementos/$arc/webview.exe"#poner
if ($file -eq $null) {
$filename = "webview.exe"
$file = "$folder\$filename"
}
if ($url -ne $null) {
Download-File -url $url -path $file
}
$exit_code = Run-Process -executable $folder"webview.exe" -arguments "/silent /install"
 if ($exit_code -ne 0 -and $exit_code -ne 3010) {
        $log_msg = "$($error_msg): exit code $exit_code"
        Write-Log -message $log_msg -level "ERROR"
        throw $log_msg
    }


}
}else{
if  (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")

{

instalado}else{
$file = $null
$url = $null
$url="https://mosaicoweb.colombina.com/corona_complementos/$arc/webview.exe"#ponerurl
if ($file -eq $null) {
$filename = "webview.exe"
$file = "$folder\$filename"
}
if ($url -ne $null) {
Download-File -url $url -path $file
}
$exit_code = Run-Process -executable $folder"webview.exe" -arguments "/silent /install"
 if ($exit_code -ne 0 -and $exit_code -ne 3010) {
        $log_msg = "$($error_msg): exit code $exit_code"
        Write-Log -message $log_msg -level "ERROR"
        throw $log_msg
    }


}}





if ((Get-Software -DisplayName *Office* | Select Architecture | sort -unique).architecture -eq "64-Bit"){
if ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\Excel\AddIns\IBPXLClient.Connect).FriendlyName -eq "SAP IBP, add-in for Microsoft Excel")
{
$file = $null
$url = $null
$url="https://mosaicoweb.colombina.com/corona_complementos/$arc/sap.msi"#ponerurl
if ($file -eq $null) {
$filename = "sap.msi"
$file = "$folder\$filename"
}
if ($url -ne $null) {
Download-File -url $url -path $file
}




$sapmsi="sap.msi"
$sapmst="sap.mst"
$exit_code=Run-Process -executable msiexec.exe -arguments "/i $folder$sapmsi COMPANYNAME='Colombina' USERNAME=$user  TRANSFORMS=$folder$sapmst /qn"
 if ($exit_code -ne 0 -and $exit_code -ne 3010) {
        $log_msg = "$($error_msg): exit code $exit_code"
        Write-Log -message $log_msg -level "ERROR"
        throw $log_msg
    }

}

}


if ((Get-Software -DisplayName *Office* | Select Architecture | sort -unique).architecture -eq "32-Bit"){

if ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\Excel\AddIns\IBPXLClient.Connect).FriendlyName -eq "SAP IBP, add-in for Microsoft Excel")
{
$file = $null
$url = $null
$url="https://mosaicoweb.colombina.com/corona_complementos/$arc/sap.msi"#ponerurl
if ($file -eq $null) {
$filename = "sap.msi"
$file = "$folder\$arq\$filename"
}
if ($url -ne $null) {
Download-File -url $url -path $file
}

$sapmsi="sap.msi"
$sapmst="sap.mst"
Run-Process -executable msiexec.exe -arguments "/i $folder$sapmsi COMPANYNAME='Colombina' USERNAME=$user  TRANSFORMS=$folder$sapmst /qn"
 if ($exit_code -ne 0 -and $exit_code -ne 3010) {
        $log_msg = "$($error_msg): exit code $exit_code"
        Write-Log -message $log_msg -level "ERROR"
        throw $log_msg
    }

}

}






$user = $env:UserName
$msoExcel = New-Object -ComObject Excel.Application  
$msoExcel | Select-Object -Property OperatingSystem
