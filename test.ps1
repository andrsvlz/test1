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

$user=Get-LoggedOnUser
$folder="C:\temp"
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($architecture -eq "AMD64") {
$folder=$folder+"\x64\"
} else {
$folder=$folder+"\x86\"
}

if ($(dotnet --list-sdks) -match "5.0.407"){
echo "si"
}else{Run-Process -executable $folder"dotnet.exe" -arguments "/quiet /norestart"}

if ((Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Office\Excel\AddIns\IBPXLClient.Connect).FriendlyName -eq "SAP IBP, add-in for Microsoft Excel"){
echo "si"
}
else
{
$sapmsi="sap.msi"
$sapmst="sap.mst"
Run-Process -executable msiexec.exe -arguments "/i $folder$sapmsi COMPANYNAME='Colombina' USERNAME=$user  TRANSFORMS=$folder$sapmst /qn"

}
