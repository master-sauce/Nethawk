Clear-Host
while($true){

$PIDs = (Get-Process -Name "$($args[0])" -ErrorAction SilentlyContinue).Id
if ($PIDs) {
    
    Write-Host
    Write-Host ("-" * 80) -ForegroundColor Gray
    Write-Host
    
    
    $pattern = " ($($PIDs -join '|'))$|^^\s{4,}"
    NETSTAT.EXE -anob | Select-String -Pattern $pattern
    if ($null -eq $args[1]) {
        Start-Sleep 2
    }

    else { 
    Start-Sleep $($args[1])
    }

}


}
