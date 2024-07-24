
#Suspicious keywords to search
$suspiciousKeywords = @("malware", "virus", "trojan", "crypto", "miner")

#function to check for processes using suspicious names
function Check-SuspiciousNames {
 Write-Host "Checking process names..."
    foreach ($keyword in $suspiciousKeywords) {
        Get-Process | Where-Object { $_.Name -like "*$keyword*" } | Format-Table -AutoSize
    }
}

#function to check processes with high CPU usage
function Check-HighCPUUsage {
    Write-Host "Checking for high CPU processes..."
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table -AutoSize
}

#function to check for processes with high memory usage
function Check-HighMemoryUsage {
    Write-Host "Checking for high memory processes..."
    Get-Process | Sort-Object PM -Descending | Select-Object -First 10 | Format-Table -AutoSize
}

#function to check for processes with network connections
function Check-NetworkConnections {
    Write-Host "Checking for processes with network connections..."
    Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object -Property State | Format-Table -AutoSize
}

#run all checks
function Run-Checks {
    Check-SuspiciousNames
    Write-Host ""
    Check-HighCPUUsage
    Write-Host ""
    Check-HighMemoryUsage
    Write-Host ""
    Check-NetworkConnections
}

#run checks 
Run-Checks
