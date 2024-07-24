# Suspicious keywords to search
$suspiciousKeywords = @("malware", "virus", "trojan", "crypto", "miner")

# Define output file
$outputFile = "ProcessesReport.txt"

# Clear the output file if it already exists
if (Test-Path $outputFile) {
    Remove-Item $outputFile
}

# Function to check for processes using suspicious names
function Check-SuspiciousNames {
    Write-Host "Checking process names..."
    Add-Content -Path $outputFile -Value "Checking process names..."
    foreach ($keyword in $suspiciousKeywords) {
        $results = Get-Process | Where-Object { $_.Name -like "*$keyword*" }
        if ($results) {
            $results | Format-Table -AutoSize | Out-String | Add-Content -Path $outputFile
        } else {
            Add-Content -Path $outputFile -Value "No suspicious processes found for keyword: $keyword"
        }
    }
}

# Function to check processes with high CPU usage
function Check-HighCPUUsage {
    Write-Host "Checking for high CPU processes..."
    Add-Content -Path $outputFile -Value "`nChecking for high CPU processes..."
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String | Add-Content -Path $outputFile
}

# Function to check for processes with high memory usage
function Check-HighMemoryUsage {
    Write-Host "Checking for high memory processes..."
    Add-Content -Path $outputFile -Value "`nChecking for high memory processes..."
    Get-Process | Sort-Object PM -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String | Add-Content -Path $outputFile
}

# Function to check for processes with network connections
function Check-NetworkConnections {
    Write-Host "Checking for processes with network connections..."
    Add-Content -Path $outputFile -Value "`nChecking for processes with network connections..."
    Get-NetTCPConnection | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Sort-Object -Property State | Format-Table -AutoSize | Out-String | Add-Content -Path $outputFile
}

# Run all checks
function Run-Checks {
    Check-SuspiciousNames
    Write-Host ""
    Check-HighCPUUsage
    Write-Host ""
    Check-HighMemoryUsage
    Write-Host ""
    Check-NetworkConnections
}

# Run checks
Run-Checks

Write-Host "Saved to $outputFile"
