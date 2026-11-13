# Emits one tab-separated snapshot of processes, sockets, memory and NIC counters per tick.
# $parentPid is prepended by server.py; the loop exits when the server is gone.
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$o = [Console]::Out
$t = "`t"
$i = 0
while ($true) {
    if (-not (Get-Process -Id $parentPid)) { exit }

    if ($i % 15 -eq 0) {
        $svc = @{}
        Get-CimInstance Win32_Service -Filter "ProcessId != 0" -Property Name, ProcessId | ForEach-Object {
            $k = [string]$_.ProcessId
            if ($svc[$k]) { $svc[$k] += ', ' + $_.Name } else { $svc[$k] = $_.Name }
        }
    }
    $i++

    $sb = New-Object Text.StringBuilder
    Get-CimInstance Win32_Process | ForEach-Object {
        $cmd = if ($_.CommandLine) { ($_.CommandLine -replace '[\t\r\n]', ' ') } else { '' }
        if ($cmd.Length -gt 400) { $cmd = $cmd.Substring(0, 400) }
        $ct = if ($_.CreationDate) { $_.CreationDate.Ticks } else { 0 }
        [void]$sb.AppendLine(('P', $_.ProcessId, $_.ParentProcessId, $_.Name, $_.WorkingSetSize, $_.PrivatePageCount,
                $_.ReadTransferCount, $_.WriteTransferCount, $_.ThreadCount, $_.HandleCount,
                ($_.KernelModeTime + $_.UserModeTime), $ct, $cmd) -join $t)
    }
    foreach ($k in $svc.Keys) { [void]$sb.AppendLine(('S', $k, $svc[$k]) -join $t) }
    Get-NetTCPConnection | ForEach-Object {
        [void]$sb.AppendLine(('T', $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, [string]$_.State, $_.OwningProcess) -join $t)
    }
    Get-NetUDPEndpoint | ForEach-Object {
        [void]$sb.AppendLine(('U', $_.LocalAddress, $_.LocalPort, $_.OwningProcess) -join $t)
    }
    $os = Get-CimInstance Win32_OperatingSystem -Property TotalVisibleMemorySize, FreePhysicalMemory
    [void]$sb.AppendLine(('M', $os.TotalVisibleMemorySize, $os.FreePhysicalMemory) -join $t)
    Get-NetAdapterStatistics | ForEach-Object {
        [void]$sb.AppendLine(('N', $_.Name, $_.ReceivedBytes, $_.SentBytes) -join $t)
    }
    [void]$sb.AppendLine('E')
    $o.Write($sb.ToString())
    $o.Flush()
    Start-Sleep -Milliseconds 700
}
