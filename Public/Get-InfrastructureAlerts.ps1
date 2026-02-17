function Get-InfrastructureAlerts {
    <#
    .SYNOPSIS
        Checks server infrastructure health across one or more remote machines.

    .DESCRIPTION
        Uses CIM sessions to query disk space, critical service status, uptime, pending
        reboots, and recent critical/error event log entries.  If a server is unreachable
        the function logs a warning and continues with the remaining servers.

    .PARAMETER ComputerName
        One or more server names or IP addresses to check.

    .PARAMETER DiskThresholdPercent
        Disk usage percentage at which to warn.  Default 90.  Usage above 95% is flagged
        as Critical; above 90% as High.

    .PARAMETER UptimeThresholdDays
        Flag servers that have been running longer than this without a reboot.  Default 90.

    .EXAMPLE
        Get-InfrastructureAlerts -ComputerName 'DC01', 'SQL02' -DiskThresholdPercent 85

    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [Parameter()]
        [ValidateRange(50, 100)]
        [int]$DiskThresholdPercent = 90,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$UptimeThresholdDays = 90
    )

    $alerts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now    = Get-Date

    # Critical Windows services to monitor
    $criticalServices = @(
        'DNS', 'DHCPServer', 'W32Time', 'NTDS', 'Netlogon',
        'DFSR', 'IsmServ', 'Kdc', 'LanmanServer', 'LanmanWorkstation'
    )

    foreach ($server in $ComputerName) {
        Write-Verbose "InfrastructureAlerts: Checking $server ..."

        # ── Establish CIM session ────────────────────────────────────
        $cimSession = $null
        try {
            $cimSession = New-CimSession -ComputerName $server -ErrorAction Stop
        }
        catch {
            Write-Warning "InfrastructureAlerts: Cannot connect to $server - $_"
            $prio = Get-AlertPriority -AlertType 'ServerUnreachable'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'ServerUnreachable'
                Priority       = $prio.Priority
                Source         = 'Infrastructure'
                AffectedObject = $server
                Detail         = "Server unreachable: $($_.Exception.Message)"
                Timestamp      = $now
                Category       = 'Infrastructure'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
            continue
        }

        try {
            # ── 1. Disk space ────────────────────────────────────────
            try {
                $disks = Get-CimInstance -CimSession $cimSession -ClassName Win32_LogicalDisk `
                    -Filter "DriveType = 3" -ErrorAction Stop

                foreach ($disk in $disks) {
                    if ($disk.Size -eq 0) { continue }
                    $usedPercent = [math]::Round(($disk.Size - $disk.FreeSpace) / $disk.Size * 100, 1)
                    $freeGB      = [math]::Round($disk.FreeSpace / 1GB, 2)

                    if ($usedPercent -ge 95) {
                        $prio = Get-AlertPriority -AlertType 'DiskSpaceCritical'
                        $alerts.Add([PSCustomObject]@{
                            AlertType      = 'DiskSpaceCritical'
                            Priority       = $prio.Priority
                            Source         = 'Infrastructure'
                            AffectedObject = "$server ($($disk.DeviceID))"
                            Detail         = "Disk $($disk.DeviceID) is $usedPercent% full ($freeGB GB free)"
                            Timestamp      = $now
                            Category       = 'Infrastructure'
                            ColorCode      = $prio.ColorCode
                            SortOrder      = $prio.SortOrder
                        })
                    }
                    elseif ($usedPercent -ge $DiskThresholdPercent) {
                        $prio = Get-AlertPriority -AlertType 'DiskSpaceWarning'
                        $alerts.Add([PSCustomObject]@{
                            AlertType      = 'DiskSpaceWarning'
                            Priority       = $prio.Priority
                            Source         = 'Infrastructure'
                            AffectedObject = "$server ($($disk.DeviceID))"
                            Detail         = "Disk $($disk.DeviceID) is $usedPercent% full ($freeGB GB free)"
                            Timestamp      = $now
                            Category       = 'Infrastructure'
                            ColorCode      = $prio.ColorCode
                            SortOrder      = $prio.SortOrder
                        })
                    }
                }
            }
            catch {
                Write-Warning "InfrastructureAlerts: Disk check failed on $server - $_"
            }

            # ── 2. Critical services stopped ─────────────────────────
            try {
                $services = Get-CimInstance -CimSession $cimSession -ClassName Win32_Service `
                    -Filter "StartMode = 'Auto'" -ErrorAction Stop

                foreach ($svc in $services) {
                    if ($svc.Name -in $criticalServices -and $svc.State -ne 'Running') {
                        $prio = Get-AlertPriority -AlertType 'ServiceStopped'
                        $alerts.Add([PSCustomObject]@{
                            AlertType      = 'ServiceStopped'
                            Priority       = $prio.Priority
                            Source         = 'Infrastructure'
                            AffectedObject = "$server ($($svc.Name))"
                            Detail         = "Service '$($svc.DisplayName)' is $($svc.State) (StartMode: $($svc.StartMode))"
                            Timestamp      = $now
                            Category       = 'Infrastructure'
                            ColorCode      = $prio.ColorCode
                            SortOrder      = $prio.SortOrder
                        })
                    }
                }
            }
            catch {
                Write-Warning "InfrastructureAlerts: Service check failed on $server - $_"
            }

            # ── 3. Uptime (server running too long) ──────────────────
            try {
                $os = Get-CimInstance -CimSession $cimSession -ClassName Win32_OperatingSystem -ErrorAction Stop
                $lastBoot   = $os.LastBootUpTime
                $uptimeDays = ($now - $lastBoot).Days

                if ($uptimeDays -ge $UptimeThresholdDays) {
                    $prio = Get-AlertPriority -AlertType 'UptimeExceeded'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'UptimeExceeded'
                        Priority       = $prio.Priority
                        Source         = 'Infrastructure'
                        AffectedObject = $server
                        Detail         = "Server has been up for $uptimeDays days (last reboot: $($lastBoot.ToString('yyyy-MM-dd')))"
                        Timestamp      = $now
                        Category       = 'Infrastructure'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
            catch {
                Write-Warning "InfrastructureAlerts: Uptime check failed on $server - $_"
            }

            # ── 4. Pending reboot ────────────────────────────────────
            try {
                $pendingReboot = $false

                # Component-Based Servicing
                $cbs = Invoke-Command -ComputerName $server -ScriptBlock {
                    Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                } -ErrorAction SilentlyContinue
                if ($cbs) { $pendingReboot = $true }

                # Windows Update
                $wu = Invoke-Command -ComputerName $server -ScriptBlock {
                    Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                } -ErrorAction SilentlyContinue
                if ($wu) { $pendingReboot = $true }

                # Pending file rename operations
                $pfr = Invoke-Command -ComputerName $server -ScriptBlock {
                    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                } -ErrorAction SilentlyContinue
                if ($pfr) { $pendingReboot = $true }

                if ($pendingReboot) {
                    $prio = Get-AlertPriority -AlertType 'PendingReboot'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'PendingReboot'
                        Priority       = $prio.Priority
                        Source         = 'Infrastructure'
                        AffectedObject = $server
                        Detail         = 'Server has a pending reboot (Windows Update or component servicing)'
                        Timestamp      = $now
                        Category       = 'Infrastructure'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
            catch {
                Write-Warning "InfrastructureAlerts: Pending reboot check failed on $server - $_"
            }

            # ── 5. Event log critical/error in last 24h ──────────────
            try {
                $yesterday   = $now.AddDays(-1)
                $filterXml   = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]</Select>
  </Query>
</QueryList>
"@
                $events = Invoke-Command -ComputerName $server -ScriptBlock {
                    param($xml)
                    Get-WinEvent -FilterXml $xml -MaxEvents 50 -ErrorAction SilentlyContinue
                } -ArgumentList $filterXml -ErrorAction SilentlyContinue

                if ($events) {
                    # Group by level: 1 = Critical, 2 = Error
                    $criticalEvents = @($events | Where-Object { $_.Level -eq 1 })
                    $errorEvents    = @($events | Where-Object { $_.Level -eq 2 })

                    if ($criticalEvents.Count -gt 0) {
                        $topCrit = $criticalEvents[0]
                        $prio = Get-AlertPriority -AlertType 'CriticalEventLog'
                        $alerts.Add([PSCustomObject]@{
                            AlertType      = 'CriticalEventLog'
                            Priority       = $prio.Priority
                            Source         = 'Infrastructure'
                            AffectedObject = $server
                            Detail         = "$($criticalEvents.Count) critical event(s). Latest: [$($topCrit.ProviderName)] $($topCrit.Message -replace '\r?\n',' ' | Select-Object -First 1)"
                            Timestamp      = $topCrit.TimeCreated
                            Category       = 'Infrastructure'
                            ColorCode      = $prio.ColorCode
                            SortOrder      = $prio.SortOrder
                        })
                    }

                    if ($errorEvents.Count -gt 0) {
                        $topErr = $errorEvents[0]
                        $prio = Get-AlertPriority -AlertType 'ErrorEventLog'
                        $alerts.Add([PSCustomObject]@{
                            AlertType      = 'ErrorEventLog'
                            Priority       = $prio.Priority
                            Source         = 'Infrastructure'
                            AffectedObject = $server
                            Detail         = "$($errorEvents.Count) error event(s). Latest: [$($topErr.ProviderName)] $($topErr.Message -replace '\r?\n',' ' | Select-Object -First 1)"
                            Timestamp      = $topErr.TimeCreated
                            Category       = 'Infrastructure'
                            ColorCode      = $prio.ColorCode
                            SortOrder      = $prio.SortOrder
                        })
                    }
                }
            }
            catch {
                Write-Warning "InfrastructureAlerts: Event log check failed on $server - $_"
            }
        }
        finally {
            if ($cimSession) {
                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
            }
        }
    }

    return , $alerts.ToArray()
}
