function Get-SecurityAlerts {
    <#
    .SYNOPSIS
        Retrieves security-focused alerts from Active Directory and optionally Microsoft 365 / Entra ID.

    .DESCRIPTION
        Scans for excessive failed login attempts, privileged group membership changes,
        unusual admin logon sources, and (with -IncludeM365) risky sign-ins and risky
        users from Microsoft Entra ID.

    .PARAMETER HoursBack
        How far back to look for security events.  Default 24.

    .PARAMETER FailedLoginThreshold
        Number of failed logins per user before raising an alert.  Default 10.

    .PARAMETER IncludeM365
        When set, also queries Microsoft Graph for risky sign-ins and risky users.
        Requires the Microsoft.Graph PowerShell module and an authenticated session
        (Connect-MgGraph).

    .EXAMPLE
        Get-SecurityAlerts -HoursBack 12 -FailedLoginThreshold 5

    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 168)]
        [int]$HoursBack = 24,

        [Parameter()]
        [ValidateRange(1, 1000)]
        [int]$FailedLoginThreshold = 10,

        [Parameter()]
        [switch]$IncludeM365
    )

    $alerts   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now      = Get-Date
    $cutoff   = $now.AddHours(-$HoursBack)

    # ────────────────────────────────────────────────────────────────────
    # 1. Failed login attempts above threshold per user  (HIGH)
    # ────────────────────────────────────────────────────────────────────
    try {
        # Event 4625 = An account failed to log on
        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) &lt;= $($HoursBack * 3600 * 1000)]]]
    </Select>
  </Query>
</QueryList>
"@
        $failedEvents = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

        if ($failedEvents) {
            # Group by target user name (index 5 in event data)
            $grouped = $failedEvents | Group-Object {
                $_.Properties[5].Value   # TargetUserName
            }

            foreach ($group in $grouped) {
                if ($group.Count -ge $FailedLoginThreshold) {
                    $userName  = $group.Name
                    $lastEvent = $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1

                    # Try to extract source IP (index 19)
                    $sourceIP = try { $lastEvent.Properties[19].Value } catch { 'Unknown' }

                    $prio = Get-AlertPriority -AlertType 'FailedLoginsExceeded'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'FailedLoginsExceeded'
                        Priority       = $prio.Priority
                        Source         = 'Security'
                        AffectedObject = $userName
                        Detail         = "$($group.Count) failed login attempt(s) in the last $HoursBack hour(s). Last source IP: $sourceIP"
                        Timestamp      = $lastEvent.TimeCreated
                        Category       = 'Security'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "SecurityAlerts: Failed to query failed logins - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 2. Privileged group membership changes  (CRITICAL)
    # ────────────────────────────────────────────────────────────────────
    try {
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )

        # Event 4728 = member added to security-enabled global group
        # Event 4732 = member added to security-enabled local group
        # Event 4756 = member added to security-enabled universal group
        # Event 4729 = member removed from global group
        # Event 4733 = member removed from local group
        # Event 4757 = member removed from universal group
        $eventIds = @(4728, 4732, 4756, 4729, 4733, 4757)
        $idFilter = ($eventIds | ForEach-Object { "EventID=$_" }) -join ' or '

        $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[($idFilter) and TimeCreated[timediff(@SystemTime) &lt;= $($HoursBack * 3600 * 1000)]]]
    </Select>
  </Query>
</QueryList>
"@
        $groupEvents = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

        if ($groupEvents) {
            foreach ($evt in $groupEvents) {
                # Properties[2] = TargetUserName (group name)
                $groupName = try { $evt.Properties[2].Value } catch { 'Unknown Group' }

                # Check if it is a privileged group
                $isPrivileged = $privilegedGroups | Where-Object {
                    $groupName -like "*$_*"
                }

                if ($isPrivileged) {
                    $memberName = try { $evt.Properties[0].Value } catch { 'Unknown' }
                    $changedBy  = try { $evt.Properties[6].Value } catch { 'Unknown' }
                    $action     = if ($evt.Id -in @(4728, 4732, 4756)) { 'added to' } else { 'removed from' }

                    $prio = Get-AlertPriority -AlertType 'PrivilegedGroupChange'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'PrivilegedGroupChange'
                        Priority       = $prio.Priority
                        Source         = 'Security'
                        AffectedObject = $groupName
                        Detail         = "Member '$memberName' $action '$groupName' by '$changedBy'"
                        Timestamp      = $evt.TimeCreated
                        Category       = 'Security'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "SecurityAlerts: Failed to query privileged group changes - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 3. Admin accounts logged in from unusual sources  (HIGH)
    # ────────────────────────────────────────────────────────────────────
    try {
        # Get members of Domain Admins
        $adminUsers = Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'user' } |
            Select-Object -ExpandProperty SamAccountName

        if ($adminUsers) {
            # Event 4624 = successful logon
            $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= $($HoursBack * 3600 * 1000)]]]
    </Select>
  </Query>
</QueryList>
"@
            $logonEvents = Get-WinEvent -FilterXml $filterXml -MaxEvents 500 -ErrorAction SilentlyContinue

            if ($logonEvents) {
                foreach ($evt in $logonEvents) {
                    $targetUser = try { $evt.Properties[5].Value } catch { continue }
                    $logonType  = try { $evt.Properties[8].Value } catch { 0 }
                    $sourceIP   = try { $evt.Properties[18].Value } catch { '' }

                    # Only flag interactive (2), remote interactive (10), or network (3) with non-local source
                    if ($targetUser -in $adminUsers -and $logonType -in @(2, 3, 10)) {
                        # Flag if source is not a known server / workstation IP
                        # Heuristic: non-empty, non-local, non-loopback
                        if ($sourceIP -and $sourceIP -ne '-' -and $sourceIP -ne '127.0.0.1' -and $sourceIP -ne '::1') {
                            $prio = Get-AlertPriority -AlertType 'AdminUnusualLogon'
                            $alerts.Add([PSCustomObject]@{
                                AlertType      = 'AdminUnusualLogon'
                                Priority       = $prio.Priority
                                Source         = 'Security'
                                AffectedObject = $targetUser
                                Detail         = "Admin logon type $logonType from $sourceIP"
                                Timestamp      = $evt.TimeCreated
                                Category       = 'Security'
                                ColorCode      = $prio.ColorCode
                                SortOrder      = $prio.SortOrder
                            })
                        }
                    }
                }

                # De-duplicate: keep only the most recent per admin+source
                $adminAlerts = @($alerts | Where-Object AlertType -eq 'AdminUnusualLogon')
                if ($adminAlerts.Count -gt 1) {
                    $unique = $adminAlerts |
                        Group-Object { "$($_.AffectedObject)|$($_.Detail -replace '.*from ','')" } |
                        ForEach-Object { $_.Group | Sort-Object Timestamp -Descending | Select-Object -First 1 }

                    # Remove duplicates and re-add unique set
                    $alerts = [System.Collections.Generic.List[PSCustomObject]]@(
                        $alerts | Where-Object AlertType -ne 'AdminUnusualLogon'
                    )
                    foreach ($a in $unique) { $alerts.Add($a) }
                }
            }
        }
    }
    catch {
        Write-Warning "SecurityAlerts: Failed to check admin logon sources - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 4. M365 / Entra risky sign-ins  (CRITICAL / HIGH)
    # ────────────────────────────────────────────────────────────────────
    if ($IncludeM365) {
        try {
            # Requires Microsoft.Graph module and an active session
            if (-not (Get-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue)) {
                Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
            }

            $riskySignIns = Get-MgRiskySignIn -Filter "createdDateTime ge $($cutoff.ToUniversalTime().ToString('o'))" `
                -Top 50 -ErrorAction Stop

            foreach ($si in $riskySignIns) {
                $riskLevel = $si.RiskLevel   # 'low', 'medium', 'high', 'hidden', 'none'
                if ($riskLevel -in @('high', 'medium')) {
                    $prio = Get-AlertPriority -AlertType 'RiskySignIn' -Detail @{ RiskLevel = $riskLevel }
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'RiskySignIn'
                        Priority       = $prio.Priority
                        Source         = 'EntraID'
                        AffectedObject = $si.UserPrincipalName
                        Detail         = "Risky sign-in ($riskLevel risk) from $($si.IpAddress) / $($si.Location.City), $($si.Location.CountryOrRegion)"
                        Timestamp      = $si.CreatedDateTime
                        Category       = 'Security'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
        catch {
            Write-Warning "SecurityAlerts: Failed to query Entra risky sign-ins - $_"
        }

        # ── 5. M365 / Entra risky users  (HIGH) ─────────────────────
        try {
            if (-not (Get-Module Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue)) {
                Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
            }

            $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -Top 50 -ErrorAction Stop

            foreach ($ru in $riskyUsers) {
                $prio = Get-AlertPriority -AlertType 'RiskyUser'
                $alerts.Add([PSCustomObject]@{
                    AlertType      = 'RiskyUser'
                    Priority       = $prio.Priority
                    Source         = 'EntraID'
                    AffectedObject = $ru.UserPrincipalName
                    Detail         = "User flagged at risk (level: $($ru.RiskLevel), last updated: $($ru.RiskLastUpdatedDateTime))"
                    Timestamp      = $ru.RiskLastUpdatedDateTime
                    Category       = 'Security'
                    ColorCode      = $prio.ColorCode
                    SortOrder      = $prio.SortOrder
                })
            }
        }
        catch {
            Write-Warning "SecurityAlerts: Failed to query Entra risky users - $_"
        }
    }

    return , $alerts.ToArray()
}
