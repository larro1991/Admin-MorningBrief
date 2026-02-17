function Get-AccountAlerts {
    <#
    .SYNOPSIS
        Checks Active Directory for account-related issues that need attention.

    .DESCRIPTION
        Scans AD for locked-out accounts, passwords expiring soon, accounts that have
        expired, recently disabled accounts, and newly created accounts.  Returns a
        uniform array of alert objects consumed by Invoke-MorningBrief.

    .PARAMETER DaysPasswordExpiry
        Warn when a user's password expires within this many days.  Default 14.

    .PARAMETER SearchBase
        Optional OU distinguished name to limit the search scope.

    .EXAMPLE
        Get-AccountAlerts -DaysPasswordExpiry 7
        Returns alerts for passwords expiring in the next 7 days plus all other account checks.

    .OUTPUTS
        PSCustomObject[] - each with AlertType, Priority, Source, AffectedObject, Detail,
        Timestamp, Category, ColorCode, SortOrder.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysPasswordExpiry = 14,

        [Parameter()]
        [string]$SearchBase
    )

    $alerts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now    = Get-Date

    # ── Common splatting for Search-ADAccount / Get-ADUser ────────────
    $searchParams = @{}
    if ($SearchBase) { $searchParams['SearchBase'] = $SearchBase }

    # ────────────────────────────────────────────────────────────────────
    # 1. Locked-out accounts  (CRITICAL)
    # ────────────────────────────────────────────────────────────────────
    try {
        $lockedOut = Search-ADAccount -LockedOut @searchParams |
            Get-ADUser -Properties LockedOut, lockoutTime, SamAccountName, DisplayName |
            Where-Object { $_.LockedOut -eq $true }

        foreach ($user in $lockedOut) {
            $lockTime = if ($user.lockoutTime) {
                [datetime]::FromFileTime($user.lockoutTime)
            } else { $now }

            $prio = Get-AlertPriority -AlertType 'LockedAccount'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'LockedAccount'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                Detail         = "Account locked out at $($lockTime.ToString('yyyy-MM-dd HH:mm'))"
                Timestamp      = $lockTime
                Category       = 'Account'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "AccountAlerts: Failed to query locked accounts - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 2. Passwords expiring within N days  (HIGH / MEDIUM)
    # ────────────────────────────────────────────────────────────────────
    try {
        # Get domain maximum password age
        $domainPolicy   = Get-ADDefaultDomainPasswordPolicy
        $maxPasswordAge = $domainPolicy.MaxPasswordAge

        if ($maxPasswordAge -and $maxPasswordAge -ne [TimeSpan]::Zero) {
            $users = Get-ADUser -Filter {
                Enabled -eq $true -and PasswordNeverExpires -eq $false
            } -Properties PasswordLastSet, DisplayName, SamAccountName @searchParams

            foreach ($user in $users) {
                if (-not $user.PasswordLastSet) { continue }

                $expiryDate    = $user.PasswordLastSet + $maxPasswordAge
                $daysRemaining = ($expiryDate - $now).Days

                if ($daysRemaining -le $DaysPasswordExpiry -and $daysRemaining -ge 0) {
                    $prio = Get-AlertPriority -AlertType 'PasswordExpiring' -Detail @{ DaysUntilExpiry = $daysRemaining }
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'PasswordExpiring'
                        Priority       = $prio.Priority
                        Source         = 'ActiveDirectory'
                        AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                        Detail         = "Password expires in $daysRemaining day(s) on $($expiryDate.ToString('yyyy-MM-dd'))"
                        Timestamp      = $now
                        Category       = 'Account'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "AccountAlerts: Failed to check password expiry - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 3. Expired accounts (account expiration date has passed)  (HIGH)
    # ────────────────────────────────────────────────────────────────────
    try {
        $expired = Search-ADAccount -AccountExpired @searchParams |
            Get-ADUser -Properties AccountExpirationDate, DisplayName, SamAccountName

        foreach ($user in $expired) {
            $prio = Get-AlertPriority -AlertType 'AccountExpired'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'AccountExpired'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                Detail         = "Account expired on $($user.AccountExpirationDate.ToString('yyyy-MM-dd'))"
                Timestamp      = $user.AccountExpirationDate
                Category       = 'Account'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "AccountAlerts: Failed to check expired accounts - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 4. Recently disabled accounts (last 24h)  (LOW - informational)
    # ────────────────────────────────────────────────────────────────────
    try {
        $yesterday = $now.AddDays(-1)
        $disabled  = Get-ADUser -Filter { Enabled -eq $false } `
            -Properties whenChanged, DisplayName, SamAccountName @searchParams |
            Where-Object { $_.whenChanged -ge $yesterday }

        foreach ($user in $disabled) {
            $prio = Get-AlertPriority -AlertType 'AccountDisabled'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'AccountDisabled'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                Detail         = "Account disabled at $($user.whenChanged.ToString('yyyy-MM-dd HH:mm'))"
                Timestamp      = $user.whenChanged
                Category       = 'Account'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "AccountAlerts: Failed to check disabled accounts - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 5. New accounts created in last 24h  (LOW - informational)
    # ────────────────────────────────────────────────────────────────────
    try {
        $yesterday  = $now.AddDays(-1)
        $newUsers   = Get-ADUser -Filter { whenCreated -ge $yesterday } `
            -Properties whenCreated, DisplayName, SamAccountName @searchParams

        foreach ($user in $newUsers) {
            $prio = Get-AlertPriority -AlertType 'AccountCreated'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'AccountCreated'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                Detail         = "Account created at $($user.whenCreated.ToString('yyyy-MM-dd HH:mm'))"
                Timestamp      = $user.whenCreated
                Category       = 'Account'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "AccountAlerts: Failed to check new accounts - $_"
    }

    return , $alerts.ToArray()
}
