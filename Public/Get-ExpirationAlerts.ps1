function Get-ExpirationAlerts {
    <#
    .SYNOPSIS
        Checks for certificates, accounts, and resources approaching expiration.

    .DESCRIPTION
        Scans local/remote certificate stores, AD service accounts with expiring
        passwords, user accounts with approaching expiration dates, domain functional
        level (informational), and DHCP scope utilization.

    .PARAMETER DaysCertExpiry
        Warn when a certificate expires within this many days.  Default 30.

    .PARAMETER DaysPasswordExpiry
        Warn when a service account password expires within this many days.  Default 14.

    .PARAMETER DaysAccountExpiry
        Warn when a user account expiration date is within this many days.  Default 14.

    .PARAMETER ComputerName
        Servers whose certificate stores should be checked.  If omitted, only the local
        machine is checked.

    .EXAMPLE
        Get-ExpirationAlerts -DaysCertExpiry 14 -ComputerName 'WEB01','WEB02'

    .OUTPUTS
        PSCustomObject[]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysCertExpiry = 30,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysPasswordExpiry = 14,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysAccountExpiry = 14,

        [Parameter()]
        [string[]]$ComputerName
    )

    $alerts = [System.Collections.Generic.List[PSCustomObject]]::new()
    $now    = Get-Date

    # ────────────────────────────────────────────────────────────────────
    # 1. Certificates expiring  (CRITICAL / HIGH / MEDIUM)
    # ────────────────────────────────────────────────────────────────────

    # Build list of machines to check
    $certTargets = @($env:COMPUTERNAME)
    if ($ComputerName) { $certTargets = $ComputerName }

    foreach ($target in $certTargets) {
        try {
            $certs = if ($target -eq $env:COMPUTERNAME) {
                Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
                    Where-Object { $_.NotAfter -and $_.NotAfter -gt $now }
            }
            else {
                Invoke-Command -ComputerName $target -ScriptBlock {
                    Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop |
                        Where-Object { $_.NotAfter -and $_.NotAfter -gt (Get-Date) } |
                        Select-Object Subject, Thumbprint, NotAfter, FriendlyName, DnsNameList
                } -ErrorAction Stop
            }

            foreach ($cert in $certs) {
                $daysLeft = ($cert.NotAfter - $now).Days

                if ($daysLeft -le $DaysCertExpiry) {
                    $certName = if ($cert.FriendlyName) { $cert.FriendlyName }
                                elseif ($cert.Subject)  { $cert.Subject -replace '^CN=', '' }
                                else                    { $cert.Thumbprint.Substring(0, 16) }

                    $prio = Get-AlertPriority -AlertType 'CertificateExpiring' -Detail @{ DaysUntilExpiry = $daysLeft }
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'CertificateExpiring'
                        Priority       = $prio.Priority
                        Source         = 'Certificates'
                        AffectedObject = "$target - $certName"
                        Detail         = "Certificate expires in $daysLeft day(s) on $($cert.NotAfter.ToString('yyyy-MM-dd')) (Thumbprint: $($cert.Thumbprint))"
                        Timestamp      = $now
                        Category       = 'Expiration'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
        catch {
            Write-Warning "ExpirationAlerts: Certificate check failed on $target - $_"
        }
    }

    # ────────────────────────────────────────────────────────────────────
    # 2. Service account passwords expiring  (HIGH)
    # ────────────────────────────────────────────────────────────────────
    try {
        $domainPolicy   = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        $maxPasswordAge = $domainPolicy.MaxPasswordAge

        if ($maxPasswordAge -and $maxPasswordAge -ne [TimeSpan]::Zero) {
            # Service accounts: commonly in specific OUs or with specific naming
            # We look for user accounts marked as service accounts (non-interactive)
            $svcAccounts = Get-ADUser -Filter {
                Enabled -eq $true -and PasswordNeverExpires -eq $false -and ServicePrincipalName -like "*"
            } -Properties PasswordLastSet, DisplayName, SamAccountName, ServicePrincipalName -ErrorAction Stop

            foreach ($svc in $svcAccounts) {
                if (-not $svc.PasswordLastSet) { continue }

                $expiryDate    = $svc.PasswordLastSet + $maxPasswordAge
                $daysRemaining = ($expiryDate - $now).Days

                if ($daysRemaining -le $DaysPasswordExpiry -and $daysRemaining -ge 0) {
                    $prio = Get-AlertPriority -AlertType 'ServiceAccountPasswordExpiring'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'ServiceAccountPasswordExpiring'
                        Priority       = $prio.Priority
                        Source         = 'ActiveDirectory'
                        AffectedObject = "$($svc.DisplayName) ($($svc.SamAccountName))"
                        Detail         = "Service account password expires in $daysRemaining day(s) on $($expiryDate.ToString('yyyy-MM-dd')). SPN: $($svc.ServicePrincipalName -join ', ')"
                        Timestamp      = $now
                        Category       = 'Expiration'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "ExpirationAlerts: Service account password check failed - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 3. User accounts with approaching expiration dates  (MEDIUM)
    # ────────────────────────────────────────────────────────────────────
    try {
        $expirationCutoff = $now.AddDays($DaysAccountExpiry)
        $expiringAccounts = Get-ADUser -Filter {
            Enabled -eq $true -and AccountExpirationDate -le $expirationCutoff -and AccountExpirationDate -ge $now
        } -Properties AccountExpirationDate, DisplayName, SamAccountName -ErrorAction Stop

        foreach ($user in $expiringAccounts) {
            $daysLeft = ($user.AccountExpirationDate - $now).Days

            $prio = Get-AlertPriority -AlertType 'AccountExpirationApproaching'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'AccountExpirationApproaching'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = "$($user.DisplayName) ($($user.SamAccountName))"
                Detail         = "Account expires in $daysLeft day(s) on $($user.AccountExpirationDate.ToString('yyyy-MM-dd'))"
                Timestamp      = $now
                Category       = 'Expiration'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "ExpirationAlerts: Account expiration check failed - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 4. Domain / Forest functional level  (LOW - informational)
    # ────────────────────────────────────────────────────────────────────
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop

        $domainFL = $domain.DomainMode
        $forestFL = $forest.ForestMode

        # Flag if not at the latest common level (Windows Server 2016 = Windows2016Domain)
        $modernLevels = @('Windows2016Domain', 'Windows2016Forest')
        if ($domainFL -notin $modernLevels -or $forestFL -notin $modernLevels) {
            $prio = Get-AlertPriority -AlertType 'DomainFunctionalLevel'
            $alerts.Add([PSCustomObject]@{
                AlertType      = 'DomainFunctionalLevel'
                Priority       = $prio.Priority
                Source         = 'ActiveDirectory'
                AffectedObject = $domain.DNSRoot
                Detail         = "Domain FL: $domainFL, Forest FL: $forestFL. Consider raising to Windows Server 2016 level."
                Timestamp      = $now
                Category       = 'Expiration'
                ColorCode      = $prio.ColorCode
                SortOrder      = $prio.SortOrder
            })
        }
    }
    catch {
        Write-Warning "ExpirationAlerts: Domain functional level check failed - $_"
    }

    # ────────────────────────────────────────────────────────────────────
    # 5. DHCP scope utilization > 90%  (HIGH)
    # ────────────────────────────────────────────────────────────────────
    try {
        # Only runs if DHCP server tools are available
        if (Get-Command Get-DhcpServerv4ScopeStatistics -ErrorAction SilentlyContinue) {
            $dhcpStats = Get-DhcpServerv4ScopeStatistics -ErrorAction Stop

            foreach ($scope in $dhcpStats) {
                if ($scope.PercentageInUse -ge 90) {
                    $prio = Get-AlertPriority -AlertType 'DHCPScopeHighUtilization'
                    $alerts.Add([PSCustomObject]@{
                        AlertType      = 'DHCPScopeHighUtilization'
                        Priority       = $prio.Priority
                        Source         = 'DHCP'
                        AffectedObject = "Scope $($scope.ScopeId)"
                        Detail         = "DHCP scope $($scope.ScopeId) is $([math]::Round($scope.PercentageInUse, 1))% utilized ($($scope.InUse) of $($scope.Free + $scope.InUse) addresses)"
                        Timestamp      = $now
                        Category       = 'Expiration'
                        ColorCode      = $prio.ColorCode
                        SortOrder      = $prio.SortOrder
                    })
                }
            }
        }
    }
    catch {
        Write-Warning "ExpirationAlerts: DHCP scope check failed - $_"
    }

    return , $alerts.ToArray()
}
