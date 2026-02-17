function Get-AlertPriority {
    <#
    .SYNOPSIS
        Assigns or validates a priority level for an alert based on type and contextual detail.

    .DESCRIPTION
        Ensures consistent priority assignment across all alert types produced by the
        Admin-MorningBrief module.  Returns a PSCustomObject with Priority, ColorCode,
        and SortOrder so callers can sort and render alerts uniformly.

    .PARAMETER AlertType
        The canonical alert type string (e.g. 'LockedAccount', 'DiskSpaceCritical').

    .PARAMETER Detail
        A hashtable carrying context-specific values that influence severity.
        Examples:
            @{ DaysUntilExpiry = 5 }
            @{ PercentUsed = 97 }
            @{ RiskLevel = 'high' }

    .OUTPUTS
        PSCustomObject with Priority, ColorCode, SortOrder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AlertType,

        [Parameter()]
        [hashtable]$Detail = @{}
    )

    # ── Priority rule table ──────────────────────────────────────────────
    # Each entry maps AlertType (with optional detail refinements) to a
    # priority level.  Evaluated top-down; first match wins.

    $priority  = 'Low'
    $colorCode = '#8b949e'   # gray
    $sortOrder = 4

    switch -Wildcard ($AlertType) {

        # ── Account alerts ───────────────────────────────────────────
        'LockedAccount' {
            $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
        }
        'PasswordExpiring' {
            if ($Detail.DaysUntilExpiry -and [int]$Detail.DaysUntilExpiry -le 3) {
                $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
            }
            else {
                $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
            }
        }
        'AccountExpired' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'AccountDisabled' {
            $priority = 'Low'; $colorCode = '#8b949e'; $sortOrder = 4
        }
        'AccountCreated' {
            $priority = 'Low'; $colorCode = '#8b949e'; $sortOrder = 4
        }

        # ── Infrastructure alerts ────────────────────────────────────
        'DiskSpaceCritical' {
            $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
        }
        'DiskSpaceWarning' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'ServiceStopped' {
            $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
        }
        'UptimeExceeded' {
            $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
        }
        'PendingReboot' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'CriticalEventLog' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'ErrorEventLog' {
            $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
        }
        'ServerUnreachable' {
            $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
        }

        # ── Security alerts ──────────────────────────────────────────
        'FailedLoginsExceeded' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'PrivilegedGroupChange' {
            $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
        }
        'AdminUnusualLogon' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'RiskySignIn' {
            if ($Detail.RiskLevel -eq 'high') {
                $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
            }
            else {
                $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
            }
        }
        'RiskyUser' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }

        # ── Expiration alerts ────────────────────────────────────────
        'CertificateExpiring' {
            if ($Detail.DaysUntilExpiry -and [int]$Detail.DaysUntilExpiry -le 7) {
                $priority = 'Critical'; $colorCode = '#f85149'; $sortOrder = 1
            }
            elseif ($Detail.DaysUntilExpiry -and [int]$Detail.DaysUntilExpiry -le 14) {
                $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
            }
            else {
                $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
            }
        }
        'ServiceAccountPasswordExpiring' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }
        'AccountExpirationApproaching' {
            $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
        }
        'DomainFunctionalLevel' {
            $priority = 'Low'; $colorCode = '#8b949e'; $sortOrder = 4
        }
        'DHCPScopeHighUtilization' {
            $priority = 'High'; $colorCode = '#d29922'; $sortOrder = 2
        }

        default {
            $priority = 'Medium'; $colorCode = '#e3b341'; $sortOrder = 3
        }
    }

    [PSCustomObject]@{
        Priority  = $priority
        ColorCode = $colorCode
        SortOrder = $sortOrder
    }
}
