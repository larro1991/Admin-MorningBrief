function Invoke-MorningBrief {
    <#
    .SYNOPSIS
        Morning Command Center - one command to see everything that needs attention today.

    .DESCRIPTION
        Orchestrates all alert checks (accounts, infrastructure, security, expirations),
        prioritises findings, generates an HTML dashboard, and optionally e-mails it.

        Run this when you sit down in the morning and get a single prioritised view of
        locked accounts, failing disks, expiring certificates, and security events.

    .PARAMETER OutputPath
        Directory where the HTML report is saved.  Defaults to .\Reports.

    .PARAMETER ComputerName
        Servers to include in infrastructure and certificate checks.  If omitted,
        infrastructure checks are skipped and only the local machine is checked for
        certificates.

    .PARAMETER DaysPasswordExpiry
        Warn when passwords expire within this many days.  Default 14.

    .PARAMETER DaysCertExpiry
        Warn when certificates expire within this many days.  Default 30.

    .PARAMETER IncludeM365
        Also check Microsoft 365 / Entra ID for risky sign-ins and risky users.

    .PARAMETER AutoRefreshSeconds
        If set, the HTML report includes a meta-refresh tag so it reloads automatically.
        Useful when the report is displayed on a wall monitor.

    .PARAMETER SendEmail
        Send the HTML report by e-mail after generation.

    .PARAMETER SmtpServer
        SMTP relay server (required when -SendEmail is used).

    .PARAMETER EmailTo
        Recipient address(es) (required when -SendEmail is used).

    .PARAMETER EmailFrom
        Sender address (required when -SendEmail is used).

    .EXAMPLE
        Invoke-MorningBrief -ComputerName DC01, SQL02, WEB01

    .EXAMPLE
        Invoke-MorningBrief -ComputerName (Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=corp,DC=com").Name -IncludeM365 -SendEmail -SmtpServer mail.corp.com -EmailTo admin@corp.com -EmailFrom brief@corp.com

    .OUTPUTS
        PSCustomObject with CriticalCount, HighCount, MediumCount, LowCount, TotalCount,
        ReportPath, and Alerts.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path -Path $PWD -ChildPath 'Reports'),

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysPasswordExpiry = 14,

        [Parameter()]
        [ValidateRange(1, 365)]
        [int]$DaysCertExpiry = 30,

        [Parameter()]
        [switch]$IncludeM365,

        [Parameter()]
        [int]$AutoRefreshSeconds = 0,

        [Parameter()]
        [switch]$SendEmail,

        [Parameter()]
        [string]$SmtpServer,

        [Parameter()]
        [string[]]$EmailTo,

        [Parameter()]
        [string]$EmailFrom
    )

    # ── Validate e-mail parameters ───────────────────────────────────
    if ($SendEmail) {
        if (-not $SmtpServer) { throw 'Invoke-MorningBrief: -SmtpServer is required when -SendEmail is specified.' }
        if (-not $EmailTo)    { throw 'Invoke-MorningBrief: -EmailTo is required when -SendEmail is specified.' }
        if (-not $EmailFrom)  { throw 'Invoke-MorningBrief: -EmailFrom is required when -SendEmail is specified.' }
    }

    $allAlerts = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Host ''
    Write-Host '  ========================================' -ForegroundColor Cyan
    Write-Host '   Morning Brief - Gathering alerts ...'   -ForegroundColor Cyan
    Write-Host '  ========================================' -ForegroundColor Cyan
    Write-Host ''

    # ── 1. Account Alerts ────────────────────────────────────────────
    Write-Host '  [1/4] Account alerts ...' -ForegroundColor DarkCyan
    try {
        $accountAlerts = Get-AccountAlerts -DaysPasswordExpiry $DaysPasswordExpiry
        if ($accountAlerts) { $allAlerts.AddRange($accountAlerts) }
        Write-Host "        Found $(@($accountAlerts).Count) account alert(s)" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Account alerts failed: $_"
    }

    # ── 2. Infrastructure Alerts ─────────────────────────────────────
    if ($ComputerName) {
        Write-Host '  [2/4] Infrastructure alerts ...' -ForegroundColor DarkCyan
        try {
            $infraAlerts = Get-InfrastructureAlerts -ComputerName $ComputerName
            if ($infraAlerts) { $allAlerts.AddRange($infraAlerts) }
            Write-Host "        Found $(@($infraAlerts).Count) infrastructure alert(s)" -ForegroundColor Gray
        }
        catch {
            Write-Warning "Infrastructure alerts failed: $_"
        }
    }
    else {
        Write-Host '  [2/4] Infrastructure alerts ... SKIPPED (no -ComputerName specified)' -ForegroundColor DarkGray
    }

    # ── 3. Security Alerts ───────────────────────────────────────────
    Write-Host '  [3/4] Security alerts ...' -ForegroundColor DarkCyan
    try {
        $securityParams = @{}
        if ($IncludeM365) { $securityParams['IncludeM365'] = $true }
        $secAlerts = Get-SecurityAlerts @securityParams
        if ($secAlerts) { $allAlerts.AddRange($secAlerts) }
        Write-Host "        Found $(@($secAlerts).Count) security alert(s)" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Security alerts failed: $_"
    }

    # ── 4. Expiration Alerts ─────────────────────────────────────────
    Write-Host '  [4/4] Expiration alerts ...' -ForegroundColor DarkCyan
    try {
        $expirationParams = @{ DaysCertExpiry = $DaysCertExpiry; DaysPasswordExpiry = $DaysPasswordExpiry }
        if ($ComputerName) { $expirationParams['ComputerName'] = $ComputerName }
        $expAlerts = Get-ExpirationAlerts @expirationParams
        if ($expAlerts) { $allAlerts.AddRange($expAlerts) }
        Write-Host "        Found $(@($expAlerts).Count) expiration alert(s)" -ForegroundColor Gray
    }
    catch {
        Write-Warning "Expiration alerts failed: $_"
    }

    # ── Sort by priority ─────────────────────────────────────────────
    $sortedAlerts = $allAlerts | Sort-Object SortOrder, Timestamp

    # ── Counts ───────────────────────────────────────────────────────
    $criticalCount = @($sortedAlerts | Where-Object Priority -eq 'Critical').Count
    $highCount     = @($sortedAlerts | Where-Object Priority -eq 'High').Count
    $mediumCount   = @($sortedAlerts | Where-Object Priority -eq 'Medium').Count
    $lowCount      = @($sortedAlerts | Where-Object Priority -eq 'Low').Count
    $totalCount    = $sortedAlerts.Count

    # ── Generate HTML dashboard ──────────────────────────────────────
    $reportFileName = "MorningBrief_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $reportFullPath = Join-Path -Path $OutputPath -ChildPath $reportFileName

    $dashboardPath = New-HtmlDashboard -Alerts $sortedAlerts `
        -OutputPath $reportFullPath `
        -AutoRefreshSeconds $AutoRefreshSeconds

    # ── Console summary ──────────────────────────────────────────────
    Write-Host ''
    Write-Host '  ── Morning Brief Summary ──' -ForegroundColor Cyan
    $summaryLine = "  Morning Brief: $criticalCount Critical, $highCount High, $mediumCount Medium, $lowCount Low"
    if ($criticalCount -gt 0) {
        Write-Host $summaryLine -ForegroundColor Red
    }
    elseif ($highCount -gt 0) {
        Write-Host $summaryLine -ForegroundColor Yellow
    }
    else {
        Write-Host $summaryLine -ForegroundColor Green
    }
    Write-Host "  Report saved: $dashboardPath" -ForegroundColor Gray
    Write-Host ''

    # ── Send e-mail ──────────────────────────────────────────────────
    if ($SendEmail) {
        Write-Host '  Sending e-mail ...' -ForegroundColor DarkCyan
        try {
            $htmlBody = [System.IO.File]::ReadAllText($dashboardPath, [System.Text.UTF8Encoding]::new($true))
            $subject  = "Morning Brief $(Get-Date -Format 'yyyy-MM-dd') - $criticalCount Critical, $highCount High"

            $mailParams = @{
                From       = $EmailFrom
                To         = $EmailTo
                Subject    = $subject
                Body       = $htmlBody
                BodyAsHtml = $true
                SmtpServer = $SmtpServer
            }
            Send-MailMessage @mailParams -ErrorAction Stop
            Write-Host '  E-mail sent successfully.' -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to send e-mail: $_"
        }
    }

    # ── Return summary object ────────────────────────────────────────
    [PSCustomObject]@{
        CriticalCount = $criticalCount
        HighCount     = $highCount
        MediumCount   = $mediumCount
        LowCount      = $lowCount
        TotalCount    = $totalCount
        ReportPath    = $dashboardPath
        Alerts        = $sortedAlerts
    }
}
