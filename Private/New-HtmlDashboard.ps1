function New-HtmlDashboard {
    <#
    .SYNOPSIS
        Generates a dark-themed HTML morning-brief dashboard from a collection of alerts.

    .DESCRIPTION
        Accepts the alert objects produced by the public alert functions, groups them by
        priority, and renders a single-file HTML dashboard with inline CSS.
        The dashboard features a top banner, summary cards, and priority-grouped alert
        sections.  It is print-friendly and optionally includes an auto-refresh meta tag
        for wall-display use.

    .PARAMETER Alerts
        Array of alert PSCustomObjects.  Each must have at minimum:
        AlertType, Priority, Source, AffectedObject, Detail, Timestamp, Category,
        ColorCode, SortOrder.

    .PARAMETER OutputPath
        Full path (including filename) for the HTML file.

    .PARAMETER DomainName
        Domain name shown in the banner.  Defaults to $env:USERDNSDOMAIN.

    .PARAMETER AutoRefreshSeconds
        If greater than zero, a <meta http-equiv="refresh"> tag is added so the page
        reloads automatically (useful for NOC wall displays).

    .OUTPUTS
        [string] The full path of the generated HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Alerts,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$DomainName = $(
            if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN }
            else { $env:COMPUTERNAME }
        ),

        [Parameter()]
        [int]$AutoRefreshSeconds = 0
    )

    # ── Counts ────────────────────────────────────────────────────────────
    $criticalCount = @($Alerts | Where-Object Priority -eq 'Critical').Count
    $highCount     = @($Alerts | Where-Object Priority -eq 'High').Count
    $mediumCount   = @($Alerts | Where-Object Priority -eq 'Medium').Count
    $lowCount      = @($Alerts | Where-Object Priority -eq 'Low').Count
    $totalCount    = $Alerts.Count

    $generatedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $dateDisplay = Get-Date -Format 'dddd, MMMM dd yyyy'

    # ── Auto-refresh meta tag ────────────────────────────────────────────
    $refreshMeta = ''
    if ($AutoRefreshSeconds -gt 0) {
        $refreshMeta = "    <meta http-equiv=`"refresh`" content=`"$AutoRefreshSeconds`">"
    }

    # ── Alert row builder ────────────────────────────────────────────────
    function Build-AlertRows {
        param([object[]]$PriorityAlerts, [string]$BorderColor)
        $rows = [System.Text.StringBuilder]::new()
        foreach ($a in $PriorityAlerts) {
            $ts = if ($a.Timestamp) { ([datetime]$a.Timestamp).ToString('HH:mm:ss') } else { '--' }
            $escapedDetail = [System.Net.WebUtility]::HtmlEncode($a.Detail)
            $escapedObject = [System.Net.WebUtility]::HtmlEncode($a.AffectedObject)
            $escapedType   = [System.Net.WebUtility]::HtmlEncode($a.AlertType)
            $escapedSource = [System.Net.WebUtility]::HtmlEncode($a.Source)
            $badge = switch ($a.Priority) {
                'Critical' { '<span class="badge badge-critical">CRITICAL</span>' }
                'High'     { '<span class="badge badge-high">HIGH</span>' }
                'Medium'   { '<span class="badge badge-medium">MEDIUM</span>' }
                'Low'      { '<span class="badge badge-low">LOW</span>' }
            }
            [void]$rows.AppendLine(@"
            <div class="alert-card" style="border-left: 4px solid $BorderColor;">
                <div class="alert-header">
                    $badge
                    <span class="alert-source">$escapedSource</span>
                    <span class="alert-type">$escapedType</span>
                    <span class="alert-time">$ts</span>
                </div>
                <div class="alert-body">
                    <span class="alert-object">$escapedObject</span>
                    <span class="alert-detail">$escapedDetail</span>
                </div>
            </div>
"@)
        }
        return $rows.ToString()
    }

    # ── Build priority sections ──────────────────────────────────────────
    $sections = [System.Text.StringBuilder]::new()

    $priorityGroups = @(
        @{ Name = 'Critical'; Color = '#f85149' },
        @{ Name = 'High';     Color = '#d29922' },
        @{ Name = 'Medium';   Color = '#e3b341' },
        @{ Name = 'Low';      Color = '#8b949e' }
    )

    foreach ($pg in $priorityGroups) {
        $groupAlerts = @($Alerts | Where-Object Priority -eq $pg.Name)
        if ($groupAlerts.Count -eq 0) { continue }
        $groupRows = Build-AlertRows -PriorityAlerts $groupAlerts -BorderColor $pg.Color
        [void]$sections.AppendLine(@"
        <div class="priority-section">
            <h2 style="color: $($pg.Color);">$($pg.Name) ($($groupAlerts.Count))</h2>
            $groupRows
        </div>
"@)
    }

    if ($totalCount -eq 0) {
        [void]$sections.AppendLine('<div class="no-alerts">All clear — no alerts this morning.</div>')
    }

    # ── Full HTML template ───────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
$refreshMeta
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Morning Brief - $dateDisplay</title>
    <style>
        /* ── Reset & base ─────────────────────────────────────── */
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.55;
        }
        a { color: #58a6ff; text-decoration: none; }

        /* ── Banner ───────────────────────────────────────────── */
        .banner {
            background: #161b22;
            border-bottom: 2px solid #58a6ff;
            padding: 24px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }
        .banner h1 {
            font-size: 1.6rem;
            color: #58a6ff;
            font-weight: 600;
        }
        .banner .meta {
            font-size: 0.85rem;
            color: #8b949e;
        }

        /* ── Summary cards ────────────────────────────────────── */
        .summary {
            display: flex;
            gap: 16px;
            padding: 24px 32px;
            flex-wrap: wrap;
        }
        .summary-card {
            flex: 1 1 140px;
            background: #161b22;
            border-radius: 8px;
            padding: 18px 22px;
            text-align: center;
            min-width: 140px;
        }
        .summary-card .count {
            font-size: 2.2rem;
            font-weight: 700;
            line-height: 1.1;
        }
        .summary-card .label {
            font-size: 0.85rem;
            color: #8b949e;
            margin-top: 4px;
        }
        .card-critical .count { color: #f85149; }
        .card-high .count     { color: #d29922; }
        .card-medium .count   { color: #e3b341; }
        .card-low .count      { color: #8b949e; }

        /* ── Priority sections ────────────────────────────────── */
        .content { padding: 0 32px 40px; }
        .priority-section { margin-bottom: 28px; }
        .priority-section h2 {
            font-size: 1.15rem;
            margin-bottom: 12px;
            padding-bottom: 6px;
            border-bottom: 1px solid #21262d;
        }

        /* ── Alert cards ──────────────────────────────────────── */
        .alert-card {
            background: #161b22;
            border-radius: 6px;
            padding: 14px 18px;
            margin-bottom: 10px;
        }
        .alert-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 6px;
            flex-wrap: wrap;
        }
        .alert-source {
            font-size: 0.8rem;
            color: #8b949e;
            background: #21262d;
            padding: 2px 8px;
            border-radius: 4px;
        }
        .alert-type {
            font-weight: 600;
            color: #c9d1d9;
        }
        .alert-time {
            margin-left: auto;
            font-size: 0.8rem;
            color: #8b949e;
        }
        .alert-body {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
        }
        .alert-object {
            color: #58a6ff;
            font-weight: 500;
        }
        .alert-detail {
            color: #8b949e;
        }

        /* ── Badges ───────────────────────────────────────────── */
        .badge {
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-critical { background: #f8514922; color: #f85149; border: 1px solid #f85149; }
        .badge-high     { background: #d2992222; color: #d29922; border: 1px solid #d29922; }
        .badge-medium   { background: #e3b34122; color: #e3b341; border: 1px solid #e3b341; }
        .badge-low      { background: #8b949e22; color: #8b949e; border: 1px solid #8b949e; }

        /* ── No alerts ────────────────────────────────────────── */
        .no-alerts {
            text-align: center;
            padding: 60px 20px;
            font-size: 1.2rem;
            color: #3fb950;
        }

        /* ── Footer ───────────────────────────────────────────── */
        .footer {
            text-align: center;
            padding: 20px;
            color: #484f58;
            font-size: 0.78rem;
            border-top: 1px solid #21262d;
        }

        /* ── Print styles ─────────────────────────────────────── */
        @media print {
            body { background: #fff; color: #1a1a1a; }
            .banner { background: #f6f8fa; border-bottom-color: #0969da; }
            .banner h1 { color: #0969da; }
            .summary-card, .alert-card { background: #f6f8fa; }
            .card-critical .count { color: #cf222e; }
            .card-high .count     { color: #9a6700; }
            .card-medium .count   { color: #7d6a00; }
            .alert-object { color: #0969da; }
            .alert-detail, .alert-source, .alert-time, .banner .meta { color: #57606a; }
            .alert-type { color: #1a1a1a; }
        }
    </style>
</head>
<body>
    <header class="banner">
        <h1>Morning Brief &mdash; $dateDisplay &mdash; $([System.Net.WebUtility]::HtmlEncode($DomainName))</h1>
        <span class="meta">Generated $generatedAt</span>
    </header>

    <section class="summary">
        <div class="summary-card card-critical">
            <div class="count">$criticalCount</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card card-high">
            <div class="count">$highCount</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card card-medium">
            <div class="count">$mediumCount</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card card-low">
            <div class="count">$lowCount</div>
            <div class="label">Low</div>
        </div>
    </section>

    <main class="content">
$($sections.ToString())
    </main>

    <footer class="footer">
        Admin-MorningBrief &bull; $totalCount alerts &bull; $generatedAt
    </footer>
</body>
</html>
"@

    # ── Write file ────────────────────────────────────────────────────────
    $parentDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    # UTF-8 with BOM for PS 5.1 compatibility
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($true))

    Write-Verbose "Dashboard written to $OutputPath"
    return $OutputPath
}
