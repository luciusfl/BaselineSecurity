#requires -Version 5.1
<#
.SYNOPSIS
    Copies the CIS description and rationale of every recommendation that
    Audit.ps1 checks into AuditCheckDetails.json.
.DESCRIPTION
    AuditCheckDetails.json is the only details file that is deployed: Audit.ps1
    reads the details of its failed checks from it and from nothing else. Its "checks" part is written
    by hand. Its "cisBenchmark" and "cisRecommendations" parts are a copy of the
    id, title, page, description and rationale from the CIS benchmark JSON
    (CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0.json, which is not
    changed), and this script writes them.

    The recommendations copied are the ones Audit.ps1 checks: the CIS numbers in
    its code (check names "CIS <id> ..." and the Recommendation, Id, SizeId and
    RetentionId values of its tables; comments are ignored) plus every cisIds
    entry in AuditCheckDetails.json. The script stops without writing if one of
    them is not in the benchmark JSON.

    Run it again after adding or removing a CIS check in Audit.ps1, after
    changing cisIds, and after regenerating the benchmark JSON with
    Export-CisBenchmarkJson.ps1. The output depends only on its inputs, so a
    second run leaves the file unchanged.

    The script replaces everything from the "cisBenchmark" property to the end
    of the file, so those two properties must stay last; everything before them
    is kept exactly as it is.
.EXAMPLE
    .\Update-AuditCheckDetails.ps1
#>
[CmdletBinding()]
param(
    [string]$CisJsonPath,
    [string]$DetailsPath,
    [string]$AuditScript
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $CisJsonPath) { $CisJsonPath = Join-Path $scriptDirectory 'CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0.json' }
if (-not $DetailsPath) { $DetailsPath = Join-Path $scriptDirectory 'AuditCheckDetails.json' }
if (-not $AuditScript) { $AuditScript = Join-Path $scriptDirectory 'Audit.ps1' }

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$cis = [System.IO.File]::ReadAllText($CisJsonPath, $utf8NoBom) | ConvertFrom-Json
$detailsText = [System.IO.File]::ReadAllText($DetailsPath, $utf8NoBom)
$details = $detailsText | ConvertFrom-Json

# Audit.ps1 without its comments, so a CIS number that is only mentioned in a comment
# (for example a section heading or an omitted recommendation) is not copied.
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($AuditScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw "Audit.ps1 has parse errors: $($parseErrors[0].Message)" }
$auditText = [System.IO.File]::ReadAllText($AuditScript)
$code = New-Object System.Text.StringBuilder
$position = 0
foreach ($token in $tokens) {
    if ($token.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment) { continue }
    [void]$code.Append($auditText.Substring($position, $token.Extent.StartOffset - $position))
    $position = $token.Extent.EndOffset
}
[void]$code.Append($auditText.Substring($position))
$code = $code.ToString()

$wanted = @{}
foreach ($match in [regex]::Matches($code, 'CIS (\d+(?:\.\d+)+) ')) { $wanted[$match.Groups[1].Value] = $true }
foreach ($match in [regex]::Matches($code, "\b(?:Recommendation|Id|SizeId|RetentionId)\s*=\s*'(\d+(?:\.\d+)+)'")) { $wanted[$match.Groups[1].Value] = $true }
foreach ($check in $details.checks) {
    foreach ($id in @($check.cisIds | Where-Object { $_ })) { $wanted[$id] = $true }
}

$known = @{}
foreach ($control in $cis.controls) { $known[$control.id] = $true }
$unknown = @($wanted.Keys | Where-Object { -not $known[$_] } | Sort-Object)
if ($unknown.Count -gt 0) {
    throw "These CIS numbers are used by Audit.ps1 or AuditCheckDetails.json but are not in '$CisJsonPath': $($unknown -join ', '). Nothing was written."
}

function ConvertTo-JsonString {
    param([string]$Value)
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    foreach ($character in $Value.ToCharArray()) {
        switch ($character) {
            '"' { [void]$builder.Append('\"') }
            '\' { [void]$builder.Append('\\') }
            "`n" { [void]$builder.Append('\n') }
            default {
                if ([int]$character -lt 0x20) { [void]$builder.Append(('\u{0:x4}' -f [int]$character)) }
                else { [void]$builder.Append($character) }
            }
        }
    }
    [void]$builder.Append('"')
    $builder.ToString()
}

# Keep the line endings the file already uses.
$newLine = if ($detailsText.Contains("`r`n")) { "`r`n" } else { "`n" }

# Everything before "cisBenchmark" (or, on the first run, before the closing brace) is kept.
$marker = [regex]::Match($detailsText, '(?m),\s*^\s*"cisBenchmark"\s*:')
if ($marker.Success) { $head = $detailsText.Substring(0, $marker.Index) }
else { $head = $detailsText.TrimEnd() -replace '\}$', '' }
$head = $head.TrimEnd()

$entries = foreach ($control in $cis.controls) {
    if (-not $wanted[$control.id]) { continue }
    $page = [int]$control.page
    @(
        '    {'
        "      `"id`": $(ConvertTo-JsonString $control.id),"
        "      `"title`": $(ConvertTo-JsonString $control.title),"
        "      `"page`": $page,"
        "      `"description`": $(ConvertTo-JsonString $control.description),"
        "      `"rationale`": $(ConvertTo-JsonString $control.rationale)"
        '    }'
    ) -join $newLine
}

$lines = @(
    $head + ','
    "  `"cisBenchmark`": $(ConvertTo-JsonString "$($cis.benchmark) $($cis.version)"),"
    '  "cisRecommendations": ['
    ($entries -join ",$newLine")
    '  ]'
    '}'
    ''
)
$output = $lines -join $newLine

# The result must parse, and every cisIds entry must resolve inside the file itself.
$parsed = $output | ConvertFrom-Json
$copied = @{}
foreach ($recommendation in $parsed.cisRecommendations) { $copied[$recommendation.id] = $true }
foreach ($check in $parsed.checks) {
    foreach ($id in @($check.cisIds | Where-Object { $_ })) {
        if (-not $copied[$id]) { throw "Internal error: cisIds $id of '$($check.name)' has no entry in cisRecommendations. Nothing was written." }
    }
}

if ($output -ceq $detailsText) {
    Write-Host "AuditCheckDetails.json is already up to date ($($copied.Count) CIS recommendations)."
} else {
    [System.IO.File]::WriteAllText($DetailsPath, $output, $utf8NoBom)
    Write-Host "Wrote $($copied.Count) CIS recommendations to '$DetailsPath'."
}
