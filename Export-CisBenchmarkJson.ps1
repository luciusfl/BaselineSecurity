#requires -Version 5.1
<#
.SYNOPSIS
    Extracts every recommendation of a CIS benchmark PDF into a JSON file. Supported:
    the CIS Microsoft Windows 11 Stand-alone Benchmark, the CIS Microsoft Edge
    Benchmark and the CIS Google Chrome Group Policy Benchmark (see
    $script:BenchmarkProfiles for what differs between them).
.DESCRIPTION
    Reads the text of the benchmark PDF (extracted with pdftotext -layout) and
    writes one JSON object per recommendation: ID, title, profile level,
    assessment (Automated or Manual), page, section path, the expected state from
    the title, the registry locations and expected values from the Audit section,
    the Group Policy path or command from the Remediation section, the
    description, the rationale (why the setting matters for security), the
    default value, the impact statement, the full Audit and Remediation text,
    the additional information, the references and the CIS Controls mapping
    (with implementation groups).

    Text sections keep the paragraphs and list items of the PDF, one per line
    (separated by a line feed). Line breaks inside a paragraph are joined: a
    line that ends with a letter or digit followed by "-" continues without a
    space (the hyphen is real; the benchmark never splits a word across lines),
    any other line break becomes a space. A built-in check fails when a joined
    hyphen looks like a split word.

    The parser is strict about what it cannot read. Every recommendation carries
    a parserWarnings list, and the file header counts them, so a gap in the data
    is visible in the data itself instead of being silently wrong. The script
    also stops with an error if the number of recommendations found in the body
    does not match the table of contents.

    Registry paths in the PDF are wrapped at a fixed width (77 characters in the
    Windows benchmark, 83 in the Edge benchmark, 82 in the Chrome benchmark; set per benchmark in
    $script:BenchmarkProfiles). A wrapped line is joined to the next line without
    a space when it has that length
    characters long (a hard break inside a word) and with a space otherwise
    (a break at a word boundary). Every joined path segment is checked against
    the segments of unwrapped paths; a segment that cannot be confirmed that way
    is reported in parserWarnings.

    For the Windows benchmark only, with -AuditScript and -RemediationScript (default: Audit.ps1 and
    Remediations.ps1 next to this script), the registry locations of the
    recommendations that those scripts reference by CIS number are compared
    with the scripts, and differences are printed. This is an independent check
    of the extraction. Its result is only printed, not written to the JSON, so
    the JSON depends on the PDF alone and does not change when the scripts do.
.PARAMETER PdfPath
    The benchmark PDF. Default: the CIS Windows 11 benchmark next to this script.
.PARAMETER TextPath
    Text already extracted from the PDF with "pdftotext -layout -enc UTF-8".
    When omitted, pdftotext.exe is run. Git for Windows ships the Xpdf version
    (ucrt64\bin or mingw64\bin); the Poppler utilities have their own. The
    version used is recorded in the JSON (textExtractor), because the two can
    lay out text differently. The file was verified with Xpdf pdftotext 4.06.
.PARAMETER TableTextPath
    Text already extracted from the PDF with "pdftotext -table -enc UTF-8", used for the
    CIS Controls tables. When omitted, pdftotext.exe is run.
.PARAMETER OutputPath
    The JSON file to write. Default: the PDF name with a .json extension.
.EXAMPLE
    .\Export-CisBenchmarkJson.ps1
    Rebuilds CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0.json.
.EXAMPLE
    .\Export-CisBenchmarkJson.ps1 -PdfPath .\CIS_Microsoft_Edge_Benchmark_v5.0.1.pdf
    Writes CIS_Microsoft_Edge_Benchmark_v5.0.1.json next to the PDF.
.EXAMPLE
    .\Export-CisBenchmarkJson.ps1 -PdfPath .\CIS_Google_Chrome_Group_Policy_Benchmark_v1.1.1.pdf
    Writes CIS_Google_Chrome_Group_Policy_Benchmark_v1.1.1.json next to the PDF.
#>
[CmdletBinding()]
param(
    [string]$PdfPath,
    [string]$TextPath,
    [string]$TableTextPath,
    [string]$OutputPath,
    [string]$AuditScript,
    [string]$RemediationScript
)

$ErrorActionPreference = 'Stop'
# Defaults are resolved here, because $PSScriptRoot is not reliable inside param() defaults.
$scriptDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
if (-not $PdfPath) { $PdfPath = Join-Path $scriptDirectory 'CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v5.0.0.pdf' }
if (-not $AuditScript) { $AuditScript = Join-Path $scriptDirectory 'Audit.ps1' }
if (-not $RemediationScript) { $RemediationScript = Join-Path $scriptDirectory 'Remediations.ps1' }
# What differs between the supported benchmarks, chosen by the PDF file name. A PDF that
# matches no profile is refused, because its layout has not been checked.
# - RegistryWrapWidth: registry lines in the PDF are wrapped at this width. A line of this
#   length continues in the middle of a word on the next line.
# - WindowsBaseline: the Windows benchmark is the one Audit.ps1 and Remediations.ps1 follow.
#   Only for it are the reviewed space joins and the Microsoft documentation confirmations
#   below used, and the registry locations cross-checked against the scripts (the scripts
#   reference recommendations by CIS number, and the numbers of other benchmarks overlap).
# - TocFromRawText: the -layout text breaks the page numbers of the table of contents apart
#   ("1.8.") or loses them, so the table of contents is read from "pdftotext -raw" instead,
#   which prints each page number on its own line after the entry (Chrome PDF).
# - LevelInTitle: the heading starts with the profile level ("2.1.1 (L2) Ensure ..."); it is
#   removed from the title, because the level is taken from Profile Applicability (Chrome PDF).
# The Chrome PDF also states the expected value without a data type ("registry location which
# should be set to 0"); such entries get valueType null, and the round-trip check compares them
# with that wording. All profiles accept that wording and the HKEY_LOCAL_MACHINE prefix.
$script:BenchmarkProfiles = @(
    @{ FilePattern = '^CIS_Microsoft_Windows_11_Stand-alone_Benchmark_v'; Name = 'CIS Microsoft Windows 11 Stand-alone Benchmark'; RegistryWrapWidth = 77; WindowsBaseline = $true; TocFromRawText = $false; LevelInTitle = $false }
    @{ FilePattern = '^CIS_Microsoft_Edge_Benchmark_v'; Name = 'CIS Microsoft Edge Benchmark'; RegistryWrapWidth = 83; WindowsBaseline = $false; TocFromRawText = $false; LevelInTitle = $false }
    @{ FilePattern = '^CIS_Google_Chrome_Group_Policy_Benchmark_v'; Name = 'CIS Google Chrome Group Policy Benchmark'; RegistryWrapWidth = 82; WindowsBaseline = $false; TocFromRawText = $true; LevelInTitle = $true }
)
$script:Benchmark = $script:BenchmarkProfiles | Where-Object { (Split-Path -Leaf $PdfPath) -match $_.FilePattern } | Select-Object -First 1
if (-not $script:Benchmark) {
    throw "'$(Split-Path -Leaf $PdfPath)' is not a supported benchmark. Supported: $(@($script:BenchmarkProfiles | ForEach-Object { $_.Name }) -join ', '). Check the layout of a new benchmark and add a profile to `$script:BenchmarkProfiles first."
}
$script:RegistryWrapWidth = $script:Benchmark.RegistryWrapWidth
$script:SpaceJoins = [System.Collections.Generic.List[string]]::new()
$script:RegistryLayoutErrors = [System.Collections.Generic.List[string]]::new()
# Per recommendation: the PDF text of each exported section without whitespace, for the
# completeness check in section 7 (an exported field must be the whole section).
$script:SectionCompact = @{}
$script:AuditCompact = @{}
$script:BlockCompact = @{}
# Joins with a space that were checked against the PDF page and are correct
# (key = previous line | next line). A join with a space just under the wrap width
# that is not listed here is reported as a parser warning.
$script:ReviewedSpaceJoins = [System.Collections.Generic.HashSet[string]]::new()
if ($script:Benchmark.WindowsBaseline) {
    [void]$script:ReviewedSpaceJoins.Add('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and|Browser protection:DisallowExploitProtectionOverride')
}

# Data types that the PDF states ambiguously or wrongly, checked against Microsoft's
# own documentation (key = recommendation ID | value name). Each one is copied into
# the matching registry entry as microsoftDocumentation. The script stops if an entry
# no longer exists, so a new benchmark version forces these to be reviewed again.
$script:MicrosoftConfirmations = [ordered]@{
    '18.4.3|EnableCertPaddingCheck' = [ordered]@{
        valueType = 'REG_DWORD'
        summary = 'Microsoft recommends REG_DWORD 1 ("EnableCertPaddingCheck"=dword:1) under HKLM\Software\Microsoft\Cryptography\Wintrust\Config and, on 64-bit Windows, under HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config. Windows reads the value as a DWORD, but its registry type does not matter: a REG_SZ "1" from earlier guidance also passes, as long as the value is 1 to 4 bytes long and non-zero. To revert, delete the value or set it to DWORD 0.'
        source = 'Microsoft Security Response Center, CVE-2013-3900 WinVerifyTrust Signature Validation Vulnerability (revisions 2.2 to 2.4)'
        url = 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900'
        verifiedOn = '2026-11-10'
    }
    '2.3.10.8|Machine' = [ordered]@{
        valueType = 'REG_MULTI_SZ'
        summary = 'Microsoft documents HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths, value Machine, as a REG_MULTI_SZ ("the REG_Multi_SZ ''Machine'' registry value"). The PDF''s REG_DWORD is an error in the benchmark.'
        source = 'Microsoft Learn, Upgrade on-premises infrastructure - Configuration Manager (Known issue for remote site systems)'
        url = 'https://learn.microsoft.com/en-us/intune/configmgr/core/servers/manage/upgrade-on-premises-infrastructure'
        verifiedOn = '2026-11-10'
    }
}
# The confirmations above are for the Windows benchmark.
if (-not $script:Benchmark.WindowsBaseline) { $script:MicrosoftConfirmations = [ordered]@{} }

# ---------------------------------------------------------------------------
# 1. PDF text
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $PdfPath -PathType Leaf)) { throw "PDF not found: $PdfPath" }
if (-not $OutputPath) { $OutputPath = [System.IO.Path]::ChangeExtension($PdfPath, '.json') }
$pdfHash = (Get-FileHash -LiteralPath $PdfPath -Algorithm SHA256).Hash.ToLowerInvariant()

# Two extractions of the same PDF: -layout for everything, and -table for the CIS Controls
# tables, because only -table prints each implementation group circle on its row and in its
# column. Both are taken from the same pdftotext.
$textExtractor = 'not recorded: the text was supplied with -TextPath'
$temporaryFiles = [System.Collections.Generic.List[string]]::new()
$pdftotext = $null
if (-not $TextPath -or -not $TableTextPath -or $script:Benchmark.TocFromRawText) {
    $pdftotext = Get-Command pdftotext.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source
    if (-not $pdftotext) {
        foreach ($candidate in @("$env:ProgramFiles\Git\ucrt64\bin\pdftotext.exe", "$env:ProgramFiles\Git\mingw64\bin\pdftotext.exe", "$env:ProgramFiles\poppler\bin\pdftotext.exe")) {
            if (Test-Path -LiteralPath $candidate) { $pdftotext = $candidate; break }
        }
    }
    if (-not $pdftotext) { throw 'pdftotext.exe was not found. Install Git for Windows or the Poppler utilities, or pass -TextPath and -TableTextPath with text extracted by "pdftotext -layout -enc UTF-8" and "pdftotext -table -enc UTF-8".' }
}
# Starts one pdftotext extraction and returns the process and its output file. The
# extractions are independent of each other, so they run at the same time (each takes a
# few seconds for the Windows benchmark).
$pdfFullPath = (Resolve-Path -LiteralPath $PdfPath).ProviderPath
function Start-PdfToText([string]$Mode) {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("cis-benchmark-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    $temporaryFiles.Add($path)
    # -enc UTF-8 is required: the default output encoding can be Latin-1, which turns
    # curly apostrophes and bullets into replacement characters.
    $process = Start-Process -FilePath $pdftotext -ArgumentList @($Mode, '-enc', 'UTF-8', "`"$pdfFullPath`"", "`"$path`"") -NoNewWindow -PassThru
    # Reading the handle now keeps the exit code available after the process has ended
    # (Windows PowerShell 5.1 loses it otherwise).
    $null = $process.Handle
    [pscustomobject]@{ Mode = $Mode; Process = $process; Path = $path }
}
function Wait-PdfToText($Extraction) {
    $Extraction.Process.WaitForExit()
    if ($Extraction.Process.ExitCode -ne 0) { throw "pdftotext $($Extraction.Mode) exited with code $($Extraction.Process.ExitCode)." }
    $Extraction.Path
}
try {
    $layoutExtraction = $null; $tableExtraction = $null; $rawExtraction = $null
    if (-not $TextPath) {
        # The first line of "pdftotext -v" names the tool and version, for example
        # "pdftotext version 4.06 [www.xpdfreader.com]" (Xpdf) or "pdftotext version 24.02.0" (Poppler).
        $versionOutput = @(& $pdftotext -v 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_ -match 'version' })
        $textExtractor = if ($versionOutput.Count) { "$($versionOutput[0].Trim()) -layout and -table, -enc UTF-8" } else { 'pdftotext (version unknown) -layout and -table, -enc UTF-8' }
        $layoutExtraction = Start-PdfToText '-layout'
    }
    if (-not $TableTextPath) { $tableExtraction = Start-PdfToText '-table' }
    if ($script:Benchmark.TocFromRawText) {
        $rawExtraction = Start-PdfToText '-raw'
        $textExtractor = $textExtractor -replace ' -layout and -table,', ' -layout, -table and -raw (table of contents),'
    }
    if ($layoutExtraction) { $TextPath = Wait-PdfToText $layoutExtraction }
    if ($tableExtraction) { $TableTextPath = Wait-PdfToText $tableExtraction }
    $all = [System.IO.File]::ReadAllLines($TextPath)
    $tableText = [System.IO.File]::ReadAllLines($TableTextPath)
    $rawText = if ($rawExtraction) { [System.IO.File]::ReadAllLines((Wait-PdfToText $rawExtraction)) } else { $null }
}
finally {
    foreach ($path in $temporaryFiles) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }
}

# ---------------------------------------------------------------------------
# 2. Layout: table of contents, body, appendix
# ---------------------------------------------------------------------------
$tocStart = -1; $bodyStart = -1; $bodyEnd = -1
for ($i = 0; $i -lt $all.Count; $i++) {
    $line = $all[$i].TrimStart([char]12)
    # The Windows PDF lists the table of contents in itself ("Table of Contents .... 2"); the Edge PDF has only the heading.
    if ($tocStart -lt 0 -and $line -match '^\s*Table of Contents(\s*\.{3,}|\s*$)') { $tocStart = $i; continue }
    if ($bodyStart -lt 0 -and $tocStart -ge 0 -and $line -match '^Recommendations\s*$') { $bodyStart = $i; continue }
    if ($bodyStart -ge 0 -and $line -match '^Appendix: Summary Table\s*$') { $bodyEnd = $i - 1; break }
}
if ($tocStart -lt 0 -or $bodyStart -lt 0 -or $bodyEnd -lt 0) { throw "Could not find the table of contents, the Recommendations section and the summary table (toc=$tocStart body=$bodyStart end=$bodyEnd)." }

# Table of contents: section headings and recommendations with their printed page.
$tocEntries = [System.Collections.Generic.List[object]]::new()
$current = $null
# The -layout table of contents, unless the profile reads it from the -raw text (below).
$layoutTocEnd = if ($script:Benchmark.TocFromRawText) { $tocStart + 1 } else { $bodyStart }
for ($i = $tocStart + 1; $i -lt $layoutTocEnd; $i++) {
    $line = $all[$i].TrimStart([char]12)
    if ([string]::IsNullOrWhiteSpace($line) -or $line -match '^\s*Page \d+\s*$') { continue }
    # An entry is complete when it ends with its page number: after "(Automated)" or
    # "(Manual)" (sometimes without dots), or after a run of dots for sections.
    $currentIsComplete = $null -ne $current -and $current.Text -match '(\((Automated|Manual)\)[\s.]*\d+|\.{2,}\s*\d+)\s*$'
    if (($null -eq $current -or $currentIsComplete) -and $line -match '^\s*(\d+(?:\.\d+)*)\s+(\S.*)$') {
        if ($current) { $tocEntries.Add($current) }
        $current = [pscustomobject]@{ Id = $Matches[1]; Text = $Matches[2] }
    } elseif ($current -and -not $currentIsComplete) {
        $current.Text += ' ' + $line.Trim()
    }
}
if ($current) { $tocEntries.Add($current) }
if ($script:Benchmark.TocFromRawText) {
    # Each entry is followed by a line with only its page number. The entries are rebuilt in the
    # form the -layout entries have, so the code below reads both the same way.
    $rawStart = -1
    for ($i = 0; $i -lt $rawText.Count; $i++) { if ($rawText[$i].TrimStart([char]12) -match '^\s*Table of Contents\s*$') { $rawStart = $i; break } }
    if ($rawStart -lt 0) { throw 'The -raw text has no "Table of Contents".' }
    $current = $null
    for ($i = $rawStart + 1; $i -lt $rawText.Count; $i++) {
        $line = $rawText[$i].TrimStart([char]12).Trim()
        if (-not $line) { continue }
        if ($line -match '^Appendix: Summary Table') { break }
        if ($line -match '^\d+$') {
            if ($current) {
                $entryText = $current.Text -replace '[\s.]+$', ''
                $current.Text = if ($entryText -match '\((?:Automated|Manual)\)$') { "$entryText $line" } else { "$entryText .. $line" }
                $tocEntries.Add($current)
                $current = $null
            }
            continue
        }
        if ($null -eq $current) {
            if ($line -match '^(\d+(?:\.\d+)*)\s+(\S.*)$') { $current = [pscustomobject]@{ Id = $Matches[1]; Text = $Matches[2] } }
        } else {
            $current.Text += ' ' + $line
        }
    }
}
$tocSections = [ordered]@{}
$tocControls = [ordered]@{}
foreach ($entry in $tocEntries) {
    $text = ($entry.Text -replace '\s+', ' ').Trim()
    if ($text -match '^(.*?\((?:Automated|Manual)\))[\s.]*(\d+)$') {
        $tocTitle = $Matches[1]; $tocPage = [int]$Matches[2]
        if ($script:Benchmark.LevelInTitle) { $tocTitle = $tocTitle -replace '^\((?:L1|L2)\)\s+', '' }
        $tocControls[$entry.Id] = [pscustomobject]@{ Title = $tocTitle; Page = $tocPage }
    }
    elseif ($text -match '^(.*?)\s*\.{2,}\s*(\d+)$') { $tocSections[$entry.Id] = $Matches[1].Trim() }
}
if ($tocControls.Count -eq 0) { throw 'No recommendations found in the table of contents.' }

# Body: one block per recommendation, found by its "Profile Applicability:" heading.
$printedPage = 0
$pageAtLine = New-Object int[] $all.Count
for ($i = 0; $i -lt $all.Count; $i++) {
    $pageAtLine[$i] = $printedPage + 1
    if ($all[$i] -match '^\s*Page (\d+)\s*$') { $printedPage = [int]$Matches[1] }
}
$blocks = [System.Collections.Generic.List[object]]::new()
for ($p = $bodyStart; $p -le $bodyEnd; $p++) {
    if ($all[$p] -notmatch '^\f?Profile Applicability:\s*$') { continue }
    $j = $p - 1
    while ($j -gt $p - 12 -and $all[$j] -notmatch '^\f?(\d+(?:\.\d+)+) \S') { $j-- }
    if ($all[$j] -notmatch '^\f?(\d+(?:\.\d+)+) (\S.*)$') { throw "No recommendation heading found above line $($p + 1)." }
    $headingLines = @($Matches[2]) + @($all[($j + 1)..($p - 1)] | ForEach-Object { $_.TrimStart([char]12).Trim() } | Where-Object { $_ -and $_ -notmatch '^Page \d+$' })
    $blocks.Add([pscustomobject]@{ Id = $Matches[1]; Line = $j; HeadingLines = $headingLines; Page = $pageAtLine[$j] })
}
$bodyIds = @($blocks | ForEach-Object Id)
$missingInBody = @($tocControls.Keys | Where-Object { $_ -notin $bodyIds })
$missingInToc = @($bodyIds | Where-Object { -not $tocControls.Contains($_) })
if ($missingInBody.Count -or $missingInToc.Count -or $bodyIds.Count -ne @($bodyIds | Sort-Object -Unique).Count) {
    throw "Table of contents and body do not agree. Only in TOC: [$($missingInBody -join ', ')]. Only in body: [$($missingInToc -join ', ')]. Body count: $($bodyIds.Count)."
}

# The CIS Controls table of each recommendation in the -table text. Recommendations are
# found the same way as in the -layout text (the heading above "Profile Applicability:"),
# and each table runs from "CIS Controls:" to the next heading.
$tableControls = @{}
$tableHeading = '^\f?(\d+(?:\.\d+)+) \S'
$tableAppendix = -1
for ($i = 0; $i -lt $tableText.Count; $i++) { if ($tableText[$i].TrimStart([char]12) -match '^\s*Appendix: Summary Table\s*$') { $tableAppendix = $i } }
if ($tableAppendix -lt 0) { throw 'The -table text has no "Appendix: Summary Table".' }
$tableStarts = [System.Collections.Generic.List[object]]::new()
for ($i = 0; $i -lt $tableAppendix; $i++) {
    if ($tableText[$i] -notmatch '^\f?Profile Applicability:') { continue }
    $j = $i - 1
    while ($j -gt $i - 20 -and $j -ge 0 -and $tableText[$j] -notmatch $tableHeading) { $j-- }
    if ($j -ge 0 -and $tableText[$j] -match $tableHeading -and $tocControls.Contains($Matches[1])) { $tableStarts.Add([pscustomobject]@{ Id = $Matches[1]; Line = $j }) }
}
for ($n = 0; $n -lt $tableStarts.Count; $n++) {
    $from = $tableStarts[$n].Line
    $to = if ($n + 1 -lt $tableStarts.Count) { $tableStarts[$n + 1].Line - 1 } else { $tableAppendix - 1 }
    $section = $null
    for ($i = $from; $i -le $to; $i++) {
        $line = $tableText[$i].Replace([string][char]12, '').TrimEnd()
        if ($null -eq $section) { if ($line -match '^CIS\s+Controls:') { $section = [System.Collections.Generic.List[string]]::new(); $section.Add($line) }; continue }
        if ($line -match $tableHeading -and $tocSections.Contains($Matches[1])) { break }
        $section.Add($line)
    }
    if ($section) { $tableControls[$tableStarts[$n].Id] = @($section) }
}
# ---------------------------------------------------------------------------
# 3. Helpers
# ---------------------------------------------------------------------------
# A section heading is "Name:" on its own line. The PDF sometimes prints other text on the
# same line after a wide gap (for example "CIS Controls:      Control  IG 1 IG 2 IG 3",
# where the table header shares the line); that text becomes the section's first line.
# The heading patterns, built once: Get-Section is called about twelve times for every
# recommendation, and building the patterns on every call took most of its time.
# IgnoreCase keeps the behavior of the -match operator used before.
$script:SectionHeadingPatterns = @{}
function Get-Section {
    param([string[]]$Lines, [string]$Name, [string[]]$NextNames)
    $ownKey = 'own|' + $Name
    $nextKey = 'next|' + [string]::Join('|', $NextNames)
    if (-not $script:SectionHeadingPatterns.ContainsKey($ownKey)) {
        $script:SectionHeadingPatterns[$ownKey] = [regex]::new("^$([regex]::Escape($Name)):(?:\s{2,}(\S.*))?$", 'IgnoreCase')
    }
    if (-not $script:SectionHeadingPatterns.ContainsKey($nextKey)) {
        $script:SectionHeadingPatterns[$nextKey] = [regex]::new("^(?:$(($NextNames | ForEach-Object { [regex]::Escape($_) }) -join '|')):(?:\s{2,}\S.*)?$", 'IgnoreCase')
    }
    $own = $script:SectionHeadingPatterns[$ownKey]
    $next = $script:SectionHeadingPatterns[$nextKey]
    $start = -1; $firstLine = $null
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $match = $own.Match($Lines[$i])
        if ($match.Success) { $start = $i + 1; $firstLine = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $null }; break }
    }
    if ($start -lt 0) { return $null }
    $end = $Lines.Count
    for ($i = $start; $i -lt $Lines.Count; $i++) { if ($next.IsMatch($Lines[$i])) { $end = $i; break } }
    $body = if ($end -gt $start) { @($Lines[$start..($end - 1)]) } else { @() }
    if ($firstLine) { @($firstLine) + $body } else { $body }
}# Joins wrapped lines of running text. A line that ends with a letter or digit
# followed by "-" continues without a space: in this benchmark every such break is
# a real hyphen (for example "stand-alone", "third-party" or inside a GUID), never
# a syllable break, so the hyphen is kept. Any other line break becomes a space.
function Join-Prose([string[]]$Lines) {
    $text = ''
    foreach ($line in ($Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
        if ($text -eq '') { $text = $line }
        elseif ($text.EndsWith('-') -and $text -match '[A-Za-z0-9]-$') { $text += $line }
        else { $text += ' ' + $line }
    }
    $text -replace '\s+', ' '
}

# Marks a page break in block lines (where the "Page N" footer was), so that text joining
# can tell a page break from a blank line between paragraphs.
$script:PageBreak = '<<page break>>'
# Bullet characters used in the benchmark: U+2022 bullet, U+25CF black circle, U+25E6 white bullet, U+25AA small square,
$script:Bullets = -join @([char]0x2022, [char]0x25CF, [char]0x25E6, [char]0x25AA, [char]0xF0B7)
$script:RegistryLinePattern = '^HK(?:LM|U|CU|EY_[A-Z_]+)\\'
# Right double and single quotation marks, which can end a sentence.
$script:ClosingQuotes = -join @([char]0x201D, [char]0x2019)

# Joins the lines of a text section into paragraphs and list items, one per line. Inside a
# paragraph the rules of Join-Prose apply (a line ending in "letter-" continues without a
# space). A new paragraph starts at a bullet, a numbered item or a "Note:", at a blank line
# on the same page, and after a line that ends a sentence and is clearly shorter than the
# section's full lines (the next word would have fitted). Registry locations are joined like
# Join-RegistryLines: a full-width line continues in the middle of a word.
function Join-Structured([string[]]$Lines) {
    $paragraphs = [System.Collections.Generic.List[string]]::new()
    $content = @($Lines | Where-Object { $_ -ne $script:PageBreak -and $_.Trim() })
    if ($content.Count -eq 0) { return '' }
    $width = [Math]::Max(80, ($content | ForEach-Object { $_.TrimEnd().Length } | Measure-Object -Maximum).Maximum)
    $current = $null; $previous = $null; $blank = $false; $page = $false; $inRegistry = $false; $itemIndent = -1
    foreach ($raw in $Lines) {
        if ($raw -eq $script:PageBreak) { $page = $true; continue }
        $line = $raw.Trim()
        if (-not $line) { $blank = $true; continue }
        $isRegistryLine = $line -match $script:RegistryLinePattern -and $line -notmatch '\. [A-Z]'
        $indent = $raw.Length - $raw.TrimStart().Length
        $isBulletLine = $line -cmatch "^(?:[$($script:Bullets)]|o\s)"
        if ($null -eq $current) {
            $current = $line; $inRegistry = $isRegistryLine
            $itemIndent = if ($isBulletLine) { $indent } else { -1 }
        }
        else {
            $previousTrimmed = $previous.Trim()
            $firstWord = ($line -split '\s+', 2)[0]
            # Case-sensitive: "a) " starts an item, but "V) must be ..." (the end of "AMD-V)") does not.
            $startsItem = $line -cmatch "^(?:[$($script:Bullets)]|o\s|-\s|\d+\.\s|\(\d+\)\s|[a-z]\)\s|Note(?: #\d+)?:|\\\\)"
            $bulletChar = $line -match "^[$($script:Bullets)]"
            $newParagraph = $false; $separator = ' '
            if ($inRegistry) {
                # A registry location continues until a blank line or a line that starts something else;
                # a line that starts in lower case continues the sentence the location is part of.
                if ($previousTrimmed.Length -ge $script:RegistryWrapWidth -or $previousTrimmed.EndsWith('-')) { $separator = '' }
                elseif ($line -cmatch '^[a-z]') { $inRegistry = $false }
                elseif ($blank -or $isRegistryLine -or $startsItem -or $line -eq 'OR' -or $line -match '^(To audit|Navigate|auditpol)') { $newParagraph = $true }
            }
            elseif ($current.EndsWith('-') -and $current -match '[A-Za-z0-9]-$' -and -not $bulletChar) { $separator = '' }
            elseif ($isRegistryLine) {
                # A registry location on its own line: a new paragraph after a sentence, otherwise
                # part of the sentence ("... the HKLM\...\Parameters registry key").
                if ($current -match '[.:]$' -or ($blank -and -not $page -and $current -notmatch '[A-Za-z,]$')) { $newParagraph = $true } else { $inRegistry = $true }
            }
            elseif ($startsItem -or $line -eq 'OR' -or $current -eq 'OR' -or $line -match '^(Computer|User) Configuration\\') { $newParagraph = $true }
            # A command after a line that introduces it ("... perform the following ...:").
            elseif ($current -match ':$' -and $line -match '^(auditpol|netsh|reg(\.exe)?|sc(\.exe)?|Get-\w+|Set-\w+)\s') { $newParagraph = $true }
            # A list item continues on lines indented further than its bullet; a line at the
            # bullet's indentation or left of it starts the next paragraph.
            elseif ($itemIndent -ge 0 -and $indent -le $itemIndent) { $newParagraph = $true }
            elseif ($current -match '(?:https?://|www\.)\S*[/_=?&#]$') { $separator = '' }
            # A line that starts in lower case continues the sentence, unless the previous one ended it.
            elseif ($line -cmatch '^[a-z(]' -and $current -notmatch '[.!?]$') { }
            # A blank line separates paragraphs, but the PDF text also has blank lines inside a
            # paragraph, so it counts only after the end of a sentence.
            elseif ($blank -and -not $page -and $current -match "[.:!?)`"$($script:ClosingQuotes)]$") { $newParagraph = $true }
            elseif ($current -match "[.:!?`"$($script:ClosingQuotes)]$" -and ($previous.TrimEnd().Length + 1 + $firstWord.Length) -le ($width - 4)) { $newParagraph = $true }
            if ($newParagraph) {
                $paragraphs.Add($current); $current = $line; $inRegistry = $isRegistryLine
                $itemIndent = if ($isBulletLine) { $indent } else { -1 }
            }
            else { $current += $separator + $line }
        }
        $previous = $raw; $blank = $false; $page = $false
    }
    if ($null -ne $current) { $paragraphs.Add($current) }
    (@($paragraphs | ForEach-Object { ($_ -replace '\s+', ' ').Trim() }) -join "`n")
}

# References: numbered items ("1. https://..."). A wrapped URL continues without a space.
function Get-References([string[]]$Lines) {
    $items = [System.Collections.Generic.List[string]]::new()
    $current = $null
    foreach ($raw in $Lines) {
        $line = $raw.Trim()
        if ($raw -eq $script:PageBreak -or -not $line) { continue }
        if ($line -match '^(\d+)\.\s+(\S.*)$' -and [int]$Matches[1] -eq $items.Count + $(if ($null -ne $current) { 2 } else { 1 })) {
            if ($null -ne $current) { $items.Add($current) }
            $current = $Matches[2]
        } elseif ($null -ne $current) {
            if ($current -notmatch '\s' -or $current -match '[A-Za-z0-9]-$') { $current += $line } else { $current += ' ' + $line }
        } else {
            $current = $line
        }
    }
    if ($null -ne $current) { $items.Add($current) }
    @($items | ForEach-Object { ($_ -replace '\s+', ' ').Trim() })
}

# CIS Controls table, from the -table text: one row per safeguard, with the Controls version
# (v8 or v7), its number and title, its description and the implementation groups marked
# with a circle. The -table text prints each circle on a line of its own row (the -layout
# text sometimes moves them to a neighbouring row). The circles are not reliably under
# their column header in either text, so the groups come from the number of circles:
# implementation groups are cumulative (a safeguard in IG 1 is also in IG 2 and IG 3), so
# 3 circles = IG 1, 2, 3; 2 = IG 2, 3; 1 = IG 3; none = no group.
function Get-CisControls([string[]]$Lines, [System.Collections.Generic.List[string]]$Warnings) {
    $mark = [regex]::Escape([string][char]0x25CF)
    $rows = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($raw in $Lines) {
        $line = $raw -replace '^CIS\s+Controls:', ''
        if ($line -match '^\s*Page\s+\d+\s*$' -or -not $line.Trim()) { continue }
        if ($line -match 'IG\s*1' -or $line.Trim() -match '^(Controls(\s+Version)?|Version)$') { continue }
        # The header word can share a line with the first row ("Version   0.0 Explicitly Not Mapped").
        $line = $line -replace '^\s*(?:Controls\s+)?Version(?=\s{2,})', ''
        $circles = ([regex]::Matches($line, $mark)).Count
        $text = ($line -replace $mark, '').Trim()
        $version = $null
        if ($text -match '^(v\d+)(?:\s+(.*))?$') { $version = $Matches[1]; $text = [string]$Matches[2] }
        if ($text -match '^(\d+\.\d+)\s+(\S.*)$') {
            if ($current) { $rows.Add($current) }
            $current = [ordered]@{ version = $version; id = $Matches[1]; title = $Matches[2]; description = ''; circles = $circles }
            continue
        }
        if (-not $current) {
            if ($text -or $circles) { $Warnings.Add("CIS Controls: text or circles before the first safeguard: '$($line.Trim())'.") }
            continue
        }
        if ($version) {
            if ($current.version -and $current.version -ne $version) { $Warnings.Add("CIS Controls: safeguard $($current.id) has two versions ($($current.version), $version).") }
            $current.version = $version
        }
        $current.circles += $circles
        if ($text -and -not $current.description -and $current.title -match '[A-Za-z0-9]-$') {
            # The title wrapped after a hyphen ("... on Portable End-" + "User Devices").
            $current.title += $text
            continue
        }
        if ($text) {
            if (-not $current.description) { $current.description = $text }
            elseif ($current.description -match '[A-Za-z0-9]-$') { $current.description += $text }
            else { $current.description += ' ' + $text }
        }
    }
    if ($current) { $rows.Add($current) }
    @(foreach ($row in $rows) {
        if (-not $row.version) { $Warnings.Add("CIS Controls: safeguard $($row.id) has no Controls version.") }
        if ($row.circles -gt 3) { $Warnings.Add("CIS Controls: safeguard $($row.id) has $($row.circles) implementation group circles.") }
        [ordered]@{
            version = $row.version
            id = $row.id
            title = ($row.title -replace '\s+', ' ').Trim()
            description = ($row.description -replace '\s+', ' ').Trim()
            implementationGroups = @(if ($row.circles -ge 1 -and $row.circles -le 3) { (4 - $row.circles)..3 })
        }
    })
}
# Joins wrapped registry lines. The PDF text wraps long registry locations at a
# fixed width: a line of exactly that width continues in the middle of a word
# (joined without a space); a shorter line was broken at a space (joined with a
# space). Lines just under the width are ambiguous and are reported. Every join
# that inserts a space is recorded in $script:SpaceJoins so it can be reviewed.
function Join-RegistryLines {
    param([string]$Id, [string[]]$Lines, [System.Collections.Generic.List[string]]$Warnings)
    $joined = $Lines[0]
    for ($i = 1; $i -lt $Lines.Count; $i++) {
        $previous = $Lines[$i - 1]
        if ($previous.Length -ge $script:RegistryWrapWidth -or $previous.EndsWith('-') -or $previous.EndsWith('\')) {
            # Hard break inside a word, a break after a hyphen (for example inside a GUID), or a
            # break after a path separator (Chrome: "...\ClipboardAllowedForUrls\" + "<number> = <url>").
            $joined += $Lines[$i]
        } elseif ($previous.EndsWith('=')) {
            # A list example ("...\1 =" + "https://www.example.com"): the value follows after a space.
            $joined += ' ' + $Lines[$i]
        } else {
            $joined += ' ' + $Lines[$i]
            $script:SpaceJoins.Add("$Id  '$previous' + '$($Lines[$i])'")
            $reviewKey = "$previous|$($Lines[$i])"
            if ($previous.Length -ge $script:RegistryWrapWidth - 8 -and -not $script:ReviewedSpaceJoins.Contains($reviewKey)) {
                $Warnings.Add("Wrapped registry line of $($previous.Length) characters is close to the wrap width; the join with a space needs review: '$previous' + '$($Lines[$i])'.")
            }
        }
    }
    $joined
}
# Turns the "with a REG_DWORD value of 1 or 2" sentence into a rule.
function ConvertTo-ValueRule {
    param([string]$Sentence, [System.Collections.Generic.List[string]]$Warnings)
    $types = @([regex]::Matches($Sentence, 'REG_[A-Z_]+') | ForEach-Object { $_.Value } | Select-Object -Unique)
    $text = $Sentence.Trim()
    $num = '(-?[\d,]+)'
    $toInt = { param($s) [long]($s -replace ',', '') }
    $rule = $null
    switch -Regex ($text) {
        "^value of ``?$num\s*$"                                              { $rule = @{ kind = 'equals'; value = & $toInt $Matches[1] }; break }
        "^value of $num or that the key does not exist\s*$"                 { $rule = @{ kind = 'equals'; value = & $toInt $Matches[1]; keyMayBeAbsent = $true }; break }
        "^value of $num or $num\s*$"                                        { $rule = @{ kind = 'anyOf'; values = @((& $toInt $Matches[1]), (& $toInt $Matches[2])) }; break }
        # Chrome: "0 or 1 (Organization dependent)".
        "^value of $num or $num \(([^)]+)\)\s*$"                            { $rule = @{ kind = 'anyOf'; values = @((& $toInt $Matches[1]), (& $toInt $Matches[2])); note = $Matches[3] }; break }
        # Chrome 2.39: "ef00000 (250609664 in hexadecimal format)". The number in brackets is the
        # decimal value of the hexadecimal one in front (0xEF00000 = 250609664), whatever the
        # wording says; the rule holds the number, and the script stops if the two disagree.
        '^value of ([0-9a-fA-F]+) \((\d+) in hexadecimal format\)\s*$' {
            if ([Convert]::ToInt64($Matches[1], 16) -ne [long]$Matches[2]) { throw "Hexadecimal value '$($Matches[1])' is not $($Matches[2]): '$Sentence'." }
            $rule = @{ kind = 'equals'; value = [long]$Matches[2]; hexadecimal = $Matches[1] }; break
        }
        "^value of $num(?: or greater| or more)\s*$"                        { $rule = @{ kind = 'minimum'; value = & $toInt $Matches[1] }; break }
        "^value of $num or less,? but not $num\s*$"                         { $rule = @{ kind = 'maximum'; value = & $toInt $Matches[1]; excluding = @((& $toInt $Matches[2])) }; break }
        "^value of $num or less\s*$"                                        { $rule = @{ kind = 'maximum'; value = & $toInt $Matches[1] }; break }
        "^value between $num and $num\s*$"                                  { $rule = @{ kind = 'range'; minimum = & $toInt $Matches[1]; maximum = & $toInt $Matches[2] }; break }
        "^value of anything other than $num\s*$"                            { $rule = @{ kind = 'notEquals'; value = & $toInt $Matches[1] }; break }
        # Edge and Chrome: "which should be set to any REG_DWORD value except 0" (or "any value except 0").
        "^value of any (?:REG_\w+ )?value except $num\s*$"                  { $rule = @{ kind = 'notEquals'; value = & $toInt $Matches[1] }; break }
        '^value of (\S+) \((\w+)\) and (?:REG_\w+ value of )?(\S+) \((\w+)\)\s*$' {
            # Two values in one setting, for example "1 (EnableSmartScreen) and REG_SZ value of Block (ShellSmartScreenLevel)".
            $first = $Matches[1]; $firstName = $Matches[2]; $second = $Matches[3]; $secondName = $Matches[4]
            $asValue = { param($s) if ($s -match '^-?\d+$') { [long]$s } else { $s } }
            $rule = @{ kind = 'perValue'; values = [ordered]@{ $firstName = (& $asValue $first); $secondName = (& $asValue $second) } }
            break
        }
        '^value of (\d+), (\d+),? or (\d+)\s*$'                             { $rule = @{ kind = 'anyOf'; values = @([long]$Matches[1], [long]$Matches[2], [long]$Matches[3]) }; break }
        '^(?:value that is blank|value of <blank>|that is <blank>)'         { $rule = @{ kind = 'blank' }; break }
        '^value of text\s*$'                                                { $rule = @{ kind = 'anyText'; note = 'Organization-defined text.' }; break }
        '^value of <path>\\<filename>\.log'                                 { $rule = @{ kind = 'anyText'; note = 'Organization-defined log file path.' }; break }
        '^value of (\{[0-9a-f-]+\}(?:, (?:and )?\{[0-9a-f-]+\})+)\s*$'      { $rule = @{ kind = 'list'; values = @([regex]::Matches($Matches[1], '\{[0-9a-fA-F-]+\}') | ForEach-Object { $_.Value }) }; break }
        '^value of ((?:[A-Za-z][^,]*?)(?:, [^,]+?)*(?:,? and [^,]+?))\s*$'  { $rule = @{ kind = 'list'; values = @($Matches[1] -split ',\s*(?:and\s+)?|\s+and\s+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }; break }
        '^value of (\S.*?)\s*$'                                             { $rule = @{ kind = 'equalsText'; value = $Matches[1] }; break }
    }
    if ($null -eq $rule) {
        $rule = @{ kind = 'unparsed' }
        $Warnings.Add("Expected registry value could not be parsed: '$Sentence'.")
    }
    [pscustomobject]@{ Types = $types; Rule = $rule }
}

# Makes the expected values carry the registry data type: numbers for REG_DWORD,
# strings for REG_SZ and REG_MULTI_SZ (so "0" for a REG_SZ is the string "0", not
# the number 0). Where the PDF states a type that cannot hold its own expected
# value, the entry keeps the type as printed and gets a typeConflict explanation.
function Set-ExpectedValueType {
    param([System.Collections.Specialized.OrderedDictionary]$Entry)
    $rule = $Entry.expected
    if (-not $rule) { return }
    $type = [string]$Entry.valueType
    $stringType = $type -in @('REG_SZ', 'REG_MULTI_SZ', 'REG_EXPAND_SZ')
    $toType = { param($v) if ($stringType -and ($v -is [long] -or $v -is [int])) { [string]$v } else { $v } }
    foreach ($name in @('value', 'minimum', 'maximum')) { if ($rule.Contains($name)) { $rule[$name] = & $toType $rule[$name] } }
    foreach ($name in @('values', 'excluding')) { if ($rule.Contains($name)) { $rule[$name] = @($rule[$name] | ForEach-Object { & $toType $_ }) } }
    if ($type -eq 'REG_DWORD' -and $rule.kind -in @('list', 'equalsText', 'anyText')) {
        $likely = if ($rule.kind -eq 'list') { 'REG_MULTI_SZ' } else { 'REG_SZ' }
        $Entry.typeConflict = "The PDF states REG_DWORD, but the expected value is text, which a REG_DWORD cannot hold. The value is a $likely (a $(if ($likely -eq 'REG_MULTI_SZ') { 'list of strings' } else { 'string' }))."
        $Entry.likelyValueType = $likely
    }
    if ($type -match ' or ') {
        $shown = if ($rule.Contains('value')) { $rule.value } else { '...' }
        $Entry.typeNote = "The PDF accepts either type: REG_DWORD $shown or REG_SZ `"$shown`"."
    }
}

# Rebuilds the expected-value sentence from a parsed rule, for the round-trip check
# in section 7. Returns normalized forms (lower case, without whitespace, commas,
# periods and backticks) that the printed sentence must match.
function Get-RuleRendering {
    param([System.Collections.Specialized.OrderedDictionary]$Entry)
    $rule = $Entry.expected; $t = [string]$Entry.valueType
    $list = { param($items) $a = @($items); if ($a.Count -le 1) { "$a" } else { (($a[0..($a.Count - 2)]) -join ', ') + ' and ' + $a[-1] } }
    $forms = switch ($rule.kind) {
        'equals'     { if ($rule.keyMayBeAbsent) { "$t value of $($rule.value) or that the key does not exist" } elseif ($rule.Contains('hexadecimal')) { "$t value of $($rule.hexadecimal) ($($rule.value) in hexadecimal format)" } else { "$t value of $($rule.value)" } }
        'equalsText' { "$t value of $($rule.value)" }
        'anyOf'      { $v = @($rule.values); $n = if ($rule.Contains('note')) { " ($($rule.note))" } else { '' }; if ($v.Count -eq 2) { "$t value of $($v[0]) or $($v[1])$n" } else { "$t value of " + (($v[0..($v.Count - 2)]) -join ', ') + " or $($v[-1])$n" } }
        'minimum'    { "$t value of $($rule.value) or greater"; "$t value of $($rule.value) or more" }
        'maximum'    { if ($rule.Contains('excluding')) { "$t value of $($rule.value) or less but not $(@($rule.excluding)[0])" } else { "$t value of $($rule.value) or less" } }
        'range'      { "$t value between $($rule.minimum) and $($rule.maximum)" }
        'notEquals'  { "$t value of anything other than $($rule.value)"; "should be set to any $t value except $($rule.value)" }
        'list'       { "$t value of " + (& $list $rule.values) }
        default      { $null }
    }
    # Without a data type the PDF says "should be set to 0" instead of "REG_DWORD value of 0".
    if (-not $t) { $forms = @($forms) + @($forms | Where-Object { $_ } | ForEach-Object { $_ -replace '^\s*value of ', 'should be set to ' }) }
    @($forms | Where-Object { $_ } | ForEach-Object { ($_ -replace '[\s,.`]', '').ToLowerInvariant() })
}

# ---------------------------------------------------------------------------
# 4. Block helpers
# ---------------------------------------------------------------------------
$sectionNames = @('Profile Applicability', 'Description', 'Rationale', 'Impact', 'Audit', 'Remediation', 'Default Value', 'References', 'CIS Controls', 'Additional Information')
# The lines of one recommendation, with $script:PageBreak in place of the page footers.
# A recommendation ends where the next one starts, or earlier at a section heading
# (for example "18.10.57.3 Remote Desktop Session Host") that follows its last table.
function Get-BlockLines([int]$Index) {
    $from = $blocks[$Index].Line
    $to = if ($Index + 1 -lt $blocks.Count) { $blocks[$Index + 1].Line - 1 } else { $bodyEnd }
    $result = [System.Collections.Generic.List[string]]::new()
    $afterReferences = $false
    foreach ($raw in $all[$from..$to]) {
        $line = $raw.TrimStart([char]12).TrimEnd()
        if ($line -match '^\s*Page \d+\s*$') { $result.Add($script:PageBreak); continue }
        if ($line -eq 'References:') { $afterReferences = $true }
        elseif ($afterReferences -and $line -match '^(\d+(?:\.\d+)+) \S' -and $tocSections.Contains($Matches[1])) { break }
        $result.Add($line)
    }
    @($result)
}
function Get-RegistryLineGroups([string[]]$AuditLines) {
    # Returns groups of consecutive lines; each group is one registry location
    # (a line starting with HK and its wrapped continuation lines).
    $groups = [System.Collections.Generic.List[object]]::new()
    $group = $null
    foreach ($raw in $AuditLines) {
        $line = $raw.Trim()
        if ($line -match '^HK(LM|U|CU|EY_[A-Z_]+)\\') { if ($group) { $groups.Add($group) }; $group = [System.Collections.Generic.List[string]]::new(); $group.Add($line); continue }
        if ($group) {
            if (-not $line -or $line -eq 'OR' -or $line -match '^(To audit|Navigate|auditpol|Note)') { $groups.Add($group); $group = $null; continue }
            $group.Add($line)
        }
    }
    if ($group) { $groups.Add($group) }
    # The comma keeps a single group from being unrolled into its lines.
    return , $groups.ToArray()
}
# ---------------------------------------------------------------------------
# 5. Second pass: build the controls
# ---------------------------------------------------------------------------
function Get-SectionPath([string]$Id) {
    $parts = $Id -split '\.'
    $path = [System.Collections.Generic.List[string]]::new()
    for ($n = 1; $n -lt $parts.Count; $n++) {
        $prefix = ($parts[0..($n - 1)] -join '.')
        if ($tocSections.Contains($prefix)) { $path.Add("$prefix $($tocSections[$prefix])") }
    }
    @($path)
}

$controls = [System.Collections.Generic.List[object]]::new()
$totalWarnings = 0
for ($b = 0; $b -lt $blocks.Count; $b++) {
    $block = $blocks[$b]
    $warnings = [System.Collections.Generic.List[string]]::new()
    # The block once with page-break markers (for the text sections, which tell a page break
    # from a blank line) and once without them (for everything else).
    $pageLines = Get-BlockLines $b
    $lines = @($pageLines | Where-Object { $_ -ne $script:PageBreak })

    # Heading: title and assessment.
    $heading = Join-Prose $block.HeadingLines
    # Everything in the recommendation without whitespace, for the character check in section 7.
    $script:BlockCompact[$block.Id] = ($lines -join '') -replace '\s', ''
    if ($heading -match '^(.*?)\s*\((Automated|Manual)\)\s*$') { $title = $Matches[1]; $assessment = $Matches[2] }
    else { $title = $heading; $assessment = $null; $warnings.Add('Assessment (Automated or Manual) not found in the heading.') }
    if ($script:Benchmark.LevelInTitle -and $title) { $title = $title -replace '^\((?:L1|L2)\)\s+', '' }
    if ($tocControls[$block.Id].Title -ne "$title ($assessment)") {
        # Accept the small differences that line wrapping causes (hyphenation, spacing).
        $normalize = { param($s) ($s -replace '[\s-]', '').ToLowerInvariant() }
        if ((& $normalize $tocControls[$block.Id].Title) -ne (& $normalize "$title ($assessment)")) { $warnings.Add("Title differs from the table of contents: '$($tocControls[$block.Id].Title)'.") }
    }

    # Expected state from the title.
    $expectedState = $null; $comparison = $null
    if ($title -match "\bis set to (?:'(.+)'|(\S.*))$")                 { $expectedState = if ($Matches[1]) { $Matches[1] } else { $Matches[2] }; $comparison = 'equals' }
    elseif ($title -match "\bis NOT set to '(.+)'$")                   { $expectedState = $Matches[1]; $comparison = 'notEquals' }
    elseif ($title -match "\b(?:is set )?to include '(.+)'$")              { $expectedState = $Matches[1]; $comparison = 'includes' }
    elseif ($title -match "\bis (?:explicitly )?(configured)$")        { $expectedState = $Matches[1]; $comparison = 'configured' }
    # Chrome titles also say "Is Enabled" or "Is Disabled" without "set to".
    elseif ($title -match "\bis (Enabled|Disabled)$")                  { $expectedState = $Matches[1]; $comparison = 'equals' }
    elseif ($title -match "^Configure '(.+)'$")                        { $comparison = 'configure' }
    elseif ($title -match "^Disable IPv6 \(Ensure TCPIP6 Parameter '(\w+)' is set to '(.+)'\)$") { $expectedState = $Matches[2]; $comparison = 'equals' }
    else { $warnings.Add('Expected state could not be read from the title.') }
    if ($comparison -eq 'equals' -and $expectedState -match "^(.+)' OR '(.+)$") { $expectedState = @($Matches[1], $Matches[2]); $comparison = 'anyOf' }

    # Profile.
    $profileText = Join-Prose (Get-Section $lines 'Profile Applicability' $sectionNames)
    $levels = @([regex]::Matches($profileText, 'Level 1 \(L1\) \+ BitLocker \(BL\)|Level 2 \(L2\) \+ BitLocker \(BL\)|Level 1 \(L1\)|Level 2 \(L2\)|BitLocker \(BL\)') | ForEach-Object { $_.Value })
    if ($levels.Count -eq 0) { $warnings.Add("Profile applicability not recognised: '$profileText'.") }
    $level = if ($levels -contains 'Level 1 (L1)') { 'L1' } elseif ($levels -contains 'Level 2 (L2)') { 'L2' } elseif ($levels.Count -gt 0) { 'BL' } else { $null }

    # Audit section: registry locations and expected values.
    $auditLines = @(Get-Section $lines 'Audit' $sectionNames)
    $auditText = Join-Prose $auditLines
    # The Audit text without any whitespace, for the character check in section 7.
    $script:AuditCompact[$block.Id] = ($auditLines -join '') -replace '\s', ''
    $registry = [System.Collections.Generic.List[object]]::new()
    $groups = Get-RegistryLineGroups $auditLines
    if ($groups.Count -gt 0) {
        # The sentence ends with a period, or with a colon before the location (Chrome 2.4.4).
        $sentence = [regex]::Match($auditText, 'registry locations? with a (.*?)[:.]?\s*HK(?:LM|U|CU|EY_)')
        # The Chrome PDF names no data type: "registry location which should be set to 0: HKEY_...".
        $untypedSentence = $false
        if (-not $sentence.Success) {
            $sentence = [regex]::Match($auditText, 'registry locations? which should be set to (.*?)[:.]?\s*HK(?:LM|U|CU|EY_)')
            $untypedSentence = $sentence.Success
        }
        $valueRule = if ($sentence.Success -and $untypedSentence) { ConvertTo-ValueRule ('value of ' + ($sentence.Groups[1].Value -replace '\s+', ' ').Trim()) $warnings } elseif ($sentence.Success) { ConvertTo-ValueRule ($sentence.Groups[1].Value -replace '^(?:REG_\w+(?: or REG_\w+)?)\s*', '') $warnings } else { $warnings.Add('Registry value sentence ("with a REG_... value of ...") not found.'); $null }
        # @(if ...) keeps a single type from being unrolled into a string.
        $types = @(if ($sentence.Success) { [regex]::Matches($sentence.Groups[1].Value, 'REG_[A-Z_]+') | ForEach-Object { $_.Value } | Select-Object -Unique })
        foreach ($group in $groups) {
            # The wrap rule needs every registry line to be at most the wrap width, and a group
            # must not end on a line that continues (a full-width line or one ending in "-"):
            # that means the location went on after a blank line or a page break.
            foreach ($groupLine in $group) { if ($groupLine.Length -gt $script:RegistryWrapWidth) { $script:RegistryLayoutErrors.Add("$($block.Id): registry line longer than $($script:RegistryWrapWidth) characters: '$groupLine'") } }
            if ($group[-1].Length -ge $script:RegistryWrapWidth -or $group[-1].EndsWith('-')) {
                # A full-width last line is fine when the location is complete. It is an error
                # when the next printed line (past blank lines and page breaks) is a path fragment.
                $at = -1; for ($q = 0; $q -lt $lines.Count; $q++) { if ($lines[$q].Trim() -eq $group[-1]) { $at = $q } }
                $after = $null; for ($q = $at + 1; $q -lt $lines.Count; $q++) { if ($lines[$q].Trim()) { $after = $lines[$q].Trim(); break } }
                if ($after -and $after -notmatch '^[^:]+:$' -and $after -ne 'OR' -and $after -notmatch $script:RegistryLinePattern -and $after -match '^[A-Za-z0-9_\\:.{}*-]+$') {
                    $script:RegistryLayoutErrors.Add("$($block.Id): registry location continues after a blank line or page break: '$($group[-1])' + '$after'")
                }
            }
            $joined = if ($group.Count -eq 1) { $group[0] } else { Join-RegistryLines $block.Id $group $warnings }
            # List policies (Chrome): "<key>\<number> = <url>" shows the format of the list and
            # "<key>\1 = https://..." lines are examples. Together they are one entry for the list
            # key (no value name, listValues = true) that carries the examples; they are not
            # registry locations of their own. The PDF sometimes drops the backslash before the
            # number ("ClipboardBlockedForUrls3 = ...").
            if ($joined -match '^(?<key>HK.+?)\\?\s*(?<name><number>|\d+)\s*=\s*(?<data>.*)$') {
                $listKey = $Matches['key'].TrimEnd('\').Trim()
                $listName = $Matches['name']; $listData = $Matches['data'].Trim()
                $listEntry = $registry | Where-Object { $_.key -eq $listKey -and $_.Contains('listValues') } | Select-Object -First 1
                if (-not $listEntry) {
                    $listEntry = [ordered]@{ key = $listKey; valueName = $null; listValues = $true; examples = @() }
                    $registry.Add($listEntry)
                }
                if ($listName -ne '<number>') { $listEntry.examples = @($listEntry.examples) + @([ordered]@{ valueName = $listName; data = $listData }) }
                continue
            }
            $colon = $joined.LastIndexOf(':')
            $valueNameInferred = $false
            if ($colon -gt 0) {
                $key = $joined.Substring(0, $colon).Trim(); $valueName = $joined.Substring($colon + 1).Trim()
            } elseif ($valueRule -and $valueRule.Rule.kind -in @('equals', 'notEquals', 'anyOf', 'minimum', 'maximum', 'range') -and $joined -match '^(HK.+)\\([^\\\s]+)$') {
                # The PDF printed no colon before the value name (Chrome 2.7.2 "...\Chrome\BasicAuthOverHttpEnabled"),
                # but it expects a single value, so the last part of the path is the value name.
                $key = $Matches[1]; $valueName = $Matches[2]; $valueNameInferred = $true
                $warnings.Add("The PDF prints no colon before the value name in '$joined'; '$valueName' is taken as the value name, because a single value is expected.")
            } else {
                # A key without a value name: a list policy, or a key that must not exist.
                $warnings.Add("Registry location without a value name: '$joined'.")
                $registry.Add([ordered]@{ key = $joined.TrimEnd('\'); valueName = $null })
                continue
            }
            $entry = [ordered]@{ key = $key; valueName = $valueName; joinedFromWrappedLines = ($group.Count -gt 1); valueType = $(if ($types.Count -eq 1) { $types[0] } elseif ($types.Count -gt 1) { $types -join ' or ' } else { $null }) }
            if ($valueNameInferred) { $entry.valueNameInferred = $true }
            if ($valueRule) {
                $rule = [ordered]@{}
                foreach ($pair in ($valueRule.Rule.GetEnumerator() | Sort-Object { if ($_.Key -eq 'kind') { 0 } else { 1 } })) { $rule[$pair.Key] = $pair.Value }
                if ($rule.kind -eq 'perValue') {
                    $rule = if ($rule.values.Contains($valueName)) {
                        $perValue = $rule.values[$valueName]
                        if ($perValue -is [string]) { [ordered]@{ kind = 'equalsText'; value = $perValue } } else { [ordered]@{ kind = 'equals'; value = $perValue } }
                    } else { $warnings.Add("No per-value expectation for '$valueName'."); [ordered]@{ kind = 'unparsed' } }
                    # Each value can have its own type ("REG_DWORD value of 1 (A) and REG_SZ value of Block (B)").
                    foreach ($typeMatch in [regex]::Matches($sentence.Groups[1].Value, '(REG_[A-Z_]+)\s+value of\s+\S+\s+\((\w+)\)')) { if ($typeMatch.Groups[2].Value -eq $valueName) { $entry.valueType = $typeMatch.Groups[1].Value } }
                }
                $entry.expected = $rule
                Set-ExpectedValueType $entry
            }
            $registry.Add($entry)
        }
        if ($sentence.Success) {
            $printedRule = ($sentence.Groups[1].Value -replace '\s+', ' ').Trim()
            if ($untypedSentence) { $printedRule = "should be set to $printedRule" }
            $registry | ForEach-Object { $_.expectedText = $printedRule }
        }
    }

    # Kind of control and non-registry details.
    $kind = 'other'; $details = [ordered]@{}
    if ($block.Id -match '^1\.') { $kind = 'accountPolicy' }
    elseif ($block.Id -match '^2\.2\.') {
        $kind = 'userRight'
        if ($comparison -eq 'equals' -and $expectedState -is [string]) { $details.accounts = @(if ($expectedState -eq 'No One') { @() } else { @($expectedState -split ',\s*') }) }
    }
    elseif ($block.Id -match '^2\.3\.') { $kind = 'securityOption' }
    elseif ($block.Id -match '^5\.') {
        $kind = 'service'
        if ($title -match "\(([A-Za-z0-9_-]+)\)' is set to") { $details.serviceName = $Matches[1] } else { $warnings.Add('Service name not found in the title.') }
    }
    elseif ($block.Id -match '^9\.') { $kind = 'firewall' }
    elseif ($block.Id -match '^17\.') {
        $kind = 'auditPolicy'
        $guid = [regex]::Match($auditText, 'auditpol /get /subcategory:"(\{[0-9a-fA-F-]+\})"')
        if ($guid.Success) { $details.auditSubcategoryGuid = $guid.Groups[1].Value } else { $warnings.Add('auditpol subcategory GUID not found.') }
    }
    elseif ($block.Id -match '^18\.|^19\.') { $kind = 'administrativeTemplate' }
    # A control whose Audit text names a registry location must yield one. Security
    # options that the benchmark audits through the local security policy (and
    # not through the registry) legitimately have none.
    $registryBacked = $registry.Count -gt 0
    if (-not $registryBacked -and $auditText -match 'HK(LM|U|CU)\\') { $warnings.Add('The Audit section mentions a registry location, but none could be read.') }
    if (-not $registryBacked -and $kind -in @('administrativeTemplate', 'firewall')) { $warnings.Add('No registry location found in the Audit section.') }

    # Remediation: Group Policy path or command.
    $remediationLines = @(Get-Section $lines 'Remediation' $sectionNames)
    $groupPolicyPath = $null; $remediationCommand = $null; $remediationRegistryValue = $null
    for ($i = 0; $i -lt $remediationLines.Count; $i++) {
        $line = $remediationLines[$i].Trim()
        if ($line -match 'run the following (?:PowerShell )?command') {
            # The command follows; "or ensure the service is not installed." may wrap in between.
            for ($k = $i + 1; $k -lt $remediationLines.Count; $k++) {
                $candidate = $remediationLines[$k].Trim()
                if ($candidate -match '^([A-Z][A-Za-z]+-[A-Za-z]+|sc(\.exe)?|reg(\.exe)?|netsh|auditpol|wevtutil|powershell(\.exe)?)\s') { $remediationCommand = $candidate; break }
            }
            break
        }
        if ($line -match 'set the following Registry value to') {
            # Settings without Group Policy backing: the registry value to set is named instead.
            for ($k = $i + 1; $k -lt $remediationLines.Count; $k++) { if ($remediationLines[$k].Trim() -match '^HK(LM|U)\\') { $remediationRegistryValue = $remediationLines[$k].Trim(); break } }
            break
        }
        if ($line -match '^(Computer|User) Configuration\\') {
            $pathLines = [System.Collections.Generic.List[string]]::new()
            for ($k = $i; $k -lt $remediationLines.Count; $k++) {
                $next = $remediationLines[$k].Trim()
                if (-not $next -or $next -match '^(Note|Impact|Default)') { break }
                $pathLines.Add($next)
            }
            # Group Policy paths wrap at spaces (and keep hyphens), like running text.
            $groupPolicyPath = Join-Prose $pathLines
            break
        }
    }
    if (-not $groupPolicyPath -and -not $remediationCommand -and -not $remediationRegistryValue) {
        # Some settings name a Group Policy item and then give the command on its own line.
        $remediationCommand = @($remediationLines | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(Set-[A-Za-z]+|Disable-[A-Za-z]+|Enable-[A-Za-z]+)\s+-' } | Select-Object -First 1)[0]
    }
    if (-not $groupPolicyPath -and -not $remediationCommand -and -not $remediationRegistryValue) { $warnings.Add('No Group Policy path, command or registry value was found in the Remediation section.') }

    # Text sections, with paragraphs and list items kept (one per line).
    $sectionText = [ordered]@{}
    $compactBySection = @{}
    foreach ($pair in @(@('Description', 'description'), @('Rationale', 'rationale'), @('Impact', 'impact'), @('Audit', 'auditText'), @('Remediation', 'remediationText'), @('Default Value', 'defaultValue'), @('Additional Information', 'additionalInformation'), @('References', 'references'), @('CIS Controls', 'cisControls'))) {
        $sectionLines = Get-Section $pageLines $pair[0] $sectionNames
        if ($null -eq $sectionLines) { $sectionText[$pair[1]] = $null; continue }
        $printedLines = @($sectionLines | Where-Object { $_ -ne $script:PageBreak })
        # The CIS Controls table header (Controls Version, Control, IG 1 IG 2 IG 3) is not data.
        if ($pair[1] -eq 'cisControls') { $printedLines = @($printedLines | Where-Object { $_ -notmatch 'IG\s*1' -and $_.Trim() -notmatch '^(Controls(\s+Version)?|Version)$' } | ForEach-Object { $_ -replace '^\s*(?:Controls\s+)?Version(?=\s{2,}|$)', '' -replace '^\s*v\d+(?=\s|$)', '' }) }
        $compactBySection[$pair[1]] = ($printedLines -join '') -replace '\s', ''
        $sectionText[$pair[1]] = switch ($pair[1]) {
            'references' { , @(Get-References $sectionLines) }
            'cisControls' { if ($tableControls.ContainsKey($block.Id)) { , @(Get-CisControls $tableControls[$block.Id] $warnings) } else { $warnings.Add('CIS Controls table not found in the -table text.'); , @() } }
            default { Join-Structured $sectionLines }
        }
    }
    $script:SectionCompact[$block.Id] = $compactBySection
    $description = $sectionText.description
    $rationale = $sectionText.rationale
    $defaultValue = $sectionText.defaultValue
    $impact = $sectionText.impact
    if (-not $sectionText.auditText) { $warnings.Add('Audit section is empty.') }
    if (-not $sectionText.remediationText) { $warnings.Add('Remediation section is empty.') }
    if (@($sectionText.references).Count -eq 0) { $warnings.Add('References section is empty.') }
    if (-not $description) { $warnings.Add('Description section is empty.') }
    if (-not $rationale) { $warnings.Add('Rationale section is empty.') }
    if (-not $defaultValue) { $warnings.Add('Default Value section is empty.') }

    $control = [ordered]@{
        id = $block.Id
        title = $title
        level = $level
        profiles = $levels
        assessment = $assessment
        page = $block.Page
        pdfPage = $block.Page + 1
        sectionPath = Get-SectionPath $block.Id
        kind = $kind
        expectedState = $expectedState
        comparison = $comparison
    }
    foreach ($pair in $details.GetEnumerator()) { $control[$pair.Key] = $pair.Value }
    $control.registryBacked = $registryBacked
    $control.registry = @($registry)
    $control.groupPolicyPath = $groupPolicyPath
    $control.remediationCommand = $remediationCommand
    $control.remediationRegistryValue = $remediationRegistryValue
    $control.description = $description
    $control.rationale = $rationale
    $control.defaultValue = $defaultValue
    $control.impact = $impact
    $control.auditText = $sectionText.auditText
    $control.remediationText = $sectionText.remediationText
    $control.additionalInformation = $sectionText.additionalInformation
    $control.references = @($sectionText.references)
    $control.cisControls = @($sectionText.cisControls)
    $control.parserWarnings = @($warnings)
    $totalWarnings += $warnings.Count
    $controls.Add($control)
}

# Copy the Microsoft documentation confirmations into the matching registry entries.
$unusedConfirmations = [System.Collections.Generic.List[string]]::new()
foreach ($confirmationKey in $script:MicrosoftConfirmations.Keys) {
    $confirmationId, $confirmationValue = $confirmationKey -split '\|', 2
    $targets = @($controls | Where-Object { $_.id -eq $confirmationId } | ForEach-Object { $_.registry } | Where-Object { $_.valueName -eq $confirmationValue })
    if ($targets.Count -eq 0) { $unusedConfirmations.Add($confirmationKey); continue }
    foreach ($target in $targets) { $target.microsoftDocumentation = $script:MicrosoftConfirmations[$confirmationKey] }
}
if ($unusedConfirmations.Count) { throw "Microsoft documentation confirmations without a matching registry entry (review them for this benchmark version): $($unusedConfirmations -join ', ')" }

# ---------------------------------------------------------------------------
# 6. Cross-check against the baseline scripts (independent of the parser)
# ---------------------------------------------------------------------------
$crossCheck = [System.Collections.Generic.List[string]]::new()
# Registry entries the scripts confirm. Kept here and printed, not written to the JSON.
$confirmedEntries = [System.Collections.Generic.HashSet[object]]::new()
$compared = 0
$crossCheckScripts = if ($script:Benchmark.WindowsBaseline) { @($AuditScript, $RemediationScript) } else { @() }
foreach ($scriptPath in $crossCheckScripts) {
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) { continue }
    $scriptText = [System.IO.File]::ReadAllText($scriptPath)
    $references = [System.Collections.Generic.List[object]]::new()
    # Table entries: @{ Id='x'; ...; Path='HKLM:\...'; Name='...' }
    foreach ($m in [regex]::Matches($scriptText, "@\{ Id='([\d.]+)';.*?Path='([^']+)'; Name='([^']+)'")) { $references.Add(@{ Id = $m.Groups[1].Value; Path = $m.Groups[2].Value; Name = $m.Groups[3].Value }) }
    # Test-Setting 'CIS x ...' { Test-RegDword 'path' 'name' ... } on one line.
    foreach ($m in [regex]::Matches($scriptText, "Test-Setting 'CIS ([\d.]+) [^']*' '[^']*' \{[^\r\n]*?Test-Reg(?:Dword|String) '([^']+)' '([^']+)'")) { $references.Add(@{ Id = $m.Groups[1].Value; Path = $m.Groups[2].Value; Name = $m.Groups[3].Value }) }
    # Set-IdempotentDword -Path 'path' -Name 'name' ... -Description 'CIS x ...'
    foreach ($m in [regex]::Matches($scriptText, "Set-Idempotent\w+ -Path '([^']+)' -Name '([^']+)'[^\r\n]*-Description 'CIS ([\d.]+) ")) { $references.Add(@{ Id = $m.Groups[3].Value; Path = $m.Groups[1].Value; Name = $m.Groups[2].Value }) }
    foreach ($reference in $references) {
        $control = $controls | Where-Object { $_.id -eq $reference.Id } | Select-Object -First 1
        if (-not $control -or $control.registry.Count -eq 0) { continue }
        $compared++
        $expectedKey = ($reference.Path -replace '^HKLM:\\', 'HKLM\').ToLowerInvariant()
        $hit = $control.registry | Where-Object { $_.key.ToLowerInvariant() -eq $expectedKey -and $_.valueName -and $_.valueName.ToLowerInvariant() -eq $reference.Name.ToLowerInvariant() }
        foreach ($confirmedEntry in @($hit)) { if ($confirmedEntry) { [void]$confirmedEntries.Add($confirmedEntry) } }
        if (-not $hit) { $crossCheck.Add("$($reference.Id): $(Split-Path -Leaf $scriptPath) uses $($reference.Path)\$($reference.Name); JSON has $(@($control.registry | ForEach-Object { "$($_.key)\$($_.valueName)" }) -join ' | ')") }
    }
}

# ---------------------------------------------------------------------------
# 7. Independent checks. These use parts of the PDF that the extraction did not
#    read, so an extraction error shows up here. A failed check stops the script.
# ---------------------------------------------------------------------------
# (a) The appendix summary table lists every recommendation once more.
$appendixEnd = $all.Count - 1
for ($i = $bodyEnd + 1; $i -lt $all.Count; $i++) { if ($all[$i].TrimStart([char]12) -match '^Appendix: Change History\s*$') { $appendixEnd = $i; break } }
$appendixLines = @($all[($bodyEnd + 1)..$appendixEnd])
$summaryCount = @($appendixLines | Where-Object { $_ -match '\((Automated|Manual)\)' }).Count
$summaryManualCount = @($appendixLines | Where-Object { $_ -match '\(Manual\)' }).Count
$manualCount = @($controls | Where-Object { $_.assessment -eq 'Manual' }).Count
# (b) The table of contents prints a page number for every recommendation.
$pageMismatches = @($controls | Where-Object { $tocControls[$_.id].Page -ne $_.page } | ForEach-Object { "$($_.id): table of contents says page $($tocControls[$_.id].Page), body says page $($_.page)" })
# (c) Structural completeness.
$incomplete = @($controls | Where-Object { -not $_.level -or -not $_.assessment -or -not $_.title } | ForEach-Object { $_.id })
# (d) Every registry location must be well formed, and its characters must all
#     appear, in the same order and ignoring whitespace, in the PDF's Audit text.
#     This catches characters dropped or added while joining wrapped lines.
$registryEntries = @($controls | ForEach-Object { $id = $_.id; $_.registry | ForEach-Object { [pscustomobject]@{ Id = $id; Entry = $_ } } })
$malformed = [System.Collections.Generic.List[string]]::new()
$notInAuditText = [System.Collections.Generic.List[string]]::new()
foreach ($item in $registryEntries) {
    $entry = $item.Entry
    # A key must not hold leftovers of a list example ("= https") or a placeholder ("<number>").
    if ($entry.key -match '=|<|>|\\$|\s\\|\\\s') { $malformed.Add("$($item.Id): $($entry.key) :: $($entry.valueName)") }
    if (-not $entry.valueName) {
        if (-not $script:AuditCompact[$item.Id].Contains(($entry.key -replace '\s', ''))) { $notInAuditText.Add("$($item.Id): $($entry.key)") }
        foreach ($example in @($entry.examples)) {
            if ($example -and -not $script:AuditCompact[$item.Id].Contains((("$($example.valueName)=$($example.data)") -replace '\s', ''))) { $notInAuditText.Add("$($item.Id): example $($example.valueName) = $($example.data)") }
        }
        continue
    }
    if ($entry.key -match ':|^\s|\s$|\s\s' -or $entry.valueName -match ':|^\s|\s$|\s\s' -or ($entry.valueName -match '\s' -and $entry.valueName -ne '<numeric value>')) { $malformed.Add("$($item.Id): $($entry.key) :: $($entry.valueName)") }
    $separator = if ($entry.Contains('valueNameInferred')) { '\' } else { ':' }
    $compact = (($entry.key + $separator + $entry.valueName) -replace '\s', '')
    if (-not $script:AuditCompact[$item.Id].Contains($compact)) { $notInAuditText.Add("$($item.Id): $($entry.key):$($entry.valueName)") }
}
$wrappedEntries = @($registryEntries | Where-Object { $_.Entry.joinedFromWrappedLines })
$wrappedConfirmed = @($wrappedEntries | Where-Object { $confirmedEntries.Contains($_.Entry) }).Count
$entriesConfirmed = @($registryEntries | Where-Object { $confirmedEntries.Contains($_.Entry) }).Count
$verificationFailures = [System.Collections.Generic.List[string]]::new()
foreach ($m in $malformed) { $verificationFailures.Add("Malformed registry location: $m") }
foreach ($m in $notInAuditText) { $verificationFailures.Add("Registry location is not in the PDF Audit text (characters dropped or added): $m") }

# (e) Data types: a REG_DWORD rule holds numbers, a REG_SZ or REG_MULTI_SZ rule holds
#     strings. An entry the PDF itself contradicts is allowed only with typeConflict.
$typeErrors = [System.Collections.Generic.List[string]]::new()
foreach ($item in $registryEntries) {
    $entry = $item.Entry; $rule = $entry.expected
    if (-not $rule) { continue }
    $ruleValues = @(foreach ($name in @('value', 'minimum', 'maximum', 'values', 'excluding')) { if ($rule.Contains($name)) { $rule[$name] } })
    $numbers = @($ruleValues | Where-Object { $_ -is [long] -or $_ -is [int] }).Count
    $strings = @($ruleValues | Where-Object { $_ -is [string] }).Count
    switch -Regex ([string]$entry.valueType) {
        '^REG_DWORD$'                     { if ($strings -and -not $entry.Contains('typeConflict')) { $typeErrors.Add("$($item.Id) $($entry.valueName): REG_DWORD with text values and no typeConflict note.") } }
        '^REG_(SZ|MULTI_SZ|EXPAND_SZ)$'   { if ($numbers) { $typeErrors.Add("$($item.Id) $($entry.valueName): $($entry.valueType) with numeric values.") } }
        ' or '                            { if (-not $entry.Contains('typeNote')) { $typeErrors.Add("$($item.Id) $($entry.valueName): type '$($entry.valueType)' without typeNote.") } }
        '^$'                              { if (-not ([string]$entry.expectedText).StartsWith('should be set to ')) { $typeErrors.Add("$($item.Id) $($entry.valueName): no value type.") } }
    }
}
foreach ($m in $typeErrors) { $verificationFailures.Add("Data type: $m") }

# (f) Round trip: rebuild the expected-value sentence from each parsed rule and
#     compare it with the sentence as printed. Catches values or types that were
#     read wrongly. Rules that are not built from numbers (blank, anyText) only
#     have to point at the matching words.
$roundTripErrors = [System.Collections.Generic.List[string]]::new()
foreach ($item in $registryEntries) {
    $entry = $item.Entry; $rule = $entry.expected
    if (-not $rule) { continue }
    $printed = ([string]$entry.expectedText -replace '[\s,.`]', '').ToLowerInvariant()
    $ok = switch ($rule.kind) {
        'blank'   { $printed -match 'blank' }
        'anyText' { $printed -match 'valueoftext$|<path>' }
        default {
            if ($printed -match '\(\w+\)and') {
                # Two values in one sentence: this entry's part must be there, with its type.
                $value = if ($rule.Contains('value')) { $rule.value } else { '' }
                $printed.Contains((("$value($($entry.valueName))") -replace '[\s,.`]', '').ToLowerInvariant()) -and $printed.Contains(([string]$entry.valueType).ToLowerInvariant())
            } else {
                @(Get-RuleRendering $entry) -contains $printed
            }
        }
    }
    if (-not $ok) { $roundTripErrors.Add("$($item.Id) $($entry.valueName): rule $($rule | ConvertTo-Json -Compress) does not match the printed '$($entry.expectedText)'") }
}
foreach ($m in $roundTripErrors) { $verificationFailures.Add("Round trip: $m") }

# (g) Every text field must consist of characters printed in that recommendation, in
#     the same order (ignoring whitespace). Catches text taken from the wrong place
#     or damaged while joining lines.
$textErrors = [System.Collections.Generic.List[string]]::new()
$textFields = @('title', 'groupPolicyPath', 'remediationCommand', 'remediationRegistryValue', 'description', 'rationale', 'defaultValue', 'impact', 'auditText', 'remediationText', 'additionalInformation', 'serviceName', 'auditSubcategoryGuid')
foreach ($control in $controls) {
    $haystack = $script:BlockCompact[$control.id]
    foreach ($field in $textFields) {
        $value = $control[$field]
        if (-not $value) { continue }
        if (-not $haystack.Contains(([string]$value -replace '\s', ''))) { $textErrors.Add("$($control.id).$field") }
    }
    foreach ($state in @($control.expectedState)) { if ($state -and -not $haystack.Contains(([string]$state -replace '\s', ''))) { $textErrors.Add("$($control.id).expectedState") } }
    foreach ($account in @($control.accounts)) { if ($account -and -not $haystack.Contains(($account -replace '\s', ''))) { $textErrors.Add("$($control.id).accounts '$account'") } }
    foreach ($entry in $control.registry) { if ($entry.expectedText -and -not $haystack.Contains(($entry.expectedText -replace '\s', ''))) { $textErrors.Add("$($control.id).registry.expectedText") } }
    foreach ($reference in @($control.references)) { if (-not $haystack.Contains(($reference -replace '\s', ''))) { $textErrors.Add("$($control.id).references '$reference'") } }
    # CIS Controls titles: in the table text without circles and version labels, because a
    # wrapped title can have a circle or a label printed between its lines.
    $tableHaystack = ([string]$script:SectionCompact[$control.id]['cisControls']) -replace [regex]::Escape([string][char]0x25CF), ''
    foreach ($row in @($control.cisControls)) { if ($row.title -and -not $tableHaystack.Contains(("$($row.id)$($row.title)" -replace '\s', ''))) { $textErrors.Add("$($control.id).cisControls $($row.version) $($row.id)") } }
}
foreach ($m in $textErrors) { $verificationFailures.Add("Text not found in the PDF recommendation: $m") }

# (h) Leftovers of the PDF layout that must not reach the data: page footers, form
#     feeds, page-break markers, runs of spaces, spaces around a line feed, and a line
#     break inside a hyphenated word ("stand- alone").
$layoutErrors = [System.Collections.Generic.List[string]]::new()
foreach ($control in $controls) {
    $values = [ordered]@{}
    foreach ($field in @('title', 'groupPolicyPath', 'description', 'rationale', 'defaultValue', 'impact', 'auditText', 'remediationText', 'additionalInformation', 'remediationCommand')) { $values[$field] = [string]$control[$field] }
    $n = 0; foreach ($reference in @($control.references)) { $n++; $values["references[$n]"] = [string]$reference }
    foreach ($row in @($control.cisControls)) { $values["cisControls $($row.id)"] = (@($row.title, $row.description) | Where-Object { $_ }) -join "`n" }
    foreach ($pair in $values.GetEnumerator()) {
        if ($pair.Value -match "\bPage \d+\b(?!\s*of)|\f|$([regex]::Escape($script:PageBreak))|[ \t]{2,}| \n|\n |^\s|\s$|\n\n|[A-Za-z0-9]-\n|[A-Za-z0-9]- (?!(?:or|and|to) )[a-z]") { $layoutErrors.Add("$($control.id).$($pair.Key): '$($Matches[0])'") }
    }
}
foreach ($m in $layoutErrors) { $verificationFailures.Add("Layout leftover: $m") }

# (j) Completeness: every exported text section must be the whole section as printed
#     (the same characters, ignoring whitespace), not just a part of it. The character
#     check (g) cannot see a section that lost its end; this one can.
$completenessErrors = [System.Collections.Generic.List[string]]::new()
foreach ($control in $controls) {
    $printed = $script:SectionCompact[$control.id]
    foreach ($field in @('description', 'rationale', 'impact', 'defaultValue', 'auditText', 'remediationText', 'additionalInformation')) {
        $expected = if ($printed.ContainsKey($field)) { $printed[$field] } else { '' }
        if ((([string]$control[$field]) -replace '\s', '') -ne $expected) { $completenessErrors.Add("$($control.id).$field") }
    }
    $number = 0
    $numberedReferences = @(@($control.references) | ForEach-Object { $number++; "$number.$_" })
    if ((($numberedReferences -join '') -replace '\s', '') -ne $printed['references']) { $completenessErrors.Add("$($control.id).references") }
    if ($printed.ContainsKey('cisControls')) {
        # The -layout table without its header, the version labels and the circles must be
        # the text of the rows read from the -table text (two independent extractions).
        $mark = [regex]::Escape([string][char]0x25CF)
        $tableCompact = $printed['cisControls'] -replace $mark, ''
        $rowText = (@($control.cisControls | ForEach-Object { "$($_.id)$($_.title)$($_.description)" }) -join '') -replace '\s', ''
        if ($tableCompact -ne $rowText) {
            $k = 0; while ($k -lt [Math]::Min($tableCompact.Length, $rowText.Length) -and $tableCompact[$k] -eq $rowText[$k]) { $k++ }
            $completenessErrors.Add("$($control.id).cisControls (from character $k, -layout: '$($tableCompact.Substring($k, [Math]::Min(40, $tableCompact.Length - $k)))', -table: '$($rowText.Substring($k, [Math]::Min(40, $rowText.Length - $k)))')")
        }
        $circles = @($control.cisControls | ForEach-Object { $g = @($_.implementationGroups).Count; $g }) | Measure-Object -Sum
        if ($circles.Sum -ne ([regex]::Matches($printed['cisControls'], $mark)).Count) { $completenessErrors.Add("$($control.id).cisControls implementation group marks: $($circles.Sum) in the rows, $(([regex]::Matches($printed['cisControls'], $mark)).Count) printed") }
    }
}
foreach ($m in $completenessErrors) { $verificationFailures.Add("Exported text is not the whole PDF section: $m") }

# (k) Hyphens at line ends. The text keeps such a hyphen and joins without a space, which
#     is right only if the benchmark never splits a word across lines. A join "word-part"
#     that is printed elsewhere without the hyphen ("wordpart"), but never with it in the
#     middle of a line, looks like a split word and fails. URLs, GUIDs and paths are exempt.
$hyphenErrors = [System.Collections.Generic.List[string]]::new()
# Loops and array operators instead of pipelines here: the body has tens of thousands of lines.
$bodyLines = [string[]]::new($bodyEnd - $bodyStart + 1)
for ($i = 0; $i -lt $bodyLines.Count; $i++) { $bodyLines[$i] = $all[$bodyStart + $i].TrimStart([char]12).Trim() }
$flatBody = [string]::Join(' ', [string[]]($bodyLines -ne '' -notmatch '^Page \d+$'))
# The words of the body, collected once (searching the whole body text for every hyphen took
# seconds). A word is a run of letters, digits and hyphens. "left-right" appears closed when a
# whole word is "leftright" (any case), and with its hyphen when "left" and "right" are
# neighbouring parts of a word (case kept): the words with a hyphen are joined as
# " -word- -word- ", so that is a search for "-left-right-". This finds exactly what the
# searches (?i)(?<![A-Za-z0-9-])leftright(?![A-Za-z0-9-]) and
# (?<![A-Za-z0-9])left-right(?![A-Za-z0-9]) find. Splitting and joining run in .NET, not in a
# PowerShell loop over every word.
$words = [regex]::Split($flatBody, '[^A-Za-z0-9-]+')
$bodyWords = [System.Collections.Generic.HashSet[string]]::new([string[]]$words, [System.StringComparer]::OrdinalIgnoreCase)
$hyphenatedWords = ' -' + [string]::Join('- -', [string[]]($words -like '*-*')) + '- '
$checkedJoins = @{}
for ($i = 0; $i -lt $bodyLines.Count - 1; $i++) {
    # EndsWith first: the pattern alone is tried from every position of every line, which took
    # seconds, although only a few hundred lines end with a hyphen.
    if (-not $bodyLines[$i].EndsWith('-') -or $bodyLines[$i] -notmatch '(\S*?)([A-Za-z0-9]+)-$') { continue }
    $token = $Matches[0]; $left = $Matches[2]
    if ($token -match '://|www\.|/|\\|^\{|[0-9A-Fa-f]{8}-') { continue }
    $k = $i + 1
    while ($k -lt $bodyLines.Count -and (-not $bodyLines[$k] -or $bodyLines[$k] -match '^Page \d+$')) { $k++ }
    if ($k -ge $bodyLines.Count -or $bodyLines[$k] -notmatch '^([A-Za-z0-9]+)') { continue }
    $right = $Matches[1]
    $key = "$left-$right"
    if ($checkedJoins.ContainsKey($key)) { continue }
    $checkedJoins[$key] = $true
    $hyphenated = $hyphenatedWords.IndexOf("-$key-", [System.StringComparison]::Ordinal) -ge 0
    $closed = $bodyWords.Contains($left + $right)
    if ($closed -and -not $hyphenated) { $hyphenErrors.Add("line $($bodyStart + $i + 1): '$left-' + '$right' is printed elsewhere as '$left$right'") }
}
foreach ($m in $hyphenErrors) { $verificationFailures.Add("Line-end hyphen looks like a split word: $m") }

# (l) Registry line layout: the wrap rule needs registry lines of at most the wrap width,
#     and no registry location may continue after a blank line or a page break.
foreach ($m in $script:RegistryLayoutErrors) { $verificationFailures.Add("Registry layout: $m") }
# (i) A Group Policy path must be complete: it ends with the setting name quoted in
#     the title. The character check (g) cannot see a path that lost its last line,
#     but this check can. Accepted forms, each seen in the benchmark: the title adds
#     a prefix ("Windows Firewall: Private: Logging: ", "Security: "), the PDF prints
#     "MSS:(" in the path but "MSS: (" in the title, the path names the policy plus a
#     note in brackets, or the title names an option of the policy ("Policy: Option").
$pathErrors = [System.Collections.Generic.List[string]]::new()
foreach ($control in $controls) {
    if (-not $control.groupPolicyPath) { continue }
    $settingName = [regex]::Match($control.title, "(?i)^(?:Ensure|Configure) '(.+?)'(?: is| to|$)").Groups[1].Value
    if (-not $settingName) { continue }
    $path = $control.groupPolicyPath
    $lastSegment = ($path -split '\\')[-1]
    $complete = $path.EndsWith($settingName) -or
        $path.EndsWith(($settingName -replace '^Windows Firewall: (Domain|Private|Public): (Settings: |Logging: )?', '')) -or
        $path.EndsWith(($settingName -replace '^(Application|Security|Setup|System): ', '')) -or
        $path.EndsWith(($settingName -replace '^MSS: \(', 'MSS:(')) -or
        $lastSegment.StartsWith("$settingName (") -or
        $settingName.StartsWith("${lastSegment}: ") -or
        ($settingName -match '^([^:]+): ' -and $lastSegment.StartsWith("$($Matches[1]): ")) -or
        # Same words, but a different case, a comma, or a period at the end of the path.
        ((($lastSegment -replace '[,.]', '').Trim()) -eq (($settingName -replace '[,.]', '').Trim()))
    if (-not $complete) {
        if ($script:Benchmark.WindowsBaseline) {
            $pathErrors.Add("$($control.id): path ends with '$lastSegment', title names '$settingName'")
        } else {
            # The browser benchmarks have a few titles that name the policy slightly differently
            # from its Group Policy path. That is an inconsistency of the PDF, not of the
            # parser, so it is recorded for the recommendation instead of stopping the run.
            $control.parserWarnings = @($control.parserWarnings) + "Group Policy path ends with '$lastSegment', but the title names '$settingName'."
            $totalWarnings++
        }
    }
}
foreach ($m in $pathErrors) { $verificationFailures.Add("Group Policy path incomplete or wrong: $m") }
if ($summaryCount -ne $controls.Count) { $verificationFailures.Add("The appendix summary table lists $summaryCount recommendations, but $($controls.Count) were extracted.") }
if ($summaryManualCount -ne $manualCount) { $verificationFailures.Add("The appendix lists $summaryManualCount Manual recommendations, but $manualCount were extracted.") }
foreach ($mismatch in $pageMismatches) { $verificationFailures.Add($mismatch) }
if ($incomplete.Count) { $verificationFailures.Add("Recommendations without a level, assessment or title: $($incomplete -join ', ').") }
$verification = [ordered]@{
    tableOfContentsMatchesBody = $true
    summaryTableCount = $summaryCount
    summaryTableManualCount = $summaryManualCount
    pageNumberMismatches = $pageMismatches.Count
    registryLocations = $registryEntries.Count
    registryLocationsWrappedInPdf = $wrappedEntries.Count
    registryLocationsFoundInPdfAuditText = $registryEntries.Count - $notInAuditText.Count
    expectedValueRulesRoundTripped = @($registryEntries | Where-Object { $_.Entry.expected }).Count - $roundTripErrors.Count
    dataTypeErrors = $typeErrors.Count
    typeConflictsInPdf = @($registryEntries | Where-Object { $_.Entry.Contains('typeConflict') } | ForEach-Object { "$($_.Id) $($_.Entry.valueName)" })
    textFieldsNotFoundInPdf = $textErrors.Count
    layoutLeftovers = $layoutErrors.Count
    textSectionsComplete = $completenessErrors.Count -eq 0
    lineEndHyphensChecked = $checkedJoins.Count
    lineEndHyphensLikeSplitWords = $hyphenErrors.Count
    registryLayoutErrors = $script:RegistryLayoutErrors.Count
    groupPolicyPathsComplete = @($controls | Where-Object { $_.groupPolicyPath }).Count - $pathErrors.Count
    wrappedRegistryJoinsWithSpace = @($script:SpaceJoins | Sort-Object -Unique).Count
    failures = @($verificationFailures)
}
if ($verificationFailures.Count -gt 0) { throw "Verification failed, nothing was written:`n - $($verificationFailures -join "`n - ")" }

# ---------------------------------------------------------------------------
# 8. Write
# ---------------------------------------------------------------------------
$document = [ordered]@{
    benchmark = $script:Benchmark.Name
    version = $(if ($PdfPath -match '_v(\d+\.\d+\.\d+)\.pdf$') { "v$($Matches[1])" } else { $null })
    sourcePdf = Split-Path -Leaf $PdfPath
    sourcePdfSha256 = $pdfHash
    textExtractor = $textExtractor
    generatedBy = Split-Path -Leaf $PSCommandPath
    generatedOn = (Get-Date).ToString('yyyy-MM-dd')
    notes = @(
        'One object per recommendation, in benchmark order. page is the printed page number; pdfPage is the page index in the PDF file (printed page + 1).'
        'level is L1 or L2 when the recommendation is in the plain Level 1 or Level 2 profile. BL means it is only in profiles that include BitLocker (BitLocker (BL), Level 1 (L1) + BitLocker (BL), Level 2 (L2) + BitLocker (BL)). profiles lists every profile exactly as printed.'
        'expectedState is the quoted state from the title; comparison says how it applies (equals, notEquals, anyOf, includes, configured, configure).'
        'registry lists the locations from the Audit section. expected is the parsed rule (kind: equals, anyOf, minimum, maximum, range, notEquals, blank, list, equalsText, anyText, unparsed); expectedText is the sentence as printed. A list policy (Chrome) is one entry for its key with valueName null, listValues true and the example values printed in the PDF (examples); valueNameInferred true means the PDF printed no colon before the value name and the last part of the path was taken as the value name, because a single value is expected.'
        'valueType is the registry data type exactly as printed in the PDF. The values in expected carry that type: JSON numbers for REG_DWORD, JSON strings for REG_SZ and REG_MULTI_SZ (for example the string "0", not the number 0). typeNote explains an entry for which the PDF allows two types. typeConflict marks an entry where the PDF states a type that cannot hold its own expected value; likelyValueType then gives the type the value must have. microsoftDocumentation records, for such entries, what Microsoft''s own documentation says about the type (valueType, summary, source, url, verifiedOn); where it differs from the PDF, Microsoft''s documentation is the correct one.'
        'description, rationale, impact, defaultValue, auditText, remediationText and additionalInformation are the sections as printed. Each paragraph or list item is one line (separated by a line feed); the line breaks inside a paragraph are joined. A line that ends with a letter or digit followed by a hyphen continues without a space (the hyphen is part of the word; the benchmark does not split words across lines). rationale explains why the setting matters for security; impact says what may stop working when it is applied.'
        'references lists the numbered references, one per item, with wrapped URLs joined. cisControls lists the CIS Controls table: version (v8 or v7), id, title, description and implementationGroups. Implementation groups are cumulative, so the number of circles printed gives them: three circles = 1, 2, 3; two = 2, 3; one = 3; none (for example 0.0 Explicitly Not Mapped) = an empty list.'
        'parserWarnings lists what the parser could not read for that recommendation. parserWarningCount in this header is the total.'
        "registry entries with joinedFromWrappedLines = true come from registry locations that the PDF wraps over several lines. A line of $($script:RegistryWrapWidth) characters continues in the middle of a word (and a line that ends with a hyphen continues without a space); any other wrapped line was broken at a space."
        'verification records the independent checks that ran when the file was generated: appendix count, page numbers, every registry location and text field found in the PDF text of its recommendation, every expected-value rule rebuilt into the printed sentence, data types consistent with the values, complete Group Policy paths, no layout leftovers, every text section complete, no line-end hyphen that looks like a split word, and registry lines within the wrap width. The file is written only when all of them pass. The comparison with Audit.ps1 and Remediations.ps1 is printed when the file is generated but not stored, so this file depends on the PDF alone. textExtractor names the pdftotext used.'
    )
    controlCount = $controls.Count
    levelCounts = [ordered]@{ L1 = @($controls | Where-Object level -eq 'L1').Count; L2 = @($controls | Where-Object level -eq 'L2').Count; BL = @($controls | Where-Object level -eq 'BL').Count }
    parserWarningCount = $totalWarnings
    verification = $verification
    sections = @($tocSections.GetEnumerator() | ForEach-Object { [ordered]@{ id = $_.Key; title = $_.Value } })
    controls = @($controls)
}
$json = $document | ConvertTo-Json -Depth 12
# ConvertTo-Json in Windows PowerShell escapes a few characters that are safe in JSON.
$json = $json -replace '\\u0027', "'" -replace '\\u0026', '&' -replace '\\u003c', '<' -replace '\\u003e', '>'
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))

Write-Host "Wrote $OutputPath"
Write-Host "Recommendations: $($controls.Count) (table of contents: $($tocControls.Count)); parser warnings: $totalWarnings in $(@($controls | Where-Object { $_.parserWarnings.Count -gt 0 }).Count) recommendations."
if ($totalWarnings -gt 0) {
    foreach ($control in ($controls | Where-Object { $_.parserWarnings.Count -gt 0 })) { foreach ($w in $control.parserWarnings) { Write-Host "  $($control.id): $w" -ForegroundColor Yellow } }
}
Write-Host "Registry locations joined from wrapped lines with a space ($($script:SpaceJoins.Count)); review that each is a real word break:"
foreach ($join in ($script:SpaceJoins | Sort-Object -Unique)) { Write-Host "  $join" }
if ($script:Benchmark.WindowsBaseline) {
    Write-Host "Cross-check against the baseline scripts (not written to the JSON): $compared registry references compared, $entriesConfirmed registry locations confirmed ($wrappedConfirmed of them wrapped in the PDF), $($crossCheck.Count) differences."
} else {
    Write-Host "Cross-check against the baseline scripts skipped: Audit.ps1 and Remediations.ps1 refer to the Windows benchmark by CIS number, and the numbers of $($script:Benchmark.Name) overlap with it."
}
foreach ($difference in $crossCheck) { Write-Host "  $difference" -ForegroundColor Yellow }
