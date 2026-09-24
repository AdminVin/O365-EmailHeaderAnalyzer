#> Functions
function Read-HeaderFields {
    param([string]$Headers)
    $fields = [System.Collections.Generic.List[object]]::new()
    $current = $null
    foreach ($line in ($Headers -split '\r\n|\n|\r')) {
        if ($line.Length -eq 0) { break }
        if ($line -match '^[ \t]') {
            if ($null -ne $current) { $current.Value += ' ' + $line.Trim() }
        } elseif ($line -match '^([^\s:]+):[ \t]*(.*)$') {
            $current = [pscustomobject]@{ Name = $matches[1]; Value = $matches[2] }
            $fields.Add($current)
        } else { $current = $null }
    }
    $fields.ToArray()
}

function Get-SingleHeader {
    param($Fields, [string]$Name)
    $items = @($Fields | Where-Object { $_.Name -ieq $Name })
    if ($items.Count -gt 1) { return 'Unknown (multiple headers)' }
    if ($items.Count -eq 0) { return 'NOT FOUND' }
    if ([string]::IsNullOrWhiteSpace($items[0].Value)) { return '(empty)' }
    $items[0].Value.Trim()
}

function ConvertTo-PublicIP {
    param([string]$Value)
    $value = $Value.Trim().Trim('[', ']') -replace '^(?i)IPv6:', ''
    $address = $null
    if ($value -match '%' -or -not [System.Net.IPAddress]::TryParse($value, [ref]$address)) { return }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4(); $value = $address.ToString() }
    $b = $address.GetAddressBytes()
    if ($b.Length -eq 4) {
        if ($value -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return }
        if ($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or
            ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
            ($b[0] -eq 169 -and $b[1] -eq 254) -or
            ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
            ($b[0] -eq 192 -and ($b[1] -eq 168 -or ($b[1] -eq 0 -and $b[2] -in @(0,2)) -or ($b[1] -eq 88 -and $b[2] -eq 99))) -or
            ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or
            ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) { return }
    } else {
        # Require global unicast; exclude documentation and special transition ranges.
        if (($b[0] -band 0xE0) -ne 0x20 -or
            ($b[0] -eq 0x20 -and $b[1] -eq 1 -and $b[2] -lt 2) -or
            ($b[0] -eq 0x20 -and $b[1] -eq 1 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8) -or
            ($b[0] -eq 0x20 -and $b[1] -eq 2) -or
            ($b[0] -eq 0x3f -and $b[1] -eq 0xff -and $b[2] -lt 0x10)) { return }
    }
    $address.ToString()
}

function Get-ExternalSenderIP {
    param([string]$Headers)
    $fields = @(Read-HeaderFields $Headers)
    $received = @($fields | Where-Object Name -IEQ 'Received')
    # Prefer the peer recorded at the Microsoft 365 ingress boundary, not internal relays.
    $boundary = @($received | Where-Object { $_.Value -match '(?i)\bby\s+[a-z0-9.-]+\.mail\.protection\.outlook\.com\b' })
    $hops = if ($boundary.Count) { @($boundary[0]) } else { $received }
    foreach ($hop in $hops) {
        $peer = [regex]::Match($hop.Value, '(?i)^from\s+(.+?)\s+by\s+')
        if (-not $peer.Success) { continue }
        foreach ($token in ($peer.Groups[1].Value -split '[\s()\[\],;]+')) {
            $ip = ConvertTo-PublicIP $token
            if ($ip) { return $ip }
        }
        if ($boundary.Count) { return 'not found' }
    }
    foreach ($spf in @($fields | Where-Object Name -IEQ 'Received-SPF')) {
        if ($spf.Value -match '(?i)(?:^|[;\s])client-ip\s*=\s*([^;\s]+)') {
            $ip = ConvertTo-PublicIP $matches[1]
            if ($ip) { return $ip }
        }
    }
    'not found'
}

function Split-AuthenticationClauses {
    param([string]$Value)
    # Tokenize comments and quoted strings together; semicolons inside either are data.
    $parts = [System.Collections.Generic.List[string]]::new()
    $buffer = [System.Text.StringBuilder]::new()
    $depth = 0; $quoted = $false; $escaped = $false
    foreach ($char in $Value.ToCharArray()) {
        if ($escaped) {
            if ($depth -eq 0) { [void]$buffer.Append($char) }
            $escaped = $false; continue
        }
        if (($depth -gt 0 -or $quoted) -and $char -eq '\') {
            if ($quoted -and $depth -eq 0) { [void]$buffer.Append($char) }
            $escaped = $true; continue
        }
        if ($depth -gt 0) {
            if ($char -eq '(') { $depth++ }
            if ($char -eq ')') { $depth-- }
            continue
        }
        if ($char -eq '"') { $quoted = -not $quoted; [void]$buffer.Append($char); continue }
        if (-not $quoted -and $char -eq '(') { $depth = 1; [void]$buffer.Append(' '); continue }
        if (-not $quoted -and $char -eq ')') { return }
        if (-not $quoted -and $char -eq ';') {
            $parts.Add($buffer.ToString().Trim()); [void]$buffer.Clear()
        } else { [void]$buffer.Append($char) }
    }
    if ($depth -ne 0 -or $quoted -or $escaped) { return }
    $parts.Add($buffer.ToString().Trim())
    $parts.ToArray()
}

function Get-AuthenticationSummary {
    param([string]$Headers)
    $result = @{ SPF='Unknown'; DKIM='Unknown'; DMARC='Unknown'; SPFDomain='not recorded';
        DKIMDomain='not recorded'; FromDomain='not recorded'; Source='unidentified';
        Note='Reported results only. Source provenance cannot be verified from pasted headers.' }
    $authHeaders = @(Read-HeaderFields $Headers | Where-Object Name -IEQ 'Authentication-Results')
    if ($authHeaders.Count -ne 1) {
        $result.Note += if ($authHeaders.Count) { ' Multiple result headers; no trusted source selected.' } else { ' Authentication-Results missing.' }
        return [pscustomobject]$result
    }
    $clauses = @(Split-AuthenticationClauses $authHeaders[0].Value)
    if (-not $clauses.Count) { $result.Note += ' Malformed authentication header.'; return [pscustomobject]$result }
    if ($clauses[0] -notmatch '^(?i)(spf|dkim|dmarc|compauth)(\s*/\s*\d+)?\s*=') {
        $result.Source = $clauses[0]
        if ($clauses[0] -match '\s+(\d+)$' -and $matches[1] -ne '1') {
            $result.Note += ' Unsupported authentication header version.'; return [pscustomobject]$result
        }
        $clauses = @($clauses | Select-Object -Skip 1)
    }
    $result.Note += " Claimed authentication service: $($result.Source)."
    foreach ($method in @('SPF','DKIM','DMARC')) {
        $entries = @()
        foreach ($clause in $clauses) {
            $m = [regex]::Match($clause, ('(?i)^' + $method + '(?:\s*/\s*(\d+))?\s*=\s*([^\s;]*)(.*)$'))
            if (-not $m.Success) { continue }
            $status = $m.Groups[2].Value.ToLowerInvariant()
            $allowed = switch ($method) {
                SPF { @('pass','fail','softfail','neutral','none','temperror','permerror') }
                DKIM { @('pass','fail','none','neutral','policy','temperror','permerror') }
                DMARC { @('pass','fail','none','temperror','permerror','bestguesspass') }
            }
            if ($status -notin $allowed -or ($m.Groups[1].Success -and $m.Groups[1].Value -ne '1')) { $status = 'Unknown' }
            $properties = @{}
            # Consume complete property assignments; quoted reason strings cannot inject properties.
            $tail = $m.Groups[3].Value
            while (-not [string]::IsNullOrWhiteSpace($tail)) {
                $p = [regex]::Match($tail, '^\s+([a-zA-Z][a-zA-Z0-9_.-]*)\s*=\s*("(?:\\.|[^"\\])*"|[^\s"]+)')
                if (-not $p.Success) { $status = 'Unknown'; break }
                $key = $p.Groups[1].Value
                $value = $p.Groups[2].Value
                if ($value.StartsWith('"')) { $value = $value.Substring(1,$value.Length-2) -replace '\\(.)','$1' }
                if ($properties.ContainsKey($key)) { $status = 'Unknown' }
                $properties[$key] = $value
                $tail = $tail.Substring($p.Length)
            }
            $identity = switch ($method) {
                SPF {
                    if ($properties.ContainsKey('smtp.mailfrom')) { 'MAIL FROM: ' + $properties['smtp.mailfrom'] }
                    elseif ($properties.ContainsKey('smtp.helo')) { 'HELO: ' + $properties['smtp.helo'] }
                    else { 'not recorded' }
                }
                DKIM { if ($properties.ContainsKey('header.d')) { $properties['header.d'] } else { 'not recorded' } }
                DMARC { if ($properties.ContainsKey('header.from')) { $properties['header.from'] } else { 'not recorded' } }
            }
            $entries += [pscustomobject]@{ Status=$status; Identity=$identity }
        }
        if ($entries.Count) {
            $statuses = @($entries.Status | Select-Object -Unique)
            $result[$method] = if ($entries.Count -eq 1) { $statuses[0] } elseif ($statuses -contains 'Unknown') { 'Unknown' } elseif ($statuses.Count -eq 1) { $statuses[0] } else { 'Mixed' }
            $key = switch ($method) { SPF {'SPFDomain'} DKIM {'DKIMDomain'} DMARC {'FromDomain'} }
            $result[$key] = ($entries | ForEach-Object { "$($_.Identity) [$($_.Status)]" }) -join '; '
            if ($entries.Count -gt 1) { $result.Note += " $method has $($entries.Count) results; see identities and individual outcomes." }
        }
    }
    [pscustomobject]$result
}

function Get-AddressDisplay {
    param([string]$Value)
    if ($Value -in @('NOT FOUND','(empty)','Unknown (multiple headers)')) { return $Value }
    try { ([System.Net.Mail.MailAddress]::new($Value)).Address }
    catch { $Value } # Preserve unsupported/multiple mailbox syntax instead of guessing.
}

function Get-Headers {
    $headers = $txtHeaders.Text
    if ([string]::IsNullOrWhiteSpace($headers)) {
        foreach ($key in $textboxes.Keys) { $textboxes[$key].Text = '' }
        foreach ($key in $emojiLabels.Keys) { $emojiLabels[$key].Text = '' }
        $authToolTip.RemoveAll()
        return
    }
    $fields = @(Read-HeaderFields $headers)
    $textboxes['Sender IP'].Text = Get-ExternalSenderIP $headers
    $authToolTip.SetToolTip($textboxes['Sender IP'], 'Reported public peer at the Microsoft 365 ingress hop, when present; otherwise the first public Received peer or Received-SPF client-ip. This is a relay peer, not proof of the original author or verified provenance.')
    $authentication = Get-AuthenticationSummary $headers
    $textboxes['SPF'].Text = $authentication.SPF
    $textboxes['DKIM'].Text = $authentication.DKIM
    $textboxes['DMARC'].Text = switch ($authentication.DMARC) { pass {'Compliant'} fail {'Non-Compliant'} default {$authentication.DMARC} }
    foreach ($method in @('SPF','DKIM','DMARC')) {
        # Icons reflect recorded results; source-verification limits are explained in the UI.
        $emojiLabels[$method].Text = if ($authentication.$method -eq 'pass') { " $greenCheck" } elseif ($authentication.$method -in @('fail','softfail')) { " $redCross" } else { ' ?' }
    }
    $authToolTip.SetToolTip($textboxes['SPF'], "SPF identities: $($authentication.SPFDomain). Pass does not establish From alignment. $($authentication.Note)")
    $authToolTip.SetToolTip($textboxes['DKIM'], "Signing domains: $($authentication.DKIMDomain). Pass does not establish From alignment. $($authentication.Note)")
    $authToolTip.SetToolTip($textboxes['DMARC'], "From domains: $($authentication.FromDomain). Explicit recorded DMARC result. $($authentication.Note)")

    $authAs = Get-SingleHeader $fields 'X-MS-Exchange-Organization-AuthAs'
    $textboxes['O365 Classification'].Text = switch ($authAs) {
        Internal {'Internal'} Anonymous {'Anonymous'} Partner {'Partner'} Authenticated {'Authenticated'} default {'Unknown'}
    }
    $authToolTip.SetToolTip($textboxes['O365 Classification'], "Reported transport authentication class: $authAs. This does not establish the author's identity or physical message origin.")
    $source = Get-SingleHeader $fields 'X-MS-Exchange-CrossTenant-FromEntityHeader'
    $textboxes['Message Source'].Text = switch ($source) { Internet {'Internet'} Hosted {'Hosted'} HybridOnPrem {'HybridOnPrem'} default {'Unknown'} }
    $authToolTip.SetToolTip($textboxes['Message Source'], "Reported CrossTenant-FromEntityHeader: $source. Independent of AuthAs; unverified header claim.")

    # Keep the complete unfolded MIME representation for header/compliance searches.
    $textboxes['Subject (Header)'].Text = Get-SingleHeader $fields 'Subject'
    $authToolTip.SetToolTip($textboxes['Subject (Header)'], 'Complete unfolded Subject header. MIME encoded words are preserved exactly; this is not the decoded Outlook display subject.')
    $from = Get-SingleHeader $fields 'From'
    $sender = Get-SingleHeader $fields 'Sender'
    if ($sender -eq 'NOT FOUND') { $sender = $from }
    $textboxes['Sender (Claimed)'].Text = Get-AddressDisplay $sender
    $textboxes['Sender (Header)'].Text = Get-AddressDisplay $from
    $authToolTip.SetToolTip($textboxes['Sender (Claimed)'], 'Claimed Sender address, falling back to From only when Sender is absent. Not an authenticated identity.')

    $returnPath = Get-SingleHeader $fields 'Return-Path'
    $textboxes['Sender (Envelope)'].Text = if ($returnPath -match '^<\s*>$') { '<> (null reverse-path)' }
        elseif ($returnPath -in @('NOT FOUND','(empty)','Unknown (multiple headers)')) { $returnPath }
        elseif ($returnPath -match '^<([^<>]+)>$') { Get-AddressDisplay $matches[1] }
        else { 'Unknown (invalid Return-Path)' }
    $authToolTip.SetToolTip($textboxes['Sender (Envelope)'], 'Recorded Return-Path. A null reverse-path is valid for messages such as delivery notifications. Missing or empty headers alone do not establish spoofing.')
}
#> GUI 
Add-Type -AssemblyName System.Windows.Forms
$greenCheck = [char]::ConvertFromUtf32(0x2705)
$redCross = [char]::ConvertFromUtf32(0x274C)
$authToolTip = New-Object System.Windows.Forms.ToolTip

$form = New-Object System.Windows.Forms.Form
$form.Text = "O365 - Email Header Analyzer"
#$form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\GitHub\O365-EmailHeaderAnalyzer\email_icon.ico")
$form.Size = New-Object System.Drawing.Size(600, 580)
$form.StartPosition = "CenterScreen"
#$form.TopMost = $true

$lblMessageDetails = New-Object System.Windows.Forms.Label
$lblMessageDetails.Text = "Message Details (reported headers; source unverified):"
$lblMessageDetails.Location = New-Object System.Drawing.Point(10, 10)
$lblMessageDetails.AutoSize = $true
$form.Controls.Add($lblMessageDetails)

$btnPaste = New-Object System.Windows.Forms.Button
$btnPaste.Size = New-Object System.Drawing.Size(30, 25)
$btnPaste.Location = New-Object System.Drawing.Point(540, 5)
$btnPaste.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 12)
$btnPaste.Text = [char]::ConvertFromUtf32(0x1F4CB)
$btnPaste.Add_Click({
    try {
        if ([Windows.Forms.Clipboard]::ContainsText()) {
            $txtHeaders.Text = [Windows.Forms.Clipboard]::GetText()
        }
    } catch {
        [void][System.Windows.Forms.MessageBox]::Show($form, 'The clipboard is unavailable. Please try pasting again.', 'Clipboard', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
})
$form.Controls.Add($btnPaste)


$txtHeaders = New-Object System.Windows.Forms.TextBox
$txtHeaders.Multiline = $true
$txtHeaders.MaxLength = [int]::MaxValue
$txtHeaders.ScrollBars = "Vertical"
$txtHeaders.Size = New-Object System.Drawing.Size(560, 150)
$txtHeaders.Location = New-Object System.Drawing.Point(10, 30)
$txtHeaders.Add_Click({ $txtHeaders.Clear() })
$form.Controls.Add($txtHeaders)

$labels = @("Sender IP", "SPF", "DKIM", "DMARC", "Subject (Header)", "Sender (Claimed)", "Sender (Envelope)", "Sender (Header)", "O365 Classification", "Message Source")
$textboxes = @{}
$emojiLabels = @{}

$yPos = 200
foreach ($label in $labels) {
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "${label}:"
    $lbl.Location = New-Object System.Drawing.Point(10, $yPos)
    $lbl.AutoSize = $true
    $form.Controls.Add($lbl)

    $txt = New-Object System.Windows.Forms.TextBox
    $txt.Size = New-Object System.Drawing.Size(150, 20)
    if ($label -in @("Subject (Header)", "Sender (Claimed)","Sender (Envelope)", "Sender (Header)")) {
        $txt.Size = New-Object System.Drawing.Size(450, 20)
    } else {
        $txt.Size = New-Object System.Drawing.Size(150, 20)
    }
    $txt.Location = New-Object System.Drawing.Point(120, $yPos)
    $txt.ReadOnly = $true
    $form.Controls.Add($txt)
    $textboxes[$label] = $txt

    if ($label -eq "Sender IP") {
        # Copy Button
        $btnCopyIP = New-Object System.Windows.Forms.Button
        $btnCopyIP.Text = "Copy"
        $btnCopyIP.Size = New-Object System.Drawing.Size(50, 20)
        $btnCopyIP.Location = New-Object System.Drawing.Point(280, $yPos)
        $btnCopyIP.Add_Click({
            $ipToCopy = $textboxes['Sender IP'].Text
            if ([string]::IsNullOrWhiteSpace($ipToCopy) -or $ipToCopy -eq 'not found') { return }
            try {
                [System.Windows.Forms.Clipboard]::SetText($ipToCopy)
            } catch {
                [void][System.Windows.Forms.MessageBox]::Show($form, 'The clipboard is unavailable. Please try copying again.', 'Clipboard', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            }
        })
        $form.Controls.Add($btnCopyIP)
    
        # IP Info Button
        $btnIPInfo = New-Object System.Windows.Forms.Button
        $btnIPInfo.Text = "Info"
        $btnIPInfo.Size = New-Object System.Drawing.Size(50, 20)
        $btnIPInfo.Location = New-Object System.Drawing.Point(340, $yPos)
        $btnIPInfo.Add_Click({
            $ip = $textboxes["Sender IP"].Text
            if ($ip -and $ip -ne "not found") {
                Start-Process "https://ipinfo.io/$ip"
            }
        })
        $form.Controls.Add($btnIPInfo)
    }     

    if ($label -in @("SPF", "DKIM", "DMARC")) {
        $emojiLbl = New-Object System.Windows.Forms.Label
        $emojiLbl.Location = New-Object System.Drawing.Point(280, $yPos)
        $emojiLbl.AutoSize = $true
        $emojiLbl.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 10)
        $form.Controls.Add($emojiLbl)
        $emojiLabels[$label] = $emojiLbl
    }

    $yPos += 30
}

$lblSpacing = New-Object System.Windows.Forms.Label
$lblSpacing.Text = ""
$lblSpacing.Location = New-Object System.Drawing.Point(10, 400)
$lblSpacing.AutoSize = $true
$form.Controls.Add($lblSpacing)

$form.Add_Shown({ $txtHeaders.Focus() })

$form.add_FormClosed({
    param($sender, $e)
    $form.Dispose()
    $authToolTip.Dispose()
})




####################

$btnAnalyze = New-Object System.Windows.Forms.Button
$btnAnalyze.Text = "Analyze"
$btnAnalyze.Location = New-Object System.Drawing.Point(10, 505)
$btnAnalyze.Add_Click({ Get-Headers })
$form.Controls.Add($btnAnalyze)

$btnReset = New-Object System.Windows.Forms.Button
$btnReset.Text = "Reset"
$btnReset.Location = New-Object System.Drawing.Point(100,505)
$btnReset.Add_Click({
    $txtHeaders.Text = ""
    foreach ($key in $textboxes.Keys) { $textboxes[$key].Text = "" }
    foreach ($key in $emojiLabels.Keys) { $emojiLabels[$key].Text = "" }
    $authToolTip.RemoveAll()
})
$form.Controls.Add($btnReset)

$txtHeaders.Add_KeyDown({
    param ($sender, $e)
    if ($e.KeyCode -eq "Enter") {
        Get-Headers
        $e.SuppressKeyPress = $true
    }
})

$txtHeaders.Add_TextChanged({
    if (-not [string]::IsNullOrWhiteSpace($txtHeaders.Text)) {
        Start-Sleep -Milliseconds 1000
    }
    Get-Headers
})

$form.ShowDialog()
