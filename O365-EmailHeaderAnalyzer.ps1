#> Functions
function Get-ExternalSenderIP {
    param ($headers)

    # Check for "Received:" lines first (IPv4)
    $matches = [regex]::Matches($headers, "Received: from \S+ \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)")
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            $ip = $match.Groups[1].Value
            if ($ip -notmatch "^127\." -and $ip -notmatch "^10\." -and $ip -notmatch "^192\." -and $ip -notmatch "^172\.") {
                return $ip
            }
        }
    }

    # Check for "Received:" lines first (IPv6)
    $matches = [regex]::Matches($headers, "Received: from \S+ \(\[?([a-fA-F0-9:]+)\]?\)")
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            $ip = $match.Groups[1].Value
            if ($ip -notmatch "^::1$" -and $ip -notmatch "^fc00:" -and $ip -notmatch "^fd00:" -and $ip -notmatch "^fe80:") {
                return $ip
            }
        }
    }

    # Check for "Received-SPF:" lines (IPv4)
    $matches = [regex]::Matches($headers, "Received-SPF: \S+ \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)")
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            $ip = $match.Groups[1].Value
            if ($ip -notmatch "^127\." -and $ip -notmatch "^10\." -and $ip -notmatch "^192\." -and $ip -notmatch "^172\.") {
                return $ip
            }
        }
    }

    # Check for "Received-SPF:" lines (IPv6)
    $matches = [regex]::Matches($headers, "Received-SPF: \S+ \(\[?([a-fA-F0-9:]+)\]?\)")
    if ($matches.Count -gt 0) {
        foreach ($match in $matches) {
            $ip = $match.Groups[1].Value
            if ($ip -notmatch "^::1$" -and $ip -notmatch "^fc00:" -and $ip -notmatch "^fd00:" -and $ip -notmatch "^fe80:") {
                return $ip
            }
        }
    }

    return "not found"
}

function Get-Headers {
    $headers = $txtHeaders.Text
    if ([string]::IsNullOrWhiteSpace($headers)) { return }

    $textboxes["Sender IP"].Text = Get-ExternalSenderIP $headers

    $spfStatus = if ($headers -match "spf=(pass|fail|softfail|neutral)") { $matches[1] } else { "Unknown" }
    $dkimStatus = if ($headers -match "dkim=(pass|fail|none)") { $matches[1] } else { "Unknown" }
    $dmarcStatus = if ($spfStatus -eq "pass" -and $dkimStatus -eq "pass") { "Compliant" } else { "Non-Compliant" }


    $textboxes["SPF"].Text = $spfStatus
    $textboxes["DKIM"].Text = $dkimStatus
    $textboxes["DMARC"].Text = $dmarcStatus

    $emojiLabels["SPF"].Text = if ($spfStatus -eq "pass") { " $greenCheck" } else { " $redCross" }
    $emojiLabels["DKIM"].Text = if ($dkimStatus -eq "pass") { " $greenCheck" } else { " $redCross" }
    $emojiLabels["DMARC"].Text = if ($dmarcStatus -eq "Compliant") { " $greenCheck" } else { " $redCross" }

    $classification = "External"
    if ($headers -match "X-MS-Exchange-Organization-AuthAs:\s*(\w+)") {
        switch ($matches[1]) {
            "Internal"      { $classification = "Internal" }
            "Partner"       { $classification = "Internal (Partner)" }
            "Anonymous"     { $classification = "External" }
            "Authenticated" { $classification = "External" }
        }
    }
    $textboxes["O365 Classification"].Text = $classification
    $textboxes["Message Source"].Text = $classification

    # Subject (raw MIME-safe, compliance copy/paste)
    $subject = "ERROR / NOT FOUND"
    if ($headers -match "(?m)^Subject:\s*(.+)$") {
        $rawSubject = $matches[1].Trim()
        if ($rawSubject -match "^\=\?utf-8\?q\?(.+?)\?=$") {
            # Extract without decoding, preserve underscores
            $subject = $matches[1]
        } else {
            $subject = $rawSubject
        }
    }
    $textboxes["Subject (Header)"].Text = $subject

    # Sender (Auth)
    $senderAuth = "NOT FOUND (Potentially Spoofed/Spam/Phishing)"
    if ($headers -match "(?m)^Sender:\s*(.+)$") {
        $senderAuth = $matches[1].Trim()
        if ($senderAuth -match "<(.+?)>") {
            $senderAuth = $matches[1]
        }
    } elseif ($headers -match "(?m)^From:\s*(.+)$") {
        $senderAuth = $matches[1].Trim()
        if ($senderAuth -match "<(.+?)>") {
            $senderAuth = $matches[1]
        }
    }
    if ($headers -match "X-MS-Exchange-Organization-AuthAs:\s*Anonymous") {
        $senderAuth += " (Unauthenticated / Likely Spoofed)"
        }
    $textboxes["Sender (Auth)"].Text = $senderAuth


    # Sender (Envelope / Return Path)
    $envelopeSender = if ($headers -match "Return-Path:\s*<?([^>\s]+)>?") {
        $matches[1].Trim()
    } else {
        "NOT FOUND (Potentially Spoofed/Spam/Phishing)"
    }
    $textboxes["Sender (Envelope)"].Text = $envelopeSender

    # Sender (Header / Outlook)
    $headerSender = "NOT FOUND (Potentially Spoofed/Spam/Phishing)"
    if ($headers -match "(?m)^From:\s*(.+)$") {
        $headerSender = $matches[1].Trim()
        if ($headerSender -match "<(.+?)>") {
            $headerSender = $matches[1]
        }
    }
    $textboxes["Sender (Header)"].Text = $headerSender
}

#> GUI 
Add-Type -AssemblyName System.Windows.Forms
$greenCheck = [char]::ConvertFromUtf32(0x2705)
$redCross = [char]::ConvertFromUtf32(0x274C)

$form = New-Object System.Windows.Forms.Form
$form.Text = "O365 - Email Header Analyzer (AdminVin)"
#$form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon("C:\GitHub\O365-EmailHeaderAnalyzer\email_icon.ico")
$form.Size = New-Object System.Drawing.Size(600, 580)
$form.StartPosition = "CenterScreen"
#$form.TopMost = $true

$lblMessageDetails = New-Object System.Windows.Forms.Label
$lblMessageDetails.Text = "Message Details:"
$lblMessageDetails.Location = New-Object System.Drawing.Point(10, 10)
$lblMessageDetails.AutoSize = $true
$form.Controls.Add($lblMessageDetails)

$form.Controls.Add($lblMessageDetails)

$btnPaste = New-Object System.Windows.Forms.Button
$btnPaste.Size = New-Object System.Drawing.Size(30, 25)
$btnPaste.Location = New-Object System.Drawing.Point(540, 5)
$btnPaste.Font = New-Object System.Drawing.Font("Segoe UI Emoji", 12)
$btnPaste.Text = [char]::ConvertFromUtf32(0x1F4CB)
$btnPaste.Add_Click({
    if ([Windows.Forms.Clipboard]::ContainsText()) {
        $txtHeaders.Text = [Windows.Forms.Clipboard]::GetText()
    }
})
$form.Controls.Add($btnPaste)


$txtHeaders = New-Object System.Windows.Forms.TextBox
$txtHeaders.Multiline = $true
$txtHeaders.ScrollBars = "Vertical"
$txtHeaders.Size = New-Object System.Drawing.Size(560, 150)
$txtHeaders.Location = New-Object System.Drawing.Point(10, 30)
$txtHeaders.Add_Click({ $txtHeaders.Clear() })
$form.Controls.Add($txtHeaders)

$labels = @("Sender IP", "SPF", "DKIM", "DMARC", "Subject (Header)", "Sender (Auth)", "Sender (Envelope)", "Sender (Header)", "O365 Classification", "Message Source")
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
    if ($label -in @("Subject (Header)", "Sender (Auth)","Sender (Envelope)", "Sender (Header)")) {
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
            [System.Windows.Forms.Clipboard]::SetText($textboxes["Sender IP"].Text)
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
        Get-Headers
    }
})

$form.ShowDialog()