# Email - Header Analyzer
<img src="https://github.com/AdminVin/EmailHeaderAnalyzer/blob/main/EmailHeaderAnalyzer-Screenshot.png?raw=true">

## What is "Email - Header Analyzer"?
**Email - Header Analyzer** is a lightweight PowerShell script designed to analyze Office 365 email headers and display the following information:
- **SPF** - Results: pass / fail / softfail / neutral / Unknown
- **DKIM** - Results: pass / fail / none / Unknown
- **DMARC** - Explicit recorded result: Compliant (pass) / Non-Compliant (fail) / none / temperror / permerror / bestguesspass / Unknown
- **Subject** - Displays the MIME Encoded subject line [Accurate O365 Compliance Searching]
- **Sender (Authenticated)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing) [Accurate O365 Compliance Searching]
- **Sender (Envelope/Return Path)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing)
- **Sender (Header/Client Display)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing)
- **O365 Classification:** Internal / Internal (Partner) / External
- **Message Source:** Internal / External

Clicking on "Info" will take you to IPINFO.IO, and display all relevant information to the IP Address.

Authentication fields report the supplied `Authentication-Results` header; they do not independently verify the message. SPF and DKIM also preserve recorded error results. A pass alone does not establish alignment with the visible From domain. Hover over the authentication fields for recorded identities and details. Missing or multiple authentication headers produce Unknown; repeated results for a method also produce Unknown for that method. A question mark indicates an indeterminate or non-pass/non-fail result. ARC results are not used.

Regression checks (Windows PowerShell with Windows Forms): `powershell.exe -NoProfile -STA -File .\tests\Authentication.Tests.ps1`. Optionally supply `-SamplePath` pointing to the original reported message headers to check that specific regression; private headers are not stored in the repository.


## Why create this and have a compiled version?
**Question:** Why have a mini program for something MxToolbox can do for free?  
- I wanted a lightweight, fast program to pin to my taskbar for easy access while limiting the exposure of personal data.

**Question:** How was it compiled?  
- It was compiled with **PS2EXE** using the following command:  
- `Invoke-PS2EXE -inputFile '.\O365-EmailHeaderAnalyzer.ps1' -outputFile '.\O365-EmailHeaderAnalyzer.exe' -iconFile '.\email_icon.ico' -noConsole -noOutput` 
- Source: [PS2EXE GitHub](https://github.com/MScholtes/PS2EXE)


## Usage
1. Run either `Message - Header Analyzer.ps1` or `Message - Header Analyzer.exe`.
2. Paste message headers into the **Message Details** textbox.


## Donate
Saved you time? Great! --- Sponsor my next coffee? [PayPal](https://www.paypal.com/donate/?hosted_button_id=EZU78ZANFT24C)
