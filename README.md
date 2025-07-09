# Email - Header Analyzer
<img src="https://github.com/AdminVin/EmailHeaderAnalyzer/blob/main/EmailHeaderAnalyzer-Screenshot.png?raw=true">

## What is "Email - Header Analyzer"?
**Email - Header Analyzer** is a lightweight PowerShell script designed to analyze Office 365 email headers and display the following information:
    - **SPF** - Results: pass / fail / softfail / neutral / Unknown
    - **DKIM** - Results: pass / fail / none / Unknown
    - **DMARC** - Results: Compliant / Non-Compliant
    - **Sender (Authenticated)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing)
        - Use this address for O365 Compliance Search Address
    - **Sender (Envelope/Return Path)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing)
    - **Sender (Header/Client Display)** - Email Address / NOT FOUND (Potentially Spoofed/Spam/Phishing)
    - **O365 Classification:** Internal / Internal (Partner) / External
    - **Message Source:** Internal / External


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