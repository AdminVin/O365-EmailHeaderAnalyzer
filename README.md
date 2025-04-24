# Email - Header Analyzer
<img src="https://github.com/AdminVin/EmailHeaderAnalyzer/blob/main/EmailHeaderAnalyzer-Screenshot.png?raw=true">

## What is "Email - Header Analyzer"?
**Email - Header Analyzer** is a lightweight PowerShell script designed to analyze Office 365 email headers and display the following information:
- **SPF** - pass / fail / softfail / neutral / Unknown
- **DKIM** - pass / fail / none / Unknown
- **DMARC** - Compliant / Non-Compliant
- **Sender (Envelope/Return Path)** - Email Address / Not Found & Likely Spoofed or Spam
- **Sender (Header/Client Display)** Email Address / Not Found & Likely Spoofed or Spam
- **O365 Classification:** Internal / Internal (Partner) / External
- **Message Source:** Internal / External


## Why create this and have a compiled version?
**Question:** Why have a mini program for something MxToolbox can do for free?  
- I wanted a lightweight, fast program to pin to my taskbar for easy access while limiting the exposure of personal data.

**Question:** How was it compiled?  
- It was compiled with **PS2EXE** using the following command:  
- Invoke-PS2EXE -inputFile '.\Message - Header Analyzer.ps1' -outputFile '.\Message - Header Analyzer.exe' -iconFile 'C:\GitHub\EmailHeaderAnalyzer\email_icon.ico' -noConsole -noOutput 
- Source: **PS2EXE** https://github.com/MScholtes/PS2EXE

## Usage
1. Run either `Message - Header Analyzer.ps1` or `Message - Header Analyzer.exe`.
2. Set your internal domain and click **Save**.
3. Paste message headers into the **Message Details** textbox.

## Donate
Saved you time? Sponsor my next coffee? [PayPal](https://www.paypal.com/donate/?hosted_button_id=EZU78ZANFT24C)