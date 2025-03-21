# Email - Header Analyzer

## What is "Email - Header Analyzer"?
Email - Header Analyzer is a small PowerShell script analyzes Office 365 email headers and checks the following:
- SPF
- DKIM
- DMARC
- O365 Classification Internal/Internal (Partner)/External
- Message Source: Internal/External
<br>

## Why create this and have a compiled version?
Question: Why have a mini program for something MxToolbox can do for free? 
- I wanted a lightweight, fast program to pin to my taskbar for easy access while limiting the exposure of personal data. 

Question: How was it compiled?
- It was compiled with PS2EXE with the command below. (Source: https://github.com/MScholtes/PS2EXE)
- Invoke-PS2EXE -inputFile '.\Message - Header Analyzer.ps1' -outputFile '.\Message - Header Analyzer.exe' -iconFile 'C:\GitHub\EmailHeaderAnalyzer\email_icon.ico' -noConsole -noOutput
<br>

## Usage
- Run either "Message - Header Analyzer.ps1" or "Message - Header Analyzer.exe"
- Set your internal domain > Save
- Paste message headers into "Message Details" textbox