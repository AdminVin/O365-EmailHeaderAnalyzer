# Email - Header Analyzer

## What is "Email - Header Analyzer"?
Email - Header Analyzer is a small PowerShell script analyzes Office 365 email headers and checks the following.
- SPF
- DKIM
- DMARC
- O365 Classification Internal/Internal (Partner)/External
- Message Source: Internal/External
<br>
<br>

## Why the compiled version?
I wanted to pin it to my taskbar for easy access. It was compiled with PS2EXE with the command below.
- Invoke-PS2EXE -inputFile '.\Message - Header Analyzer.ps1' -outputFile '.\Message - Header Analyzer.exe' -iconFile 'C:\GitHub\EmailHeaderAnalyzer\email_icon.ico' -noConsole -noOutput

If you prefer to run the script manually, you can do that as well.

## How do I get/use Email - Header Analyzer?
-