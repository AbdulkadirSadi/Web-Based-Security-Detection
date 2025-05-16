@echo off
REM Bu bir test dosyasıdır, zararlı değildir.
REM SecurityAgent'ın şüpheli kalıpları algılamasını test etmek için oluşturulmuştur.

echo Test başlıyor...

REM Şüpheli kalıp: mshta javascript kullanımı
REM mshta javascript:alert('Test');close();

REM Şüpheli kalıp: PowerShell Encoding
REM powershell.exe -EncodedCommand UABvAHcAZQByAFMAaABlAGwAbAAgAHQAZQBzAHQA

REM Şüpheli kalıp: wmic işlem oluşturma
REM wmic process call create "calc.exe"

REM Şüpheli kalıp: bitsadmin
REM bitsadmin /transfer testJob /download /priority high https://example.com/test.txt %TEMP%\test.txt

echo Test tamamlandı.
echo Bu dosya zararlı bir dosya DEĞİLDİR. Sadece SecurityAgent'ın şüpheli kalıpları algılayabildiğini test etmek için oluşturulmuştur.
pause 