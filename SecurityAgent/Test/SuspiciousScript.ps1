# Bu bir test dosyasıdır, zararlı değildir.
# SecurityAgent'ın şüpheli kalıpları algılamasını test etmek için oluşturulmuştur.

# Şüpheli komut kalıbı örneği
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host 'Bu bir test mesajıdır'"))
powershell -enc $encoded

# Şüpheli kalıp: cmd.exe çağrısı
cmd.exe /c echo "Test komut çalıştırma"

# Şüpheli kalıp: dosya indirme
$downloadUrl = "https://example.com/test.txt"
$outputFile = "$env:TEMP\test.txt"
# certutil -urlcache -split -f $downloadUrl $outputFile

# Şüpheli kalıp: register dll
# regsvr32 /s /u scrobj.dll

Write-Host "Bu dosya zararlı bir dosya DEĞİLDİR. Sadece SecurityAgent'ın şüpheli kalıpları algılayabildiğini test etmek için oluşturulmuştur." 