# Bu bir test dosyasıdır, zararlı değildir.
# Base64 kodlanmış içerik, SecurityAgent tarafından şüpheli olarak algılanmalıdır.

$encodedCommand = "UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAYwBhAGwAYwAuAGUAeABlAA=="

Write-Host "Kodlanmış komut:" $encodedCommand
Write-Host "Bu komut dekode edilirse: Start-Process -FilePath calc.exe (Zararsız hesap makinesi açma komutu)"

# Şüpheli görünecek, kırmızı bayrak olarak algılanacak komut
powershell.exe -EncodedCommand $encodedCommand

Write-Host "Bu dosya zararlı DEĞİLDİR. SecurityAgent'ın tespitlerini test etmek için oluşturulmuştur." 