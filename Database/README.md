# Veritabanı Kurulum ve Güncelleme Yönergeleri

Bu klasör, proje için gerekli veritabanı yapılandırma komut dosyalarını içerir.

## CreateScanResultsTable.sql

Bu komut dosyası, ML metrikleri için tüm gerekli alanları içeren yeni bir ScanResultsML tablosu oluşturur.

### Özellikler:
- ML metriklerinin tamamını (entropi, PE header, şüpheli API, vb.) içerir
- VirusTotal entegrasyonu için alanlar bulunur
- Performans için gerekli indeksler tanımlıdır

### Komut Dosyasını Çalıştırma

Bu komut dosyasını çalıştırmak için:

1. SQL Server Management Studio'yu açın
2. AntivirusDB veritabanına bağlanın
3. CreateScanResultsTable.sql dosyasını açın
4. Execute (F5) tuşuna basın

Alternatif olarak, komut satırından sqlcmd aracını kullanabilirsiniz:

```
sqlcmd -S nesneprojeserver.database.windows.net -d AntivirusDB -U antivirus -P your_password -i CreateScanResultsTable.sql
```

### Eski Tablodan Veri Taşıma

Eğer eski ScanResultModels tablosundan verileri yeni tabloya taşımak istiyorsanız, aşağıdaki komutu çalıştırabilirsiniz (erişim izniniz olduğu takdirde):

```sql
INSERT INTO dbo.ScanResultsML(FilePath, FileName, ScanDate, IsMalicious, DetectedBy, DetectedPatterns)
SELECT FilePath, FileName, ScanDate, IsMalicious, DetectedBy, DetectedPatterns FROM dbo.ScanResultModels;
```

## Uyarılar

- Bu işlem mevcut veritabanını değiştirmez, yeni bir tablo oluşturur
- Kod, ScanResultsML tablosunu kullanacak şekilde güncellenmiştir
- Eski tablodaki verileri elle yeni tabloya taşımanız gerekecektir 