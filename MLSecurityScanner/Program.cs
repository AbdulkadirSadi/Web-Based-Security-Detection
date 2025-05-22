using System;
using System.IO;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using MLSecurityScanner.Data;
using MLSecurityScanner.Models;
using MLSecurityScanner.Services;

namespace MLSecurityScanner
{
    public class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("ML.NET tabanlı Zararlı Yazılım Tespit Modülü");
            Console.WriteLine("===========================================");

            // Yapılandırma dosyasını yükle
            var configuration = LoadConfiguration();
            if (configuration == null)
            {
                Console.WriteLine("Yapılandırma dosyası yüklenemedi. Çıkılıyor...");
                return;
            }

            // DbContext oluştur
            var optionsBuilder = new DbContextOptionsBuilder<MalwareDbContext>();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
            using var dbContext = new MalwareDbContext(optionsBuilder.Options);

            try
            {
                // Veritabanını oluştur
                dbContext.Database.EnsureCreated();
                Console.WriteLine("Veritabanı hazır.");

                // Komut satırı argümanlarına göre işlem yap
                if (args.Length > 0)
                {
                    ProcessCommand(args, dbContext, configuration);
                }
                else
                {
                    // İnteraktif menü göster
                    ShowMenu(dbContext, configuration);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static IConfiguration? LoadConfiguration()
        {
            try
            {
                return new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Yapılandırma yüklenirken hata oluştu: {ex.Message}");
                return null;
            }
        }

        private static void ShowMenu(MalwareDbContext dbContext, IConfiguration configuration)
        {
            while (true)
            {
                Console.WriteLine("\nNe yapmak istiyorsunuz?");
                Console.WriteLine("1) Sentetik veri üret ve veritabanına kaydet");
                Console.WriteLine("2) Güvenlik Ajanı tarama sonuçlarını içe aktar");
                Console.WriteLine("3) Modeli eğit");
                Console.WriteLine("4) Dosya analiz et ve tahmin yap");
                Console.WriteLine("5) Modeli değerlendir");
                Console.WriteLine("6) ScanResults tablosunu temizle");
                Console.WriteLine("7) Çıkış");
                Console.Write("\nSeçiminiz (1-7): ");

                if (!int.TryParse(Console.ReadLine(), out int choice))
                {
                    Console.WriteLine("Geçersiz seçim. Lütfen 1-7 arası bir sayı girin.");
                    continue;
                }

                switch (choice)
                {
                    case 1:
                        GenerateSyntheticData(dbContext);
                        break;
                    case 2:
                        ImportScanResults(dbContext, configuration);
                        break;
                    case 3:
                        TrainModel(dbContext);
                        break;
                    case 4:
                        AnalyzeFile(dbContext);
                        break;
                    case 5:
                        EvaluateModel(dbContext);
                        break;
                    case 6:
                        TruncateScanResults(dbContext);
                        break;
                    case 7:
                        Console.WriteLine("Programdan çıkılıyor...");
                        return;
                    default:
                        Console.WriteLine("Geçersiz seçim. Lütfen 1-7 arası bir sayı girin.");
                        break;
                }
            }
        }

        private static void ProcessCommand(string[] args, MalwareDbContext dbContext, IConfiguration configuration)
        {
            switch (args[0].ToLower())
            {
                case "generate":
                    int count = args.Length > 1 && int.TryParse(args[1], out int c) ? c : 1000;
                    GenerateSyntheticData(dbContext, count);
                    break;
                case "import":
                    int days = args.Length > 1 && int.TryParse(args[1], out int d) ? d : 30;
                    ImportScanResults(dbContext, configuration, days);
                    break;
                case "train":
                    TrainModel(dbContext);
                    break;
                case "analyze":
                    if (args.Length > 1)
                    {
                        string filePath = args[1];
                        AnalyzeFile(dbContext, filePath);
                    }
                    else
                    {
                        Console.WriteLine("Dosya yolu belirtilmedi.");
                    }
                    break;
                case "evaluate":
                    EvaluateModel(dbContext);
                    break;
                case "truncate":
                    TruncateScanResults(dbContext);
                    break;
                default:
                    Console.WriteLine("Bilinmeyen komut. Kullanım:");
                    Console.WriteLine("  generate [sayi] - Sentetik veri üret");
                    Console.WriteLine("  import [günSayısı] - Güvenlik Ajanı tarama sonuçlarını içe aktar");
                    Console.WriteLine("  train - Modeli eğit");
                    Console.WriteLine("  analyze <dosya_yolu> - Dosyayı analiz et");
                    Console.WriteLine("  evaluate - Modelin performansını değerlendir");
                    Console.WriteLine("  truncate - ScanResults tablosunu temizle");
                    break;
            }
        }

        private static void GenerateSyntheticData(MalwareDbContext dbContext, int count = 1000)
        {
            Console.WriteLine($"{count} adet sentetik veri üretiliyor...");
            
            var generator = new DataGenerator();
            var syntheticData = generator.GenerateSyntheticData(count);
            
            Console.WriteLine($"Üretilen veri sayısı: {syntheticData.Count}");
            Console.WriteLine($"Zararlı: {syntheticData.Count(x => x.IsMalicious)}");
            Console.WriteLine($"Zararsız: {syntheticData.Count(x => !x.IsMalicious)}");
            
            // Verileri veritabanına kaydet
            dbContext.ScanResults.AddRange(syntheticData);
            int savedCount = dbContext.SaveChanges();
            
            Console.WriteLine($"{savedCount} kayıt veritabanına eklendi.");
        }
        
        private static void ImportScanResults(MalwareDbContext dbContext, IConfiguration configuration, int days = 30)
        {
            Console.WriteLine($"Son {days} günün tarama sonuçları içe aktarılıyor...");
            
            var importer = new ScanResultImporter(configuration);
            var importedResults = importer.ImportRecentScanResults(days);
            
            if (importedResults.Count == 0)
            {
                Console.WriteLine("İçe aktarılacak sonuç bulunamadı.");
                return;
            }
            
            // Önce veritabanındaki mevcut Id'leri al
            var existingIds = dbContext.ScanResults.Select(r => r.Id).ToHashSet();
            
            // Sadece veritabanında olmayan kayıtları ekle
            var newResults = importedResults.Where(r => !existingIds.Contains(r.Id)).ToList();
            
            if (newResults.Count == 0)
            {
                Console.WriteLine("Tüm kayıtlar zaten veritabanında mevcut.");
                return;
            }
            
            // Verileri veritabanına kaydet
            dbContext.ScanResults.AddRange(newResults);
            int savedCount = dbContext.SaveChanges();
            
            Console.WriteLine($"{savedCount} yeni kayıt ScanResults tablosuna eklendi.");
        }

        private static void TrainModel(MalwareDbContext dbContext)
        {
            var data = dbContext.ScanResults.ToList();
            if (data.Count == 0)
            {
                Console.WriteLine("Veritabanında eğitim için veri bulunamadı.");
                return;
            }

            Console.WriteLine($"Toplam {data.Count} kayıt ile model eğitiliyor...");
            Console.WriteLine($"Zararlı: {data.Count(x => x.IsMalicious)}, Zararsız: {data.Count(x => !x.IsMalicious)}");
            
            var classifier = new MalwareClassifier();
            classifier.TrainModel(data);
            
            Console.WriteLine("Model eğitimi tamamlandı ve kaydedildi.");
        }

        private static void AnalyzeFile(MalwareDbContext dbContext, string? filePath = null)
        {
            if (string.IsNullOrEmpty(filePath))
            {
                Console.Write("Analiz edilecek dosyanın yolunu girin: ");
                filePath = Console.ReadLine();
                if (string.IsNullOrEmpty(filePath))
                {
                    Console.WriteLine("Geçersiz dosya yolu.");
                    return;
                }
            }

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Dosya bulunamadı: {filePath}");
                return;
            }

            try
            {
                Console.WriteLine($"Dosya analiz ediliyor: {filePath}");
                
                var analyzer = new FileAnalyzer();
                // ScanResultModel nesnesi oluştur
                var scanResult = new ScanResultModel
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanDate = DateTime.Now,
                    IsMalicious = false // Başlangıçta zararsız olarak varsayalım
                };
                
                // FileAnalyzer ile dosyayı analiz et ve metrikleri ScanResultModel'e aktar
                var fileInfo = new FileInfo(filePath);
                scanResult.FileSize = fileInfo.Length;
                
                var metrics = analyzer.AnalyzeFile(filePath);
                scanResult.EntropyScore = metrics.EntropyScore;
                scanResult.HasValidPEHeader = metrics.HasValidPEHeader;
                scanResult.SuspiciousAPICount = metrics.SuspiciousAPICount;
                scanResult.StringEntropyValue = metrics.StringEntropyValue;
                scanResult.SuspiciousStringCount = metrics.SuspiciousStringCount;
                scanResult.ObfuscatedCodeRatio = metrics.ObfuscatedCodeRatio;
                scanResult.HasValidSignature = metrics.HasValidSignature;
                scanResult.ExecutableCodeRatio = metrics.ExecutableCodeRatio;
                scanResult.CompressionRatio = metrics.CompressionRatio;
                scanResult.EncryptedSectionRatio = metrics.EncryptedSectionRatio;
                
                Console.WriteLine("Dosya Metrikleri:");
                Console.WriteLine($"Dosya Adı: {scanResult.FileName}");
                Console.WriteLine($"Boyut: {scanResult.FileSize:N0} bayt");
                Console.WriteLine($"Entropi: {scanResult.EntropyScore:F2}");
                Console.WriteLine($"PE Header: {(scanResult.HasValidPEHeader ? "Geçerli" : "Geçersiz/Yok")}");
                Console.WriteLine($"Şüpheli API Sayısı: {scanResult.SuspiciousAPICount}");
                Console.WriteLine($"String Entropi: {scanResult.StringEntropyValue:F2}");
                Console.WriteLine($"Şüpheli String Sayısı: {scanResult.SuspiciousStringCount}");
                Console.WriteLine($"Obfuscation Oranı: {scanResult.ObfuscatedCodeRatio:P2}");
                Console.WriteLine($"İmza Durumu: {(scanResult.HasValidSignature ? "Geçerli" : "Geçersiz/Yok")}");
                Console.WriteLine($"Çalıştırılabilir Kod Oranı: {scanResult.ExecutableCodeRatio:P2}");
                Console.WriteLine($"Sıkıştırma Oranı: {scanResult.CompressionRatio:P2}");
                Console.WriteLine($"Şifrelenmiş Bölüm Oranı: {scanResult.EncryptedSectionRatio:P2}");
                
                // Modeli kullanarak tahmin yap
                var classifier = new MalwareClassifier();
                try
                {
                    var prediction = classifier.PredictSample(scanResult);
                    
                    Console.WriteLine("\nML.NET Model Tahmini:");
                    Console.WriteLine($"Zararlı mı?: {(prediction.IsMalware ? "EVET" : "HAYIR")}");
                    Console.WriteLine($"Olasılık: {prediction.Probability:P2}");
                    
                    // Tahmin sonucunu ScanResultModel'e aktar
                    scanResult.IsMalicious = prediction.IsMalware;
                    scanResult.DetectedBy = prediction.IsMalware ? "ML.NET Model" : "";
                    scanResult.DetectedPatterns = prediction.IsMalware ? "AI Detection" : "";
                    
                    // Sonucu veritabanına kaydet
                    dbContext.ScanResults.Add(scanResult);
                    dbContext.SaveChanges();
                    
                    Console.WriteLine("Analiz sonuçları veritabanına kaydedildi.");
                }
                catch (FileNotFoundException)
                {
                    Console.WriteLine("Model dosyası bulunamadı. Lütfen önce modeli eğitin.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Dosya analizi sırasında hata oluştu: {ex.Message}");
            }
        }

        private static void EvaluateModel(MalwareDbContext dbContext)
        {
            try
            {
                var classifier = new MalwareClassifier();
                
                // Değerlendirme için veri setini al (mevcut verilerden %20'si)
                var testData = dbContext.ScanResults
                    .OrderBy(x => Guid.NewGuid()) // Rastgele sırala
                    .Take(Math.Min(1000, dbContext.ScanResults.Count() / 5))
                    .ToList();
                
                if (testData.Count == 0)
                {
                    Console.WriteLine("Değerlendirme için yeterli veri bulunamadı.");
                    return;
                }
                
                Console.WriteLine($"{testData.Count} kayıt ile model değerlendiriliyor...");
                
                var metrics = classifier.EvaluateModel(testData);
                
                Console.WriteLine("\nModel Performans Metrikleri:");
                Console.WriteLine($"Doğruluk (Accuracy): {metrics.Accuracy:P2}");
                Console.WriteLine($"AUC: {metrics.AreaUnderRocCurve:F4}");
                Console.WriteLine($"F1 Skor: {metrics.F1Score:F4}");
                Console.WriteLine($"Kesinlik (Precision): {metrics.PositivePrecision:P2}");
                Console.WriteLine($"Duyarlılık (Recall): {metrics.PositiveRecall:P2}");
                
                Console.WriteLine("\nKarmaşıklık Matrisi (Confusion Matrix):");
                Console.WriteLine($"Gerçek Pozitif (TP): {metrics.ConfusionMatrix.TruePositives}");
                Console.WriteLine($"Gerçek Negatif (TN): {metrics.ConfusionMatrix.TrueNegatives}");
                Console.WriteLine($"Yanlış Pozitif (FP): {metrics.ConfusionMatrix.FalsePositives}");
                Console.WriteLine($"Yanlış Negatif (FN): {metrics.ConfusionMatrix.FalseNegatives}");
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Model dosyası bulunamadı. Lütfen önce modeli eğitin.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Model değerlendirme sırasında hata oluştu: {ex.Message}");
            }
        }

        private static void TruncateScanResults(MalwareDbContext dbContext)
        {
            Console.Write("Bu işlem tüm ScanResults verilerini silecek. Devam etmek istediğinize emin misiniz? (E/H): ");
            var response = Console.ReadLine()?.ToUpper();
            
            if (response == "E")
            {
                try
                {
                    // Bütün kayıtları sil
                    var allRecords = dbContext.ScanResults.ToList();
                    dbContext.ScanResults.RemoveRange(allRecords);
                    int count = dbContext.SaveChanges();
                    
                    // Kaydedilen model dosyasını da sil
                    string modelPath = "MalwareModel.zip";
                    if (File.Exists(modelPath))
                    {
                        File.Delete(modelPath);
                        Console.WriteLine("Eğitilmiş model dosyası silindi.");
                    }
                    
                    Console.WriteLine($"{count} kayıt başarıyla silindi ve tablo temizlendi.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Tablo temizlenirken hata oluştu: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("İşlem iptal edildi.");
            }
        }
    }
}
