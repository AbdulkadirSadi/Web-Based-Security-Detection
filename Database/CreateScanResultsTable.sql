-- Yeni, özelleştirilmiş ScanResultsML tablosunu oluştur
CREATE TABLE dbo.ScanResultsML
(
    Id INT IDENTITY(1,1) PRIMARY KEY,
    FilePath NVARCHAR(1000) NULL,
    FileName NVARCHAR(255) NULL,
    ScanDate DATETIME NULL,
    IsMalicious BIT NULL,
    DetectedBy NVARCHAR(255) NULL,
    DetectedPatterns NVARCHAR(MAX) NULL,
    
    -- ML Metrikleri
    FileSize BIGINT NULL,
    EntropyScore FLOAT NULL,
    HasValidPEHeader BIT NULL,
    SuspiciousAPICount INT NULL,
    StringEntropyValue FLOAT NULL,
    SuspiciousStringCount INT NULL, 
    ObfuscatedCodeRatio FLOAT NULL,
    HasValidSignature BIT NULL,
    ExecutableCodeRatio FLOAT NULL,
    CompressionRatio FLOAT NULL,
    EncryptedSectionRatio FLOAT NULL,
    VirusTotalDetectionCount INT NULL,
    VirusTotalTotalScans INT NULL,
    IsGeneratedData BIT NULL DEFAULT 0
);

-- Performans için indeksler ekle
CREATE INDEX IX_ScanResultsML_FileName ON dbo.ScanResultsML (FileName);
CREATE INDEX IX_ScanResultsML_IsMalicious ON dbo.ScanResultsML (IsMalicious);
CREATE INDEX IX_ScanResultsML_EntropyScore ON dbo.ScanResultsML (EntropyScore);
CREATE INDEX IX_ScanResultsML_ScanDate ON dbo.ScanResultsML (ScanDate);

-- Eski tablodan verileri al (eğer eski tablo ve erişim izni varsa)
-- Bu komutu manuel olarak çalıştırın, erişim sorunu varsa atlayın
-- INSERT INTO dbo.ScanResultsML(FilePath, FileName, ScanDate, IsMalicious, DetectedBy, DetectedPatterns)
-- SELECT FilePath, FileName, ScanDate, IsMalicious, DetectedBy, DetectedPatterns FROM dbo.ScanResultModels; 