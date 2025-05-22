-- Add new ML metric columns to ScanResultModels table
ALTER TABLE dbo.ScanResultModels ADD
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
    IsGeneratedData BIT NULL DEFAULT 0;

-- Update existing NULL values with defaults
UPDATE dbo.ScanResultModels SET
    FileSize = 0,
    EntropyScore = 0,
    HasValidPEHeader = 0,
    SuspiciousAPICount = 0,
    StringEntropyValue = 0,
    SuspiciousStringCount = 0,
    ObfuscatedCodeRatio = 0,
    HasValidSignature = 0,
    ExecutableCodeRatio = 0,
    CompressionRatio = 0,
    EncryptedSectionRatio = 0,
    VirusTotalDetectionCount = 0,
    VirusTotalTotalScans = 0,
    IsGeneratedData = 0
WHERE FilePath IS NOT NULL;

-- Add indexes for ML performance
CREATE INDEX IX_ScanResultModels_EntropyScore ON dbo.ScanResultModels (EntropyScore);
CREATE INDEX IX_ScanResultModels_IsMalicious ON dbo.ScanResultModels (IsMalicious); 