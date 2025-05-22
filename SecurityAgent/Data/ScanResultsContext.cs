using Microsoft.EntityFrameworkCore;
using SecurityAgent.Models;
using System.IO;
using System.Configuration;
using Microsoft.Extensions.Configuration;

namespace SecurityAgent
{
    public class ScanResultsContext : DbContext
    {
        public DbSet<ScanResultModel> ScanResults { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                // appsettings.json'dan bağlantı dizesini al
                var configuration = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();

                string connectionString = configuration.GetConnectionString("DefaultConnection");
                optionsBuilder.UseSqlServer(connectionString);
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Tablo adını manuel olarak belirt
            modelBuilder.Entity<ScanResultModel>()
                .ToTable("ScanResultsML");

            // İndeksler
            modelBuilder.Entity<ScanResultModel>()
                .HasIndex(f => f.FileName);

            modelBuilder.Entity<ScanResultModel>()
                .HasIndex(f => f.IsMalicious);
        }
    }
} 