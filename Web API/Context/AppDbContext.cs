using Microsoft.EntityFrameworkCore;
using Web_API.Models;

namespace Web_API.Context
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<ScanResultModel> ScanResultModels { get; set; }
    }
}
