using Microsoft.EntityFrameworkCore;

namespace WebAPI.Models
{
    public class DatabaseContext : DbContext
    {
        public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
        {
        }

        public DbSet<EmployeeDto> Employee { get; set; }
    }
}