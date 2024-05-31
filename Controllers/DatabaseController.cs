using Microsoft.AspNetCore.Mvc;
using Npgsql;
using WebAPI.Models;

namespace WebAPI.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class DatabaseController : ControllerBase
    {
        private readonly string _databaseConnectionString;

        public DatabaseController(IConfiguration config)
        {
            _databaseConnectionString = config["Settings:Database:ConnectionString"];
        }

        /* Test postgresql connection */
        [HttpGet("")]
        public async Task<ActionResult> DatabaseConnectAsync()
        {
            try
            {
                using (var conn = new NpgsqlConnection(_databaseConnectionString))
                {
                    await conn.OpenAsync();
                }
                return Ok("\nPOSTGRES:\n Connected to database \n");
            }
            catch (Exception ex)
            {
                // Log the exception
                return BadRequest("\nPOSTGRES:\n Failed to connect to database \n");
            }
        }

        [HttpPost("add")]
        public async Task<ActionResult> AddRecordAsync([FromBody] EmployeeDto employee, [FromServices] DatabaseContext context)
        {
            try
            {
                context.Employee.Add(employee);
                await context.SaveChangesAsync();
                return Ok("Record added successfully");
            }
            catch (Exception ex)
            {
                // Log the exception
                return BadRequest($"Failed to add record: {ex.Message}");
            }
        }

        [HttpDelete("remove/{id}")]
        public async Task<ActionResult> RemoveRecordAsync(int id, [FromServices] DatabaseContext context)
        {
            try
            {
                var employee = await context.Employee.FindAsync(id);
                if (employee == null)
                    return NotFound();

                context.Employee.Remove(employee);
                await context.SaveChangesAsync();
                return Ok("Record removed successfully");
            }
            catch (Exception ex)
            {
                // Log the exception
                return BadRequest($"Failed to remove record: {ex.Message}");
            }
        }

        [HttpPut("update/{id}")]
        public async Task<ActionResult> UpdateRecordAsync(int id, [FromBody] EmployeeDto updatedEmployee, [FromServices] DatabaseContext context)
        {
            try
            {
                var employee = await context.Employee.FindAsync(id);
                if (employee == null)
                    return NotFound();

                // Update properties of the existing employee with the provided values
                employee.EmployeeNumber = updatedEmployee.EmployeeNumber;
                employee.TaxNumber = updatedEmployee.TaxNumber;
                // Update other properties similarly

                await context.SaveChangesAsync();
                return Ok("Record updated successfully");
            }
            catch (Exception ex)
            {
                // Log the exception
                return BadRequest($"Failed to update record: {ex.Message}");
            }
        }
    }
}