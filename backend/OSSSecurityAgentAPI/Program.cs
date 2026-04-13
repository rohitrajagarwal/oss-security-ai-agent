var builder = WebApplication.CreateBuilder(args);

// Load environment variables from .env file
var envPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "OssSecurityAgent", ".env");
if (File.Exists(envPath))
{
    var envVars = File.ReadAllLines(envPath)
        .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith("#"))
        .Select(l => l.Split('=', 2))
        .Where(p => p.Length == 2);

    foreach (var (key, value) in envVars.Select(p => (p[0], p[1])))
    {
        Environment.SetEnvironmentVariable(key, value);
    }
}

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddOpenApi();

// Add CORS for React frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("ReactApp", policy =>
    {
        policy.WithOrigins("http://localhost:3000", "http://localhost:3001", "http://localhost:3003", 
                          "http://127.0.0.1:3000", "http://127.0.0.1:3001", "http://127.0.0.1:3003")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("ReactApp");
app.UseAuthorization();
app.MapControllers();

app.Run();
