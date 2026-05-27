using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Data.Sqlite;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
    });
});

var app = builder.Build();

app.UseCors();
app.UseStaticFiles();

// Redirect root to admin dashboard
app.MapGet("/", () => Results.Redirect("/index.html"));

// Cryptographic client-server response signing middleware
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/1.2"))
    {
        var originalBodyStream = context.Response.Body;
        using (var responseBody = new MemoryStream())
        {
            context.Response.Body = responseBody;

            await next();

            context.Response.Body = originalBodyStream;
            if (context.Response.StatusCode == 200)
            {
                responseBody.Seek(0, SeekOrigin.Begin);
                byte[] jsonBytes = responseBody.ToArray();
                string jsonString = Encoding.UTF8.GetString(jsonBytes);

                string secret = "22c3837291affbeb7b26947e768fe7b77938695c3df1b0ba521f96546abda53d";
                using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
                {
                    byte[] hash = hmac.ComputeHash(jsonBytes);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hash)
                    {
                        sb.Append(b.ToString("x2"));
                    }
                    context.Response.Headers["X-Signature"] = sb.ToString();
                }

                await context.Response.WriteAsync(jsonString);
            }
            else
            {
                responseBody.Seek(0, SeekOrigin.Begin);
                await responseBody.CopyToAsync(originalBodyStream);
            }
        }
    }
    else
    {
        await next();
    }
});

// Database initialization
string dbPath = Path.Combine(AppContext.BaseDirectory, "auth.db");
string connString = $"Data Source={dbPath};";

InitializeDatabase(connString);
MigrateDatabase(connString);

string currentAdminKey = LoadAdminKey(connString);
SaveAdminKey(connString, "zuwki-admin");
currentAdminKey = "zuwki-admin";
Console.WriteLine($"[SECURITY] CURRENT MASTER KEY IS: '{currentAdminKey}'");
const string ADMIN_PIN = "0909";

// ----------------------------------------------------
// CLIENT API ENDPOINT (KeyAuth compatible)
// ----------------------------------------------------
app.MapPost("/api/1.2/", async (HttpContext context) =>
{
    var form = await context.Request.ReadFormAsync();
    string type = form["type"];
    string name = form["name"];
    string ownerid = form["ownerid"];
    string ver = form["ver"];
    string sessionid = form["sessionid"];
    string key = form["key"];
    string hwid = form["hwid"];
    string username = form["username"];
    string pass = form["pass"];
    string email = form["email"];
    string discord = form["discord"];

    string ip = context.Connection.RemoteIpAddress?.ToString() ?? "127.0.0.1";
    // Resolve forwarded IP if behind proxy
    if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
    {
        var fwd = forwardedFor.ToString().Split(',')[0].Trim();
        if (!string.IsNullOrEmpty(fwd)) ip = fwd;
    }

    // Lookup application
    var application = GetApplication(connString, name ?? "plasma.lol");
    if (application == null)
    {
        return Results.Json(new { success = false, message = "Application not found." });
    }

    if (application.Paused == 1)
    {
        return Results.Json(new { success = false, message = "Application is currently paused." });
    }

    // Handle Init
    if (type == "init")
    {
        if (ownerid != application.OwnerId)
        {
            return Results.Json(new { success = false, message = "Owner ID mismatch." });
        }

        string newSessionId = Guid.NewGuid().ToString();
        InsertSession(connString, application.Id, newSessionId, ip);
        InsertLog(connString, application.Id, "init", "", "Session initialized", ip);

        int numUsers = CountUsers(connString, application.Id);
        int numKeys = CountLicenses(connString, application.Id);

        return Results.Json(new
        {
            success = true,
            sessionid = newSessionId,
            message = "Initialized successfully",
            appinfo = new
            {
                version = application.Version,
                numUsers = numUsers.ToString(),
                numKeys = numKeys.ToString()
            }
        });
    }

    // Session Verification
    if (string.IsNullOrEmpty(sessionid))
    {
        return Results.Json(new { success = false, message = "Session ID is required." });
    }

    var session = GetSession(connString, sessionid);
    if (session == null || session.AppId != application.Id)
    {
        return Results.Json(new { success = false, message = "Session expired or invalid." });
    }

    // Handle License Activation / Login
    if (type == "license")
    {
        if (string.IsNullOrEmpty(key) || string.IsNullOrEmpty(hwid))
        {
            return Results.Json(new { success = false, message = "License key and HWID are required." });
        }

        var license = GetLicenseByKey(connString, key);
        if (license == null || license.AppId != application.Id)
        {
            InsertLog(connString, application.Id, "license_fail", "", $"License not found: {key}", ip);
            return Results.Json(new { success = false, message = "License key not found." });
        }

        if (license.Status == "banned")
        {
            InsertLog(connString, application.Id, "license_fail", "", $"Banned license key: {key}", ip);
            return Results.Json(new { success = false, message = "License key has been banned." });
        }

        DateTime now = DateTime.UtcNow;

        if (license.Status == "unused")
        {
            // Activate license and store user info
            string expiresAt = now.AddDays(license.DurationDays).ToString("o");
            UpdateLicenseStatus(connString, license.Id, "used", "anonymous", hwid, now.ToString("o"), expiresAt);
            // Store email/discord on the license row for license-only users
            UpdateLicenseUserInfo(connString, license.Id, email, discord, ip);
            InsertLog(connString, application.Id, "license_activate", "", $"Activated license key: {key} | Email: {email ?? "N/A"} | Discord: {discord ?? "N/A"}", ip);
            return Results.Json(new { success = true, message = "License activated successfully." });
        }

        if (license.Status == "used")
        {
            // Check expiry
            if (DateTime.Parse(license.ExpiresAt) < now)
            {
                UpdateLicenseStatus(connString, license.Id, "expired", license.UsedBy, license.Hwid, license.UsedAt, license.ExpiresAt);
                InsertLog(connString, application.Id, "license_fail", "", $"Expired license key: {key}", ip);
                return Results.Json(new { success = false, message = "License key has expired." });
            }

            // Check HWID Lock
            if (!string.IsNullOrEmpty(license.Hwid) && license.Hwid != hwid)
            {
                InsertLog(connString, application.Id, "license_fail", "", $"HWID mismatch for key: {key}", ip);
                return Results.Json(new { success = false, message = "HWID mismatch. Please reset HWID via administrator." });
            }

            // Update email/discord/ip on re-login
            UpdateLicenseUserInfo(connString, license.Id, email, discord, ip);
            InsertLog(connString, application.Id, "license_login", "", $"Logged in with license key: {key} | Email: {email ?? "N/A"} | Discord: {discord ?? "N/A"}", ip);
            return Results.Json(new { success = true, message = "Logged in successfully." });
        }

        if (license.Status == "expired")
        {
            return Results.Json(new { success = false, message = "License key has expired." });
        }

        return Results.Json(new { success = false, message = "Invalid license key status." });
    }

    // Handle User Registration
    if (type == "register")
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(key) || string.IsNullOrEmpty(hwid))
        {
            return Results.Json(new { success = false, message = "All fields (username, password, key, HWID) are required." });
        }

        var existingUser = GetUserByUsername(connString, application.Id, username);
        if (existingUser != null)
        {
            return Results.Json(new { success = false, message = "Username is already taken." });
        }

        var license = GetLicenseByKey(connString, key);
        if (license == null || license.AppId != application.Id)
        {
            return Results.Json(new { success = false, message = "License key not found." });
        }

        if (license.Status != "unused")
        {
            return Results.Json(new { success = false, message = "License key is already used or banned." });
        }

        // Hash password
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(pass);
        DateTime now = DateTime.UtcNow;
        string expiresAt = now.AddDays(license.DurationDays).ToString("o");

        // Create User & Update License
        InsertUser(connString, application.Id, username, passwordHash, hwid, license.Level, expiresAt, email, discord, ip);
        UpdateLicenseStatus(connString, license.Id, "used", username, hwid, now.ToString("o"), expiresAt);

        InsertLog(connString, application.Id, "register", username, $"Registered with key: {key} | Email: {email ?? "N/A"} | Discord: {discord ?? "N/A"}", ip);

        return Results.Json(new { success = true, message = "Successfully registered user." });
    }

    // Handle User Login
    if (type == "login")
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(pass) || string.IsNullOrEmpty(hwid))
        {
            return Results.Json(new { success = false, message = "Username, password, and HWID are required." });
        }

        var user = GetUserByUsername(connString, application.Id, username);
        if (user == null)
        {
            return Results.Json(new { success = false, message = "Username not found." });
        }

        if (user.Banned == 1)
        {
            InsertLog(connString, application.Id, "login_fail", username, "Attempted login to banned account", ip);
            return Results.Json(new { success = false, message = "User account has been banned." });
        }

        bool passMatches = BCrypt.Net.BCrypt.Verify(pass, user.PasswordHash);
        if (!passMatches)
        {
            InsertLog(connString, application.Id, "login_fail", username, "Password mismatch", ip);
            return Results.Json(new { success = false, message = "Incorrect password." });
        }

        DateTime now = DateTime.UtcNow;
        if (DateTime.Parse(user.ExpiresAt) < now)
        {
            InsertLog(connString, application.Id, "login_fail", username, "Subscription expired", ip);
            return Results.Json(new { success = false, message = "User subscription has expired." });
        }

        // HWID Lock logic
        if (string.IsNullOrEmpty(user.Hwid))
        {
            UpdateUserHwid(connString, user.Id, hwid);
            user.Hwid = hwid;
        }
        else if (user.Hwid != hwid)
        {
            InsertLog(connString, application.Id, "login_fail", username, $"HWID mismatch. Submitted: {hwid}, Expected: {user.Hwid}", ip);
            return Results.Json(new { success = false, message = "HWID mismatch. Please reset HWID via administrator." });
        }

        UpdateUserLogin(connString, user.Id, ip, now.ToString("o"), email, discord);
        InsertLog(connString, application.Id, "login", username, $"Logged in successfully | Email: {email ?? "N/A"} | Discord: {discord ?? "N/A"}", ip);

        double timeLeft = Math.Max(0, (DateTime.Parse(user.ExpiresAt) - now).TotalSeconds);

        return Results.Json(new
        {
            success = true,
            message = "Logged in successfully",
            info = new
            {
                username = user.Username,
                subscriptions = new[]
                {
                    new
                    {
                        subscription = "default",
                        expiry = user.ExpiresAt,
                        timeleft = ((int)timeLeft).ToString()
                    }
                }
            }
        });
    }

    // Handle HWID Reset for License
    if (type == "reset_hwid")
    {
        if (string.IsNullOrEmpty(key))
        {
            return Results.Json(new { success = false, message = "License key is required." });
        }

        var license = GetLicenseByKey(connString, key);
        if (license == null || license.AppId != application.Id)
        {
            InsertLog(connString, application.Id, "reset_hwid_fail", "", $"License not found for HWID reset: {key}", ip);
            return Results.Json(new { success = false, message = "License key not found." });
        }

        if (license.Status == "banned")
        {
            InsertLog(connString, application.Id, "reset_hwid_fail", "", $"Attempted HWID reset on banned key: {key}", ip);
            return Results.Json(new { success = false, message = "License key is banned." });
        }

        // Reset the HWID
        ResetLicenseHwid(connString, license.Id);
        InsertLog(connString, application.Id, "reset_hwid", "", $"HWID reset for license key: {key}", ip);

        return Results.Json(new { success = true, message = "HWID has been reset successfully. You can now authenticate." });
    }

    return Results.Json(new { success = false, message = "Unknown request type." });
});

// ----------------------------------------------------
// ADMIN DASHBOARD API ENDPOINTS
// ----------------------------------------------------
bool CheckAdminKey(HttpContext context)
{
    string key = context.Request.Headers["X-Admin-Key"];
    return !string.IsNullOrEmpty(key) && key == currentAdminKey;
}

app.MapPost("/api/admin/auth", async (HttpContext context) =>
{
    using var document = await JsonDocument.ParseAsync(context.Request.Body);
    var root = document.RootElement;
    if (root.TryGetProperty("password", out var passwordProp))
    {
        string password = passwordProp.GetString();
        if (password == currentAdminKey)
        {
            return Results.Json(new { success = true, message = "Authentication successful." });
        }
    }
    return Results.Json(new { success = false, message = "Incorrect admin key." });
});

app.MapGet("/api/admin/stats", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);

    int appId = 1;
    int totalUsers = CountUsers(connString, appId);
    int totalLicenses = CountLicenses(connString, appId);
    int activeLicenses = CountLicensesByStatus(connString, appId, "used");
    int unusedLicenses = CountLicensesByStatus(connString, appId, "unused");
    var recentLogs = GetLogs(connString, appId, 10, 0, null);

    var recentLogins = new List<object>();
    foreach (var l in recentLogs)
    {
        if (l.Event == "login" || l.Event == "license_login")
        {
            recentLogins.Add(l);
        }
    }

    return Results.Json(new
    {
        success = true,
        stats = new
        {
            totalUsers,
            totalLicenses,
            activeLicenses,
            unusedLicenses,
            recentLogins
        }
    });
});

app.MapGet("/api/admin/settings", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    var appInfo = GetApplication(connString, "plasma.lol");
    return Results.Json(new { success = true, settings = appInfo });
});

app.MapPost("/api/admin/settings/pause", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    var appInfo = GetApplication(connString, "plasma.lol");
    int newPaused = appInfo.Paused == 1 ? 0 : 1;
    UpdateApplicationPause(connString, appInfo.Id, newPaused);
    return Results.Json(new { success = true, paused = newPaused });
});

app.MapPost("/api/admin/settings/refresh-secret", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    var appInfo = GetApplication(connString, "plasma.lol");
    byte[] randomBytes = new byte[32];
    RandomNumberGenerator.Fill(randomBytes);
    string newSecret = Convert.ToHexString(randomBytes).ToLower();
    UpdateApplicationSecret(connString, appInfo.Id, newSecret);
    return Results.Json(new { success = true, secret = newSecret });
});

app.MapPost("/api/admin/settings/change-key", async (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    
    using var document = await JsonDocument.ParseAsync(context.Request.Body);
    var root = document.RootElement;
    
    if (!root.TryGetProperty("newKey", out var newKeyProp) || !root.TryGetProperty("pin", out var pinProp))
    {
        return Results.Json(new { success = false, message = "Missing newKey or pin." });
    }
    
    string newKey = newKeyProp.GetString()?.Trim();
    string pin = pinProp.GetString()?.Trim();
    
    if (string.IsNullOrEmpty(newKey))
    {
        return Results.Json(new { success = false, message = "New Master Key cannot be empty." });
    }
    
    if (pin != ADMIN_PIN)
    {
        return Results.Json(new { success = false, message = "Incorrect Security PIN." });
    }
    
    SaveAdminKey(connString, newKey);
    currentAdminKey = newKey;
    
    return Results.Json(new { success = true, message = "Master Admin Key updated successfully." });
});

app.MapGet("/api/admin/licenses", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    int page = int.TryParse(context.Request.Query["page"], out var p) ? p : 1;
    int limit = int.TryParse(context.Request.Query["limit"], out var l) ? l : 20;
    int offset = (page - 1) * limit;

    int total = CountLicenses(connString, 1);
    var licenses = GetLicenses(connString, 1, limit, offset);

    return Results.Json(new { success = true, licenses, total, page, limit });
});

app.MapPost("/api/admin/licenses/generate", async (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    using var document = await JsonDocument.ParseAsync(context.Request.Body);
    var root = document.RootElement;
    
    int count = root.TryGetProperty("count", out var c) ? int.Parse(c.GetString() ?? "1") : 1;
    int duration = root.TryGetProperty("duration_days", out var d) ? int.Parse(d.GetString() ?? "30") : 30;
    int level = root.TryGetProperty("level", out var lvl) ? int.Parse(lvl.GetString() ?? "1") : 1;
    string prefix = root.TryGetProperty("prefix", out var pr) ? pr.GetString() : "";
    string note = root.TryGetProperty("note", out var nt) ? nt.GetString() : "";

    var keys = new List<string>();
    const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    var rand = new Random();

    for (int i = 0; i < count; i++)
    {
        string part() => new string(Enumerable.Repeat(chars, 5).Select(s => s[rand.Next(s.Length)]).ToArray());
        string key = $"{part()}-{part()}-{part()}-{part()}";
        if (!string.IsNullOrEmpty(prefix)) key = $"{prefix}-{key}";

        InsertLicense(connString, 1, key, duration, level, note ?? "");
        keys.Add(key);
    }

    return Results.Json(new { success = true, keys });
});

app.MapDelete("/api/admin/licenses/{id}", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    DeleteLicense(connString, id);
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/licenses/{id}/ban", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    UpdateLicenseStatusById(connString, id, "banned");
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/licenses/{id}/unban", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    var lic = GetLicenseById(connString, id);
    string originalStatus = (lic != null && !string.IsNullOrEmpty(lic.UsedAt)) ? "used" : "unused";
    UpdateLicenseStatusById(connString, id, originalStatus);
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/licenses/{id}/reset-hwid", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    ResetLicenseHwid(connString, id);
    return Results.Json(new { success = true });
});

app.MapGet("/api/admin/users", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    int page = int.TryParse(context.Request.Query["page"], out var p) ? p : 1;
    int limit = int.TryParse(context.Request.Query["limit"], out var l) ? l : 20;
    int offset = (page - 1) * limit;

    int total = CountUsers(connString, 1);
    var users = GetUsers(connString, 1, limit, offset);

    return Results.Json(new { success = true, users, total, page, limit });
});

app.MapDelete("/api/admin/users/{id}", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    DeleteUser(connString, id);
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/users/{id}/ban", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    UpdateUserBan(connString, id, 1);
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/users/{id}/unban", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    UpdateUserBan(connString, id, 0);
    return Results.Json(new { success = true });
});

app.MapPost("/api/admin/users/{id}/reset-hwid", (HttpContext context, int id) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    UpdateUserHwid(connString, id, null);
    return Results.Json(new { success = true });
});

app.MapGet("/api/admin/logs", (HttpContext context) =>
{
    if (!CheckAdminKey(context)) return Results.Json(new { success = false, message = "Unauthorized." }, statusCode: 401);
    int page = int.TryParse(context.Request.Query["page"], out var p) ? p : 1;
    int limit = int.TryParse(context.Request.Query["limit"], out var l) ? l : 20;
    int offset = (page - 1) * limit;
    string filter = context.Request.Query["event"];

    int total = CountLogs(connString, 1, filter);
    var logs = GetLogs(connString, 1, limit, offset, filter);

    return Results.Json(new { success = true, logs, total, page, limit });
});

var port = Environment.GetEnvironmentVariable("PORT") ?? "3000";
app.Run($"http://0.0.0.0:{port}");

// ----------------------------------------------------
// DATABASE & MODEL HELPER FUNCTIONS
// ----------------------------------------------------
void InitializeDatabase(string connectionString)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();

    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            ownerid TEXT UNIQUE,
            secret TEXT,
            version TEXT,
            paused INTEGER DEFAULT 0,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            key TEXT UNIQUE,
            duration_days INTEGER,
            level INTEGER DEFAULT 1,
            hwid TEXT,
            used_by TEXT,
            status TEXT DEFAULT 'unused',
            note TEXT,
            created_at TEXT,
            used_at TEXT,
            expires_at TEXT,
            email TEXT,
            discord TEXT,
            last_ip TEXT
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            username TEXT,
            password_hash TEXT,
            hwid TEXT,
            subscription_level INTEGER DEFAULT 1,
            created_at TEXT,
            expires_at TEXT,
            banned INTEGER DEFAULT 0,
            last_login TEXT,
            ip TEXT,
            email TEXT,
            discord TEXT,
            UNIQUE(app_id, username)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            session_id TEXT UNIQUE,
            created_at TEXT,
            ip TEXT
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id INTEGER,
            event TEXT,
            username TEXT,
            details TEXT,
            ip TEXT,
            created_at TEXT
        );

        INSERT OR IGNORE INTO applications (name, ownerid, secret, version, paused, created_at)
        VALUES ('plasma.lol', '7zmx6hWXmd', '22c3837291affbeb7b26947e768fe7b77938695c3df1b0ba521f96546abda53d', '1.0', 0, datetime('now'));
    ";
    cmd.ExecuteNonQuery();
}

// Safe migration for existing databases — adds columns if they don't exist
void MigrateDatabase(string connectionString)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    var migrations = new[]
    {
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE users ADD COLUMN discord TEXT",
        "ALTER TABLE licenses ADD COLUMN email TEXT",
        "ALTER TABLE licenses ADD COLUMN discord TEXT",
        "ALTER TABLE licenses ADD COLUMN last_ip TEXT",
        "ALTER TABLE applications ADD COLUMN admin_key TEXT"
    };
    foreach (var sql in migrations)
    {
        try
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }
        catch { /* Column already exists — ignore */ }
    }
}

string LoadAdminKey(string connectionString)
{
    try
    {
        using var conn = new SqliteConnection(connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT admin_key FROM applications WHERE name = 'plasma.lol'";
        var val = cmd.ExecuteScalar();
        if (val != null && val != DBNull.Value && !string.IsNullOrEmpty(val.ToString()))
        {
            return val.ToString();
        }
    }
    catch {}
    return "zuwki-admin";
}

void SaveAdminKey(string connectionString, string newKey)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE applications SET admin_key = @key WHERE name = 'plasma.lol'";
    cmd.Parameters.AddWithValue("@key", newKey);
    cmd.ExecuteNonQuery();
}

Application GetApplication(string connectionString, string name)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM applications WHERE name = @name";
    cmd.Parameters.AddWithValue("@name", name);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        return new Application
        {
            Id = Convert.ToInt32(reader["id"]),
            Name = reader["name"].ToString(),
            OwnerId = reader["ownerid"].ToString(),
            Secret = reader["secret"].ToString(),
            Version = reader["version"].ToString(),
            Paused = Convert.ToInt32(reader["paused"]),
            AdminKey = reader["admin_key"] != DBNull.Value ? reader["admin_key"]?.ToString() : "zuwki-admin"
        };
    }
    return null;
}

void UpdateApplicationPause(string connectionString, int id, int paused)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE applications SET paused = @paused WHERE id = @id";
    cmd.Parameters.AddWithValue("@paused", paused);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void UpdateApplicationSecret(string connectionString, int id, string secret)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE applications SET secret = @secret WHERE id = @id";
    cmd.Parameters.AddWithValue("@secret", secret);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

License GetLicenseByKey(string connectionString, string key)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM licenses WHERE key = @key";
    cmd.Parameters.AddWithValue("@key", key);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        return new License
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Key = reader["key"].ToString(),
            DurationDays = Convert.ToInt32(reader["duration_days"]),
            Level = Convert.ToInt32(reader["level"]),
            Hwid = reader["hwid"]?.ToString(),
            UsedBy = reader["used_by"]?.ToString(),
            Status = reader["status"].ToString(),
            Note = reader["note"]?.ToString(),
            CreatedAt = reader["created_at"]?.ToString(),
            UsedAt = reader["used_at"]?.ToString(),
            ExpiresAt = reader["expires_at"]?.ToString()
        };
    }
    return null;
}

License GetLicenseById(string connectionString, int id)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM licenses WHERE id = @id";
    cmd.Parameters.AddWithValue("@id", id);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        return new License
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Key = reader["key"].ToString(),
            DurationDays = Convert.ToInt32(reader["duration_days"]),
            Level = Convert.ToInt32(reader["level"]),
            Hwid = reader["hwid"]?.ToString(),
            UsedBy = reader["used_by"]?.ToString(),
            Status = reader["status"].ToString(),
            Note = reader["note"]?.ToString(),
            CreatedAt = reader["created_at"]?.ToString(),
            UsedAt = reader["used_at"]?.ToString(),
            ExpiresAt = reader["expires_at"]?.ToString()
        };
    }
    return null;
}

void InsertLicense(string connectionString, int appId, string key, int durationDays, int level, string note)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        INSERT INTO licenses (app_id, key, duration_days, level, status, note, created_at)
        VALUES (@appId, @key, @durationDays, @level, 'unused', @note, datetime('now'))";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@key", key);
    cmd.Parameters.AddWithValue("@durationDays", durationDays);
    cmd.Parameters.AddWithValue("@level", level);
    cmd.Parameters.AddWithValue("@note", note);
    cmd.ExecuteNonQuery();
}

void UpdateLicenseStatus(string connectionString, int id, string status, string usedBy, string hwid, string usedAt, string expiresAt)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        UPDATE licenses
        SET status = @status, used_by = @usedBy, hwid = @hwid, used_at = @usedAt, expires_at = @expiresAt
        WHERE id = @id";
    cmd.Parameters.AddWithValue("@status", status);
    cmd.Parameters.AddWithValue("@usedBy", usedBy);
    cmd.Parameters.AddWithValue("@hwid", hwid);
    cmd.Parameters.AddWithValue("@usedAt", usedAt);
    cmd.Parameters.AddWithValue("@expiresAt", expiresAt);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void UpdateLicenseStatusById(string connectionString, int id, string status)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE licenses SET status = @status WHERE id = @id";
    cmd.Parameters.AddWithValue("@status", status);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void DeleteLicense(string connectionString, int id)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "DELETE FROM licenses WHERE id = @id";
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void ResetLicenseHwid(string connectionString, int id)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE licenses SET hwid = NULL WHERE id = @id";
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

List<License> GetLicenses(string connectionString, int appId, int limit, int offset)
{
    var list = new List<License>();
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM licenses WHERE app_id = @appId ORDER BY id DESC LIMIT @limit OFFSET @offset";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@limit", limit);
    cmd.Parameters.AddWithValue("@offset", offset);
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        list.Add(new License
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Key = reader["key"].ToString(),
            DurationDays = Convert.ToInt32(reader["duration_days"]),
            Level = Convert.ToInt32(reader["level"]),
            Hwid = reader["hwid"]?.ToString(),
            UsedBy = reader["used_by"]?.ToString(),
            Status = reader["status"].ToString(),
            Note = reader["note"]?.ToString(),
            CreatedAt = reader["created_at"]?.ToString(),
            UsedAt = reader["used_at"]?.ToString(),
            ExpiresAt = reader["expires_at"]?.ToString()
        });
    }
    return list;
}

int CountLicenses(string connectionString, int appId)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT COUNT(*) FROM licenses WHERE app_id = @appId";
    cmd.Parameters.AddWithValue("@appId", appId);
    return Convert.ToInt32(cmd.ExecuteScalar());
}

int CountLicensesByStatus(string connectionString, int appId, string status)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT COUNT(*) FROM licenses WHERE app_id = @appId AND status = @status";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@status", status);
    return Convert.ToInt32(cmd.ExecuteScalar());
}

User GetUserByUsername(string connectionString, int appId, string username)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM users WHERE app_id = @appId AND username = @username";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@username", username);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        return new User
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Username = reader["username"].ToString(),
            PasswordHash = reader["password_hash"].ToString(),
            Hwid = reader["hwid"]?.ToString(),
            SubscriptionLevel = Convert.ToInt32(reader["subscription_level"]),
            CreatedAt = reader["created_at"]?.ToString(),
            ExpiresAt = reader["expires_at"]?.ToString(),
            Banned = Convert.ToInt32(reader["banned"]),
            LastLogin = reader["last_login"]?.ToString(),
            Ip = reader["ip"]?.ToString(),
            Email = reader["email"]?.ToString(),
            Discord = reader["discord"]?.ToString()
        };
    }
    return null;
}

void InsertUser(string connectionString, int appId, string username, string passwordHash, string hwid, int level, string expiresAt, string email, string discord, string ip)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        INSERT INTO users (app_id, username, password_hash, hwid, subscription_level, created_at, expires_at, email, discord, ip)
        VALUES (@appId, @username, @passwordHash, @hwid, @level, datetime('now'), @expiresAt, @email, @discord, @ip)";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@username", username);
    cmd.Parameters.AddWithValue("@passwordHash", passwordHash);
    cmd.Parameters.AddWithValue("@hwid", hwid);
    cmd.Parameters.AddWithValue("@level", level);
    cmd.Parameters.AddWithValue("@expiresAt", expiresAt);
    cmd.Parameters.AddWithValue("@email", (object)email ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@discord", (object)discord ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@ip", (object)ip ?? DBNull.Value);
    cmd.ExecuteNonQuery();
}

void UpdateUserLogin(string connectionString, int id, string ip, string lastLogin, string email, string discord)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    // Always update IP and last_login; only update email/discord if provided
    cmd.CommandText = @"
        UPDATE users SET ip = @ip, last_login = @lastLogin,
        email = CASE WHEN @email IS NOT NULL AND @email != '' THEN @email ELSE email END,
        discord = CASE WHEN @discord IS NOT NULL AND @discord != '' THEN @discord ELSE discord END
        WHERE id = @id";
    cmd.Parameters.AddWithValue("@ip", ip);
    cmd.Parameters.AddWithValue("@lastLogin", lastLogin);
    cmd.Parameters.AddWithValue("@email", (object)email ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@discord", (object)discord ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void UpdateLicenseUserInfo(string connectionString, int id, string email, string discord, string ip)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        UPDATE licenses SET
        email = CASE WHEN @email IS NOT NULL AND @email != '' THEN @email ELSE email END,
        discord = CASE WHEN @discord IS NOT NULL AND @discord != '' THEN @discord ELSE discord END,
        last_ip = @ip
        WHERE id = @id";
    cmd.Parameters.AddWithValue("@email", (object)email ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@discord", (object)discord ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@ip", (object)ip ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void UpdateUserHwid(string connectionString, int id, string hwid)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE users SET hwid = @hwid WHERE id = @id";
    cmd.Parameters.AddWithValue("@hwid", (object)hwid ?? DBNull.Value);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void UpdateUserBan(string connectionString, int id, int banned)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "UPDATE users SET banned = @banned WHERE id = @id";
    cmd.Parameters.AddWithValue("@banned", banned);
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

void DeleteUser(string connectionString, int id)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "DELETE FROM users WHERE id = @id";
    cmd.Parameters.AddWithValue("@id", id);
    cmd.ExecuteNonQuery();
}

List<User> GetUsers(string connectionString, int appId, int limit, int offset)
{
    var list = new List<User>();
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM users WHERE app_id = @appId ORDER BY id DESC LIMIT @limit OFFSET @offset";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@limit", limit);
    cmd.Parameters.AddWithValue("@offset", offset);
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        list.Add(new User
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Username = reader["username"].ToString(),
            PasswordHash = reader["password_hash"].ToString(),
            Hwid = reader["hwid"]?.ToString(),
            SubscriptionLevel = Convert.ToInt32(reader["subscription_level"]),
            CreatedAt = reader["created_at"]?.ToString(),
            ExpiresAt = reader["expires_at"]?.ToString(),
            Banned = Convert.ToInt32(reader["banned"]),
            LastLogin = reader["last_login"]?.ToString(),
            Ip = reader["ip"]?.ToString(),
            Email = reader["email"]?.ToString(),
            Discord = reader["discord"]?.ToString()
        });
    }
    return list;
}

int CountUsers(string connectionString, int appId)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT COUNT(*) FROM users WHERE app_id = @appId";
    cmd.Parameters.AddWithValue("@appId", appId);
    return Convert.ToInt32(cmd.ExecuteScalar());
}

void InsertSession(string connectionString, int appId, string sessionId, string ip)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        INSERT INTO sessions (app_id, session_id, ip, created_at)
        VALUES (@appId, @sessionId, @ip, datetime('now'))";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@sessionId", sessionId);
    cmd.Parameters.AddWithValue("@ip", ip);
    cmd.ExecuteNonQuery();
}

Session GetSession(string connectionString, string sessionId)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT * FROM sessions WHERE session_id = @sessionId";
    cmd.Parameters.AddWithValue("@sessionId", sessionId);
    using var reader = cmd.ExecuteReader();
    if (reader.Read())
    {
        return new Session
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            SessionId = reader["session_id"].ToString(),
            CreatedAt = reader["created_at"].ToString(),
            Ip = reader["ip"].ToString()
        };
    }
    return null;
}

void InsertLog(string connectionString, int appId, string ev, string username, string details, string ip)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = @"
        INSERT INTO logs (app_id, event, username, details, ip, created_at)
        VALUES (@appId, @event, @username, @details, @ip, datetime('now'))";
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@event", ev);
    cmd.Parameters.AddWithValue("@username", username ?? "");
    cmd.Parameters.AddWithValue("@details", details ?? "");
    cmd.Parameters.AddWithValue("@ip", ip ?? "");
    cmd.ExecuteNonQuery();
}

List<LogEntry> GetLogs(string connectionString, int appId, int limit, int offset, string filter)
{
    var list = new List<LogEntry>();
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    if (!string.IsNullOrEmpty(filter))
    {
        cmd.CommandText = "SELECT * FROM logs WHERE app_id = @appId AND event = @filter ORDER BY id DESC LIMIT @limit OFFSET @offset";
        cmd.Parameters.AddWithValue("@filter", filter);
    }
    else
    {
        cmd.CommandText = "SELECT * FROM logs WHERE app_id = @appId ORDER BY id DESC LIMIT @limit OFFSET @offset";
    }
    cmd.Parameters.AddWithValue("@appId", appId);
    cmd.Parameters.AddWithValue("@limit", limit);
    cmd.Parameters.AddWithValue("@offset", offset);

    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        list.Add(new LogEntry
        {
            Id = Convert.ToInt32(reader["id"]),
            AppId = Convert.ToInt32(reader["app_id"]),
            Event = reader["event"].ToString(),
            Username = reader["username"]?.ToString(),
            Details = reader["details"]?.ToString(),
            Ip = reader["ip"]?.ToString(),
            CreatedAt = reader["created_at"]?.ToString()
        });
    }
    return list;
}

int CountLogs(string connectionString, int appId, string filter)
{
    using var conn = new SqliteConnection(connectionString);
    conn.Open();
    using var cmd = conn.CreateCommand();
    if (!string.IsNullOrEmpty(filter))
    {
        cmd.CommandText = "SELECT COUNT(*) FROM logs WHERE app_id = @appId AND event = @filter";
        cmd.Parameters.AddWithValue("@filter", filter);
    }
    else
    {
        cmd.CommandText = "SELECT COUNT(*) FROM logs WHERE app_id = @appId";
    }
    cmd.Parameters.AddWithValue("@appId", appId);
    return Convert.ToInt32(cmd.ExecuteScalar());
}

// ----------------------------------------------------
// DATABASE MODELS
// ----------------------------------------------------
class Application
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string OwnerId { get; set; }
    public string Secret { get; set; }
    public string Version { get; set; }
    public int Paused { get; set; }
    public string AdminKey { get; set; }
}

class License
{
    public int Id { get; set; }
    public int AppId { get; set; }
    public string Key { get; set; }
    public int DurationDays { get; set; }
    public int Level { get; set; }
    public string Hwid { get; set; }
    public string UsedBy { get; set; }
    public string Status { get; set; }
    public string Note { get; set; }
    public string CreatedAt { get; set; }
    public string UsedAt { get; set; }
    public string ExpiresAt { get; set; }
}

class User
{
    public int Id { get; set; }
    public int AppId { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public string Hwid { get; set; }
    public int SubscriptionLevel { get; set; }
    public string CreatedAt { get; set; }
    public string ExpiresAt { get; set; }
    public int Banned { get; set; }
    public string LastLogin { get; set; }
    public string Ip { get; set; }
    public string Email { get; set; }
    public string Discord { get; set; }
}

class Session
{
    public int Id { get; set; }
    public int AppId { get; set; }
    public string SessionId { get; set; }
    public string CreatedAt { get; set; }
    public string Ip { get; set; }
}

class LogEntry
{
    public int Id { get; set; }
    public int AppId { get; set; }
    public string Event { get; set; }
    public string Username { get; set; }
    public string Details { get; set; }
    public string Ip { get; set; }
    public string CreatedAt { get; set; }
}
