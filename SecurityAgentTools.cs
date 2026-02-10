using Microsoft.Agents.AI;
using NuGet.ProjectModel;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Globalization;
using System.ComponentModel;
using System.IO;
using Cvss.Suite;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.CodeAnalysis.FindSymbols;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;
using System.Threading;


public class SecurityAgentTools
{
    // --- TOOL A: SCAN FOR OSS DEPENDENCIES ---
    [Description("Scans the project at the given path for all installed NuGet packages and their exact versions and returns them as a list.")]
    public static IEnumerable<(string packageName, string version)> GetProjectDependencies(string projectFilePath)
    {
        var safePath = projectFilePath ?? string.Empty;

        // Use the assets file which lists ALL transitive dependencies
        // If the caller provided a directory, use it; otherwise treat the input as a project file path
        var dir = Directory.Exists(safePath) ? safePath : Path.GetDirectoryName(safePath) ?? string.Empty;
        var assetsPath = Path.Combine(dir, "obj", "project.assets.json");
        var lockFile = LockFileUtilities.GetLockFile(assetsPath, null);
        if (lockFile == null) return Enumerable.Empty<(string packageName, string version)>();

        var packages = lockFile.Targets
            .SelectMany(t => t.Libraries)
            .Select(l => (packageName: l.Name ?? string.Empty, version: l.Version?.ToNormalizedString() ?? string.Empty))
            .Where(p => !string.IsNullOrEmpty(p.packageName) && !string.IsNullOrEmpty(p.version))
            .Distinct()
            .ToList();

        // Fire-and-forget: Generate dependency graph with metadata as a side effect
        _ = Task.Run(async () =>
        {
            try
            {
                var graph = new DependencyGraph();
                
                // Add all packages as nodes with metadata
                foreach (var (name, version) in packages)
                {
                    var key = $"{name}@{version}";
                    graph.AddNode(name, version);
                    
                    // Populate metadata
                    if (!graph.Metadata.ContainsKey(key))
                    {
                        graph.Metadata[key] = new PackageMetadata
                        {
                            PackageName = name,
                            Version = version,
                            NuGetMetadata = new NuGetMetadata()
                        };
                    }
                }

                // Build dependency relationships from lockFile
                foreach (var target in lockFile.Targets)
                {
                    foreach (var lib in target.Libraries)
                    {
                        if (!string.IsNullOrEmpty(lib.Name))
                        {
                            var libVersion = lib.Version?.ToNormalizedString() ?? "0.0.0";
                            if (lib.Dependencies != null)
                            {
                                foreach (var dep in lib.Dependencies)
                                {
                                    if (!string.IsNullOrEmpty(dep.Id))
                                    {
                                        var depVersion = dep.VersionRange?.ToString() ?? "0.0.0";
                                        graph.AddDependency(lib.Name, libVersion, dep.Id, depVersion);
                                    }
                                }
                            }
                        }
                    }
                }

                // Save to dependency-graph.json
                await graph.SaveToFileAsync(dir);
            }
            catch
            {
                // Silently fail - this is a side effect
            }
        });

        return packages;
    }

    

    // --- TOOL B: SEARCH FOR VULNERABILITIES (OSV.dev) ---
    [Description("Queries the OSV.dev API for known vulnerabilities for a list of package+version pairs using batch queries (ecosystem=NuGet).")]
    public static async Task<string> CheckVulnerabilities(IEnumerable<(string packageName, string version)> packages)
    {
        if (packages == null) return JsonSerializer.Serialize(new { error = "packages argument is required" });

        // Normalize input and dedupe
        var pkgList = packages.Where(p => !string.IsNullOrWhiteSpace(p.packageName) && !string.IsNullOrWhiteSpace(p.version))
                              .Select(p => (name: p.packageName.Trim(), version: p.version.Trim()))
                              .ToList();

        if (!pkgList.Any()) return JsonSerializer.Serialize(new { error = "no valid package entries provided" });

        var finalResult = new Dictionary<string, object>();
        var cache = new Dictionary<string, object>(); // in-run cache keyed by "name@version"

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        const int batchSize = 100;
        const int maxAttempts = 3;

        // Process in chunks
        for (int i = 0; i < pkgList.Count; i += batchSize)
        {
            var chunk = pkgList.Skip(i).Take(batchSize).ToList();

            // Build queries array
            var queries = chunk.Select(p => new { package = new { name = p.name, ecosystem = "NuGet" }, version = p.version }).ToArray();
            var payload = JsonSerializer.Serialize(new { queries });
            using var content = new StringContent(payload, Encoding.UTF8, "application/json");

            HttpResponseMessage? response = null;
            string? body = null;
            int attempt = 0;
            while (attempt < maxAttempts)
            {
                attempt++;
                try
                {
                    // Use the documented batch endpoint
                    response = await client.PostAsync("https://api.osv.dev/v1/querybatch", content);
                    if (response.IsSuccessStatusCode)
                    {
                        body = await response.Content.ReadAsStringAsync();
                        break;
                    }

                    // Handle rate limits
                    if ((int)response.StatusCode == 429 || ((int)response.StatusCode >= 500 && (int)response.StatusCode < 600))
                    {
                        // respect Retry-After if present
                        if (response.Headers.TryGetValues("Retry-After", out var vals))
                        {
                            if (int.TryParse(vals.FirstOrDefault(), out var secs))
                                await Task.Delay(TimeSpan.FromSeconds(secs));
                        }
                        else
                        {
                            await Task.Delay(TimeSpan.FromMilliseconds(500 * attempt));
                        }
                        continue; // retry
                    }

                    // Non-retriable error for this chunk
                    body = await response.Content.ReadAsStringAsync();
                    break;
                }
                catch (Exception)
                {
                    // transient network error -> backoff and retry
                    await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt));
                }
            }

            if (string.IsNullOrEmpty(body))
            {
                // mark each package in chunk with error
                foreach (var p in chunk)
                {
                    var key = $"{p.name}@{p.version}";
                    if (!finalResult.ContainsKey(key)) finalResult[key] = new { error = "OSV query failed or timed out" };
                }
                continue;
            }

            // Parse response body
            try
            {
                using var doc = JsonDocument.Parse(body);

                if (!doc.RootElement.TryGetProperty("results", out var resultsElem) || resultsElem.ValueKind != JsonValueKind.Array)
                {
                    // Unexpected shape: mark errors
                    foreach (var p in chunk)
                    {
                        var key = $"{p.name}@{p.version}";
                        if (!finalResult.ContainsKey(key)) finalResult[key] = new { error = "Unexpected OSV response format" };
                    }
                    continue;
                }

                var results = resultsElem.EnumerateArray().ToArray();

                for (int idx = 0; idx < results.Length; idx++)
                {
                    var p = chunk[idx];
                    var key = $"{p.name}@{p.version}";
                    if (cache.TryGetValue(key, out var cached))
                    {
                        finalResult[key] = cached;
                        continue;
                    }

                    var resElem = results[idx];
                    var vulnsList = new List<Dictionary<string, object?>>();

                    if (resElem.TryGetProperty("vulns", out var vulnsElem) && vulnsElem.ValueKind == JsonValueKind.Array)
                    {
                        // Each entry in the batch result contains vuln ids and modified; fetch full vuln details per id
                        foreach (var vulnSummary in vulnsElem.EnumerateArray())
                        {
                            if (!vulnSummary.TryGetProperty("id", out var idProp) || idProp.ValueKind != JsonValueKind.String)
                                continue;
                            var vulnId = idProp.GetString();
                            if (string.IsNullOrEmpty(vulnId)) continue;

                            // GET full vulnerability object
                            try
                            {
                                var vulnUrl = $"https://api.osv.dev/v1/vulns/{Uri.EscapeDataString(vulnId)}";
                                var vulnBody = await client.GetStringAsync(vulnUrl);
                                using var vulnDoc = JsonDocument.Parse(vulnBody);
                                var vulnElemFull = vulnDoc.RootElement;

                                string? id = null;
                                if (vulnElemFull.TryGetProperty("id", out var idFull) && idFull.ValueKind == JsonValueKind.String)
                                    id = idFull.GetString();

                                string? summary = null;
                                if (vulnElemFull.TryGetProperty("summary", out var sumFull) && sumFull.ValueKind == JsonValueKind.String)
                                    summary = sumFull.GetString();

                                string? details = null;
                                if (vulnElemFull.TryGetProperty("details", out var detFull) && detFull.ValueKind == JsonValueKind.String)
                                    details = detFull.GetString();

                                string? description = details ?? summary;

                                double? score = null;

                                // If still null, check the 'severity' array for a CVSS v3 vector (type=="CVSS_V3" and score contains the vector)
                                if (score == null && vulnElemFull.TryGetProperty("severity", out var severityFull) && severityFull.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var sevEntry in severityFull.EnumerateArray())
                                    {
                                        if (sevEntry.ValueKind != JsonValueKind.Object) continue;
                                        if (sevEntry.TryGetProperty("type", out var typeProp) && typeProp.ValueKind == JsonValueKind.String &&
                                            string.Equals(typeProp.GetString(), "CVSS_V3", StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (sevEntry.TryGetProperty("score", out var scoreProp) && scoreProp.ValueKind == JsonValueKind.String)
                                            {
                                                var vec = scoreProp.GetString();
                                                try
                                                {
                                                    if (!string.IsNullOrWhiteSpace(vec))
                                                    {
                                                        try
                                                        {
                                                            var cv = CvssSuite.Create(vec ?? string.Empty);
                                                            if (cv != null && cv.IsValid())
                                                            {
                                                                double? parsed = null;
                                                                try { parsed = Math.Round(cv.BaseScore(), 1); } catch { }
                                                                if (!parsed.HasValue)
                                                                {
                                                                    try
                                                                    {
                                                                        var scoreObj = cv.Score();
                                                                        var s = scoreObj.ToString()?.Replace(',', '.');
                                                                        if (double.TryParse(s, System.Globalization.NumberStyles.Any, System.Globalization.CultureInfo.InvariantCulture, out var val))
                                                                            parsed = Math.Round(val, 1);
                                                                    }
                                                                    catch { }
                                                                }
                                                                if (!parsed.HasValue)
                                                                {
                                                                    try { parsed = Math.Round(cv.OverallScore(), 1); } catch { }
                                                                }
                                                                if (parsed.HasValue)
                                                                {
                                                                    score = parsed.Value;
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                        catch { }
                                                    }
                                                }
                                                catch { }
                                            }
                                        }
                                    }
                                }

                                string? publishedDate = null;
                                if (vulnElemFull.TryGetProperty("published", out var pubFull) && pubFull.ValueKind == JsonValueKind.String)
                                {
                                    var pd = pubFull.GetString();
                                    if (pd != null) publishedDate = pd;
                                }
                                else if (vulnElemFull.TryGetProperty("modified", out var modFull) && modFull.ValueKind == JsonValueKind.String)
                                {
                                    var md = modFull.GetString();
                                    if (md != null) publishedDate = md;
                                }

                                var references = new List<string>();
                                if (vulnElemFull.TryGetProperty("references", out var refsFull) && refsFull.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var r in refsFull.EnumerateArray())
                                    {
                                                        if (r.ValueKind == JsonValueKind.Object && r.TryGetProperty("url", out var urlProp) && urlProp.ValueKind == JsonValueKind.String)
                                                        {
                                                            var url = urlProp.GetString();
                                                            if (url != null) references.Add(url);
                                                        }
                                                        else if (r.ValueKind == JsonValueKind.String)
                                                        {
                                                            var url = r.GetString();
                                                            if (url != null) references.Add(url);
                                                        }
                                    }
                                }

                                var affectedVersions = new List<string>();
                                var fixedIn = new List<string>();
                                if (vulnElemFull.TryGetProperty("affected", out var affectedFull) && affectedFull.ValueKind == JsonValueKind.Array)
                                {
                                    foreach (var affectedEntry in affectedFull.EnumerateArray())
                                    {
                                        if (affectedEntry.TryGetProperty("versions", out var versionsProp) && versionsProp.ValueKind == JsonValueKind.Array)
                                        {
                                            foreach (var v in versionsProp.EnumerateArray())
                                            {
                                                if (v.ValueKind == JsonValueKind.String)
                                                {
                                                    var vs = v.GetString();
                                                    if (vs != null) affectedVersions.Add(vs);
                                                }
                                            }
                                        }

                                        if (affectedEntry.TryGetProperty("ranges", out var rangesProp) && rangesProp.ValueKind == JsonValueKind.Array)
                                        {
                                            foreach (var range in rangesProp.EnumerateArray())
                                            {
                                                if (range.TryGetProperty("events", out var eventsProp) && eventsProp.ValueKind == JsonValueKind.Array)
                                                {
                                                    foreach (var ev in eventsProp.EnumerateArray())
                                                    {
                                                        if (ev.TryGetProperty("introduced", out var intro) && intro.ValueKind == JsonValueKind.String)
                                                        {
                                                            var introS = intro.GetString();
                                                            if (introS != null) affectedVersions.Add($"introduced:{introS}");
                                                        }
                                                        if (ev.TryGetProperty("fixed", out var fixedProp) && fixedProp.ValueKind == JsonValueKind.String)
                                                        {
                                                            var fixedS = fixedProp.GetString();
                                                            if (fixedS != null) fixedIn.Add(fixedS);
                                                        }
                                                    }
                                                }
                                                if (range.TryGetProperty("introduced", out var rtIntro) && rtIntro.ValueKind == JsonValueKind.String)
                                                {
                                                    var rtIntroS = rtIntro.GetString();
                                                    if (rtIntroS != null) affectedVersions.Add($"introduced:{rtIntroS}");
                                                }
                                                if (range.TryGetProperty("fixed", out var rtFixed) && rtFixed.ValueKind == JsonValueKind.String)
                                                {
                                                    var rtFixedS = rtFixed.GetString();
                                                    if (rtFixedS != null) fixedIn.Add(rtFixedS);
                                                }
                                            }
                                        }
                                    }
                                }

                                var vulnObj = new Dictionary<string, object?>
                                {
                                    ["id"] = id,
                                    ["summary"] = summary,
                                    ["details"] = details,
                                    ["score"] = score,
                                    ["description"] = description,
                                    ["fixed_in"] = fixedIn.Distinct().ToList(),
                                    ["affected_versions"] = affectedVersions.Distinct().ToList(),
                                    ["published_date"] = publishedDate,
                                    ["references"] = references
                                };

                                vulnsList.Add(vulnObj);
                            }
                            catch (Exception)
                            {
                                // if fetching the full vuln fails, skip and continue
                                continue;
                            }
                        }
                    }

                    // store result and cache
                    cache[key] = vulnsList;
                    finalResult[key] = vulnsList;
                }
            }
            catch (Exception ex)
            {
                foreach (var p in chunk)
                {
                    var key = $"{p.name}@{p.version}";
                    if (!finalResult.ContainsKey(key)) finalResult[key] = new { error = ex.Message };
                }
            }
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
        return JsonSerializer.Serialize(finalResult, options);
    }

    // --- TOOL C: SEMANTIC CODE USAGE ANALYSIS (Roslyn) ---
    [Description("Analyze code usage for packages with detected vulnerabilities and produce risk summaries and upgrade recommendations.")]
    public static async Task<string> AnalyzeCodeUsage(string vulnerabilitiesJson, string repoPath)
    {
        
        if (string.IsNullOrWhiteSpace(vulnerabilitiesJson))
            return JsonSerializer.Serialize(new { error = "vulnerabilitiesJson is required" });

        // Parse the vulnerabilities JSON produced by CheckVulnerabilities
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(vulnerabilitiesJson);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = "Invalid JSON provided to AnalyzeCodeUsage", detail = ex.Message });
        }

        // Locate all .csproj files under repoPath (do not use .sln)
        string[] projFiles;
        try
        {
            projFiles = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
        }
        catch
        {
            projFiles = Array.Empty<string>();
        }

        if (projFiles.Length == 0)
            return JsonSerializer.Serialize(new { error = "No .csproj files found under repoPath" });

        // Parse PackageReference entries to map package -> projects that reference it
        var packageToProjects = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var pf in projFiles)
            {
                try
                {
                    var docXml = System.Xml.Linq.XDocument.Load(pf);
                    var pkgRefs = docXml.Descendants().Where(x => x.Name.LocalName == "PackageReference");
                    foreach (var pr in pkgRefs)
                    {
                        var include = pr.Attribute("Include")?.Value ?? pr.Attribute("Update")?.Value;
                        if (string.IsNullOrWhiteSpace(include)) continue;
                        if (!packageToProjects.TryGetValue(include, out var list))
                        {
                            list = new List<string>();
                            packageToProjects[include] = list;
                        }
                        list.Add(pf);
                    }
                }
                catch { }
            }
        }
        catch { }

        Microsoft.CodeAnalysis.Solution? solution = null;
        using var workspace = MSBuildWorkspace.Create();
        // Open all projects to populate the workspace solution
        foreach (var pf in projFiles)
        {
            try { await workspace.OpenProjectAsync(pf); } catch { }
        }
        solution = workspace.CurrentSolution;

        var results = new Dictionary<string, object?>();

        // Determine which packages to analyze.
        // If the vulnerabilities JSON contains no entries or only empty arrays, fall back to analyzing all project dependencies.
        var props = doc.RootElement.EnumerateObject().ToArray();
        var packagesToProcess = new List<string>();
        if (props.Length == 0)
        {
            // no vuln info at all -> analyze all project dependencies
            var deps = GetProjectDependencies(repoPath ?? string.Empty).Select(p => p.packageName).Distinct(StringComparer.OrdinalIgnoreCase);
            packagesToProcess.AddRange(deps);
        }
        else
        {
            // collect keys that have vulnerabilities (non-empty arrays) or, if none have vulns, collect all keys
            foreach (var p in props)
            {
                packagesToProcess.Add(p.Name);
            }

            // if every entry is an empty array or error, prefer analyzing all project deps instead
            bool anyWithVulns = props.Any(pr => pr.Value.ValueKind == JsonValueKind.Array && pr.Value.GetArrayLength() > 0);
            if (!anyWithVulns)
            {
                var deps = GetProjectDependencies(repoPath ?? string.Empty).Select(p => p.packageName).Distinct(StringComparer.OrdinalIgnoreCase);
                packagesToProcess = deps.ToList();
            }
        }

        // For lookup convenience, keep the parsed doc properties in a dictionary
        var vulnDict = props.ToDictionary(p => p.Name, p => p.Value);

        // For each package to process, analyze usage
        foreach (var pkgKey in packagesToProcess)
        {
            var pkgParts = pkgKey.Split('@');
            var pkgName = pkgParts.Length > 0 ? pkgParts[0] : pkgKey;
            var pkgVersion = pkgParts.Length > 1 ? pkgParts[1] : string.Empty;

            // Look up vulnerability entry if available
            JsonElement entry;
            var vulnDetails = new List<Dictionary<string, object?>>();
            if (vulnDict.TryGetValue(pkgKey, out entry))
            {
                // If entry is an object with 'error', record and continue
                if (entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("error", out var err))
                {
                    results[pkgKey] = new { package = pkgName, version = pkgVersion, error = err.GetString() };
                    continue;
                }

                if (entry.ValueKind == JsonValueKind.Array && entry.GetArrayLength() > 0)
                {
                    foreach (var v in entry.EnumerateArray())
                    {
                        var vd = new Dictionary<string, object?>();
                        if (v.ValueKind == JsonValueKind.Object)
                        {
                            if (v.TryGetProperty("id", out var idp) && idp.ValueKind == JsonValueKind.String) vd["id"] = idp.GetString();
                            if (v.TryGetProperty("summary", out var sp) && sp.ValueKind == JsonValueKind.String) vd["summary"] = sp.GetString();
                            if (v.TryGetProperty("details", out var dp) && dp.ValueKind == JsonValueKind.String) vd["details"] = dp.GetString();
                            if (v.TryGetProperty("score", out var sc))
                            {
                                if (sc.ValueKind == JsonValueKind.Number)
                                    vd["score"] = sc.GetDouble();
                                else if (sc.ValueKind == JsonValueKind.String)
                                    vd["score"] = sc.GetString();
                                else
                                    vd["score"] = sc.GetRawText();
                            }
                            if (v.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array)
                            {
                                var rlist = new List<string>();
                                foreach (var r in refs.EnumerateArray())
                                {
                                    if (r.ValueKind == JsonValueKind.String)
                                    {
                                        var s = r.GetString();
                                        if (s != null) rlist.Add(s);
                                    }
                                }
                                vd["references"] = rlist;
                            }
                            if (v.TryGetProperty("fixed_in", out var fixedProp) && fixedProp.ValueKind == JsonValueKind.Array)
                            {
                                var fixedList = new List<string>();
                                foreach (var fi in fixedProp.EnumerateArray())
                                {
                                    if (fi.ValueKind == JsonValueKind.String)
                                    {
                                        var s = fi.GetString();
                                        if (s != null) fixedList.Add(s);
                                    }
                                }
                                vd["fixed_in"] = fixedList.Distinct().ToList();
                            }
                        }
                        vulnDetails.Add(vd);
                    }
                }
            }

                // If this package has no vulnerabilities, do not call OpenAI — return a default message.
                if (vulnDetails.Count == 0)
                {
                    results[pkgKey] = new
                    {
                        package = pkgName,
                        version = pkgVersion,
                        aiRecommendation = string.Empty,
                        riskSummary = "There are no vulnerabilities therefore no risk summary/recommendation was generated.",
                        vulnerabilities = vulnDetails
                    };
                    continue;
                }

            // Derive candidate symbol tokens from package name (split by '.' and '-')
            var tokens = pkgName.Split(new[] { '.', '-', '_' }, StringSplitOptions.RemoveEmptyEntries)
                                .Where(t => t.Length >= 2)
                                .Distinct(StringComparer.OrdinalIgnoreCase)
                                .ToList();
            if (!tokens.Any()) tokens.Add(pkgName);

            int totalUsage = 0;
            var topLocations = new List<string>();

            foreach (var token in tokens)
            {
                if (solution != null)
                {
                    var symbols = await SymbolFinder.FindSourceDeclarationsAsync(solution, token, false);
                    foreach (var sym in symbols)
                    {
                        var refs = await SymbolFinder.FindReferencesAsync(sym, solution);
                        var locations = refs.SelectMany(r => r.Locations).ToList();
                        totalUsage += locations.Count;

                        // capture up to 3 location snippets
                        foreach (var loc in locations.Take(3))
                        {
                            if (loc.Location.IsInSource)
                            {
                                try
                                {
                                    var text = await loc.Location.SourceTree.GetTextAsync();
                                    var span = loc.Location.SourceSpan;
                                    var line = text.Lines.GetLineFromPosition(span.Start);
                                    var snippet = line.ToString().Trim();
                                    var filePath = loc.Location.SourceTree?.FilePath ?? "";
                                    topLocations.Add($"{filePath}:{line.LineNumber + 1}: {snippet}");
                                }
                                catch { }
                            }
                        }
                    }
                }
                else
                {
                    // Fallback: simple token-based text scan across .cs files
                    try
                    {
                        var csFiles = Directory.GetFiles(repoPath ?? ".", "*.cs", SearchOption.AllDirectories);
                        foreach (var file in csFiles)
                        {
                            string text;
                            try { text = File.ReadAllText(file); }
                            catch { continue; }

                            var matches = Regex.Matches(text, "\\b" + Regex.Escape(token) + "\\b", RegexOptions.IgnoreCase);
                            if (matches.Count == 0) continue;
                            totalUsage += matches.Count;

                            // capture first match line
                            var firstIndex = matches[0].Index;
                            var upto = text.Substring(0, firstIndex);
                            var lineNo = upto.Count(c => c == '\n');
                            var lines = text.Split('\n');
                            string snippet = lineNo >= 0 && lineNo < lines.Length ? lines[lineNo].Trim() : lines.FirstOrDefault()?.Trim() ?? "";
                            topLocations.Add($"{file}:{lineNo + 1}: {snippet}");
                        }
                    }
                    catch { }
                }
            }

            // No heuristic recommendation calculation here; we preserve per-vulnerability scores as parsed above.

            // Build AI prompt context and let the model generate the risk summary.
            var referencingProjects = packageToProjects.TryGetValue(pkgName, out var projList) ? projList : new List<string>();

            var promptContextFull = new
            {
                package = pkgName,
                version = pkgVersion,
                vulnerabilities = vulnDetails,
                usage_count = totalUsage,
                top_locations = topLocations,
                referencing_projects = referencingProjects
            };

            string generatedSummary = string.Empty;
            try
            {
                // Prefer credentials from api_key.env located at the repo root, fallback to .env and then environment variables.
                    // Use the project root (current working directory) to locate api_key.env/.env
                    string baseDir = string.Empty;
                    try { baseDir = Directory.GetCurrentDirectory(); } catch { baseDir = repoPath ?? string.Empty; }
                    string apiEnvPath = string.Empty;
                    try
                    {
                        apiEnvPath = Path.Combine(baseDir ?? string.Empty, "api_key.env");
                    }
                    catch { apiEnvPath = string.Empty; }
                    string dotEnvPath = string.Empty;
                    try { dotEnvPath = Path.Combine(baseDir ?? string.Empty, ".env"); } catch { dotEnvPath = string.Empty; }
                string? fileUrl = null;
                string? fileKey = null;

                // Helper to parse simple KEY=VALUE files (ignores comments starting with #)
                static void ParseKeyFile(string path, ref string? outUrl, ref string? outKey)
                {
                    try
                    {
                        if (!File.Exists(path)) return;
                        foreach (var line in File.ReadAllLines(path))
                        {
                            var l = line.Trim();
                            if (string.IsNullOrEmpty(l) || l.StartsWith("#")) continue;
                            var idx = l.IndexOf('=');
                            if (idx <= 0) continue;
                            var k = l.Substring(0, idx).Trim();
                            var v = l.Substring(idx + 1).Trim().Trim('"');
                            if (k.Equals("COPILOT_API_URL", StringComparison.OrdinalIgnoreCase) || k.Equals("API_URL", StringComparison.OrdinalIgnoreCase)) outUrl = v;
                            if (k.Equals("COPILOT_API_KEY", StringComparison.OrdinalIgnoreCase) || k.Equals("API_KEY", StringComparison.OrdinalIgnoreCase) || k.Equals("OPENAI_API_KEY", StringComparison.OrdinalIgnoreCase)) outKey = v;
                        }
                    }
                    catch { }
                }

                try
                {
                    ParseKeyFile(apiEnvPath, ref fileUrl, ref fileKey);
                    // If not found in api_key.env, try .env
                    if (string.IsNullOrEmpty(fileKey)) ParseKeyFile(dotEnvPath, ref fileUrl, ref fileKey);
                }
                catch { }

                var copilotUrl = fileUrl ?? Environment.GetEnvironmentVariable("COPILOT_API_URL") ?? "https://api.openai.com/v1/chat/completions";
                var copilotKey = fileKey ?? Environment.GetEnvironmentVariable("COPILOT_API_KEY") ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY");

                // Determine where the key came from for diagnostics (do not print the key)
                string keySource = string.Empty;
                try
                {
                    if (!string.IsNullOrEmpty(fileKey) && File.Exists(apiEnvPath)) keySource = "api_key.env";
                    else if (!string.IsNullOrEmpty(fileKey) && File.Exists(dotEnvPath)) keySource = ".env";
                    else if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("COPILOT_API_KEY")) || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("OPENAI_API_KEY"))) keySource = "environment";
                }
                catch { }

                var requestBody = new Dictionary<string, object?>();
                requestBody["model"] = "gpt-4.1-nano";
                requestBody["messages"] = new[] {
                    new { role = "system", content = "You are a security analyst. Based only on the provided JSON context, produce a focused ~200-token risk summary explaining whether and how the reported vulnerabilities affect this codebase, and provide a concise recommendation label (Upgrade / Consider / Monitor / No action). Return the summary and recommendation as plain text." },
                    new { role = "user", content = JsonSerializer.Serialize(promptContextFull) }
                };
                requestBody["max_completion_tokens"] = 300;
                requestBody["temperature"] = 0.1;

                // If no API key is configured, skip the AI call and use the deterministic fallback.
                if (string.IsNullOrEmpty(copilotKey))
                {
                    // do not attempt a network call without credentials
                }
                else
                {
                    using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
                    using var contentCopilot = new StringContent(JsonSerializer.Serialize(requestBody), Encoding.UTF8, "application/json");
                    http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", copilotKey);

                    var resp = await http.PostAsync(copilotUrl, contentCopilot);
                    var respBody = await resp.Content.ReadAsStringAsync();
                    if (!resp.IsSuccessStatusCode)
                    {
                        Console.WriteLine($"[AI] Request failed: {resp.StatusCode}. Response: { (string.IsNullOrEmpty(respBody) ? "(empty)" : respBody.Length>2000? respBody.Substring(0,2000)+"...": respBody)}");
                    }
                    else
                    {
                        try
                        {
                            using var respDoc = JsonDocument.Parse(respBody);
                            if (respDoc.RootElement.TryGetProperty("choices", out var choices) && choices.ValueKind == JsonValueKind.Array && choices.GetArrayLength() > 0)
                            {
                                var choice = choices[0];
                                if (choice.TryGetProperty("message", out var msg) && msg.TryGetProperty("content", out var contentProp) && contentProp.ValueKind == JsonValueKind.String)
                                {
                                    var text = contentProp.GetString();
                                    if (!string.IsNullOrEmpty(text)) generatedSummary = text.Trim();
                                }
                                else if (choice.TryGetProperty("text", out var textProp) && textProp.ValueKind == JsonValueKind.String)
                                {
                                    var text = textProp.GetString();
                                    if (!string.IsNullOrEmpty(text)) generatedSummary = text.Trim();
                                }
                            }
                            else
                            {
                                Console.WriteLine($"[AI] Unexpected response shape; raw body: {(string.IsNullOrEmpty(respBody)?"(empty)": (respBody.Length>2000? respBody.Substring(0,2000)+"...": respBody))}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[AI] Failed to parse response body: {ex.Message}. Raw: {(string.IsNullOrEmpty(respBody)?"(empty)": (respBody.Length>2000? respBody.Substring(0,2000)+"...": respBody))}");
                        }
                    }
                }
            }
            catch
            {
                // network or parsing failure -> fallback
            }

            if (string.IsNullOrEmpty(generatedSummary))
            {
                // Fallback: short deterministic summary without recommendation
                generatedSummary = $"Usage count: {totalUsage}. Referencing projects: {string.Join(", ", referencingProjects.Take(3))}.";
            }

            // Derive a one-line recommendation from the AI-generated summary when possible.
            string aiRecommendation = string.Empty;
            try
            {
                if (!string.IsNullOrEmpty(generatedSummary))
                {
                    // First, look for one of the canonical labels the model is asked to produce.
                    var labelMatch = System.Text.RegularExpressions.Regex.Match(generatedSummary, "\\b(Upgrade|Consider|Monitor|No\\s*action)\\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (labelMatch.Success)
                    {
                        aiRecommendation = labelMatch.Value.Trim();
                    }
                    else
                    {
                        // Otherwise try to capture after a 'Recommendation:' prefix (up to punctuation or newline)
                        var recMatch = System.Text.RegularExpressions.Regex.Match(generatedSummary, "Recommendation[:\\-]\\s*(.+?)(?:\\r?\\n|\\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (recMatch.Success && recMatch.Groups.Count > 1)
                        {
                            aiRecommendation = recMatch.Groups[1].Value.Trim();
                        }
                    }
                }
            }
            catch { aiRecommendation = string.Empty; }

            if (string.IsNullOrWhiteSpace(aiRecommendation))
            {
                // No AI recommendation available; leave empty
                aiRecommendation = string.Empty;
            }


            results[pkgKey] = new
            {
                package = pkgName,
                version = pkgVersion,
                aiRecommendation = aiRecommendation,
                riskSummary = generatedSummary,
                vulnerabilities = vulnDetails
            };
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };

        return JsonSerializer.Serialize(results, options);
    }
}
