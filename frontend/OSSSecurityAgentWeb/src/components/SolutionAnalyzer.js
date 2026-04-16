import React, { useState } from 'react';
import '../styles/SolutionAnalyzer.css';

export default function SolutionAnalyzer({ analysisResult, onRemediatePackage, isLoading }) {
  const [expandedProject, setExpandedProject] = useState(null);
  const [expandedPackage, setExpandedPackage] = useState(null);
  const [expandedSummaries, setExpandedSummaries] = useState({});
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [showAllDependencies, setShowAllDependencies] = useState(false);

  if (!analysisResult) {
    return (
      <div className="solution-analyzer">
        <p className="no-analysis">No analysis performed yet</p>
      </div>
    );
  }

  const { solution, projects, packages, vulnerabilities, recommendations } = analysisResult;

  const getSeverityColor = (severity) => {
    const map = {
      CRITICAL: '#d32f2f',
      HIGH: '#f57c00',
      MEDIUM: '#fbc02d',
      LOW: '#388e3c'
    };
    return map[severity] || '#666';
  };

  // Extract vulnerable packages from projects
  const getVulnerablePackages = () => {
    let vulnPackages = [];

    // Try primary source: projects array
    if (projects && projects.length > 0) {
      const vulnerableMap = new Map();

      projects.forEach((project) => {
        if (project.packages && Array.isArray(project.packages)) {
          project.packages.forEach((pkg) => {
            if (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) {
              const key = `${pkg.name}@${pkg.version}`;
              if (!vulnerableMap.has(key)) {
                vulnerableMap.set(key, {
                  name: pkg.name,
                  version: pkg.version,
                  key,
                  count: pkg.vulnerabilities.length,
                  vulnerabilities: pkg.vulnerabilities,
                  aiRecommendation: pkg.aiRecommendation || '',
                  riskSummary: pkg.riskSummary || '',
                  severities: getSeverityCounts(pkg.vulnerabilities)
                });
              }
            }
          });
        }
      });

      vulnPackages = Array.from(vulnerableMap.values());
    } else if (packages && packages.detailed && Array.isArray(packages.detailed)) {
      // Fallback: get from packages.detailed
      vulnPackages = packages.detailed
        .filter(pkg => pkg.vulnerabilityCount > 0)
        .map(pkg => ({
          name: pkg.name,
          version: pkg.version,
          key: `${pkg.name}@${pkg.version}`,
          count: pkg.vulnerabilityCount,
          vulnerabilities: pkg.vulnerabilities || [],
          aiRecommendation: pkg.aiRecommendation || '',
          riskSummary: pkg.riskSummary || '',
          severities: pkg.vulnerabilities ? getSeverityCounts(pkg.vulnerabilities) : {}
        }));
    }

    return vulnPackages;
  };

  const getSeverityCounts = (vulns) => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    if (!vulns) return counts;
    vulns.forEach((v) => {
      if (counts.hasOwnProperty(v.severity)) {
        counts[v.severity]++;
      }
    });
    return counts;
  };

  // Get all packages aggregated from all projects (for the dependencies table)
  const getAllPackages = () => {
    // Use the complete packages.detailed array from the API response
    if (packages && packages.detailed && Array.isArray(packages.detailed)) {
      return packages.detailed.map(pkg => ({
        name: pkg.name,
        version: pkg.version,
        vulnCount: pkg.vulnerabilityCount || 0,
        isVulnerable: (pkg.vulnerabilityCount || 0) > 0
      })).sort((a, b) => {
        // Sort vulnerable first, then by name
        if (a.isVulnerable !== b.isVulnerable) {
          return b.isVulnerable - a.isVulnerable;
        }
        return a.name.localeCompare(b.name);
      });
    }

    // Fallback to aggregating from projects if packages.detailed unavailable
    if (!projects) return [];
    const packageMap = new Map();

    projects.forEach((project) => {
      if (project.packages && Array.isArray(project.packages)) {
        project.packages.forEach((pkg) => {
          const key = `${pkg.name}@${pkg.version}`;
          if (!packageMap.has(key)) {
            packageMap.set(key, {
              name: pkg.name,
              version: pkg.version,
              vulnCount: (pkg.vulnerabilities && pkg.vulnerabilities.length) || 0,
              isVulnerable: (pkg.vulnerabilities && pkg.vulnerabilities.length > 0) || false
            });
          }
        });
      }
    });

    return Array.from(packageMap.values()).sort((a, b) => {
      // Sort vulnerable first, then by name
      if (a.isVulnerable !== b.isVulnerable) {
        return b.isVulnerable - a.isVulnerable;
      }
      return a.name.localeCompare(b.name);
    });
  };

  const toggleProject = (projectName) => {
    setExpandedProject(expandedProject === projectName ? null : projectName);
  };

  const togglePackage = (packageKey) => {
    setExpandedPackage(expandedPackage === packageKey ? null : packageKey);
  };

  const toggleSummary = (packageKey) => {
    setExpandedSummaries((prev) => ({
      ...prev,
      [packageKey]: !prev[packageKey]
    }));
  };

  const extractRecommendedVersion = (recommendationText) => {
    if (!recommendationText) return '';
    const match = recommendationText.match(/(\d+\.\d+\.\d+(?:\.\d+)*)/);
    return match ? match[1] : '';
  };

  const filterVulnerabilities = (vulns) => {
    if (!vulns) return [];
    if (severityFilter === 'ALL') return vulns;
    return vulns.filter(v => v.severity === severityFilter);
  };

  const getHighestSeverity = (vulns) => {
    if (!vulns || vulns.length === 0) return null;
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    for (const severity of severities) {
      if (vulns.some(v => v.severity === severity)) {
        return severity;
      }
    }
    return null;
  };

  const vulnerablePackagesList = getVulnerablePackages();

  return (
    <div className="solution-analyzer">
      {/* Solution Summary */}
      <div className="solution-summary">
        <h2>Solution Analysis: {solution.name}</h2>
        <div className="summary-metrics">
          <div className="metric">
            <span className="metric-label">Projects</span>
            <span className="metric-value">{solution.projectsCount}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Packages</span>
            <span className="metric-value">{solution.totalPackages}</span>
          </div>
          <div className="metric">
            <span className="metric-label">Vulnerabilities</span>
            <span className="metric-value" style={{ color: solution.totalVulnerabilities > 0 ? '#d32f2f' : '#388e3c' }}>
              {solution.totalVulnerabilities}
            </span>
          </div>
        </div>
      </div>

      {/* Projects with Vulnerabilities - MOVED TO TOP */}
      {vulnerabilities?.affectedProjects && Object.keys(vulnerabilities.affectedProjects).length > 0 && (
        <div className="affected-projects-section">
          <h3>Projects with Vulnerabilities</h3>
          <div className="projects-list">
            {Object.entries(vulnerabilities.affectedProjects).map(([projName, vulnCount]) => (
              <div key={projName} className="project-vuln-item">
                <span className="project-name">{projName}</span>
                <span className="vuln-count">{vulnCount} vulnerable packages</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerable Packages Cards Section - PROMINENT DISPLAY */}
      {vulnerablePackagesList.length > 0 && (
        <div className="vulnerabilities-section">
          <h2>Vulnerable Packages ({vulnerablePackagesList.length})</h2>
          <div className="packages-grid">
            {vulnerablePackagesList.map((pkg) => (
              <div key={pkg.key} className="package-card vulnerable-card">
                <div className="package-header">
                  <h3>{pkg.name}</h3>
                  <span className="vuln-count">{pkg.count} vulnerabilities</span>
                </div>

                <button
                  className="btn btn-remediate"
                  onClick={() => onRemediatePackage(pkg.name, extractRecommendedVersion(pkg.aiRecommendation))}
                  disabled={isLoading}
                >
                  Remediate
                </button>

                <button
                  className="btn btn-ai-summary"
                  onClick={() => toggleSummary(pkg.key)}
                  disabled={isLoading}
                >
                  {expandedSummaries[pkg.key] ? 'Hide AI Summary' : 'Show AI Summary'}
                </button>

                {expandedSummaries[pkg.key] && (
                  <div className="ai-summary-box">
                    {pkg.aiRecommendation ? (
                      <p><strong>Recommendation:</strong> {pkg.aiRecommendation}</p>
                    ) : (
                      <p><em>No recommendation available</em></p>
                    )}
                    {pkg.riskSummary ? (
                      <p><strong>Summary:</strong> {pkg.riskSummary}</p>
                    ) : (
                      <p><em>No summary available</em></p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Projects Breakdown */}
      {projects && projects.length > 0 && (
        <div className="projects-section">
          <h3>Projects ({projects.length})</h3>
          <div className="projects-list">
            {projects.map((project) => (
              <div key={project.name} className="project-card">
                <div className="project-header" onClick={() => toggleProject(project.name)}>
                  <span className="project-name">{project.name}</span>
                  <span className="project-meta">
                    <span className="badge">{project.packageCount} packages</span>
                    {project.vulnerabilityCount > 0 && (
                      <span className="badge alert">{project.vulnerabilityCount} vulns</span>
                    )}
                  </span>
                  <span className="toggle-icon">{expandedProject === project.name ? '▼' : '▶'}</span>
                </div>
                {expandedProject === project.name && (
                  <div className="project-details">
                    <p className="project-path">{project.path}</p>
                    {project.packages && project.packages.length > 0 && (
                      <div className="dependencies">
                        <h5>Project Packages ({project.packages.length}):</h5>
                        <div className="project-packages-list">
                          {project.packages.map((pkg, idx) => (
                            <div key={idx} className="project-package-item">
                              <span className="pkg-name">{pkg.name}@{pkg.version}</span>
                              {pkg.vulnerabilities && pkg.vulnerabilities.length > 0 && (
                                <span className="pkg-vuln-count">{pkg.vulnerabilities.length} vulns</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Dependencies Table */}
      <div className="all-dependencies-section">
        <button
          className="btn btn-toggle"
          onClick={() => setShowAllDependencies(!showAllDependencies)}
        >
          {showAllDependencies ? '▼' : '▶'} Show All Dependencies ({solution.totalPackages})
        </button>

        {showAllDependencies && (
          <div className="dependencies-table-wrapper">
            <table className="dependencies-table">
              <thead>
                <tr>
                  <th>Package Name</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Vulnerabilities</th>
                </tr>
              </thead>
              <tbody>
                {getAllPackages().map((pkg) => (
                  <tr key={`${pkg.name}@${pkg.version}`} className={pkg.isVulnerable ? 'vuln-row' : 'clean-row'}>
                    <td className="pkg-name">{pkg.name}</td>
                    <td className="pkg-version">{pkg.version}</td>
                    <td className="pkg-status">
                      <span className={`status-badge ${pkg.isVulnerable ? 'status-vulnerable' : 'status-clean'}`}>
                        {pkg.isVulnerable ? '⚠️ Vulnerable' : '✅ Clean'}
                      </span>
                    </td>
                    <td className="pkg-vulns">
                      {pkg.vulnCount > 0 ? `${pkg.vulnCount} found` : 'None'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
