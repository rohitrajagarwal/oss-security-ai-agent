import React, { useState } from 'react';
import '../styles/SolutionAnalyzer.css';

export default function SolutionAnalyzer({ analysisResult, onRemediatePackage, isLoading }) {
  const [expandedProject, setExpandedProject] = useState(null);
  const [expandedPackage, setExpandedPackage] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');

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

  const toggleProject = (projectName) => {
    setExpandedProject(expandedProject === projectName ? null : projectName);
  };

  const togglePackage = (packageKey) => {
    setExpandedPackage(expandedPackage === packageKey ? null : packageKey);
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

      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <div className="recommendations-section">
          <h3>Recommendations</h3>
          <ul className="recommendations-list">
            {recommendations.map((rec, idx) => (
              <li key={idx} className="recommendation-item">{rec}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Vulnerability Summary */}
      {vulnerabilities && (
        <div className="vulnerability-summary-section">
          <h3>Vulnerabilities by Severity</h3>
          <div className="severity-filter">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
              <button
                key={sev}
                className={`filter-btn ${severityFilter === sev ? 'active' : ''}`}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev}
                {sev !== 'ALL' && ` (${vulnerabilities.bySeverity[sev] || 0})`}
              </button>
            ))}
          </div>

          {/* Top Vulnerable Packages */}
          {vulnerabilities.topVulnerablePackages && vulnerabilities.topVulnerablePackages.length > 0 && (
            <div className="top-vulnerable-packages">
              <h4>Top Vulnerable Packages</h4>
              <div className="package-list">
                {vulnerabilities.topVulnerablePackages.map((pkg, idx) => (
                  <div key={idx} className="package-item">
                    <div className="package-header">
                      <span className="package-name">{pkg.packageName}@{pkg.version}</span>
                      <span className="vuln-badge" style={{ backgroundColor: getSeverityColor(pkg.highestSeverity) }}>
                        {pkg.vulnerabilityCount} vulns
                      </span>
                    </div>
                    <div className="package-details">
                      <small>Used by: {pkg.affectedProjects?.join(', ') || 'N/A'}</small>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Affected Projects */}
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
                    {project.dependencies && project.dependencies.length > 0 && (
                      <div className="dependencies">
                        <h5>Project Dependencies:</h5>
                        <ul>
                          {project.dependencies.map((dep, idx) => (
                            <li key={idx}>{dep}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Packages */}
      {packages && (
        <div className="packages-section">
          <h3>All Packages ({packages.total})</h3>

          {/* Packages by Type */}
          {packages.byType && Object.keys(packages.byType).length > 0 && (
            <div className="packages-by-type">
              <h4>By Type</h4>
              <div className="type-badges">
                {Object.entries(packages.byType).map(([type, count]) => (
                  <div key={type} className="type-badge">
                    <span className="type-name">{type}</span>
                    <span className="type-count">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detailed Package List */}
          {packages.detailed && packages.detailed.length > 0 && (
            <div className="detailed-packages">
              <h4>Detailed List</h4>
              <div className="package-list">
                {packages.detailed
                  .filter(pkg => {
                    if (severityFilter === 'ALL') return true;
                    const highest = getHighestSeverity(pkg.vulnerabilities);
                    return highest === severityFilter;
                  })
                  .map((pkg, idx) => (
                    <div key={idx} className="package-item">
                      <div className="package-header" onClick={() => togglePackage(`${pkg.name}@${pkg.version}`)}>
                        <div className="package-info">
                          <span className="package-name">{pkg.name}@{pkg.version}</span>
                          <span className="package-type">{pkg.type}</span>
                        </div>
                        {pkg.vulnerabilityCount > 0 && (
                          <span className="vuln-badge" style={{ backgroundColor: getSeverityColor(getHighestSeverity(pkg.vulnerabilities)) }}>
                            {pkg.vulnerabilityCount}
                          </span>
                        )}
                        <span className="toggle-icon">
                          {expandedPackage === `${pkg.name}@${pkg.version}` ? '▼' : '▶'}
                        </span>
                      </div>
                      {expandedPackage === `${pkg.name}@${pkg.version}` && (
                        <div className="package-details">
                          <p className="used-by">
                            <strong>Used by:</strong> {pkg.usedByProjects?.join(', ') || 'N/A'}
                          </p>
                          {pkg.vulnerabilities && pkg.vulnerabilities.length > 0 && (
                            <div className="vulnerabilities">
                              <h5>Vulnerabilities:</h5>
                              <div className="vuln-list">
                                {filterVulnerabilities(pkg.vulnerabilities).map((vuln, vidx) => (
                                  <div key={vidx} className="vuln-item">
                                    <div className="vuln-header">
                                      <span className="vuln-id" style={{ color: getSeverityColor(vuln.severity) }}>
                                        {vuln.id}
                                      </span>
                                      <span className="vuln-severity" style={{ backgroundColor: getSeverityColor(vuln.severity) }}>
                                        {vuln.severity}
                                      </span>
                                    </div>
                                    <p className="vuln-summary">{vuln.summary}</p>
                                    {vuln.details && (
                                      <p className="vuln-details">{vuln.details}</p>
                                    )}
                                    <button className="remediate-btn" onClick={() => onRemediatePackage?.(pkg.name, pkg.version)}>
                                      Get Remediation
                                    </button>
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
        </div>
      )}
    </div>
  );
}
