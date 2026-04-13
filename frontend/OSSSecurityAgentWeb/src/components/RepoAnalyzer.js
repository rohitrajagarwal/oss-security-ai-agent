import React, { useState } from 'react';
import '../styles/RepoAnalyzer.css';

export default function RepoAnalyzer({ onAnalyze, repoUrl, vulnerabilities, onRemediatePackage, isLoading, allDependencies }) {
  const [showAllDependencies, setShowAllDependencies] = useState(false);
  const [expandedSummaries, setExpandedSummaries] = useState({});

  const handleAnalyze = () => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      return;
    }
    onAnalyze();
  };

  // Get vulnerable packages
  const vulnerablePackageList = Object.entries(vulnerabilities || {}).map(([pkg, data]) => ({
    name: data.package || pkg,
    key: pkg,
    count: data.count || 0,
    severities: data.severities || {},
    aiRecommendation: data.aiRecommendation || '',
    riskSummary: data.riskSummary || ''
  }));

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

  // Get all dependencies
  const allPackageList = Object.entries(allDependencies || {}).map(([pkg, data]) => ({
    name: data.package || pkg,
    key: pkg,
    version: data.version || 'unknown',
    vulnCount: data.vulnerabilities?.length || 0,
    isVulnerable: (data.vulnerabilities?.length || 0) > 0
  })).sort((a, b) => {
    // Sort by vulnerable first, then by name
    if (a.isVulnerable !== b.isVulnerable) {
      return b.isVulnerable - a.isVulnerable;
    }
    return a.name.localeCompare(b.name);
  });

  const totalDependencies = allPackageList.length;
  const vulnerableDependencies = allPackageList.filter(p => p.isVulnerable).length;
  const cleanDependencies = totalDependencies - vulnerableDependencies;

  return (
    <div className="repo-analyzer">
      <div className="analyze-action">
        <button
          className="btn btn-primary"
          onClick={handleAnalyze}
          disabled={isLoading || !repoUrl.trim()}
        >
          {isLoading ? '⏳ Analyzing...' : 'Analyze'}
        </button>
      </div>

      {totalDependencies > 0 && (
        <div className="results-section">
          {/* Summary Stats */}
          <div className="summary-stats">
            <div className="stat-card total">
              <div className="stat-value">{totalDependencies}</div>
              <div className="stat-label">Total Dependencies</div>
            </div>
            <div className="stat-card vulnerable">
              <div className="stat-value">{vulnerableDependencies}</div>
              <div className="stat-label">Vulnerable</div>
            </div>
            <div className="stat-card clean">
              <div className="stat-value">{cleanDependencies}</div>
              <div className="stat-label">Clean</div>
            </div>
          </div>

          {/* Vulnerable Packages Section */}
          {vulnerablePackageList.length > 0 && (
            <div className="vulnerabilities-section">
              <h2>Vulnerable Packages ({vulnerablePackageList.length})</h2>
              <div className="packages-grid">
                {vulnerablePackageList.map((pkg) => (
                  <div key={pkg.key} className="package-card vulnerable-card">
                    <div className="package-header">
                      <h3>{pkg.name}</h3>
                      <span className="vuln-count">{pkg.count} vulnerabilities</span>
                    </div>
                    
                    {pkg.severities && (
                      <div className="severity-breakdown">
                        {Object.entries(pkg.severities).map(([severity, count]) => (
                          <span key={severity} className={`severity-badge severity-${severity.toLowerCase()}`}>
                            {severity}: {count}
                          </span>
                        ))}
                      </div>
                    )}

                    <button
                      className="btn btn-remediate"
                      onClick={() => onRemediatePackage(pkg.name, extractRecommendedVersion(pkg.aiRecommendation))}
                      disabled={isLoading}
                    >
                      Remediate
                    </button>

                    {(pkg.riskSummary || pkg.aiRecommendation) && (
                      <>
                        <button
                          className="btn btn-ai-summary"
                          onClick={() => toggleSummary(pkg.key)}
                          disabled={isLoading}
                        >
                          {expandedSummaries[pkg.key] ? 'Hide AI Summary' : 'Show AI Summary'}
                        </button>

                        {expandedSummaries[pkg.key] && (
                          <div className="ai-summary-box">
                            {pkg.aiRecommendation && (
                              <p><strong>Recommendation:</strong> {pkg.aiRecommendation}</p>
                            )}
                            {pkg.riskSummary && (
                              <p><strong>Summary:</strong> {pkg.riskSummary}</p>
                            )}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* All Dependencies Toggle and Table */}
          <div className="all-dependencies-section">
            <button
              className="btn btn-toggle"
              onClick={() => setShowAllDependencies(!showAllDependencies)}
            >
              {showAllDependencies ? '▼' : '▶'} Show All Dependencies ({totalDependencies})
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
                    {allPackageList.map((pkg) => (
                      <tr key={pkg.key} className={pkg.isVulnerable ? 'vuln-row' : 'clean-row'}>
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
      )}

      {totalDependencies === 0 && !isLoading && repoUrl && (
        <div className="empty-state">
          <p>✅ No dependencies found or analysis not yet started!</p>
        </div>
      )}
    </div>
  );
}
