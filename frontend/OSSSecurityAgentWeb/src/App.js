import React, { useState } from 'react';
import './styles/App.css';
import RepoAnalyzer from './components/RepoAnalyzer';
import SolutionAnalyzer from './components/SolutionAnalyzer';
import IssuesAndPRsTab from './components/IssuesAndPRsTab';

export default function App() {
  const [activeTab, setActiveTab] = useState('analyze');
  const [analysisMode, setAnalysisMode] = useState('project'); // 'project' or 'solution'
  const [repoUrl, setRepoUrl] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState({});
  const [allDependencies, setAllDependencies] = useState({});
  const [solutionAnalysis, setSolutionAnalysis] = useState(null);
  const [issues, setIssues] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [prActionMessages, setPrActionMessages] = useState({});
  const [globalActionMessage, setGlobalActionMessage] = useState(null);

  const normalizeDependencyMap = (rawDependencies) => {
    const normalized = {};

    Object.entries(rawDependencies || {}).forEach(([key, entry]) => {
      const details = entry?.data || entry || {};
      const vulnerabilities = Array.isArray(details.vulnerabilities) ? details.vulnerabilities : [];
      const packageName = details.package || key.split('@')[0] || key;
      const versionFromKey = key.includes('@') ? key.substring(key.lastIndexOf('@') + 1) : undefined;
      const version = details.version || versionFromKey || 'unknown';

      normalized[key] = {
        package: packageName,
        version,
        vulnerabilities,
        count: typeof entry?.count === 'number' ? entry.count : vulnerabilities.length,
        severities: entry?.severities || {},
        aiRecommendation: details.aiRecommendation || '',
        riskSummary: details.riskSummary || ''
      };
    });

    return normalized;
  };

  const handleAnalyze = async () => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return;
    }

    if (analysisMode === 'solution') {
      await handleAnalyzeSolution();
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`http://localhost:5001/api/scan/analyze?repo=${encodeURIComponent(repoUrl)}`);
      const data = await response.json();

      const allDeps = normalizeDependencyMap(data.vulnerabilitiesByPackage || {});
      setAllDependencies(allDeps);

      const vulnDeps = {};
      Object.entries(allDeps).forEach(([pkg, pkgData]) => {
        if ((pkgData?.count || 0) > 0) {
          vulnDeps[pkg] = pkgData;
        }
      });
      setVulnerabilities(vulnDeps);
    } catch (error) {
      console.error('Error analyzing repository:', error);
      alert('Failed to analyze repository: ' + error.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnalyzeSolution = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('http://localhost:5001/api/scan/scan-solution', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repositoryPath: repoUrl
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to analyze solution');
      }

      setSolutionAnalysis(data);
      setGlobalActionMessage({
        type: 'success',
        message: `Solution analysis complete: ${data.solution.projectsCount} projects, ${data.solution.totalPackages} packages`
      });
      
      // Auto-clear the message after 5 seconds
      setTimeout(() => {
        setGlobalActionMessage(null);
      }, 5000);
    } catch (error) {
      console.error('Error analyzing solution:', error);
      alert('Failed to analyze solution: ' + error.message);
      setGlobalActionMessage({
        type: 'error',
        message: error.message
      });
      
      // Auto-clear error message after 5 seconds
      setTimeout(() => {
        setGlobalActionMessage(null);
      }, 5000);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRemediatePackage = async (packageName, recommendedVersion = '') => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`http://localhost:5001/api/remediate/package`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          packageName,
          recommendedVersion
        })
      });
      const data = await response.json();
      if (response.ok) {
        setGlobalActionMessage({ 
          type: 'success', 
          message: `Remediation started for ${packageName}` 
        });
        setActiveTab('issues');
        await loadIssuesAndPRs();
      } else {
        setGlobalActionMessage({ 
          type: 'error', 
          message: `Failed to remediate: ${data.message}` 
        });
      }
    } catch (error) {
      console.error('Error remediating package:', error);
      setGlobalActionMessage({ 
        type: 'error', 
        message: `Failed to remediate: ${error.message}` 
      });
    } finally {
      setIsLoading(false);
    }
  };

  const loadIssuesAndPRs = async () => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return false;
    }

    setIsLoading(true);
    try {
      const response = await fetch(`http://localhost:5001/api/remediation/issues-and-prs?repo=${encodeURIComponent(repoUrl)}`);
      const data = await response.json();
      setIssues(data.items || []);
      return true;
    } catch (error) {
      console.error('Error loading issues and PRs:', error);
      return false;
    } finally {
      setIsLoading(false);
    }
  };

  const handleCheckMergeability = async (prNumber) => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return;
    }

    setPrActionMessages((prev) => ({
      ...prev,
      [prNumber]: { type: 'pending', message: `Checking mergeability for PR #${prNumber}...` }
    }));

    try {
      const refreshed = await loadIssuesAndPRs();
      if (refreshed) {
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'success', message: `Mergeability refreshed for PR #${prNumber}.` }
        }));
        
        // Auto-dismiss the PR action message after 5 seconds
        setTimeout(() => {
          setPrActionMessages((prev) => {
            const updated = { ...prev };
            delete updated[prNumber];
            return updated;
          });
        }, 5000);
      } else {
        throw new Error('Unable to refresh mergeability right now.');
      }
    } catch (error) {
      console.error('Error checking mergeability:', error);
      const message = 'Failed to check mergeability: ' + error.message;
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
      
      // Auto-dismiss error after 5 seconds
      setTimeout(() => {
        setPrActionMessages((prev) => {
          const updated = { ...prev };
          delete updated[prNumber];
          return updated;
        });
      }, 5000);
    }
  };

  const handleApprovePR = async (prNumber) => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return;
    }

    setPrActionMessages((prev) => ({
      ...prev,
      [prNumber]: { type: 'pending', message: `Approving PR #${prNumber}...` }
    }));

    try {
      const response = await fetch(`http://localhost:5001/api/remediation/approve-pr`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          prNumber
        })
      });
      const data = await response.json();
      if (response.ok) {
        const successMessage = data.message || `PR #${prNumber} approved successfully`;
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'success', message: successMessage }
        }));
        
        // Auto-dismiss the PR action message after 5 seconds
        setTimeout(() => {
          setPrActionMessages((prev) => {
            const updated = { ...prev };
            delete updated[prNumber];
            return updated;
          });
        }, 5000);
        
        await loadIssuesAndPRs();
      } else {
        const message = data.message || `Failed to approve PR #${prNumber}`;
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'error', message }
        }));
        
        // Auto-dismiss error after 5 seconds
        setTimeout(() => {
          setPrActionMessages((prev) => {
            const updated = { ...prev };
            delete updated[prNumber];
            return updated;
          });
        }, 5000);
      }
    } catch (error) {
      console.error('Error approving PR:', error);
      const message = 'Failed to approve PR: ' + error.message;
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
      
      // Auto-dismiss error after 5 seconds
      setTimeout(() => {
        setPrActionMessages((prev) => {
          const updated = { ...prev };
          delete updated[prNumber];
          return updated;
        });
      }, 5000);
    }
  };

  const handleMergePR = async (prNumber) => {
    if (!repoUrl.trim()) {
      alert('Please enter a GitHub repository URL at the top first.');
      setActiveTab('analyze');
      return;
    }

    setPrActionMessages((prev) => ({
      ...prev,
      [prNumber]: { type: 'pending', message: `Merging PR #${prNumber}...` }
    }));

    try {
      const response = await fetch(`http://localhost:5001/api/remediation/merge-pr`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          prNumber
        })
      });
      const data = await response.json();
      if (response.ok) {
        const successMessage = data.message || `PR #${prNumber} merged successfully`;
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'success', message: successMessage }
        }));
        
        // Auto-dismiss the PR action message after 5 seconds
        setTimeout(() => {
          setPrActionMessages((prev) => {
            const updated = { ...prev };
            delete updated[prNumber];
            return updated;
          });
        }, 5000);
        
        await loadIssuesAndPRs();
      } else {
        const message = data.message || `Failed to merge PR #${prNumber}`;
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'error', message }
        }));
        
        // Auto-dismiss error after 5 seconds
        setTimeout(() => {
          setPrActionMessages((prev) => {
            const updated = { ...prev };
            delete updated[prNumber];
            return updated;
          });
        }, 5000);
      }
    } catch (error) {
      console.error('Error merging PR:', error);
      const message = 'Failed to merge PR: ' + error.message;
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
      
      // Auto-dismiss error after 5 seconds
      setTimeout(() => {
        setPrActionMessages((prev) => {
          const updated = { ...prev };
          delete updated[prNumber];
          return updated;
        });
      }, 5000);
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>🔒 OSS Security Agent</h1>
        <p>Automated vulnerability detection and remediation</p>
      </header>

      <main className="app-main">
        <div className="global-repo-input">
          <label htmlFor="global-repo-url">GitHub Repository URL / Local Path (.git)</label>
          <input
            id="global-repo-url"
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/user/repo.git or /path/to/local/repo"
            disabled={isLoading}
          />
        </div>

        <div className="tabs">
          <button
            className={`tab-btn ${activeTab === 'analyze' ? 'active' : ''}`}
            onClick={() => setActiveTab('analyze')}
            disabled={!repoUrl.trim()}
          >
            Analyze & Remediate
          </button>
          <button
            className={`tab-btn ${activeTab === 'issues' ? 'active' : ''}`}
            onClick={() => { setActiveTab('issues'); loadIssuesAndPRs(); }}
            disabled={!repoUrl.trim()}
          >
            Issues & PRs
          </button>
        </div>

        {globalActionMessage && (
          <div className={`global-message ${globalActionMessage.type}`}>
            {globalActionMessage.message}
          </div>
        )}

        <div className="tab-content">
          {activeTab === 'analyze' && (
            <>
              <div className="analysis-mode-selector">
                <label>Analysis Mode:</label>
                <button
                  className={`mode-btn ${analysisMode === 'project' ? 'active' : ''}`}
                  onClick={() => {
                    setAnalysisMode('project');
                    setGlobalActionMessage(null);
                  }}
                  disabled={isLoading}
                >
                  📦 Project-Level
                </button>
                <button
                  className={`mode-btn ${analysisMode === 'solution' ? 'active' : ''}`}
                  onClick={() => {
                    setAnalysisMode('solution');
                    setGlobalActionMessage(null);
                  }}
                  disabled={isLoading}
                >
                  🏢 Solution-Level
                </button>
              </div>

              {analysisMode === 'project' && (
                <RepoAnalyzer
                  onAnalyze={handleAnalyze}
                  repoUrl={repoUrl}
                  vulnerabilities={vulnerabilities}
                  allDependencies={allDependencies}
                  onRemediatePackage={handleRemediatePackage}
                  isLoading={isLoading}
                />
              )}

              {analysisMode === 'solution' && (
                <div className="solution-mode-container">
                  <button 
                    className="analyze-btn-large" 
                    onClick={handleAnalyze}
                    disabled={isLoading || !repoUrl.trim()}
                  >
                    {isLoading ? '🔄 Analyzing...' : '🔍 Analyze Solution'}
                  </button>
                  <SolutionAnalyzer
                    analysisResult={solutionAnalysis}
                    onRemediatePackage={handleRemediatePackage}
                    isLoading={isLoading}
                  />
                </div>
              )}
            </>
          )}

          {activeTab === 'issues' && (
            <IssuesAndPRsTab
              issues={issues}
              onApprovePR={handleApprovePR}
              onMergePR={handleMergePR}
              onCheckMergeability={handleCheckMergeability}
              isLoading={isLoading}
              actionMessages={prActionMessages}
              globalActionMessage={globalActionMessage}
            />
          )}
        </div>
      </main>
    </div>
  );
}
