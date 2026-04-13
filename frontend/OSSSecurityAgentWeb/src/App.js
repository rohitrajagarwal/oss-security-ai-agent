import React, { useState } from 'react';
import './styles/App.css';
import RepoAnalyzer from './components/RepoAnalyzer';
import IssuesAndPRsTab from './components/IssuesAndPRsTab';

export default function App() {
  const [activeTab, setActiveTab] = useState('analyze');
  const [repoUrl, setRepoUrl] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState({});
  const [allDependencies, setAllDependencies] = useState({});
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
        alert(`Remediation started for ${packageName}`);
        setActiveTab('issues');
        await loadIssuesAndPRs();
      } else {
        alert(`Failed to remediate: ${data.message}`);
      }
    } catch (error) {
      console.error('Error remediating package:', error);
      alert('Failed to remediate: ' + error.message);
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
      } else {
        throw new Error('Unable to refresh mergeability right now.');
      }
    } catch (error) {
      console.error('Error checking mergeability:', error);
      const message = 'Failed to check mergeability: ' + error.message;
      setGlobalActionMessage({ type: 'error', message });
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
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
        setGlobalActionMessage({ type: 'success', message: successMessage });
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'success', message: successMessage }
        }));
        await loadIssuesAndPRs();
      } else {
        const message = data.message || `Failed to approve PR #${prNumber}`;
        setGlobalActionMessage({ type: 'error', message });
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'error', message }
        }));
      }
    } catch (error) {
      console.error('Error approving PR:', error);
      const message = 'Failed to approve PR: ' + error.message;
      setGlobalActionMessage({ type: 'error', message });
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
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
        setGlobalActionMessage({ type: 'success', message: successMessage });
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'success', message: successMessage }
        }));
        await loadIssuesAndPRs();
      } else {
        const message = data.message || `Failed to merge PR #${prNumber}`;
        setGlobalActionMessage({ type: 'error', message });
        setPrActionMessages((prev) => ({
          ...prev,
          [prNumber]: { type: 'error', message }
        }));
      }
    } catch (error) {
      console.error('Error merging PR:', error);
      const message = 'Failed to merge PR: ' + error.message;
      setGlobalActionMessage({ type: 'error', message });
      setPrActionMessages((prev) => ({
        ...prev,
        [prNumber]: { type: 'error', message }
      }));
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
          <label htmlFor="global-repo-url">GitHub Repository URL (.git)</label>
          <input
            id="global-repo-url"
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            placeholder="https://github.com/user/repo.git"
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

        <div className="tab-content">
          {activeTab === 'analyze' && (
            <RepoAnalyzer
              onAnalyze={handleAnalyze}
              repoUrl={repoUrl}
              vulnerabilities={vulnerabilities}
              allDependencies={allDependencies}
              onRemediatePackage={handleRemediatePackage}
              isLoading={isLoading}
            />
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
