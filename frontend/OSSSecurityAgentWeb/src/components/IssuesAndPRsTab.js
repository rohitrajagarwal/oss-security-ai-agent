import React from 'react';
import '../styles/IssuesAndPRsTab.css';

export default function IssuesAndPRsTab({ issues, onApprovePR, onMergePR, onCheckMergeability, isLoading, actionMessages = {}, globalActionMessage = null }) {
  const prs = issues.filter(item => item.type === 'pr');
  const issuesList = issues.filter(item => item.type === 'issue');

  const getMergeabilityBadge = (pr) => {
    if (pr.readyToMerge) {
      return <span className="status-badge status-ready">Ready to merge</span>;
    }

    if (pr.approved && pr.mergeableState === 'dirty') {
      return <span className="status-badge status-outofdate">Branch out of date</span>;
    }

    return null;
  };

  const getApprovalBadge = (pr) => {
    if (pr.approved) {
      return <span className="status-badge status-approved">Approved</span>;
    }

    if (pr.status === 'open') {
      return <span className="status-badge status-awaiting">Awaiting approval</span>;
    }

    return null;
  };

  return (
    <div className="issues-prs-tab">
      {globalActionMessage && (
        <div className={`tab-message tab-message-${globalActionMessage.type}`}>
          {globalActionMessage.message}
        </div>
      )}

      {isLoading && (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading issues and PRs from GitHub...</p>
        </div>
      )}

      {prs.length > 0 && (
        <div className="prs-section">
          <h2>Pull Requests ({prs.length})</h2>
          <div className="pr-list">
            {prs.map((pr) => (
              <div key={pr.id} className="pr-card">
                <div className="pr-header">
                  <h3>
                    <a href={pr.url} target="_blank" rel="noopener noreferrer">
                      #{pr.number}: {pr.title}
                    </a>
                  </h3>
                  <div className="pr-badges">
                    {getApprovalBadge(pr)}
                    {getMergeabilityBadge(pr)}
                    <span className={`status-badge status-${pr.status.toLowerCase()}`}>
                      {pr.status}
                    </span>
                  </div>
                </div>

                <div className="pr-details">
                  <p><strong>Package:</strong> {pr.package}</p>
                  <p><strong>Branch:</strong> <code>{pr.branch}</code></p>
                  <p><strong>Created:</strong> {new Date(pr.createdAt).toLocaleDateString()}</p>
                </div>

                {actionMessages[pr.number] && (
                  <div className={`pr-action-message pr-action-${actionMessages[pr.number].type}`}>
                    {actionMessages[pr.number].message}
                  </div>
                )}

                {pr.status === 'open' && (
                  <div className="pr-actions">
                    <button
                      className="btn btn-secondary"
                      onClick={() => onCheckMergeability(pr.number)}
                      disabled={isLoading || actionMessages[pr.number]?.type === 'pending'}
                    >
                      ⏳ Check mergeability
                    </button>
                    <button
                      className="btn btn-approve"
                      onClick={() => onApprovePR(pr.number)}
                      disabled={isLoading || actionMessages[pr.number]?.type === 'pending' || pr.approved}
                    >
                      {pr.approved ? '✅ Approved' : '✅ Approve'}
                    </button>
                    <button
                      className="btn btn-merge"
                      onClick={() => onMergePR(pr.number)}
                      disabled={isLoading || actionMessages[pr.number]?.type === 'pending' || !pr.approved || pr.mergeableState === 'dirty'}
                      title={!pr.approved ? 'Approve the PR before merging' : pr.mergeableState === 'dirty' ? 'Branch is out of date. Update branch before merge.' : 'Merge the approved PR'}
                    >
                      🔀 Merge
                    </button>
                  </div>
                )}
                {pr.status === 'merged' && (
                  <div className="status-merged">✓ Merged</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {issuesList.length > 0 && (
        <div className="issues-section">
          <h2>Issues ({issuesList.length})</h2>
          <div className="issues-list">
            {issuesList.map((issue) => (
              <div key={issue.id} className="issue-card">
                <div className="issue-header">
                  <h3>
                    <a href={issue.url} target="_blank" rel="noopener noreferrer">
                      #{issue.number}: {issue.title}
                    </a>
                  </h3>
                  <span className={`status-badge status-${issue.status.toLowerCase()}`}>
                    {issue.status}
                  </span>
                </div>

                <div className="issue-details">
                  <p><strong>Package:</strong> {issue.package}</p>
                  <p><strong>Created:</strong> {new Date(issue.createdAt).toLocaleDateString()}</p>
                  {issue.linkedPR && (
                    <p><strong>Linked PR:</strong> <a href={issue.linkedPR.url} target="_blank" rel="noopener noreferrer">#{issue.linkedPR.number}</a></p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {issues.length === 0 && !isLoading && (
        <div className="empty-state">
          <p>📭 No issues or pull requests found yet.</p>
          <p>Go to "Analyze & Remediate" tab to start fixing vulnerabilities.</p>
        </div>
      )}
    </div>
  );
}
