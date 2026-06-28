'use client'

import { memo } from 'react'
import Link from 'next/link'
import { Code, GitPullRequest, ExternalLink, AlertTriangle, RefreshCw, Settings } from 'lucide-react'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface CodeFixButtonProps {
  remediation: Remediation
  onStartCodeFix: (remediationId: string) => void
  missingSettings?: string[]
  projectId?: string
}

export const CodeFixButton = memo(function CodeFixButton({
  remediation,
  onStartCodeFix,
  missingSettings = [],
  projectId,
}: CodeFixButtonProps) {
  // If PR already exists, show link instead
  if (remediation.prUrl) {
    return (
      <div className={styles.codeFixArea}>
        <a
          href={remediation.prUrl}
          target="_blank"
          rel="noopener noreferrer"
          className={styles.prLink}
        >
          <GitPullRequest size={16} />
          View Pull Request
          <ExternalLink size={12} />
        </a>
        <span className={styles.prStatus}>
          PR status: {remediation.prStatus}
        </span>
      </div>
    )
  }

  // If currently in progress
  if (remediation.status === 'in_progress') {
    return (
      <div className={styles.codeFixArea}>
        <button className={styles.codeFixBtn} disabled>
          <Code size={16} />
          CodeFix in Progress...
        </button>
      </div>
    )
  }

  // If agent ran but couldn't fix — show notes and retry button
  if (remediation.status === 'no_fix') {
    return (
      <div className={styles.codeFixArea}>
        {remediation.agentNotes && (
          <div className={styles.agentNotes}>
            <AlertTriangle size={14} />
            <div>
              <strong>Agent could not fix this issue:</strong>
              <p>{remediation.agentNotes}</p>
            </div>
          </div>
        )}
        <button
          className={styles.codeFixBtn}
          onClick={() => onStartCodeFix(remediation.id)}
          disabled={missingSettings.length > 0}
        >
          <RefreshCw size={16} />
          Retry CodeFix Agent
        </button>
      </div>
    )
  }

  // Only secret_rotation and infrastructure require manual intervention
  const agentSupportedTypes = ['code_fix', 'dependency_update', 'config_change']
  if (!agentSupportedTypes.includes(remediation.remediationType)) {
    return (
      <div className={styles.codeFixArea}>
        <p className={styles.noCodeFix}>
          This remediation type ({remediation.remediationType}) requires manual intervention.
        </p>
      </div>
    )
  }

  const settingsMissing = missingSettings.length > 0

  return (
    <div className={styles.codeFixArea}>
      {settingsMissing && (
        <div className={styles.settingsAlert}>
          <AlertTriangle size={14} />
          <span>
            Missing settings: {missingSettings.join(', ')}.
            Update your project settings in the CypherFix tab to enable CodeFix.
            {projectId && (
              <>
                {' '}
                <Link
                  href={`/projects/${projectId}/settings?tab=cypherfix`}
                  className={styles.settingsLink}
                >
                  <Settings size={12} />
                  Open CypherFix settings
                </Link>
              </>
            )}
          </span>
        </div>
      )}
      <button
        className={styles.codeFixBtn}
        onClick={() => onStartCodeFix(remediation.id)}
        disabled={settingsMissing}
      >
        <Code size={16} />
        Start CodeFix Agent
      </button>
      {!settingsMissing && (
        <p className={styles.codeFixHint}>
          The agent will clone the repository, explore the codebase, and implement the fix.
        </p>
      )}
    </div>
  )
})
