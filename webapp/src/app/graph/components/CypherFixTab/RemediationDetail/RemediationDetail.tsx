'use client'

import { ArrowLeft, Trash2, XCircle } from 'lucide-react'
import { SeverityBadge } from '../RemediationDashboard/SeverityBadge'
import { StatusBadge } from '../RemediationDashboard/StatusBadge'
import { RemediationTypeIcon } from '../RemediationDashboard/RemediationTypeIcon'
import { EvidenceSection } from './EvidenceSection'
import { SolutionSection } from './SolutionSection'
import { CodeFixButton } from './CodeFixButton'
import type { Remediation } from '@/lib/cypherfix-types'
import styles from './RemediationDetail.module.css'

interface RemediationDetailProps {
  remediation: Remediation
  projectId: string
  userId: string
  onBack: () => void
  onDismiss: (id: string) => void
  onDelete: (id: string) => void
  onRefresh: () => void
  onStartCodeFix: (remediationId: string) => void
  missingSettings?: string[]
}

export function RemediationDetail({
  remediation,
  projectId,
  userId,
  onBack,
  onDismiss,
  onDelete,
  onRefresh,
  onStartCodeFix,
  missingSettings = [],
}: RemediationDetailProps) {
  return (
    <div className={styles.detail}>
      {/* Top bar */}
      <div className={styles.topBar}>
        <button className={styles.backBtn} onClick={onBack}>
          <ArrowLeft size={14} />
          Back to Dashboard
        </button>
        <div className={styles.topActions}>
          {remediation.status === 'pending' && (
            <button
              className={styles.dismissBtn}
              onClick={() => onDismiss(remediation.id)}
            >
              <XCircle size={14} />
              Dismiss
            </button>
          )}
          <button
            className={styles.deleteBtn}
            onClick={() => {
              onDelete(remediation.id)
            }}
          >
            <Trash2 size={14} />
            Delete
          </button>
        </div>
      </div>

      {/* Scrollable content */}
      <div className={styles.content}>
        {/* Header */}
        <div className={styles.detailHeader}>
          <div className={styles.badges}>
            <SeverityBadge severity={remediation.severity} />
            <StatusBadge status={remediation.status} />
            <RemediationTypeIcon type={remediation.remediationType} />
            {remediation.cvssScore !== null && (
              <span className={styles.cvss}>CVSS {remediation.cvssScore.toFixed(1)}</span>
            )}
          </div>
          <h2 className={styles.detailTitle}>{remediation.title}</h2>
          <p className={styles.description}>{remediation.description}</p>
        </div>

        {/* Evidence */}
        <EvidenceSection remediation={remediation} />

        {/* Solution */}
        <SolutionSection remediation={remediation} />

        {/* CodeFix */}
        <CodeFixButton remediation={remediation} onStartCodeFix={onStartCodeFix} missingSettings={missingSettings} projectId={projectId} />
      </div>
    </div>
  )
}
