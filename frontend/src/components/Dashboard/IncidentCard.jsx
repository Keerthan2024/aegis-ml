import { memo, useState } from 'react'
import { ShieldAlert, Crosshair, Target, Activity, FileText, FastForward, ShieldCheck, PlayCircle, Fingerprint } from 'lucide-react'
import useAlertStore from '../../store/alertStore'

const TABS = ['Executive Summary', 'Kill Chain Context', 'Remediation Playbook']
const KILL_CHAIN = ['Recon', 'Weaponize', 'Delivery', 'Exploit', 'Install', 'C2', 'Exfiltrate']

const PLAYBOOK = {
  brute_force:      ['Block source IP at perimeter firewall.', 'Reset credentials for targeted accounts.', 'Enable MFA on affected services.', 'Review auth logs for successful logins.'],
  lateral_movement: ['Isolate affected endpoints from network.', 'Revoke active sessions on compromised accounts.', 'Run EDR scan across movement path.', 'Preserve memory dumps before remediation.'],
  data_exfiltration:['Block outbound connection to destination.', 'Identify and classify data transferred.', 'Notify DLP team and compliance.', 'Preserve network captures for forensics.'],
  c2_beaconing:     ['Block C2 IP/domain at DNS and firewall.', 'Quarantine beaconing host.', 'Run full malware scan.', 'Search for similar patterns across fleet.'],
  default:          ['Collect and preserve evidence.', 'Escalate to Incident Response team.', 'Document event timeline.', 'Follow standard IR guidelines.'],
}

function FeatureBar({ label, value }) {
  const pct = Math.min(100, Math.round((value || 0) * 100))
  const color = pct > 70 ? 'var(--accent-critical)' : pct > 40 ? 'var(--accent-high)' : 'var(--accent-brand)'
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6, fontWeight: 600 }}>
        <span>{label.replace(/_/g, ' ')}</span>
        <span className="mono-font" style={{ color, fontWeight: 700 }}>{pct}%</span>
      </div>
      <div style={{ height: 6, background: 'var(--bg-page)', borderRadius: 6, overflow: 'hidden', border: '1px solid var(--border-light)' }}>
        <div style={{ 
          height: '100%', width: `${pct}%`, background: color,
          borderRadius: 6, transition: 'width 0.6s cubic-bezier(0.16, 1, 0.3, 1)' 
        }} />
      </div>
    </div>
  )
}

function InsightChip({ icon: Icon, label, value }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12,
      padding: '12px 16px', background: 'var(--bg-page)',
      borderRadius: 12, border: '1px solid var(--border-light)'
    }}>
      <div style={{ color: 'var(--accent-brand)' }}>
        <Icon size={18} strokeWidth={2} />
      </div>
      <div>
        <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5, color: 'var(--text-tertiary)', fontWeight: 700 }}>{label}</div>
        <div className="mono-font" style={{ fontSize: 13, color: 'var(--text-primary)', fontWeight: 600, marginTop: 2 }}>{value}</div>
      </div>
    </div>
  )
}

export default memo(function IncidentCard() {
  const [activeTab, setActiveTab] = useState(0)
  const alerts = useAlertStore(s => s.alerts)
  const incidents = useAlertStore(s => s.incidents)
  const selectedId = useAlertStore(s => s.selectedIncident)
  const selectIncident = useAlertStore(s => s.selectIncident)
  const incident = incidents.find(i => i.incident_id === selectedId) || alerts.find(a => (a.event_id || a.alert_id || a.incident_id) === selectedId) || incidents[0] || alerts[0]

  if (!incident) return (
    <div className="glass-panel animate-slide-up" style={{ 
      padding: 40, textAlign: 'center', color: 'var(--text-tertiary)', gridColumn: '1 / -1',
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16
    }}>
      <ShieldCheck size={48} strokeWidth={1} />
      <div style={{ fontSize: 14, fontWeight: 500 }}>Select an alert or entity to view incident details</div>
    </div>
  )

  const playbook = PLAYBOOK[incident.threat_type] || PLAYBOOK.default
  const stageIdx = Math.max(0, KILL_CHAIN.findIndex(
    s => s.toLowerCase() === (incident.current_kill_chain_stage || '').toLowerCase()
  ))
  const isResolved = incident.status === 'resolved' || incident.status === 'isolated'
  const threatName = incident.threat_type?.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())

  return (
    <div className="glass-panel animate-slide-up" style={{ gridColumn: '1 / -1', display: 'flex', overflow: 'hidden' }}>
      
      {/* Left: Critical Narrative */}
      <div style={{ width: 380, borderRight: '1px solid var(--border-light)', padding: 32, background: 'rgba(250, 249, 246, 0.4)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <div style={{
            fontSize: 10, fontWeight: 800, padding: '6px 12px', borderRadius: 20,
            background: isResolved ? 'rgba(5, 150, 105, 0.08)' : 'rgba(220, 38, 38, 0.08)',
            color: isResolved ? 'var(--accent-success)' : 'var(--accent-critical)',
            border: `1px solid ${isResolved ? 'rgba(5, 150, 105, 0.2)' : 'rgba(220, 38, 38, 0.2)'}`,
            textTransform: 'uppercase', letterSpacing: 1
          }}>
            {isResolved ? 'Resolved' : 'Active Investigation'}
          </div>
          <span className="mono-font" style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>#{incident.incident_id?.slice(0,8)}</span>
        </div>

        <div style={{ fontSize: 26, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.2, marginBottom: 8, letterSpacing: '-0.5px' }}>
          {threatName} Activity Detected
        </div>
        <div style={{ fontSize: 14, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 32 }}>
          AEGIS identified anomalous {incident.threat_type?.replace(/_/g, ' ')} behavior originating from <span className="mono-font" style={{fontWeight:600}}>{incident.src_entity}</span> targeting <span className="mono-font" style={{fontWeight:600}}>{incident.dst_entity}</span>.
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <InsightChip icon={Crosshair} label="Attacker Source" value={incident.src_entity} />
          <InsightChip icon={Target} label="Target Destination" value={incident.dst_entity} />
          <InsightChip icon={Fingerprint} label="Confidence Score" value={`${Math.round((incident.confidence||0)*100)}%`} />
        </div>
      </div>

      {/* Right: Analytical Tabs */}
      <div style={{ flex: 1, padding: 32 }}>
        {/* Tab Navigation */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 32, borderBottom: '1px solid var(--border-light)', paddingBottom: 16 }}>
          {TABS.map((t, i) => (
            <button key={t} onClick={() => setActiveTab(i)} style={{
              background: activeTab === i ? 'var(--text-primary)' : 'transparent',
              color: activeTab === i ? '#fff' : 'var(--text-secondary)',
              border: 'none', padding: '10px 20px', borderRadius: 24,
              fontSize: 13, fontWeight: 700, cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}>
              {t}
            </button>
          ))}
        </div>

        {/* Tab 0: Exec Summary / Feature Importance */}
        {activeTab === 0 && (
          <div className="animate-slide-up" style={{ animationDelay: '50ms' }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 20, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={18} color="var(--accent-brand)" /> Machine Learning Insights
            </h3>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)', marginBottom: 24, lineHeight: 1.6 }}>
              The isolation forest model and threat classifier flagged this event based on multiple anomalous network characteristics. Below are the primary contributing factors driving the high confidence score.
            </p>
            <div style={{ maxWidth: 500 }}>
              {Object.entries(incident.feature_importance || {}).slice(0, 5).map(([k, v]) => (
                <FeatureBar key={k} label={k} value={v} />
              ))}
              {!incident.feature_importance && (
                <div style={{ color: 'var(--text-tertiary)', fontSize: 13, fontStyle: 'italic' }}>
                  Raw feature extraction parameters unavailable for this legacy event.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 1: Kill Chain */}
        {activeTab === 1 && (
          <div className="animate-slide-up" style={{ animationDelay: '50ms' }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 32, display: 'flex', alignItems: 'center', gap: 8 }}>
              <FastForward size={18} color="var(--accent-high)" /> MITRE ATT&CK Progression
            </h3>

            {incident.predicted_next_stage && (
              <div style={{ padding: '16px 20px', background: 'rgba(217, 119, 6, 0.08)', borderRadius: 12, border: '1px solid rgba(217, 119, 6, 0.2)', marginBottom: 24, fontSize: 13, color: 'var(--text-primary)', fontWeight: 500 }}>
                <strong style={{color: 'var(--accent-high)'}}>PREDICTED ESCALATION:</strong> Automated behavioral analysis indicates high probability the adversary will transition to the <strong className="mono-font" style={{fontSize: 14}}>{incident.predicted_next_stage.toUpperCase()}</strong> stage. 
              </div>
            )}
            
            <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', marginTop: 40, padding: '0 20px' }}>
              <div style={{
                position: 'absolute', top: 20, left: 40, right: 40, height: 2,
                background: 'var(--border-light)', zIndex: 0
              }}/>
              <div style={{
                position: 'absolute', top: 20, left: 40, 
                width: `${(stageIdx / (KILL_CHAIN.length - 1)) * 100}%`, height: 2,
                background: 'var(--accent-high)', zIndex: 0,
                transition: 'width 1s cubic-bezier(0.16, 1, 0.3, 1)'
              }}/>
              
              {KILL_CHAIN.map((stage, i) => {
                const isPast = i <= stageIdx;
                const isCurrent = i === stageIdx;
                return (
                  <div key={stage} style={{
                    position: 'relative', zIndex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16
                  }}>
                    <div style={{
                      width: 42, height: 42, borderRadius: '50%',
                      background: isCurrent ? 'var(--accent-high)' : isPast ? 'var(--accent-info)' : 'var(--bg-page)',
                      color: isPast ? '#fff' : 'var(--text-tertiary)',
                      border: `2px solid ${isCurrent ? 'var(--accent-high)' : isPast ? 'var(--accent-info)' : 'var(--border-light)'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontWeight: 800, fontSize: 13,
                      boxShadow: isCurrent ? '0 0 0 6px rgba(217, 119, 6, 0.15)' : 'none',
                      transition: 'all 0.3s ease'
                    }}>
                      {i + 1}
                    </div>
                    <span style={{
                      fontSize: 12, fontWeight: isCurrent ? 800 : 600,
                      color: isCurrent ? 'var(--accent-high)' : isPast ? 'var(--text-primary)' : 'var(--text-tertiary)'
                    }}>
                      {stage}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {/* Tab 2: Playbook */}
        {activeTab === 2 && (
          <div className="animate-slide-up" style={{ animationDelay: '50ms' }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 24, display: 'flex', alignItems: 'center', gap: 8 }}>
              <FileText size={18} color="var(--accent-critical)" /> Recommended Remediation
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {playbook.map((step, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 16, padding: '16px 20px',
                  background: 'var(--bg-page)', borderRadius: 12, border: '1px solid var(--border-light)'
                }}>
                  <div style={{
                    width: 28, height: 28, borderRadius: '50%', background: 'rgba(79, 70, 229, 0.1)',
                    color: 'var(--accent-brand)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 12, fontWeight: 800, flexShrink: 0
                  }}>
                    {i + 1}
                  </div>
                  <div style={{ fontSize: 14, color: 'var(--text-primary)', lineHeight: 1.5, fontWeight: 500 }}>
                    {step}
                  </div>
                </div>
              ))}
            </div>
            {!isResolved && (
              <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                <button onClick={() => fetch(`/api/incident/${incident.event_id || incident.incident_id}/remediate`, { method: 'POST' })} style={{
                  marginTop: 32, padding: '14px 28px', background: 'var(--text-primary)',
                  color: '#fff', border: 'none', borderRadius: 12, fontSize: 14, fontWeight: 700,
                  cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                  boxShadow: '0 8px 24px rgba(31, 41, 55, 0.2)'
                }}>
                  <PlayCircle size={18} /> Execute Playbook
                </button>

                {incident.severity === 'critical' && (
                  <button onClick={() => fetch(`/api/incident/${incident.event_id || incident.incident_id}/isolate`, { method: 'POST' })} style={{
                    marginTop: 32, padding: '14px 28px', background: 'var(--accent-critical)',
                    color: '#fff', border: 'none', borderRadius: 12, fontSize: 14, fontWeight: 700,
                    cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8,
                    boxShadow: '0 8px 24px rgba(220, 38, 38, 0.3)'
                  }}>
                    <ShieldAlert size={18} /> ISOLATE HOST (KILL SWITCH)
                  </button>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
})
