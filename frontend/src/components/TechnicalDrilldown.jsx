import React from 'react';
import { GitBranch, Server, AlertTriangle, ShieldCheck, Flame, ExternalLink, Network, AlertCircle, Activity, Cpu } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';
import EmptyState from './EmptyState';

export default function TechnicalDrilldown({ summary, driversData, entitiesData, onNavigateToIngestion }) {
  if (summary?.status === 'NO_DATA' || summary?.status === 'NO_FINDINGS') {
    return (
      <EmptyState
        status={summary.status}
        message={summary.message}
        onNavigateToIngestion={onNavigateToIngestion}
      />
    );
  }
  const drivers = (driversData && driversData.top_drivers) || (summary && summary.drivers) || [];
  const chokePoints = (driversData && driversData.choke_points) || (summary && summary.choke_points) || [];
  const services = (summary && summary.services) || [];
  const emergingThreats = driversData?.emerging_threats || [];
  const anomalyInfo = driversData?.anomaly_detection;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Emerging Threat Signals (Unsupervised Anomaly Detection Layer) */}
      <div className="glass-panel" style={{ padding: 22, borderLeft: '4px solid var(--accent-amber)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Activity size={20} color="var(--accent-amber)" />
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 2 }}>
                <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Emerging Threat Signals (IsolationForest Telemetry Layer)</h3>
                {anomalyInfo?.is_demo && (
                  <span
                    className="badge"
                    style={{
                      fontSize: 10,
                      fontWeight: 700,
                      background: 'rgba(245, 158, 11, 0.18)',
                      color: 'var(--accent-amber)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      padding: '2px 8px',
                      letterSpacing: '0.04em'
                    }}
                  >
                    DEMO DATA — not from live ingestion
                  </span>
                )}
                {anomalyInfo?.source && (
                  <span
                    className={`badge ${['Wazuh Live API', 'Wazuh Indexer API'].includes(anomalyInfo.source) ? 'badge-real' : anomalyInfo.source === 'Wazuh Telemetry Mock' ? 'badge-simulated' : ''}`}
                    style={{
                      fontSize: 10,
                      background: ['Wazuh Live API', 'Wazuh Indexer API'].includes(anomalyInfo.source) ? undefined : 'rgba(255, 255, 255, 0.05)',
                      border: '1px solid var(--border-color)',
                      color: ['Wazuh Live API', 'Wazuh Indexer API'].includes(anomalyInfo.source) ? 'var(--accent-green)' : 'var(--text-dim)',
                      padding: '2px 8px'
                    }}
                  >
                    Source: {anomalyInfo.source}
                  </span>
                )}
              </div>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Unsupervised anomaly detection over per-agent telemetry (indexed alert volume, auth-failure rate, alert severity mix)
              </p>
            </div>
          </div>
          <span className="badge badge-amber" style={{ fontSize: 10 }}>
            unsupervised anomaly (IsolationForest), not a confirmed incident
          </span>
        </div>

        {/* Cold Start vs Active Anomalies vs Nominal */}
        {anomalyInfo?.status === 'insufficient_baseline_data' ? (
          (['Wazuh Live API', 'Wazuh Indexer API'].includes(anomalyInfo?.source) || anomalyInfo?.message?.includes('Building baseline')) ? (
            <div style={{ padding: '14px 18px', background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: 8, fontSize: 12, color: 'var(--text-dim)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <Activity size={16} color="var(--primary)" />
                <strong style={{ color: 'var(--text-main)', fontSize: 13 }}>
                  {anomalyInfo?.message || `Building baseline: ${anomalyInfo?.total_windows ?? 0}/5 hourly windows`}
                </strong>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                Anomaly scoring requires at least five distinct completed hourly alert windows. Connect the Wazuh Indexer and refresh; repeated refreshes do not create new windows.
              </div>
              <div style={{ marginTop: 10, background: 'rgba(255, 255, 255, 0.08)', borderRadius: 4, height: 6, width: '100%', maxWidth: 320, overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${Math.min(100, (((anomalyInfo?.total_windows ?? 0) / 5) * 100))}%`,
                    background: 'var(--primary)',
                    transition: 'width 0.3s ease'
                  }}
                />
              </div>
            </div>
          ) : (
            <div style={{ padding: '12px 16px', background: 'rgba(255,255,255,0.02)', borderRadius: 8, fontSize: 12, color: 'var(--text-dim)' }}>
              <strong>insufficient baseline data</strong>: Requires minimum 5 observation windows before scoring. Signal layer is strictly outside the deterministic FAIR loss core.
            </div>
          )
        ) : emergingThreats.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            {emergingThreats.map((threat, idx) => (
              <div key={idx} className="glass-panel" style={{ padding: 14, background: 'rgba(201, 114, 114, 0.08)', border: '1px solid rgba(201, 114, 114, 0.3)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>{threat.agent_name || threat.agent_id}</strong>
                    {threat.is_demo && (
                      <span className="badge" style={{ fontSize: 9, background: 'rgba(245, 158, 11, 0.15)', color: 'var(--accent-amber)' }}>
                        DEMO
                      </span>
                    )}
                  </div>
                  <span className="badge badge-critical" style={{ fontSize: 11 }}>
                    Anomaly Score: {(threat.anomaly_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
                  Observed Window: {threat.window_timestamp ? new Date(threat.window_timestamp).toLocaleTimeString() : 'Recent'} · Agent ID: <span className="mono">{threat.agent_id}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, fontSize: 11, background: 'rgba(0,0,0,0.2)', padding: 8, borderRadius: 6 }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Event Vol</span>
                    <div style={{ fontWeight: 600 }}>{threat.features?.event_volume || '—'}</div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Auth Fail %</span>
                    <div style={{ fontWeight: 600, color: 'var(--accent-amber)' }}>
                      {threat.features?.auth_failure_rate != null ? `${(threat.features.auth_failure_rate * 100).toFixed(1)}%` : '—'}
                    </div>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>High Sev %</span>
                    <div style={{ fontWeight: 600, color: 'var(--accent-red)' }}>
                      {threat.features?.alert_severity_mix != null ? `${(threat.features.alert_severity_mix * 100).toFixed(1)}%` : '—'}
                    </div>
                  </div>
                </div>
                <div style={{ marginTop: 8, fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                  {threat.label || 'unsupervised anomaly (IsolationForest), not a confirmed incident'}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: '12px 16px', background: 'rgba(126, 143, 129, 0.08)', borderRadius: 8, fontSize: 12, color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} />
            <span>All monitored SIEM agents are operating within normal baseline bounds. Baseline telemetry history active.</span>
          </div>
        )}
      </div>
      
      {/* Excluded Assets Visibility Banner */}
      {summary?.excluded_assets_count > 0 && (
        <div className="glass-panel" style={{
          borderLeft: '4px solid var(--accent-amber)',
          padding: '16px 20px',
          background: 'rgba(217, 119, 6, 0.06)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <AlertCircle size={20} color="var(--accent-amber)" />
              <div>
                <strong style={{ color: 'var(--text-main)', fontSize: 14 }}>
                  EAL Excludes {summary.excluded_assets_count} Discovered Asset{summary.excluded_assets_count > 1 ? 's' : ''} (₹0 Loss Imputed)
                </strong>
                <p style={{ margin: '2px 0 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
                  FAIR risk engine excludes assets without declared business context. Pending: {summary.excluded_assets.map(a => a.name || a.asset_id).join(', ')}.
                </p>
              </div>
            </div>
            <button
              className="btn btn-outline"
              style={{ fontSize: 11, padding: '5px 12px' }}
              onClick={onNavigateToIngestion}
            >
              Assign Business Context →
            </button>
          </div>
        </div>
      )}

      {/* Choke Points Section */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={20} color="var(--primary)" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Asset Topology & High-Centrality Choke Points</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Assets identified by NetworkX directed graph where failure propagates to multiple critical business services
              </p>
            </div>
          </div>
          <span className="badge badge-cyan">Graph Theory / Betweenness</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
          {chokePoints.map((cp, idx) => (
            <div key={idx} className="glass-panel" style={{
              padding: 16,
              borderLeft: '4px solid var(--primary)',
              background: 'rgba(255,255,255,0.02)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>{cp.asset_name}</strong>
                <span className="mono badge badge-cyan">{cp.asset_id}</span>
              </div>
              <div style={{ margin: '8px 0', fontSize: 12, color: 'var(--text-muted)' }}>
                Supports <strong>{cp.dependent_service_count} downstream service{cp.dependent_service_count !== 1 ? 's' : ''}</strong>:
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                  {cp.dependent_services.map((sName, sIdx) => (
                    <span key={sIdx} className="badge" style={{ background: 'rgba(183, 140, 102, 0.1)', color: '#38bdf8', fontSize: 10 }}>
                      {sName}
                    </span>
                  ))}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)', borderTop: '1px solid var(--border-color)', paddingTop: 6, marginTop: 8 }}>
                <span>Effective Revenue at Risk:</span>
                <span className="mono" style={{ color: 'var(--primary)', fontWeight: 600 }}>{formatINR(cp.effective_revenue_per_hour)}/hr</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerability Remediation Backlog sorted by Marginal EAL */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Flame size={20} color="var(--accent-red)" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Vulnerability Remediation Backlog (Ranked by Marginal EAL)</h3>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
                Leave-One-Out (LOO) marginal risk contribution: exact expected financial loss removed if patched
              </p>
            </div>
          </div>
          <span className="badge badge-real">Real OpenVAS Lab Scan Data</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Vulnerability CVE</th>
                <th>Target Asset</th>
                <th>CVSS / Severity</th>
                <th>Threat Intel (EPSS / KEV)</th>
                <th>Marginal EAL Contribution</th>
                <th>Telemetry Source</th>
              </tr>
            </thead>
            <tbody>
              {drivers.map((d, idx) => (
                <tr key={idx}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong className="mono" style={{ color: 'var(--text-main)', fontSize: 13 }}>{d.cve_id || d.finding_id || d.id}</strong>
                    </div>
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-main)' }}>{d.asset_name}</div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{d.asset_id}</div>
                  </td>
                  <td>
                    <span className={`badge ${d.severity === 'Critical' ? 'badge-critical' : 'badge-simulated'}`}>
                      CVSS {d.cvss} ({d.severity})
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <span className="badge badge-cyan" style={{ fontSize: 10 }}>
                        EPSS: {d.epss == null ? 'Unknown' : `${(d.epss * 100).toFixed(1)}%`}
                      </span>
                      {d.in_kev && (
                        <span className="badge badge-kev" style={{ fontSize: 10 }}>
                          CISA KEV ACTIVE
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="display-title" style={{ color: '#f87171', fontSize: 15 }}>
                      {formatINR(d.marginal_eal)}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>LOO delta reduction</div>
                  </td>
                  <td>
                    <span className="badge badge-real" style={{ fontSize: 10 }}>
                      {d.source || 'OpenVAS Scanner'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Business Services Financial Breakdown */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-main)' }}>Business Services Financial Exposure</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Service level EAL aggregated across dependent asset graphs and RTO tolerances
            </p>
          </div>
          <span className="badge badge-simulated">Business services</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Service Name</th>
                <th>Hourly Revenue</th>
                <th>Recovery Time Objective (RTO)</th>
                <th>Aggregated Service EAL</th>
                <th>VaR 95 (1-in-20 Yr)</th>
              </tr>
            </thead>
            <tbody>
              {services.map((svc, idx) => (
                <tr key={idx}>
                  <td>
                    <strong style={{ color: 'var(--text-main)' }}>{svc.name}</strong>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{svc.service_id}</div>
                  </td>
                  <td className="mono" style={{ color: '#38bdf8' }}>
                    {formatINR(svc.revenue_per_hour)}/hr
                  </td>
                  <td>
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-main)' }}>
                      {svc.rto_hours || 4} Hours Max Outage
                    </span>
                  </td>
                  <td>
                    <strong className="mono" style={{ color: 'var(--primary)' }}>{formatINR(svc.eal)}</strong>
                  </td>
                  <td>
                    <strong className="mono" style={{ color: '#f87171' }}>{formatINR(svc.var95)}</strong>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}
