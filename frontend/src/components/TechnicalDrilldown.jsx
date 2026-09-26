import React from 'react';
import { GitBranch, Server, AlertTriangle, ShieldCheck, Flame, ExternalLink, Network } from 'lucide-react';
import { formatINR, formatINRFull } from '../utils/formatters';

export default function TechnicalDrilldown({ summary, driversData, entitiesData }) {
  const drivers = (driversData && driversData.top_drivers) || (summary && summary.drivers) || [];
  const chokePoints = (driversData && driversData.choke_points) || (summary && summary.choke_points) || [];
  const services = (summary && summary.services) || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      
      {/* Choke Points Section */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Network size={20} color="#00f2fe" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>Asset Topology & High-Centrality Choke Points</h3>
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
              borderLeft: '4px solid #00f2fe',
              background: 'rgba(255,255,255,0.02)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <strong style={{ fontSize: 13, color: '#fff' }}>{cp.asset_name}</strong>
                <span className="mono badge badge-cyan">{cp.asset_id}</span>
              </div>
              <div style={{ margin: '8px 0', fontSize: 12, color: 'var(--text-muted)' }}>
                Supports <strong>{cp.dependent_service_count} downstream service{cp.dependent_service_count !== 1 ? 's' : ''}</strong>:
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                  {cp.dependent_services.map((sName, sIdx) => (
                    <span key={sIdx} className="badge" style={{ background: 'rgba(0, 242, 254, 0.1)', color: '#38bdf8', fontSize: 10 }}>
                      {sName}
                    </span>
                  ))}
                </div>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-dim)', borderTop: '1px solid var(--border-color)', paddingTop: 6, marginTop: 8 }}>
                <span>Effective Revenue at Risk:</span>
                <span className="mono" style={{ color: '#00f2fe', fontWeight: 600 }}>{formatINR(cp.effective_revenue_per_hour)}/hr</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Vulnerability Remediation Backlog sorted by Marginal EAL */}
      <div className="glass-panel" style={{ padding: 22 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Flame size={20} color="#ef4444" />
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>Vulnerability Remediation Backlog (Ranked by Marginal EAL)</h3>
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
                      <strong className="mono" style={{ color: '#fff', fontSize: 13 }}>{d.id}</strong>
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
                        EPSS: {(d.epss * 100).toFixed(1)}%
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
            <h3 style={{ margin: 0, fontSize: 16, color: '#fff' }}>Business Services Financial Exposure</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-dim)' }}>
              Service level EAL aggregated across dependent asset graphs and RTO tolerances
            </p>
          </div>
          <span className="badge badge-simulated">Apex FinCorp Services</span>
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
                    <strong style={{ color: '#fff' }}>{svc.name}</strong>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--text-dim)' }}>{svc.service_id}</div>
                  </td>
                  <td className="mono" style={{ color: '#38bdf8' }}>
                    {formatINR(svc.revenue_per_hour)}/hr
                  </td>
                  <td>
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', color: '#fff' }}>
                      {svc.rto_hours || 4} Hours Max Outage
                    </span>
                  </td>
                  <td>
                    <strong className="mono" style={{ color: '#00f2fe' }}>{formatINR(svc.eal)}</strong>
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
