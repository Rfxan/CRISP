import React, { useState, useEffect } from 'react';
import { X, Server, AlertCircle, CheckCircle2, Shield, Plus, Building2, Database, DollarSign, Globe } from 'lucide-react';
import { api } from '../services/api';

export default function AddAssetForm({ isOpen, onClose, existingServices = [], onAssetAdded }) {
  const [assetId, setAssetId] = useState('');
  const [name, setName] = useState('');
  const [selectedService, setSelectedService] = useState('');
  const [customService, setCustomService] = useState('');
  const [isCustomService, setIsCustomService] = useState(false);
  const [criticality, setCriticality] = useState(3);
  const [recordsCount, setRecordsCount] = useState(0);
  const [revenuePerHour, setRevenuePerHour] = useState(0);
  const [internetFacing, setInternetFacing] = useState(false);
  const [assetType, setAssetType] = useState('Server');
  const [environment, setEnvironment] = useState('Production');
  const [classification, setClassification] = useState('Confidential');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Initialize service selection when modal opens or existingServices change
  useEffect(() => {
    if (isOpen) {
      setError(null);
      if (existingServices && existingServices.length > 0) {
        const firstSvc = existingServices[0].service_id || existingServices[0].id || existingServices[0];
        setSelectedService(firstSvc);
        setIsCustomService(false);
      } else {
        setSelectedService('__NEW__');
        setIsCustomService(true);
      }
    }
  }, [isOpen, existingServices]);

  if (!isOpen) return null;

  const handleServiceChange = (e) => {
    const val = e.target.value;
    if (val === '__NEW__') {
      setIsCustomService(true);
      setSelectedService('__NEW__');
    } else {
      setIsCustomService(false);
      setSelectedService(val);
    }
  };

  const resetForm = () => {
    setAssetId('');
    setName('');
    setCriticality(3);
    setRecordsCount(0);
    setRevenuePerHour(0);
    setInternetFacing(false);
    setCustomService('');
    setError(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const trimmedId = assetId.trim();
    if (!trimmedId) {
      setError('Asset ID / Hostname is required.');
      return;
    }

    const critNum = Number(criticality);
    if (!critNum || critNum < 1 || critNum > 5) {
      setError('Criticality is required and must be between 1 and 5.');
      return;
    }

    const recNum = Number(recordsCount);
    if (isNaN(recNum) || recNum < 0) {
      setError('PII Records count must be a non-negative number (0 or higher).');
      return;
    }

    const revNum = Number(revenuePerHour);
    if (isNaN(revNum) || revNum < 0) {
      setError('Revenue per Hour must be a non-negative number (0 or higher).');
      return;
    }

    const finalService = isCustomService ? customService.trim() : selectedService;

    const payload = {
      id: trimmedId,
      name: name.trim() || `Host ${trimmedId}`,
      business_service_id: finalService || 'General',
      criticality_1_5: critNum,
      records_count: recNum,
      revenue_per_hour: revNum,
      internet_facing: Boolean(internetFacing),
      type: assetType,
      environment: environment,
      data_classification: classification
    };

    setLoading(true);
    try {
      const res = await api.addAsset(payload);
      resetForm();
      if (onAssetAdded) {
        onAssetAdded(res);
      }
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to add asset.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(5, 10, 20, 0.85)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: 16
    }}>
      <div 
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: 640,
          maxHeight: '92vh',
          overflowY: 'auto',
          backgroundColor: '#0c1322',
          border: '1px solid rgba(183, 140, 102, 0.25)',
          borderRadius: 16,
          boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7), 0 0 30px rgba(183, 140, 102, 0.1)',
          padding: 24,
          position: 'relative'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{
              width: 42,
              height: 42,
              borderRadius: 10,
              background: 'rgba(183, 140, 102, 0.12)',
              border: '1px solid rgba(183, 140, 102, 0.3)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Server size={22} color="var(--primary)" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, color: 'var(--text-main)', fontWeight: 700 }}>
                Add Network Asset Manually
              </h3>
              <p style={{ margin: '3px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Register an inventory node with business context, financial exposure, and criticality.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={loading}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-dim)',
              cursor: 'pointer',
              padding: 6,
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center'
            }}
            title="Close"
          >
            <X size={20} />
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            marginBottom: 18,
            padding: '10px 14px',
            borderRadius: 8,
            background: 'rgba(201, 114, 114, 0.15)',
            border: '1px solid var(--accent-red)',
            color: '#fca5a5',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 10
          }}>
            <AlertCircle size={16} color="var(--accent-red)" style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Row 1: Asset ID & Name */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                Asset ID / Hostname <span style={{ color: 'var(--accent-red)' }}>*</span>
              </label>
              <input
                type="text"
                placeholder="e.g. srv-prod-db-01 or 192.168.1.50"
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 8,
                  background: '#090e1a',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-main)',
                  fontFamily: 'monospace',
                  fontSize: 13
                }}
                required
              />
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Unique node identifier (matches vulnerability scan target)
              </span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                Asset Name / Role
              </label>
              <input
                type="text"
                placeholder="e.g. Production PostgreSQL Cluster"
                value={name}
                onChange={(e) => setName(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 8,
                  background: '#090e1a',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-main)',
                  fontSize: 13
                }}
              />
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Human-friendly name for reporting
              </span>
            </div>
          </div>

          {/* Row 2: Business Service & Criticality */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                Business Service <span style={{ color: 'var(--accent-red)' }}>*</span>
              </label>
              <select
                value={isCustomService ? '__NEW__' : selectedService}
                onChange={handleServiceChange}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: 8,
                  background: '#090e1a',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-main)',
                  fontSize: 13
                }}
              >
                {existingServices && existingServices.map((svc, idx) => {
                  const sId = typeof svc === 'object' ? (svc.service_id || svc.id) : svc;
                  const sName = typeof svc === 'object' ? (svc.name || sId) : svc;
                  return (
                    <option key={idx} value={sId}>
                      {sName} ({sId})
                    </option>
                  );
                })}
                <option value="__NEW__">+ Add Custom Service...</option>
              </select>

              {isCustomService && (
                <input
                  type="text"
                  placeholder="Enter new service ID (e.g. SVC-CHECKOUT)"
                  value={customService}
                  onChange={(e) => setCustomService(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    borderRadius: 8,
                    background: '#090e1a',
                    border: '1px solid rgba(183, 140, 102, 0.4)',
                    color: 'var(--text-main)',
                    fontSize: 12,
                    marginTop: 8
                  }}
                  autoFocus
                />
              )}
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>
                  Criticality (1-5) <span style={{ color: 'var(--accent-red)' }}>*</span>
                </label>
                <span className={`badge ${criticality >= 4 ? 'badge-critical' : (criticality >= 3 ? 'badge-simulated' : 'badge-real')}`}>
                  Level {criticality} / 5
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
                <input
                  type="range"
                  min="1"
                  max="5"
                  step="1"
                  value={criticality}
                  onChange={(e) => setCriticality(Number(e.target.value))}
                  style={{ flex: 1, accentColor: criticality >= 4 ? 'var(--accent-red)' : 'var(--primary)', cursor: 'pointer' }}
                />
                <select
                  value={criticality}
                  onChange={(e) => setCriticality(Number(e.target.value))}
                  style={{
                    width: 70,
                    padding: '6px 8px',
                    borderRadius: 6,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-main)',
                    fontSize: 12,
                    textAlign: 'center'
                  }}
                >
                  <option value={1}>1 - Low</option>
                  <option value={2}>2 - Guard</option>
                  <option value={3}>3 - Med</option>
                  <option value={4}>4 - High</option>
                  <option value={5}>5 - Crit</option>
                </select>
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                1 = Non-critical internal tool, 5 = Core revenue-generating platform
              </span>
            </div>
          </div>

          {/* Row 3: PII Records & Revenue Exposure per Hour */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                PII / Sensitive Records Count
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="number"
                  min="0"
                  step="100"
                  value={recordsCount}
                  onChange={(e) => setRecordsCount(Math.max(0, parseInt(e.target.value) || 0))}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 8,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-main)',
                    fontSize: 13
                  }}
                />
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Customer records stored (used in DPDP / GDPR breach fines sampling)
              </span>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                Revenue Exposure / Hour (₹)
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type="number"
                  min="0"
                  step="1000"
                  value={revenuePerHour}
                  onChange={(e) => setRevenuePerHour(Math.max(0, parseFloat(e.target.value) || 0))}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 8,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: 'var(--accent-green)',
                    fontWeight: 600,
                    fontSize: 13
                  }}
                />
              </div>
              <span style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4, display: 'block' }}>
                Financial loss per hour of business outage
              </span>
            </div>
          </div>

          {/* Row 4: Internet Facing Toggle & Asset Type */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div style={{
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 8,
              border: '1px solid var(--border-color)',
              padding: '12px 14px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 4 }}>
                  Internet-Facing Node?
                </label>
                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                  Exposed to public web vs internal perimeter
                </span>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 10 }}>
                <button
                  type="button"
                  onClick={() => setInternetFacing(false)}
                  style={{
                    flex: 1,
                    padding: '6px 12px',
                    borderRadius: 6,
                    border: !internetFacing ? '1px solid var(--accent-green)' : '1px solid var(--border-color)',
                    background: !internetFacing ? 'rgba(126, 143, 129, 0.15)' : 'transparent',
                    color: !internetFacing ? 'var(--accent-green)' : 'var(--text-dim)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Internal (Private)
                </button>
                <button
                  type="button"
                  onClick={() => setInternetFacing(true)}
                  style={{
                    flex: 1,
                    padding: '6px 12px',
                    borderRadius: 6,
                    border: internetFacing ? '1px solid var(--accent-red)' : '1px solid var(--border-color)',
                    background: internetFacing ? 'rgba(201, 114, 114, 0.15)' : 'transparent',
                    color: internetFacing ? '#f87171' : 'var(--text-dim)',
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: 'pointer'
                  }}
                >
                  Yes (Public Web)
                </button>
              </div>
            </div>

            <div style={{
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 8,
              border: '1px solid var(--border-color)',
              padding: '12px 14px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between'
            }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--text-main)', marginBottom: 4 }}>
                  Environment & Classification
                </label>
                <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                  Lifecycle tier and governance level
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 10 }}>
                <select
                  value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  style={{
                    padding: '6px 8px',
                    borderRadius: 6,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-main)',
                    fontSize: 11
                  }}
                >
                  <option value="Production">Production</option>
                  <option value="Staging">Staging</option>
                  <option value="Development">Development</option>
                </select>

                <select
                  value={classification}
                  onChange={(e) => setClassification(e.target.value)}
                  style={{
                    padding: '6px 8px',
                    borderRadius: 6,
                    background: '#090e1a',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-main)',
                    fontSize: 11
                  }}
                >
                  <option value="Confidential">Confidential</option>
                  <option value="Restricted">Restricted</option>
                  <option value="Public">Public</option>
                </select>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 12,
            marginTop: 10,
            paddingTop: 16,
            borderTop: '1px solid var(--border-color)'
          }}>
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="btn btn-outline"
              style={{ padding: '8px 18px', fontSize: 13 }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{
                padding: '8px 22px',
                fontSize: 13,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)',
                color: '#031326',
                fontWeight: 700
              }}
            >
              {loading ? (
                <span>Adding Asset & Recalculating...</span>
              ) : (
                <>
                  <Plus size={16} />
                  <span>Add Asset to Inventory</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
