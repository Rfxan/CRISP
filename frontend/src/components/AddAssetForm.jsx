import React, { useState, useEffect } from 'react';
import { X, Server, AlertCircle, Plus, Pencil, Save } from 'lucide-react';
import { api } from '../services/api';

const DEFAULT_SERVICES = [
  { id: 'SVC-PAY', name: 'UPI & Payment Gateway Switch' },
  { id: 'SVC-CORE', name: 'Core Banking System (CBS Engine)' },
  { id: 'SVC-NETBANK', name: 'Retail NetBanking & Mobile API' },
  { id: 'SVC-LOAN', name: 'Corporate & Retail Lending Engine' },
  { id: 'SVC-CRM', name: 'Enterprise CRM & Customer Portal' },
  { id: 'SVC-CORP', name: 'Treasury & Corporate Portals' }
];

export default function AddAssetForm({ 
  isOpen, 
  onClose, 
  existingServices = [], 
  onAssetAdded,
  assetToEdit = null,
  onAssetUpdated 
}) {
  const isEditMode = Boolean(assetToEdit);
  const [assetId, setAssetId] = useState('');
  const [name, setName] = useState('');
  const [selectedService, setSelectedService] = useState('SVC-PAY');
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

  const servicesList = (existingServices && existingServices.length > 0)
    ? existingServices
    : DEFAULT_SERVICES;

  const getFirstServiceId = (list) => {
    if (!list || list.length === 0) return 'SVC-PAY';
    const first = list[0];
    return typeof first === 'object' ? (first.id || first.service_id || 'SVC-PAY') : (first || 'SVC-PAY');
  };

  // Sync values when modal opens or assetToEdit changes
  useEffect(() => {
    if (isOpen) {
      setError(null);
      const list = (existingServices && existingServices.length > 0) ? existingServices : DEFAULT_SERVICES;
      const fallbackId = getFirstServiceId(list);

      if (assetToEdit) {
        setAssetId(assetToEdit.id || assetToEdit.asset_id || '');
        setName(assetToEdit.name || '');
        const rawSvc = (assetToEdit.business_service_id || assetToEdit.service || '').trim();
        if (rawSvc) {
          const matchingSvc = list.find(s => {
            const sid = typeof s === 'object' ? (s.id || s.service_id) : s;
            return sid === rawSvc;
          });
          if (matchingSvc) {
            setSelectedService(rawSvc);
            setIsCustomService(false);
            setCustomService('');
          } else {
            setSelectedService('__NEW__');
            setIsCustomService(true);
            setCustomService(rawSvc);
          }
        } else {
          setSelectedService(fallbackId);
          setIsCustomService(false);
          setCustomService('');
        }
        setCriticality(assetToEdit.criticality_1_5 ?? assetToEdit.criticality ?? 3);
        setRecordsCount(assetToEdit.records_count ?? assetToEdit.records ?? 0);
        setRevenuePerHour(assetToEdit.revenue_per_hour ?? 0);
        setInternetFacing(Boolean(assetToEdit.internet_facing));
        setAssetType(assetToEdit.type || 'Server');
        setEnvironment(assetToEdit.environment || 'Production');
        setClassification(assetToEdit.data_classification || 'Confidential');
      } else {
        setAssetId('');
        setName('');
        setSelectedService(fallbackId);
        setIsCustomService(false);
        setCustomService('');
        setCriticality(3);
        setRecordsCount(0);
        setRevenuePerHour(0);
        setInternetFacing(false);
        setAssetType('Server');
        setEnvironment('Production');
        setClassification('Confidential');
      }
    }
  }, [isOpen, assetToEdit, existingServices]);

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
    const fallbackId = getFirstServiceId(servicesList);
    setSelectedService(fallbackId);
    setCriticality(3);
    setRecordsCount(0);
    setRevenuePerHour(0);
    setInternetFacing(false);
    setCustomService('');
    setIsCustomService(false);
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
    if (isCustomService && !finalService) {
      setError('Please enter a valid Custom Service ID.');
      return;
    }

    const payload = {
      id: trimmedId,
      name: name.trim() || `Host ${trimmedId}`,
      business_service_id: finalService || 'SVC-PAY',
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
      if (isEditMode) {
        const res = await api.updateAsset(trimmedId, payload);
        if (onAssetUpdated) {
          onAssetUpdated(res);
        }
        onClose();
      } else {
        const res = await api.addAsset(payload);
        resetForm();
        if (onAssetAdded) {
          onAssetAdded(res);
        }
        onClose();
      }
    } catch (err) {
      setError(err.message || (isEditMode ? 'Failed to update asset.' : 'Failed to add asset.'));
    } finally {
      setLoading(false);
    }
  };


  const activeServiceValue = isCustomService
    ? '__NEW__'
    : (selectedService || getFirstServiceId(servicesList));

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
      <style>{`
        .crisp-add-asset-modal h1,
        .crisp-add-asset-modal h2,
        .crisp-add-asset-modal h3,
        .crisp-add-asset-modal h4 {
          color: #F4F1EA !important;
        }
        .crisp-add-asset-modal label {
          color: #C9C4B8 !important;
        }
        .crisp-add-asset-modal .modal-helper-text {
          color: #A39E93 !important;
        }
        .crisp-add-asset-modal input.modal-dark-input,
        .crisp-add-asset-modal select.modal-dark-select {
          color: #F4F1EA !important;
          background-color: #070c18 !important;
        }
        .crisp-add-asset-modal input.modal-dark-input::placeholder {
          color: #A39E93 !important;
          opacity: 1 !important;
        }
        .crisp-add-asset-modal select.modal-dark-select option {
          background-color: #0c1322 !important;
          color: #F4F1EA !important;
        }
        .crisp-add-asset-modal input.modal-dark-input:focus,
        .crisp-add-asset-modal select.modal-dark-select:focus {
          border-color: rgba(212, 181, 149, 0.85) !important;
          outline: none !important;
          box-shadow: 0 0 0 2px rgba(183, 140, 102, 0.3) !important;
        }
      `}</style>
      <div 
        className="crisp-add-asset-modal"
        style={{
          width: '100%',
          maxWidth: 660,
          maxHeight: '90vh',
          overflowY: 'auto',
          backgroundColor: '#0c1322',
          border: '1px solid rgba(183, 140, 102, 0.35)',
          borderRadius: 16,
          boxShadow: '0 25px 60px rgba(0, 0, 0, 0.85), 0 0 35px rgba(183, 140, 102, 0.12)',
          padding: '26px 28px',
          position: 'relative',
          boxSizing: 'border-box'
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 22 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 44,
              height: 44,
              borderRadius: 12,
              background: 'rgba(183, 140, 102, 0.18)',
              border: '1px solid rgba(183, 140, 102, 0.45)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0
            }}>
              <Server size={22} color="#f4f1ea" />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, color: '#F4F1EA', fontWeight: 700, letterSpacing: '-0.01em' }}>
                {isEditMode ? 'Edit Network Asset & Business Context' : 'Add Network Asset Manually'}
              </h3>
              <p className="modal-helper-text" style={{ margin: '4px 0 0 0', fontSize: 12, color: '#A39E93', lineHeight: 1.4 }}>
                {isEditMode
                  ? 'Update business criticality, downtime revenue exposure, and CMDB parameters for FAIR modeling.'
                  : 'Register an inventory node with business context, financial exposure, and criticality.'}
              </p>
            </div>
          </div>
          <button
            type="button"
            aria-label="Close dialog" onClick={onClose}
            disabled={loading}
            style={{
              background: 'rgba(255, 255, 255, 0.06)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#C9C4B8',
              cursor: 'pointer',
              padding: 7,
              borderRadius: 8,
              display: 'flex',
              alignItems: 'center',
              transition: 'all 0.15s ease'
            }}
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div style={{
            marginBottom: 18,
            padding: '10px 14px',
            borderRadius: 8,
            background: 'rgba(239, 68, 68, 0.18)',
            border: '1px solid #ef4444',
            color: '#fca5a5',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 10
          }}>
            <AlertCircle size={16} color="#ef4444" style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          {/* Row 1: Asset ID & Name */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                Asset ID / Hostname <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <input
                type="text"
                className="modal-dark-input"
                placeholder="e.g. srv-prod-db-01 or 192.168.1.50"
                aria-label="Asset ID" value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                disabled={isEditMode || loading}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 8,
                  backgroundColor: isEditMode ? 'rgba(255, 255, 255, 0.05)' : '#070c18',
                  border: isEditMode ? '1px solid rgba(255, 255, 255, 0.12)' : '1px solid rgba(255, 255, 255, 0.18)',
                  color: isEditMode ? '#A39E93' : '#F4F1EA',
                  fontFamily: 'monospace',
                  fontSize: 13,
                  boxSizing: 'border-box',
                  cursor: isEditMode ? 'not-allowed' : 'text'
                }}
                required
              />
              <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', marginTop: 5, display: 'block', lineHeight: 1.3 }}>
                {isEditMode
                  ? 'Asset ID is the primary key and cannot be modified.'
                  : 'Unique node identifier (matches vulnerability scan target)'}
              </span>
            </div>

            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                Asset Name / Role
              </label>
              <input
                type="text"
                className="modal-dark-input"
                placeholder="e.g. Production PostgreSQL Cluster"
                aria-label="Asset name" value={name}
                onChange={(e) => setName(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 8,
                  backgroundColor: '#070c18',
                  border: '1px solid rgba(255, 255, 255, 0.18)',
                  color: '#F4F1EA',
                  fontSize: 13,
                  boxSizing: 'border-box'
                }}
              />
              <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', marginTop: 5, display: 'block', lineHeight: 1.3 }}>
                Human-friendly name for reporting
              </span>
            </div>
          </div>

          {/* Row 2: Business Service & Criticality */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                Business Service <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <select
                className="modal-dark-select"
                aria-label="Business service" value={activeServiceValue}
                onChange={handleServiceChange}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 8,
                  backgroundColor: '#070c18',
                  border: '1px solid rgba(255, 255, 255, 0.18)',
                  color: '#F4F1EA',
                  fontSize: 13,
                  cursor: 'pointer',
                  boxSizing: 'border-box'
                }}
              >
                {servicesList.map((svc, idx) => {
                  const sId = typeof svc === 'object' ? (svc.service_id || svc.id) : svc;
                  const sName = typeof svc === 'object' ? (svc.name || sId) : svc;
                  return (
                    <option key={idx} value={sId} style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>
                      {sName} ({sId})
                    </option>
                  );
                })}
                <option value="__NEW__" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>
                  + Add Custom Service...
                </option>
              </select>

              {isCustomService && (
                <input
                  type="text"
                  className="modal-dark-input"
                  placeholder="Enter new service ID (e.g. SVC-CHECKOUT)"
                  aria-label="New business service" value={customService}
                  onChange={(e) => setCustomService(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: 8,
                    backgroundColor: '#070c18',
                    border: '1px solid rgba(212, 181, 149, 0.6)',
                    color: '#F4F1EA',
                    fontSize: 12,
                    marginTop: 8,
                    boxSizing: 'border-box'
                  }}
                  autoFocus
                />
              )}
            </div>

            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                Criticality (1-5) <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, height: 42, boxSizing: 'border-box' }}>
                <input
                  type="range"
                  min="1"
                  max="5"
                  step="1"
                  aria-label="Criticality from 1 to 5" value={criticality}
                  onChange={(e) => setCriticality(Number(e.target.value))}
                  style={{
                    flex: 1,
                    accentColor: criticality >= 4 ? '#ef4444' : (criticality >= 3 ? '#d97706' : '#22c55e'),
                    cursor: 'pointer'
                  }}
                />
                <span style={{
                  padding: '6px 14px',
                  borderRadius: 6,
                  fontSize: 12,
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  whiteSpace: 'nowrap',
                  flexShrink: 0,
                  backgroundColor: criticality >= 4 ? 'rgba(239, 68, 68, 0.22)' : (criticality >= 3 ? 'rgba(217, 119, 6, 0.22)' : 'rgba(34, 197, 94, 0.22)'),
                  color: criticality >= 4 ? '#fca5a5' : (criticality >= 3 ? '#fcd34d' : '#86efac'),
                  border: `1px solid ${criticality >= 4 ? 'rgba(239, 68, 68, 0.5)' : (criticality >= 3 ? 'rgba(217, 119, 6, 0.5)' : 'rgba(34, 197, 94, 0.5)')}`
                }}>
                  LEVEL {criticality} / 5
                </span>
              </div>
              <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', marginTop: 5, display: 'block', lineHeight: 1.3 }}>
                1 = Non-critical internal tool, 5 = Core revenue-generating platform
              </span>
            </div>
          </div>

          {/* Row 3: PII Records & Revenue Exposure per Hour */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                PII / Sensitive Records Count
              </label>
              <input
                type="number"
                min="0"
                step="100"
                className="modal-dark-input"
                aria-label="Record count" value={recordsCount}
                onChange={(e) => setRecordsCount(Math.max(0, parseInt(e.target.value) || 0))}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 8,
                  backgroundColor: '#070c18',
                  border: '1px solid rgba(255, 255, 255, 0.18)',
                  color: '#F4F1EA',
                  fontSize: 13,
                  boxSizing: 'border-box'
                }}
              />
              <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', marginTop: 5, display: 'block', lineHeight: 1.3 }}>
                Customer records stored (used in DPDP / GDPR breach fines sampling)
              </span>
            </div>

            <div style={{ minWidth: 0 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 6 }}>
                Revenue Exposure / Hour (₹)
              </label>
              <input
                type="number"
                min="0"
                step="1000"
                className="modal-dark-input"
                aria-label="Revenue per hour" value={revenuePerHour}
                onChange={(e) => setRevenuePerHour(Math.max(0, parseFloat(e.target.value) || 0))}
                style={{
                  width: '100%',
                  padding: '10px 12px',
                  borderRadius: 8,
                  backgroundColor: '#070c18',
                  border: '1px solid rgba(255, 255, 255, 0.18)',
                  color: '#86efac',
                  fontWeight: 600,
                  fontSize: 13,
                  boxSizing: 'border-box'
                }}
              />
              <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', marginTop: 5, display: 'block', lineHeight: 1.3 }}>
                Financial loss per hour of business outage
              </span>
            </div>
          </div>

          {/* Row 4: Internet Facing Toggle & Environment/Classification */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 10,
              border: '1px solid rgba(255, 255, 255, 0.12)',
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxSizing: 'border-box',
              minWidth: 0
            }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 4 }}>
                  Internet-Facing Node?
                </label>
                <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', lineHeight: 1.3, display: 'block' }}>
                  Exposed to public web vs internal perimeter
                </span>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 12 }}>
                <button
                  type="button"
                  onClick={() => setInternetFacing(false)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: !internetFacing ? '1px solid #16a34a' : '1px solid rgba(255, 255, 255, 0.15)',
                    backgroundColor: !internetFacing ? '#22c55e' : 'transparent',
                    color: !internetFacing ? '#052e16' : '#9E988E',
                    boxShadow: !internetFacing ? '0 2px 10px rgba(34, 197, 94, 0.4)' : 'none',
                    fontSize: 12,
                    fontWeight: !internetFacing ? 700 : 500,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  Internal (Private)
                </button>
                <button
                  type="button"
                  onClick={() => setInternetFacing(true)}
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    borderRadius: 6,
                    border: internetFacing ? '1px solid #dc2626' : '1px solid rgba(255, 255, 255, 0.15)',
                    backgroundColor: internetFacing ? '#ef4444' : 'transparent',
                    color: internetFacing ? '#450a0a' : '#9E988E',
                    boxShadow: internetFacing ? '0 2px 10px rgba(239, 68, 68, 0.4)' : 'none',
                    fontSize: 12,
                    fontWeight: internetFacing ? 700 : 500,
                    cursor: 'pointer',
                    transition: 'all 0.15s ease'
                  }}
                >
                  Yes (Public Web)
                </button>
              </div>
            </div>

            <div style={{
              backgroundColor: 'rgba(255, 255, 255, 0.02)',
              borderRadius: 10,
              border: '1px solid rgba(255, 255, 255, 0.12)',
              padding: '14px 16px',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxSizing: 'border-box',
              minWidth: 0
            }}>
              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#C9C4B8', marginBottom: 4 }}>
                  Environment & Classification
                </label>
                <span className="modal-helper-text" style={{ fontSize: 11, color: '#A39E93', lineHeight: 1.3, display: 'block' }}>
                  Lifecycle tier and governance level
                </span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 12 }}>
                <select
                  className="modal-dark-select"
                  aria-label="Environment" value={environment}
                  onChange={(e) => setEnvironment(e.target.value)}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    backgroundColor: '#070c18',
                    border: '1px solid rgba(255, 255, 255, 0.18)',
                    color: '#F4F1EA',
                    fontSize: 12,
                    cursor: 'pointer',
                    boxSizing: 'border-box'
                  }}
                >
                  <option value="Production" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Production</option>
                  <option value="Staging" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Staging</option>
                  <option value="Development" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Development</option>
                </select>

                <select
                  className="modal-dark-select"
                  aria-label="Data classification" value={classification}
                  onChange={(e) => setClassification(e.target.value)}
                  style={{
                    padding: '8px 10px',
                    borderRadius: 6,
                    backgroundColor: '#070c18',
                    border: '1px solid rgba(255, 255, 255, 0.18)',
                    color: '#F4F1EA',
                    fontSize: 12,
                    cursor: 'pointer',
                    boxSizing: 'border-box'
                  }}
                >
                  <option value="Confidential" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Confidential</option>
                  <option value="Restricted" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Restricted</option>
                  <option value="Public" style={{ backgroundColor: '#0c1322', color: '#F4F1EA' }}>Public</option>
                </select>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{
            display: 'flex',
            justifyContent: 'flex-end',
            gap: 12,
            marginTop: 8,
            paddingTop: 18,
            borderTop: '1px solid rgba(255, 255, 255, 0.12)'
          }}>
            <button
              type="button"
              aria-label="Close dialog" onClick={onClose}
              disabled={loading}
              style={{
                padding: '9px 20px',
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 600,
                backgroundColor: 'rgba(255, 255, 255, 0.06)',
                border: '1px solid rgba(255, 255, 255, 0.18)',
                color: '#C9C4B8',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              style={{
                padding: '9px 24px',
                borderRadius: 8,
                fontSize: 13,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                background: 'linear-gradient(135deg, #d4b595 0%, #b78c66 100%)',
                color: '#031326',
                border: 'none',
                cursor: loading ? 'not-allowed' : 'pointer',
                boxShadow: '0 4px 16px rgba(183, 140, 102, 0.35)',
                transition: 'all 0.15s ease'
              }}
            >
              {loading ? (
                <span>{isEditMode ? 'Saving Changes & Recalculating...' : 'Adding Asset & Recalculating...'}</span>
              ) : (
                <>
                  {isEditMode ? <Save size={16} strokeWidth={2.5} /> : <Plus size={16} strokeWidth={2.5} />}
                  <span>{isEditMode ? 'Save Asset Changes' : 'Add Asset to Inventory'}</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
