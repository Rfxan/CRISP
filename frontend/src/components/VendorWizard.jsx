import React, { useState } from 'react';
import { 
  UploadCloud, CheckCircle2, AlertTriangle, ArrowRight, ArrowLeft, 
  FileText, Settings2, Sparkles, Eye, Save, RefreshCw, Layers, ShieldCheck, HelpCircle
} from 'lucide-react';
import { api } from '../services/api';

export default function VendorWizard({ onVendorSaved, onCancel }) {
  const [currentStep, setCurrentStep] = useState(1);
  
  // Step 1 State
  const [selectedFile, setSelectedFile] = useState(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectResult, setInspectResult] = useState(null);
  const [step1Error, setStep1Error] = useState(null);

  // Step 2 State (Mapping)
  const [isNonCve, setIsNonCve] = useState(false);
  const [mapping, setMapping] = useState({
    asset_id: '',
    cve_id: '',
    cvss: '',
    severity: '',
    port: '',
    issue_type: ''
  });
  const [previewing, setPreviewing] = useState(false);
  const [previewResult, setPreviewResult] = useState(null);
  const [mappingError, setMappingError] = useState(null);

  // Step 3 State (Save)
  const [vendorName, setVendorName] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(null);
  const [saveError, setSaveError] = useState(null);

  // Intelligent heuristic auto-suggestion based on available field names
  const autoSuggestMapping = (fields, format) => {
    const suggested = {
      asset_id: '',
      cve_id: '',
      cvss: '',
      severity: '',
      port: '',
      issue_type: ''
    };

    const findMatch = (patterns) => {
      for (const p of patterns) {
        const found = fields.find(f => {
          const lower = f.toLowerCase().replace(/[@._-]/g, ' ');
          return lower.includes(p) || f.toLowerCase() === p;
        });
        if (found) return found;
      }
      return '';
    };

    suggested.asset_id = findMatch(['host ip', 'ip', 'host', 'asset', 'resource arn', 'resource', 'target', 'node']);
    suggested.cve_id = findMatch(['cve id', 'cve', 'cve_name', 'vulnerability id']);
    suggested.cvss = findMatch(['cvss base', 'cvss', 'score', 'base score', 'cvss_score', 'cvss v3']);
    suggested.severity = findMatch(['severity', 'threat', 'risk', 'level', 'crit']);
    suggested.port = findMatch(['port', 'service port', 'protocol port']);
    suggested.issue_type = findMatch(['checkid', 'check id', 'check', 'rule', 'issue', 'title', 'plugin name']);

    setMapping(suggested);
  };

  // Step 1: Upload & Inspect
  const handleFileSelected = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setStep1Error(null);
    setInspecting(true);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await api.inspectVendorFile(formData);
      setInspectResult(res);
      autoSuggestMapping(res.available_fields || [], res.format);
      
      // Auto-populate vendor name guess from filename
      const baseName = file.name.replace(/\.[^/.]+$/, "").replace(/[_-]/g, " ");
      const capitalized = baseName.replace(/\b\w/g, l => l.toUpperCase());
      setVendorName(capitalized);
    } catch (err) {
      setStep1Error(err.message);
    } finally {
      setInspecting(false);
    }
  };

  // Step 2: Live Preview Verification
  const handlePreview = async () => {
    setMappingError(null);
    setPreviewResult(null);

    // Validate minimum requirements
    if (!mapping.asset_id) {
      setMappingError('Asset ID is a required field mapping.');
      return;
    }
    if (!mapping.severity) {
      setMappingError('Severity is a required field mapping.');
      return;
    }
    if (!isNonCve && !mapping.cve_id) {
      setMappingError('Please select a CVE ID field or mark this as a non-CVE / configuration scanner.');
      return;
    }
    if (isNonCve && !mapping.issue_type) {
      setMappingError('Please select an Issue Type field for this non-CVE scanner.');
      return;
    }

    setPreviewing(true);

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('vendor_name', vendorName || 'Sample Vendor');
    formData.append('format', inspectResult.format);
    formData.append('record_path', inspectResult.detected_record_path || '');
    formData.append('field_mapping', JSON.stringify({
      asset_id: mapping.asset_id,
      cve_id: isNonCve ? null : (mapping.cve_id || null),
      cvss: mapping.cvss || null,
      severity: mapping.severity,
      port: mapping.port || null,
      issue_type: isNonCve ? mapping.issue_type : (mapping.issue_type || null)
    }));

    try {
      const res = await api.previewVendorMapping(formData);
      setPreviewResult(res);
    } catch (err) {
      setMappingError(err.message);
    } finally {
      setPreviewing(false);
    }
  };

  // Step 3: Save Vendor Config
  const handleSaveVendor = async () => {
    if (!vendorName.trim()) {
      setSaveError('Please provide a vendor or tool name.');
      return;
    }

    setSaving(true);
    setSaveError(null);

    const payload = {
      vendor_name: vendorName.trim(),
      format: inspectResult.format,
      record_path: inspectResult.detected_record_path || '',
      field_mapping: {
        asset_id: mapping.asset_id,
        cve_id: isNonCve ? null : (mapping.cve_id || null),
        cvss: mapping.cvss || null,
        severity: mapping.severity,
        port: mapping.port || null,
        issue_type: isNonCve ? mapping.issue_type : (mapping.issue_type || null)
      },
      sample_file_used: selectedFile?.name || 'sample'
    };

    try {
      const res = await api.saveVendorConfig(payload);
      setSaveSuccess(res.config);
      if (onVendorSaved) {
        onVendorSaved(res.config);
      }
    } catch (err) {
      setSaveError(err.message);
    } finally {
      setSaving(false);
    }
  };

  const availableFields = inspectResult?.available_fields || [];

  return (
    <div className="glass-panel" style={{ padding: 26, border: '1px solid var(--primary)', position: 'relative' }}>
      {/* Wizard Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="badge badge-cyan" style={{ fontSize: 11 }}>NO-CODE INTEGRATION</span>
            <h3 style={{ margin: 0, fontSize: 18, color: 'var(--text-main)' }}>Vendor Onboarding Wizard</h3>
          </div>
          <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
            Teach CRISP to ingest any scanner export (Qualys, Rapid7, Snyk, Prisma, etc.) by uploading one sample and mapping fields once.
          </p>
        </div>

        {onCancel && (
          <button 
            onClick={onCancel}
            className="btn btn-secondary" 
            style={{ fontSize: 12, padding: '6px 12px' }}
          >
            Close Wizard
          </button>
        )}
      </div>

      {/* Stepper Indicator */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 24 }}>
        {[
          { num: 1, title: 'Upload Sample File', desc: 'Inspect Structure' },
          { num: 2, title: 'Map Fields & Validate', desc: 'Live Preview' },
          { num: 3, title: 'Name & Save', desc: 'Register Ingestion Option' }
        ].map((s) => {
          const isActive = currentStep === s.num;
          const isDone = currentStep > s.num;

          return (
            <div
              key={s.num}
              style={{
                flex: 1,
                padding: '10px 14px',
                borderRadius: 8,
                background: isActive 
                  ? 'rgba(183, 140, 102, 0.12)' 
                  : isDone 
                  ? 'rgba(126, 143, 129, 0.1)' 
                  : 'rgba(255,255,255,0.02)',
                border: isActive 
                  ? '1px solid var(--primary)' 
                  : isDone 
                  ? '1px solid var(--accent-green)' 
                  : '1px solid var(--border-color)',
                display: 'flex',
                alignItems: 'center',
                gap: 10
              }}
            >
              <div style={{
                width: 26,
                height: 26,
                borderRadius: '50%',
                background: isDone ? 'var(--accent-green)' : isActive ? 'var(--primary)' : 'var(--bg-card)',
                color: isDone || isActive ? 'var(--bg-main)' : 'var(--text-main)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 700,
                fontSize: 12
              }}>
                {isDone ? <CheckCircle2 size={16} /> : s.num}
              </div>
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: isActive ? 'var(--primary)' : isDone ? 'var(--accent-green)' : 'var(--text-main)' }}>
                  {s.title}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-dim)' }}>{s.desc}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ======================================================== */}
      {/* STEP 1: Upload a sample file */}
      {/* ======================================================== */}
      {currentStep === 1 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div 
            style={{
              padding: 32,
              borderRadius: 10,
              border: '2px dashed var(--border-color)',
              background: 'rgba(255,255,255,0.01)',
              textAlign: 'center'
            }}
          >
            <UploadCloud size={40} color="var(--primary)" style={{ margin: '0 auto 12px auto' }} />
            <h4 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)' }}>
              Step 1: Upload a Sample File from the New Tool
            </h4>
            <p style={{ margin: '6px auto 16px auto', fontSize: 12, color: 'var(--text-dim)', maxWidth: 480 }}>
              Upload any real XML, CSV, or JSON export from your scanner. CRISP will sniffer-inspect the file to auto-detect its repeated record shape and all available field names.
            </p>

            <label className="btn btn-primary" style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 8, padding: '10px 22px' }}>
              <FileText size={16} />
              <span>{inspecting ? 'Sniffing Structure...' : selectedFile ? `Selected: ${selectedFile.name}` : 'Choose Sample File (.xml, .csv, .json)'}</span>
              <input 
                type="file" 
                accept=".xml,.nessus,.csv,.json"
                onChange={handleFileSelected} 
                disabled={inspecting}
                style={{ display: 'none' }} 
              />
            </label>

            {inspecting && (
              <div style={{ marginTop: 14, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, fontSize: 12, color: 'var(--primary)' }}>
                <RefreshCw size={14} className="animate-spin" />
                <span>Inspecting structure, record boundaries, and tag paths...</span>
              </div>
            )}
          </div>

          {step1Error && (
            <div style={{
              padding: '10px 14px', borderRadius: 8,
              background: 'rgba(201, 114, 114, 0.15)', border: '1px solid var(--accent-red)',
              color: 'var(--text-main)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8
            }}>
              <AlertTriangle size={16} color="var(--accent-red)" />
              <span>Inspection Error: {step1Error}</span>
            </div>
          )}

          {inspectResult && (
            <div className="glass-panel" style={{ padding: 18, background: 'rgba(183, 140, 102, 0.03)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <CheckCircle2 size={18} color="var(--accent-green)" />
                  <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>Structure Detected Successfully</strong>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <span className="badge badge-cyan" style={{ textTransform: 'uppercase' }}>Format: {inspectResult.format}</span>
                  <span className="badge badge-amber">Sample Count: {inspectResult.record_count_sample}</span>
                </div>
              </div>

              <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 10 }}>
                <strong>Detected Record Path:</strong> <code style={{ color: 'var(--primary)', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>{inspectResult.detected_record_path || 'Direct Rows'}</code>
              </div>

              <div>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-main)', marginBottom: 6 }}>
                  Available Fields Inside Finding Record ({availableFields.length}):
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, maxHeight: 110, overflowY: 'auto', padding: 6, background: 'rgba(0,0,0,0.2)', borderRadius: 6 }}>
                  {availableFields.map((f, i) => (
                    <span key={i} style={{
                      fontSize: 11, padding: '2px 8px', borderRadius: 4,
                      background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)',
                      color: 'var(--text-bright)', fontFamily: 'monospace'
                    }}>
                      {f}
                    </span>
                  ))}
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
                <button
                  onClick={() => setCurrentStep(2)}
                  className="btn btn-primary"
                  style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 18px', fontSize: 13 }}
                >
                  <span>Proceed to Field Mapping</span>
                  <ArrowRight size={15} />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* STEP 2: Map the fields */}
      {/* ======================================================== */}
      {currentStep === 2 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h4 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)' }}>Step 2: Map Fields to CRISP Standard Canonical Model</h4>
              <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
                Select which field in the vendor file corresponds to each CRISP property. Heuristics have suggested matches below.
              </p>
            </div>

            <button
              onClick={() => autoSuggestMapping(availableFields, inspectResult?.format)}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '5px 10px' }}
              title="Re-run auto-suggest heuristics"
            >
              <Sparkles size={13} color="var(--primary)" />
              <span>Auto-Suggest</span>
            </button>
          </div>

          {/* Toggle for non-CVE / CSPM scanners */}
          <div style={{
            padding: '10px 14px', borderRadius: 8,
            background: 'rgba(154, 150, 179, 0.08)', border: '1px solid rgba(154, 150, 179, 0.3)',
            display: 'flex', alignItems: 'center', gap: 10
          }}>
            <input
              type="checkbox"
              id="nonCveToggle"
              checked={isNonCve}
              onChange={(e) => setIsNonCve(e.target.checked)}
              style={{ cursor: 'pointer', width: 16, height: 16 }}
            />
            <label htmlFor="nonCveToggle" style={{ fontSize: 12, color: 'var(--text-main)', cursor: 'pointer', userSelect: 'none' }}>
              <strong>N/A — This is a Configuration / Misconfiguration / CSPM Scanner</strong>
              <div style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                Bypasses CVE requirement and maps an Issue/Check Type instead (e.g. S3 Public Access, Root MFA Disabled).
              </div>
            </label>
          </div>

          {/* Field Mapping Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
            {/* 1. Asset ID (Required) */}
            <div className="glass-panel" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>
                  Target Asset ID <span style={{ color: 'var(--accent-red)' }}>*</span>
                </label>
                <span className="badge badge-cyan" style={{ fontSize: 9 }}>Required</span>
              </div>
              <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>Host IP, hostname, or Cloud Resource ARN</p>
              <select
                value={mapping.asset_id}
                onChange={(e) => setMapping(m => ({ ...m, asset_id: e.target.value }))}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
              >
                <option value="">-- Select Field --</option>
                {availableFields.map((f, i) => (
                  <option key={i} value={f}>{f}</option>
                ))}
              </select>
            </div>

            {/* 2. Severity (Required) */}
            <div className="glass-panel" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>
                  Severity Level <span style={{ color: 'var(--accent-red)' }}>*</span>
                </label>
                <span className="badge badge-cyan" style={{ fontSize: 9 }}>Required</span>
              </div>
              <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>Critical, High, Medium, Low, or numeric 0-4</p>
              <select
                value={mapping.severity}
                onChange={(e) => setMapping(m => ({ ...m, severity: e.target.value }))}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
              >
                <option value="">-- Select Field --</option>
                {availableFields.map((f, i) => (
                  <option key={i} value={f}>{f}</option>
                ))}
              </select>
            </div>

            {/* 3. CVE ID (Optional or hidden if isNonCve) */}
            {!isNonCve && (
              <div className="glass-panel" style={{ padding: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>
                    CVE Identifier <span style={{ color: 'var(--accent-red)' }}>*</span>
                  </label>
                  <span className="badge badge-amber" style={{ fontSize: 9 }}>Required for Vuln Scanners</span>
                </div>
                <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>CVE-YYYY-NNNN format for EPSS/KEV enrichment</p>
                <select
                  value={mapping.cve_id}
                  onChange={(e) => setMapping(m => ({ ...m, cve_id: e.target.value }))}
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
                >
                  <option value="">-- Select Field --</option>
                  {availableFields.map((f, i) => (
                    <option key={i} value={f}>{f}</option>
                  ))}
                </select>
              </div>
            )}

            {/* 4. Issue Type (Shown when isNonCve or optional) */}
            {isNonCve && (
              <div className="glass-panel" style={{ padding: 14, border: '1px solid var(--accent-purple)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-purple)' }}>
                    Issue / Check ID <span style={{ color: 'var(--accent-red)' }}>*</span>
                  </label>
                  <span className="badge" style={{ background: 'rgba(154, 150, 179, 0.2)', color: 'var(--accent-purple)', fontSize: 9 }}>Required for CSPM</span>
                </div>
                <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>Check rule ID or title (e.g. s3_public_access)</p>
                <select
                  value={mapping.issue_type}
                  onChange={(e) => setMapping(m => ({ ...m, issue_type: e.target.value }))}
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
                >
                  <option value="">-- Select Field --</option>
                  {availableFields.map((f, i) => (
                    <option key={i} value={f}>{f}</option>
                  ))}
                </select>
              </div>
            )}

            {/* 5. CVSS Score (Optional) */}
            <div className="glass-panel" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>CVSS Score (0.0 - 10.0)</label>
                <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)', fontSize: 9 }}>Optional</span>
              </div>
              <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>Base CVSS score numeric value</p>
              <select
                value={mapping.cvss}
                onChange={(e) => setMapping(m => ({ ...m, cvss: e.target.value }))}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
              >
                <option value="">-- None / N/A --</option>
                {availableFields.map((f, i) => (
                  <option key={i} value={f}>{f}</option>
                ))}
              </select>
            </div>

            {/* 6. Port (Optional) */}
            <div className="glass-panel" style={{ padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)' }}>Network Port / Service</label>
                <span className="badge" style={{ background: 'rgba(255,255,255,0.06)', color: 'var(--text-dim)', fontSize: 9 }}>Optional</span>
              </div>
              <p style={{ margin: '0 0 8px 0', fontSize: 11, color: 'var(--text-dim)' }}>Port number or service string (e.g. 443/tcp)</p>
              <select
                value={mapping.port}
                onChange={(e) => setMapping(m => ({ ...m, port: e.target.value }))}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, background: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-main)', fontSize: 12 }}
              >
                <option value="">-- None / N/A --</option>
                {availableFields.map((f, i) => (
                  <option key={i} value={f}>{f}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Validation & Preview Action */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
            <button
              onClick={() => setCurrentStep(1)}
              className="btn btn-secondary"
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
            >
              <ArrowLeft size={14} /> Back to File
            </button>

            <button
              onClick={handlePreview}
              disabled={previewing}
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 20px', fontSize: 13, background: 'linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%)' }}
            >
              <Eye size={15} />
              <span>{previewing ? 'Parsing Preview...' : 'Preview Extracted Findings'}</span>
            </button>
          </div>

          {mappingError && (
            <div style={{
              padding: '10px 14px', borderRadius: 8,
              background: 'rgba(201, 114, 114, 0.15)', border: '1px solid var(--accent-red)',
              color: 'var(--text-main)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8
            }}>
              <AlertTriangle size={16} color="var(--accent-red)" />
              <span>{mappingError}</span>
            </div>
          )}

          {/* Live Preview Verification Table */}
          {previewResult && (
            <div className="glass-panel" style={{ padding: 18, background: 'rgba(0,0,0,0.2)', border: '1px solid var(--accent-green)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldCheck size={18} color="var(--accent-green)" />
                  <strong style={{ fontSize: 13, color: 'var(--text-main)' }}>Live Validation Preview</strong>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <span className="badge badge-cyan">Extracted: {previewResult.total_extracted}</span>
                  <span className="badge badge-amber">Skipped: {previewResult.total_skipped}</span>
                </div>
              </div>

              {previewResult.sample_findings?.length > 0 ? (
                <div style={{ overflowX: 'auto', marginBottom: 14 }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-dim)' }}>
                        <th style={{ padding: '6px 10px' }}>Generated ID</th>
                        <th style={{ padding: '6px 10px' }}>Asset ID</th>
                        <th style={{ padding: '6px 10px' }}>CVE / Issue Type</th>
                        <th style={{ padding: '6px 10px' }}>Severity</th>
                        <th style={{ padding: '6px 10px' }}>CVSS</th>
                        <th style={{ padding: '6px 10px' }}>Port</th>
                      </tr>
                    </thead>
                    <tbody>
                      {previewResult.sample_findings.map((f, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                          <td style={{ padding: '8px 10px', color: 'var(--primary)', fontFamily: 'monospace' }}>{f.id}</td>
                          <td style={{ padding: '8px 10px', fontWeight: 600 }}>{f.asset_id}</td>
                          <td style={{ padding: '8px 10px', color: f.cve_id ? 'var(--accent-amber)' : 'var(--accent-purple)', fontFamily: 'monospace' }}>
                            {f.cve_id || f.issue_type}
                          </td>
                          <td style={{ padding: '8px 10px' }}>
                            <span style={{
                              padding: '2px 8px', borderRadius: 4,
                              background: f.severity === 'Critical' ? 'rgba(201, 114, 114, 0.2)' : 'rgba(209, 184, 121, 0.2)',
                              color: f.severity === 'Critical' ? 'var(--accent-red)' : 'var(--accent-amber)',
                              fontWeight: 700
                            }}>
                              {f.severity}
                            </span>
                          </td>
                          <td style={{ padding: '8px 10px' }}>{f.cvss !== null ? f.cvss : '—'}</td>
                          <td style={{ padding: '8px 10px' }}>{f.port !== null ? f.port : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div style={{ padding: 16, textAlign: 'center', color: 'var(--accent-red)', fontSize: 12 }}>
                  No findings extracted with this mapping. Please check field selections.
                </div>
              )}

              {previewResult.skip_reasons?.length > 0 && (
                <div style={{ fontSize: 11, color: 'var(--accent-amber)', marginBottom: 12 }}>
                  <strong>Skipped Records Note:</strong> {previewResult.skip_reasons.join('; ')}
                </div>
              )}

              {previewResult.total_extracted > 0 && (
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 10 }}>
                  <button
                    onClick={() => setCurrentStep(3)}
                    className="btn btn-primary"
                    style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 20px', fontSize: 13 }}
                  >
                    <span>Confirm Mapping & Continue</span>
                    <ArrowRight size={15} />
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ======================================================== */}
      {/* STEP 3: Name and Save */}
      {/* ======================================================== */}
      {currentStep === 3 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <h4 style={{ margin: 0, fontSize: 15, color: 'var(--text-main)' }}>Step 3: Name and Save Your Vendor Configuration</h4>
            <p style={{ margin: '4px 0 0 0', fontSize: 12, color: 'var(--text-dim)' }}>
              Provide a name for this tool. Once saved, it will appear as a permanent ingestion source in the CRISP dashboard with no backend code changes.
            </p>
          </div>

          <div className="glass-panel" style={{ padding: 20 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-main)', display: 'block', marginBottom: 6 }}>
              Human-Readable Vendor / Tool Name <span style={{ color: 'var(--accent-red)' }}>*</span>
            </label>
            <input
              type="text"
              value={vendorName}
              onChange={(e) => setVendorName(e.target.value)}
              placeholder="e.g. Rapid7 InsightVM, Qualys VMDR, Snyk Container..."
              style={{
                width: '100%',
                padding: '10px 14px',
                borderRadius: 8,
                background: 'var(--bg-card)',
                border: '1px solid var(--border-color)',
                color: 'var(--text-main)',
                fontSize: 14,
                marginBottom: 14
              }}
            />

            <div style={{ fontSize: 12, color: 'var(--text-dim)', marginBottom: 18 }}>
              <strong>Generated Slug:</strong> <code style={{ color: 'var(--primary)' }}>{vendorName.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') || 'custom_vendor'}</code>
              <br />
              <strong>Ingestion API Endpoint:</strong> <code style={{ color: 'var(--accent-green)' }}>POST /api/ingest/vendor/{'{vendor_slug}'}</code>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <button
                onClick={() => setCurrentStep(2)}
                className="btn btn-secondary"
                style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}
              >
                <ArrowLeft size={14} /> Back to Mapping
              </button>

              <button
                onClick={handleSaveVendor}
                disabled={saving || !vendorName.trim()}
                className="btn btn-primary"
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px', fontSize: 13,
                  background: 'linear-gradient(135deg, var(--accent-green) 0%, var(--accent-green) 100%)'
                }}
              >
                <Save size={16} />
                <span>{saving ? 'Saving Config...' : 'Save & Register Vendor'}</span>
              </button>
            </div>
          </div>

          {saveError && (
            <div style={{
              padding: '10px 14px', borderRadius: 8,
              background: 'rgba(201, 114, 114, 0.15)', border: '1px solid var(--accent-red)',
              color: 'var(--text-main)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8
            }}>
              <AlertTriangle size={16} color="var(--accent-red)" />
              <span>{saveError}</span>
            </div>
          )}

          {saveSuccess && (
            <div style={{
              padding: '18px 20px', borderRadius: 10,
              background: 'rgba(126, 143, 129, 0.15)', border: '1px solid var(--accent-green)',
              color: 'var(--text-main)', display: 'flex', flexDirection: 'column', gap: 10
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <CheckCircle2 size={24} color="var(--accent-green)" />
                <div>
                  <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--accent-green)' }}>Vendor Successfully Onboarded!</div>
                  <div style={{ fontSize: 12, color: 'var(--text-dim)' }}>
                    "{saveSuccess.vendor_name}" has been saved to disk and is now ready for production report uploads.
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 10, marginTop: 6 }}>
                <button
                  onClick={() => {
                    setCurrentStep(1);
                    setSelectedFile(null);
                    setInspectResult(null);
                    setPreviewResult(null);
                    setSaveSuccess(null);
                    setVendorName('');
                  }}
                  className="btn btn-secondary"
                  style={{ fontSize: 12, padding: '6px 14px' }}
                >
                  Onboard Another Vendor
                </button>

                {onCancel && (
                  <button
                    onClick={onCancel}
                    className="btn btn-primary"
                    style={{ fontSize: 12, padding: '6px 14px' }}
                  >
                    Done & Return to Ingestion Hub
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
