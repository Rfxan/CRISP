import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';
import homeBg from '../home_bg.png';

export default function LandingPage({ onSignIn }) {
  return (
    <div style={{
      width: '100%',
      minHeight: '100vh',
      /* Background image with white overlay to achieve 20% opacity look */
      background: `linear-gradient(rgba(255,255,255,0.8), rgba(255,255,255,0.8)), url(${homeBg}) center/cover no-repeat, #ffffff`,
      backgroundColor: '#ffffff',
      position: 'relative',
      fontFamily: 'var(--font-sans)',
      WebkitFontSmoothing: 'antialiased',
      MozOsxFontSmoothing: 'grayscale',
      textRendering: 'optimizeLegibility'
    }}>
      {/* Navigation */}
      <nav style={{
        display: 'grid',
        gridTemplateColumns: '1fr auto 1fr',
        alignItems: 'center',
        padding: '24px 48px',
        position: 'relative',
        zIndex: 10
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, justifySelf: 'start' }}>
          <span style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em', color: '#222' }}>CRISP</span>
        </div>

        {/* Links */}
        <div style={{ display: 'flex', gap: 32, color: '#555', fontSize: 15 }}>
        </div>

        <div style={{ justifySelf: 'end' }}>
          <button
            onClick={onSignIn}
            style={{
              background: '#1a1a1a',
              color: '#fdfdfd',
              border: 'none',
              padding: '10px 24px',
              borderRadius: 12,
              fontSize: 15,
              fontWeight: 600,
              cursor: 'pointer'
            }}>
            Dashboard
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      <main style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        paddingTop: '80px',
        position: 'relative',
        zIndex: 10,
        maxWidth: 800,
        margin: '0 auto'
      }}>
        {/* Pill */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.6)',
          backdropFilter: 'blur(10px)',
          padding: '8px 16px',
          borderRadius: 30,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          fontSize: 14,
          fontWeight: 500,
          color: '#444',
          marginBottom: 32,
          boxShadow: '0 4px 12px rgba(0,0,0,0.05)'
        }}>
          <ShieldCheck size={16} color="#8a7373" /> Built by Security Experts, for CISOs
        </div>

        {/* Title */}
        <h1 style={{
          fontSize: 72,
          lineHeight: 1.1,
          fontWeight: 500,
          color: '#1a1a1a',
          marginBottom: 32,
          letterSpacing: '-0.03em',
          fontFamily: "'Georgia', serif"
        }}>
          Meet CRISP,<br />The ultimate cyber risk<br />optimization platform.
        </h1>

        {/* Subtitle */}
        <p style={{
          fontSize: 18,
          lineHeight: 1.6,
          color: '#555',
          maxWidth: 680,
          marginBottom: 48
        }}>
          Replace static, manual risk assessments. A continuous, data-driven simulation ecosystem for real-time FAIR loss magnitude, compliance auditing, and security investment optimization.
        </p>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: 16 }}>
          <button
            onClick={onSignIn}
            style={{
              background: '#1a1a1a',
              color: '#fdfdfd',
              border: 'none',
              padding: '14px 32px',
              borderRadius: 16,
              fontSize: 16,
              fontWeight: 600,
              cursor: 'pointer',
              boxShadow: '0 8px 24px rgba(0,0,0,0.1)'
            }}>
            Dashboard
          </button>
        </div>
      </main>
    </div>
  );
}
