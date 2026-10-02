/**
 * Currency and numbers formatters calibrated for Indian context (₹, Lakhs, Crores)
 */
export function formatINR(val) {
  if (val === undefined || val === null || isNaN(val)) return 'Unknown';
  const num = Number(val);
  const abs = Math.abs(num);
  const sign = num < 0 ? '-' : '';

  if (abs >= 10_000_000) {
    return `${sign}₹${(abs / 10_000_000).toFixed(2)} Cr`;
  } else if (abs >= 100_000) {
    return `${sign}₹${(abs / 100_000).toFixed(2)} L`;
  } else {
    return `${sign}₹${abs.toLocaleString('en-IN')}`;
  }
}

export function formatINRFull(val) {
  if (val === undefined || val === null || isNaN(val)) return 'Unknown';
  return `₹${Math.round(val).toLocaleString('en-IN')}`;
}
