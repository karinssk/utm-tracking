'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Swal from 'sweetalert2';
import * as XLSX from 'xlsx';

interface Customer {
  id: number;
  customer_code: string;
  display_name: string;
  picture_url: string;
  is_blocked: boolean;
  created_at: string;
  utm_source: string;
  utm_medium: string;
  utm_campaign: string;
  linked_at: string;
  source_type?: string;
  follow_requested_at?: string;
}

interface CustomerExportFilters {
  customer_code?: string;
  display_name?: string;
  date_from?: string;
  date_to?: string;
  utm_source?: string;
  utm_medium?: string;
  utm_campaign?: string;
  is_blocked?: string;
  linked?: string;
}

export default function CustomersPage() {
  const router = useRouter();
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [date, setDate] = useState('');
  const [utmSource, setUtmSource] = useState('');
  const [loading, setLoading] = useState(false);

  function load(p = page) {
    setLoading(true);
    const params = new URLSearchParams({ page: String(p) });
    if (date) params.set('date', date);
    if (utmSource) params.set('utm_source', utmSource);

    fetch(`/api/customers?${params}`, { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => {
        setCustomers(data.customers);
        setTotal(data.total);
      })
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(1); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const totalPages = Math.ceil(total / 50);

  async function handleEditCode(e: React.MouseEvent, c: Customer) {
    e.stopPropagation();
    const result = await Swal.fire({
      title: 'แก้ไขรหัสลูกค้า',
      html: `<div style="font-size:13px;color:#546e7a;margin-bottom:8px">${c.display_name || '-'}</div>`,
      input: 'text',
      inputValue: c.customer_code,
      inputLabel: 'รหัสลูกค้า',
      inputPlaceholder: 'เช่น JWD/000001',
      showCancelButton: true,
      confirmButtonText: 'บันทึก',
      cancelButtonText: 'ยกเลิก',
      confirmButtonColor: '#0b57b7',
      cancelButtonColor: '#8a94a4',
      reverseButtons: true,
      didOpen: () => {
        const input = Swal.getInput();
        if (input) input.addEventListener('input', () => { input.value = input.value.toUpperCase(); });
      },
      preConfirm: (value: string) => {
        if (!value?.trim()) { Swal.showValidationMessage('กรุณาใส่รหัสลูกค้า'); return false; }
        return value.trim().toUpperCase();
      },
    });

    if (!result.isConfirmed || !result.value) return;

    const res = await fetch(`/api/customers/${c.id}/code`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ customer_code: result.value }),
    });
    const data = await res.json();
    if (!res.ok) {
      Swal.fire({ toast: true, position: 'top-end', icon: 'error', title: data.error || 'Failed to update', timer: 3000, showConfirmButton: false });
      return;
    }
    setCustomers((prev) => prev.map((x) => x.id === c.id ? { ...x, customer_code: data.customer_code } : x));
    Swal.fire({ toast: true, position: 'top-end', icon: 'success', title: `บันทึกรหัส ${data.customer_code} สำเร็จ`, timer: 2000, showConfirmButton: false });
  }

  const EXPORT_HEADERS = ['Customer Code', 'Name', 'LINE UID', 'Status', 'Source Type', 'UTM Source', 'UTM Medium', 'UTM Campaign', 'Follow Requested', 'Linked At', 'Created At'];
  function toExportRow(c: Record<string, unknown>) {
    return [
      c.customer_code || '',
      c.display_name || '',
      c.line_uid || '',
      c.is_blocked ? 'Blocked' : 'Active',
      c.source_type || '',
      c.utm_source || '',
      c.utm_medium || '',
      c.utm_campaign || '',
      c.follow_requested_at ? new Date(String(c.follow_requested_at)).toLocaleString('th-TH') : '',
      c.linked_at ? new Date(String(c.linked_at)).toLocaleString('th-TH') : '',
      c.created_at ? new Date(String(c.created_at)).toLocaleString('th-TH') : '',
    ];
  }

  function buildExportParams(filters: CustomerExportFilters) {
    const params = new URLSearchParams();
    if (filters.customer_code) params.set('customer_code', filters.customer_code);
    if (filters.display_name) params.set('display_name', filters.display_name);
    if (filters.date_from) params.set('date_from', filters.date_from);
    if (filters.date_to) params.set('date_to', filters.date_to);
    if (filters.utm_source) params.set('utm_source', filters.utm_source);
    if (filters.utm_medium) params.set('utm_medium', filters.utm_medium);
    if (filters.utm_campaign) params.set('utm_campaign', filters.utm_campaign);
    if (filters.is_blocked) params.set('is_blocked', filters.is_blocked);
    if (filters.linked) params.set('linked', filters.linked);
    return params;
  }

  async function fetchExportData(filters: CustomerExportFilters) {
    const res = await fetch(`/api/customers/export?${buildExportParams(filters)}`, { credentials: 'include' });
    if (!res.ok) throw new Error('Export failed');
    const data = await res.json();
    return (data.customers || []) as Record<string, unknown>[];
  }

  async function exportCsv(filters: CustomerExportFilters) {
    const rows = await fetchExportData(filters);
    const lines = [EXPORT_HEADERS, ...rows.map(toExportRow)];
    const csv = lines.map((r) => r.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = `${filters.date_from || 'all'}_${filters.date_to || 'all'}`;
    a.href = url;
    a.download = `customers_${stamp}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function exportXlsx(filters: CustomerExportFilters) {
    const rows = await fetchExportData(filters);
    const ws = XLSX.utils.aoa_to_sheet([EXPORT_HEADERS, ...rows.map(toExportRow)]);
    ws['!cols'] = EXPORT_HEADERS.map((h, i) => {
      const max = Math.max(h.length, ...rows.map((r) => String(toExportRow(r)[i] ?? '').length));
      return { wch: Math.min(max + 2, 40) };
    });
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Customers');
    const stamp = `${filters.date_from || 'all'}_${filters.date_to || 'all'}`;
    XLSX.writeFile(wb, `customers_${stamp}.xlsx`);
  }

  async function handleExportModal() {
    const result = await Swal.fire({
      title: 'Export Customers',
      width: 760,
      html: `
        <div style="display:grid;gap:10px;text-align:left">
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <input id="cx-code" class="input" placeholder="Customer code" />
            <input id="cx-name" class="input" placeholder="Display name" />
            <select id="cx-blocked" class="select">
              <option value="">All status</option>
              <option value="false">Active</option>
              <option value="true">Blocked</option>
            </select>
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <input id="cx-date-from" class="input" type="date" />
            <input id="cx-date-to" class="input" type="date" />
            <select id="cx-linked" class="select">
              <option value="">Linked: all</option>
              <option value="yes">Linked only</option>
              <option value="no">Unlinked only</option>
            </select>
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <input id="cx-utm-source" class="input" placeholder="UTM Source" />
            <input id="cx-utm-medium" class="input" placeholder="UTM Medium" />
            <input id="cx-utm-campaign" class="input" placeholder="UTM Campaign" />
          </div>
          <select id="cx-format" class="select">
            <option value="xlsx">XLSX</option>
            <option value="csv">CSV</option>
          </select>
        </div>
      `,
      showCancelButton: true,
      confirmButtonText: 'Export',
      cancelButtonText: 'Cancel',
      didOpen: () => {
        const fromEl = document.getElementById('cx-date-from') as HTMLInputElement | null;
        const toEl = document.getElementById('cx-date-to') as HTMLInputElement | null;
        const sourceEl = document.getElementById('cx-utm-source') as HTMLInputElement | null;
        if (fromEl) fromEl.value = date;
        if (toEl) toEl.value = date;
        if (sourceEl) sourceEl.value = utmSource;
      },
      preConfirm: () => {
        const getVal = (id: string) => ((document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null)?.value || '').trim();
        return {
          filters: {
            customer_code: getVal('cx-code') || undefined,
            display_name: getVal('cx-name') || undefined,
            date_from: getVal('cx-date-from') || undefined,
            date_to: getVal('cx-date-to') || undefined,
            utm_source: getVal('cx-utm-source') || undefined,
            utm_medium: getVal('cx-utm-medium') || undefined,
            utm_campaign: getVal('cx-utm-campaign') || undefined,
            is_blocked: getVal('cx-blocked') || undefined,
            linked: getVal('cx-linked') || undefined,
          } as CustomerExportFilters,
          format: getVal('cx-format') || 'xlsx',
        };
      },
    });
    if (!result.isConfirmed || !result.value) return;

    try {
      if (result.value.format === 'csv') {
        await exportCsv(result.value.filters);
      } else {
        await exportXlsx(result.value.filters);
      }
    } catch {
      Swal.fire({ toast: true, position: 'top-end', icon: 'error', title: 'Export failed', timer: 2500, showConfirmButton: false });
    }
  }

  return (
    <section>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>ลูกค้า ({total.toLocaleString()})</h1>
          <p className="page-subtitle">ติดตามสถานะลูกค้าและข้อมูลแคมเปญ</p>
        </div>
        <div>
          <button type="button" className="btn btn-soft" onClick={handleExportModal}>Export</button>
        </div>
      </div>

      <div className="filter-row">
        <input
          type="date"
          value={date}
          onChange={(e) => setDate(e.target.value)}
          className="input"
          placeholder="Date"
        />
        <input
          type="text"
          value={utmSource}
          onChange={(e) => setUtmSource(e.target.value)}
          className="input"
          placeholder="UTM Source"
        />
        <button onClick={() => { setPage(1); load(1); }} className="btn btn-primary" type="button">Search</button>
        <button
          onClick={() => { setDate(''); setUtmSource(''); setPage(1); load(1); }}
          className="btn btn-soft"
          type="button"
        >
          Reset
        </button>
      </div>

      {loading ? (
        <p className="page-subtitle">Loading...</p>
      ) : (
        <div className="table-shell table-wrap">
          <table className="table">
            <thead>
              <tr>
                {['Code', 'Name', 'UTM Source', 'UTM Campaign', 'Linked', 'Status', 'Created'].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {customers.map((c) => (
                <tr key={c.id} onClick={() => router.push(`/admin/customers/${c.id}`)} style={{ cursor: 'pointer' }}>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: 13 }}>{c.customer_code}</span>
                      <button
                        type="button"
                        onClick={(e) => handleEditCode(e, c)}
                        title="แก้ไขรหัสลูกค้า"
                        style={{ background: 'transparent', border: '1px solid #dde2ea', borderRadius: 5, padding: '2px 6px', cursor: 'pointer', fontSize: 11, color: '#546e7a', lineHeight: 1 }}
                      >
                        ✎
                      </button>
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {c.picture_url && (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img src={c.picture_url} alt="" style={{ width: 26, height: 26, borderRadius: '50%', objectFit: 'cover' }} />
                      )}
                      <span>{c.display_name || '-'}</span>
                    </div>
                  </td>
                  <td>{c.utm_source || '-'}</td>
                  <td>{c.utm_campaign || '-'}</td>
                  <td>{c.linked_at ? 'Yes' : 'No'}</td>
                  <td>
                    <span className={`badge ${c.is_blocked ? 'badge-danger' : 'badge-success'}`}>
                      {c.is_blocked ? 'Blocked' : 'Active'}
                    </span>
                  </td>
                  <td>{new Date(c.created_at).toLocaleDateString('th-TH')}</td>
                </tr>
              ))}
              {customers.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: '#8a94a4' }}>
                    No data
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="pagination">
          <button
            onClick={() => { setPage(page - 1); load(page - 1); }}
            disabled={page <= 1}
            className="btn btn-soft"
            type="button"
          >
            Prev
          </button>
          <span className="page-subtitle" style={{ margin: 0 }}>Page {page} / {totalPages}</span>
          <button
            onClick={() => { setPage(page + 1); load(page + 1); }}
            disabled={page >= totalPages}
            className="btn btn-soft"
            type="button"
          >
            Next
          </button>
        </div>
      )}
    </section>
  );
}
