'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Swal from 'sweetalert2';
import * as XLSX from 'xlsx';

interface Order {
  id: number;
  order_code: string;
  customer_code: string;
  display_name: string;
  template_type: string;
  stage: string;
  amount: number;
  total_amount: number;
  status: 'PENDING' | 'CONFIRMED' | 'UNCONFIRMED';
  created_at: string;
}

interface ExportFilters {
  customer_code?: string;
  date_from?: string;
  date_to?: string;
  status?: string;
  template_type?: string;
  stage?: string;
  account_type?: string;
  utm_source?: string;
  utm_medium?: string;
}

const STATUS_LABELS: Record<string, string> = {
  PENDING: 'Pending',
  CONFIRMED: 'Confirmed',
  UNCONFIRMED: 'Cancelled',
};

const STATUS_BADGES: Record<string, string> = {
  PENDING: 'badge-warning',
  CONFIRMED: 'badge-success',
  UNCONFIRMED: 'badge-danger',
};

const TEMPLATE_LABELS: Record<string, string> = {
  CONFIRM: 'คำสั่งซื้อสินค้า',
};

export default function OrdersPage() {
  const router = useRouter();
  const [orders, setOrders] = useState<Order[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [customerCode, setCustomerCode] = useState('');
  const [date, setDate] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const [actingId, setActingId] = useState<number | null>(null);

  function load(p = page) {
    setLoading(true);
    const params = new URLSearchParams({ page: String(p) });
    if (customerCode) params.set('customer_code', customerCode);
    if (date) params.set('date', date);
    if (status) params.set('status', status);

    fetch(`/api/orders?${params}`, { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => {
        setOrders(data.orders);
        setTotal(data.total);
      })
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(1); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function updateOrder(id: number, action: 'confirm' | 'cancel') {
    const isConfirm = action === 'confirm';
    const result = await Swal.fire({
      title: isConfirm ? 'ยืนยันคำสั่งซื้อ?' : 'ยกเลิกคำสั่งซื้อ?',
      text: isConfirm
        ? 'กดยืนยันเพื่อเปลี่ยนสถานะเป็น "ยืนยันแล้ว"'
        : 'กดยืนยันเพื่อยกเลิกคำสั่งซื้อนี้',
      icon: isConfirm ? 'question' : 'warning',
      showCancelButton: true,
      confirmButtonColor: isConfirm ? '#1d975f' : '#e53935',
      cancelButtonColor: '#8a94a4',
      confirmButtonText: isConfirm ? 'ยืนยัน' : 'ยกเลิกคำสั่งซื้อ',
      cancelButtonText: 'ปิด',
      reverseButtons: true,
    });
    if (!result.isConfirmed) return;

    setActingId(id);
    try {
      const res = await fetch(`/api/orders/${id}/${action}`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        Swal.fire({ icon: 'error', title: 'เกิดข้อผิดพลาด', text: data.error || 'Update failed' });
      } else {
        Swal.fire({ icon: 'success', title: isConfirm ? 'ยืนยันสำเร็จ' : 'ยกเลิกสำเร็จ', timer: 1500, showConfirmButton: false });
      }
      load(page);
    } finally {
      setActingId(null);
    }
  }

  const totalPages = Math.ceil(total / 50);

  const EXPORT_HEADERS = ['Order Code', 'Customer Code', 'Name', 'Type', 'Account Type', 'Amount', 'Exchange Rate', 'Currency', 'Total', 'Status', 'Stage', 'UTM Source', 'UTM Medium', 'UTM Campaign', 'Seller Tracking', 'Delivery Tracking', 'Confirmed At', 'Created At'];
  const TEMPLATE_EXPORT_LABELS: Record<string, string> = { CONFIRM: 'คำสั่งซื้อสินค้า', IMPORT_INVOICE: 'ใบแจ้งหนี้นำเข้า', RECEIPT: 'ใบเสร็จรับเงิน' };
  const STATUS_EXPORT_LABELS: Record<string, string> = { PENDING: 'รอยืนยัน', CONFIRMED: 'ยืนยันแล้ว', UNCONFIRMED: 'ยกเลิก' };

  function buildExportParams(filters?: ExportFilters) {
    const f = filters || {};
    const params = new URLSearchParams();
    if (f.customer_code) params.set('customer_code', f.customer_code);
    if (f.date_from && f.date_to && f.date_from === f.date_to) {
      params.set('date', f.date_from);
    } else {
      if (f.date_from) params.set('date_from', f.date_from);
      if (f.date_to) params.set('date_to', f.date_to);
    }
    if (f.status) params.set('status', f.status);
    if (f.template_type) params.set('template_type', f.template_type);
    if (f.stage) params.set('stage', f.stage);
    if (f.account_type) params.set('account_type', f.account_type);
    if (f.utm_source) params.set('utm_source', f.utm_source);
    if (f.utm_medium) params.set('utm_medium', f.utm_medium);
    return params;
  }

  function toRow(o: Record<string, unknown>) {
    return [
      o.order_code, o.customer_code, o.display_name,
      TEMPLATE_EXPORT_LABELS[o.template_type as string] ?? o.template_type,
      o.account_type ?? '-',
      o.amount != null ? Number(o.amount) : '',
      o.exchange_rate != null ? Number(o.exchange_rate) : '',
      o.exchange_rate_currency ?? '',
      o.total_amount != null ? Number(o.total_amount) : '',
      STATUS_EXPORT_LABELS[o.status as string] ?? o.status,
      o.stage,
      o.utm_source ?? '',
      o.utm_medium ?? '',
      o.utm_campaign ?? '',
      o.seller_tracking_no ?? '',
      o.delivery_tracking_no ?? '',
      o.confirmed_at ? new Date(o.confirmed_at as string).toLocaleString('th-TH') : '',
      new Date(o.created_at as string).toLocaleString('th-TH'),
    ];
  }

  async function fetchExportData(filters?: ExportFilters) {
    const res = await fetch(`/api/orders/export?${buildExportParams(filters)}`, { credentials: 'include' });
    if (!res.ok) throw new Error('Export failed');
    const data = await res.json();
    return (data.orders || []) as Record<string, unknown>[];
  }

  async function handleExportCSV(filters: ExportFilters) {
    try {
      const rows = await fetchExportData(filters);
      const lines = [EXPORT_HEADERS, ...rows.map(toRow)];
      const csv = lines.map((r) => r.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n');
      const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      const stamp = `${filters.date_from || 'all'}_${filters.date_to || 'all'}`;
      a.href = url; a.download = `orders_${stamp}.csv`; a.click();
      URL.revokeObjectURL(url);
    } catch {
      Swal.fire({ toast: true, position: 'top-end', icon: 'error', title: 'Export failed', timer: 2500, showConfirmButton: false });
    }
  }

  async function handleExportXLSX(filters: ExportFilters) {
    try {
      const rows = await fetchExportData(filters);
      const ws = XLSX.utils.aoa_to_sheet([EXPORT_HEADERS, ...rows.map(toRow)]);
      const colWidths = EXPORT_HEADERS.map((h, i) => {
        const max = Math.max(h.length, ...rows.map((r) => String(toRow(r)[i] ?? '').length));
        return { wch: Math.min(max + 2, 40) };
      });
      ws['!cols'] = colWidths;
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Orders');
      const stamp = `${filters.date_from || 'all'}_${filters.date_to || 'all'}`;
      XLSX.writeFile(wb, `orders_${stamp}.xlsx`);
    } catch {
      Swal.fire({ toast: true, position: 'top-end', icon: 'error', title: 'Export failed', timer: 2500, showConfirmButton: false });
    }
  }

  async function handleExportModal() {
    const result = await Swal.fire({
      title: 'Export Orders',
      width: 760,
      html: `
        <div style="display:grid;gap:10px;text-align:left">
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <input id="exp-customer-code" class="input" placeholder="Customer code" />
            <input id="exp-date-from" class="input" type="date" />
            <input id="exp-date-to" class="input" type="date" />
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <select id="exp-status" class="select">
              <option value="">All status</option>
              <option value="PENDING">Pending</option>
              <option value="CONFIRMED">Confirmed</option>
              <option value="UNCONFIRMED">Cancelled</option>
            </select>
            <select id="exp-template" class="select">
              <option value="">All template</option>
              <option value="CONFIRM">Purchase Order</option>
              <option value="IMPORT_INVOICE">Import Invoice</option>
              <option value="RECEIPT">Custom Message</option>
            </select>
            <input id="exp-stage" class="input" placeholder="Stage contains..." />
          </div>
          <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px">
            <input id="exp-account-type" class="input" placeholder="Account type" />
            <input id="exp-utm-source" class="input" placeholder="UTM Source" />
            <input id="exp-utm-medium" class="input" placeholder="UTM Medium" />
          </div>
          <select id="exp-format" class="select">
            <option value="xlsx">XLSX</option>
            <option value="csv">CSV</option>
          </select>
        </div>
      `,
      showCancelButton: true,
      confirmButtonText: 'Export',
      cancelButtonText: 'Cancel',
      didOpen: () => {
        const customerCodeEl = document.getElementById('exp-customer-code') as HTMLInputElement | null;
        const dateFromEl = document.getElementById('exp-date-from') as HTMLInputElement | null;
        const dateToEl = document.getElementById('exp-date-to') as HTMLInputElement | null;
        const statusEl = document.getElementById('exp-status') as HTMLSelectElement | null;
        const templateEl = document.getElementById('exp-template') as HTMLSelectElement | null;
        if (customerCodeEl) customerCodeEl.value = customerCode;
        if (dateFromEl) dateFromEl.value = date;
        if (dateToEl) dateToEl.value = date;
        if (statusEl) statusEl.value = status;
        if (templateEl) templateEl.value = '';
      },
      preConfirm: () => {
        const getVal = (id: string) => ((document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null)?.value || '').trim();
        const filters: ExportFilters = {
          customer_code: getVal('exp-customer-code') || undefined,
          date_from: getVal('exp-date-from') || undefined,
          date_to: getVal('exp-date-to') || undefined,
          status: getVal('exp-status') || undefined,
          template_type: getVal('exp-template') || undefined,
          stage: getVal('exp-stage') || undefined,
          account_type: getVal('exp-account-type') || undefined,
          utm_source: getVal('exp-utm-source') || undefined,
          utm_medium: getVal('exp-utm-medium') || undefined,
        };
        return { filters, format: getVal('exp-format') || 'xlsx' };
      },
    });

    if (!result.isConfirmed || !result.value) return;
    if (result.value.format === 'csv') {
      await handleExportCSV(result.value.filters);
    } else {
      await handleExportXLSX(result.value.filters);
    }
  }

  return (
    <section>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <h1 className="page-title" style={{ margin: 0 }}>คำสั่งซื้อ ({total.toLocaleString()})</h1>
          <p className="page-subtitle">ติดตาม purchase order หลักและสถานะ workflow</p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button type="button" className="btn btn-soft" onClick={handleExportModal} style={{ fontSize: 13 }}>Export</button>
        </div>
      </div>

      <div className="filter-row">
        <input
          type="text"
          value={customerCode}
          onChange={(e) => setCustomerCode(e.target.value)}
          className="input"
          placeholder="Customer code"
        />
        <input type="date" value={date} onChange={(e) => setDate(e.target.value)} className="input" />
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="select">
          <option value="">All status</option>
          <option value="PENDING">Pending</option>
          <option value="CONFIRMED">Confirmed</option>
          <option value="UNCONFIRMED">Cancelled</option>
        </select>
        <button onClick={() => { setPage(1); load(1); }} className="btn btn-primary" type="button">Search</button>
        <button onClick={() => { setCustomerCode(''); setDate(''); setStatus(''); setPage(1); load(1); }} className="btn btn-soft" type="button">Reset</button>
      </div>

      {loading ? (
        <p className="page-subtitle">Loading...</p>
      ) : (
        <div className="table-shell table-wrap">
          <table className="table">
            <thead>
              <tr>
                {['Order', 'Customer', 'Name', 'Type', 'Amount', 'Total', 'Status', 'Stage', 'Actions', 'Created'].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {orders.map((o) => (
                <tr key={o.id} onClick={() => router.push(`/admin/orders/${o.id}`)} style={{ cursor: 'pointer' }}>
                  <td><code>{o.order_code}</code></td>
                  <td>{o.customer_code}</td>
                  <td>{o.display_name}</td>
                  <td>{TEMPLATE_LABELS[o.template_type] ?? o.template_type}</td>
                  <td>{o.amount ? Number(o.amount).toLocaleString() : '-'}</td>
                  <td>{o.total_amount ? Number(o.total_amount).toLocaleString() : '-'}</td>
                  <td>
                    <span className={`badge ${STATUS_BADGES[o.status]}`}>{STATUS_LABELS[o.status]}</span>
                  </td>
                  <td>{o.stage}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    {o.status === 'PENDING' ? (
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          type="button"
                          className="btn btn-primary"
                          style={{ height: 30, padding: '0 10px' }}
                          disabled={actingId === o.id}
                          onClick={() => updateOrder(o.id, 'confirm')}
                        >
                          ยืนยัน
                        </button>
                        <button
                          type="button"
                          className="btn btn-soft"
                          style={{ height: 30, padding: '0 10px' }}
                          disabled={actingId === o.id}
                          onClick={() => updateOrder(o.id, 'cancel')}
                        >
                          ยกเลิก
                        </button>
                      </div>
                    ) : '-'}
                  </td>
                  <td>{new Date(o.created_at).toLocaleDateString('th-TH')}</td>
                </tr>
              ))}
              {orders.length === 0 && (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', color: '#8a94a4' }}>No data</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="pagination">
          <button onClick={() => { setPage(page - 1); load(page - 1); }} disabled={page <= 1} className="btn btn-soft" type="button">Prev</button>
          <span className="page-subtitle" style={{ margin: 0 }}>Page {page} / {totalPages}</span>
          <button onClick={() => { setPage(page + 1); load(page + 1); }} disabled={page >= totalPages} className="btn btn-soft" type="button">Next</button>
        </div>
      )}
    </section>
  );
}
