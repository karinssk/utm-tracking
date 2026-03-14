'use client';

import { useEffect, useState } from 'react';
import Swal from 'sweetalert2';

interface AccountType {
  id: number;
  code: string;
  label: string;
  account_name: string | null;
  account_number: string | null;
  account_note: string | null;
  is_active: boolean;
  sort_order: number;
  updated_at: string;
}

export default function AccountTypesPage() {
  const [rows, setRows] = useState<AccountType[]>([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState<number | 'new' | null>(null);
  const [draggingId, setDraggingId] = useState<number | null>(null);
  const [dragOverId, setDragOverId] = useState<number | null>(null);
  const [reordering, setReordering] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const res = await fetch('/api/account-types', { credentials: 'include' });
      const data = await res.json();
      setRows(data.accountTypes || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function patch(id: number, patchValue: Partial<AccountType>) {
    setRows((prev) => prev.map((r) => (r.id === id ? { ...r, ...patchValue } : r)));
  }

  function toast(icon: 'success' | 'error', title: string) {
    return Swal.fire({
      toast: true,
      position: 'top-end',
      icon,
      title,
      showConfirmButton: false,
      timer: 2200,
      timerProgressBar: true,
    });
  }

  async function save(row: AccountType) {
    setSavingId(row.id);
    try {
      const res = await fetch(`/api/account-types/${row.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          label: row.label,
          account_name: row.account_name || null,
          account_number: row.account_number || null,
          account_note: row.account_note || null,
          is_active: row.is_active,
          sort_order: row.sort_order,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        await Swal.fire({ icon: 'error', title: 'Save failed', text: data.error || 'Save failed' });
        return;
      }
      patch(row.id, data.accountType);
      await toast('success', `Saved ${data.accountType?.code || row.code}`);
    } finally {
      setSavingId(null);
    }
  }

  async function createRow() {
    const result = await Swal.fire({
      title: 'เพิ่ม Account Type',
      width: 760,
      background: 'linear-gradient(180deg, #ffffff 0%, #fff9ef 100%)',
      color: '#1f2a44',
      showClass: { popup: 'swal2-show' },
      html: `
        <div style="text-align:left;border:1px solid #f2ddbd;border-radius:14px;background:#fff;padding:14px">
          <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 12px">
            <label style="display:block;font-size:12px;font-weight:700;color:#5f6780">
              CODE <span style="color:#e51f2e">*</span>
              <input id="swal-account-code" class="input" placeholder="เช่น KBANK" style="width:100%;margin-top:6px" />
            </label>
            <label style="display:block;font-size:12px;font-weight:700;color:#5f6780">
              Label <span style="color:#e51f2e">*</span>
              <input id="swal-account-label" class="input" placeholder="เช่น KBank Main" style="width:100%;margin-top:6px" />
            </label>
            <label style="display:block;font-size:12px;font-weight:700;color:#5f6780">
              Account Name
              <input id="swal-account-name" class="input" placeholder="Jawanda Cargo Co.,Ltd." style="width:100%;margin-top:6px" />
            </label>
            <label style="display:block;font-size:12px;font-weight:700;color:#5f6780">
              Account Number
              <input id="swal-account-number" class="input" placeholder="123-456-7890" style="width:100%;margin-top:6px" />
            </label>
          </div>
          <div style="display:grid;grid-template-columns:1fr;gap:10px 12px;margin-top:10px">
            <label style="display:block;font-size:12px;font-weight:700;color:#5f6780">
              Account Note
              <input id="swal-account-note" class="input" placeholder="ข้อความท้าย footer (ถ้ามี)" style="width:100%;margin-top:6px" />
            </label>
          </div>
        </div>
      `,
      showCancelButton: true,
      confirmButtonText: 'บันทึก',
      cancelButtonText: 'ยกเลิก',
      confirmButtonColor: '#ff8a00',
      cancelButtonColor: '#8a94a4',
      reverseButtons: true,
      focusConfirm: false,
      preConfirm: () => {
        const codeEl = document.getElementById('swal-account-code') as HTMLInputElement | null;
        const labelEl = document.getElementById('swal-account-label') as HTMLInputElement | null;
        const nameEl = document.getElementById('swal-account-name') as HTMLInputElement | null;
        const numberEl = document.getElementById('swal-account-number') as HTMLInputElement | null;
        const noteEl = document.getElementById('swal-account-note') as HTMLInputElement | null;

        const code = (codeEl?.value || '').trim().toUpperCase();
        const label = (labelEl?.value || '').trim();
        if (!code || !label) {
          Swal.showValidationMessage('CODE and Label are required');
          return false;
        }

        return {
          code,
          label,
          account_name: (nameEl?.value || '').trim() || null,
          account_number: (numberEl?.value || '').trim() || null,
          account_note: (noteEl?.value || '').trim() || null,
        };
      },
    });

    if (!result.isConfirmed || !result.value) return;

    setSavingId('new');
    try {
      const res = await fetch('/api/account-types', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          ...result.value,
          sort_order: rows.length,
          is_active: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        await Swal.fire({ icon: 'error', title: 'Create failed', text: data.error || 'Create failed' });
        return;
      }
      setRows((prev) => [...prev, data.accountType]);
      await toast('success', `Added ${data.accountType?.code || result.value.code}`);
    } finally {
      setSavingId(null);
    }
  }

  async function removeRow(id: number) {
    if (!confirm('Delete this account type?')) return;
    const res = await fetch(`/api/account-types/${id}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    if (!res.ok) return;
    setRows((prev) => prev.filter((r) => r.id !== id));
  }

  function reorderRows(sourceId: number, targetId: number) {
    const sourceIndex = rows.findIndex((r) => r.id === sourceId);
    const targetIndex = rows.findIndex((r) => r.id === targetId);
    if (sourceIndex < 0 || targetIndex < 0 || sourceIndex === targetIndex) return rows;

    const next = [...rows];
    const [moved] = next.splice(sourceIndex, 1);
    next.splice(targetIndex, 0, moved);
    return next.map((r, idx) => ({ ...r, sort_order: idx }));
  }

  async function persistSortOrder(nextRows: AccountType[]) {
    setReordering(true);
    try {
      const results = await Promise.all(
        nextRows.map(async (row, index) => {
          const res = await fetch(`/api/account-types/${row.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ sort_order: index }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data.error || `Failed to reorder ${row.code}`);
          return data.accountType as AccountType;
        }),
      );
      setRows(results.sort((a, b) => a.sort_order - b.sort_order || a.id - b.id));
      await toast('success', 'Reordered account types');
    } catch (err) {
      await Swal.fire({ icon: 'error', title: 'Reorder failed', text: (err as Error).message || 'Unable to save order' });
      load();
    } finally {
      setReordering(false);
      setDraggingId(null);
      setDragOverId(null);
    }
  }

  async function handleDrop(targetId: number) {
    if (!draggingId || draggingId === targetId) {
      setDragOverId(null);
      return;
    }
    const next = reorderRows(draggingId, targetId);
    setRows(next);
    await persistSortOrder(next);
  }

  return (
    <section>
      <h1 className="page-title">Account Type Config</h1>
      <p className="page-subtitle">ตั้งค่า Account Type แล้วเลือกใช้งานผ่าน dropdown ในหน้า Send Message</p>

      <div className="table-shell" style={{ padding: 14, marginBottom: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-primary" onClick={createRow} disabled={savingId === 'new' || reordering}>
            {savingId === 'new' ? 'Adding...' : 'Add Account Type'}
          </button>
        </div>
        <p style={{ marginTop: 8, fontSize: 12, color: '#6b7280' }}>ลากแถวด้วยปุ่ม <b>⋮⋮</b> เพื่อจัดลำดับ</p>
      </div>

      {loading ? (
        <p className="page-subtitle">Loading...</p>
      ) : (
        <div className="table-shell table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 48, textAlign: 'center' }}>Drag</th>
                <th>Code</th>
                <th>Label</th>
                <th>Account Name</th>
                <th>Account Number</th>
                <th style={{ minWidth: 220 }}>Account Note (footer)</th>
                <th>Order</th>
                <th>Active</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={r.id}
                  draggable={!reordering}
                  onDragStart={() => setDraggingId(r.id)}
                  onDragEnd={() => { setDraggingId(null); setDragOverId(null); }}
                  onDragOver={(e) => { e.preventDefault(); if (!reordering) setDragOverId(r.id); }}
                  onDrop={(e) => { e.preventDefault(); if (!reordering) handleDrop(r.id); }}
                  style={{
                    background: dragOverId === r.id ? '#eef5ff' : 'transparent',
                    opacity: draggingId === r.id ? 0.55 : 1,
                  }}
                >
                  <td style={{ textAlign: 'center', color: '#8a94a4', fontSize: 16, cursor: reordering ? 'not-allowed' : 'grab', userSelect: 'none' }}>⋮⋮</td>
                  <td><code>{r.code}</code></td>
                  <td>
                    <input className="input" style={{ width: '100%' }} value={r.label} onChange={(e) => patch(r.id, { label: e.target.value })} />
                  </td>
                  <td>
                    <input className="input" style={{ width: '100%' }} value={r.account_name || ''} onChange={(e) => patch(r.id, { account_name: e.target.value })} />
                  </td>
                  <td>
                    <input className="input" style={{ width: '100%' }} value={r.account_number || ''} onChange={(e) => patch(r.id, { account_number: e.target.value })} />
                  </td>
                  <td>
                    <input
                      className="input"
                      style={{ width: '100%' }}
                      value={r.account_note || ''}
                      onChange={(e) => patch(r.id, { account_note: e.target.value })}
                      placeholder="หมายเหตุ footer..."
                    />
                  </td>
                  <td>
                    <span style={{ fontSize: 12, color: '#6b7280' }}>{r.sort_order + 1}</span>
                  </td>
                  <td>
                    <input type="checkbox" checked={r.is_active} onChange={(e) => patch(r.id, { is_active: e.target.checked })} />
                  </td>
                  <td>{new Date(r.updated_at).toLocaleString('th-TH')}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button type="button" className="btn btn-primary" style={{ height: 30, padding: '0 10px' }} disabled={savingId === r.id || reordering} onClick={() => save(r)}>
                        {savingId === r.id ? '...' : 'Save'}
                      </button>
                      <button type="button" className="btn btn-soft" style={{ height: 30, padding: '0 10px' }} disabled={reordering} onClick={() => removeRow(r.id)}>
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={10} style={{ textAlign: 'center', color: '#8a94a4' }}>No data</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
