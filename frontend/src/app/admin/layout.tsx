'use client';

import Image from 'next/image';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';

const NAV_SECTIONS = [
  {
    title: 'Workspace',
    items: [
      { href: '/admin', label: 'Dashboard', icon: '◫' },
      { href: '/admin/customers', label: 'Customers', icon: '◎' },
      { href: '/admin/orders', label: 'Orders', icon: '▦' },
    ],
  },
  {
    title: 'Messaging',
    items: [
      { href: '/admin/messages/send', label: 'Send Message', icon: '✉' },
      { href: '/admin/messages/history', label: 'Message Logs', icon: '◷' },
      { href: '/admin/messages/templates', label: 'Template Config', icon: '⚙' },
      { href: '/admin/messages/account-types', label: 'Account Types', icon: '▤' },
    ],
  },
  {
    title: 'Landing Pages Management',
    items: [
      { href: '/admin/landing', label: 'Landing Page', icon: '▣' },
      { href: '/admin/site',    label: 'Site Settings',  icon: '⚙' },
    ],
  },
];

type NavItem = { href: string; label: string; icon: string };
type SearchNavItem = NavItem & { section: string };

function isItemActive(pathname: string, href: string) {
  if (href === '/admin') return pathname === '/admin';
  return pathname === href || pathname.startsWith(`${href}/`) || pathname.startsWith(href);
}

function findActiveItem(pathname: string, items: SearchNavItem[]) {
  let best: SearchNavItem | null = null;
  for (const item of items) {
    if (isItemActive(pathname, item.href)) {
      if (!best || item.href.length > best.href.length) best = item;
    }
  }
  return best;
}

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');

  const navItems = useMemo<SearchNavItem[]>(
    () =>
      NAV_SECTIONS.flatMap((section) =>
        section.items.map((item) => ({ ...item, section: section.title })),
      ),
    [],
  );

  const activeItem = useMemo(() => findActiveItem(pathname, navItems), [pathname, navItems]);

  const searchResults = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return [];
    return navItems.filter(
      (item) => item.label.toLowerCase().includes(q) || item.section.toLowerCase().includes(q),
    );
  }, [query, navItems]);

  useEffect(() => {
    function onHotkey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    }
    window.addEventListener('keydown', onHotkey);
    return () => window.removeEventListener('keydown', onHotkey);
  }, []);

  useEffect(() => {
    setQuery('');
  }, [pathname]);

  function handleGo(item: SearchNavItem) {
    setQuery('');
    router.push(item.href);
  }

  function handleSearchSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!query.trim()) return;
    const exact = navItems.find((item) => item.label.toLowerCase() === query.trim().toLowerCase());
    if (exact) {
      handleGo(exact);
      return;
    }
    if (searchResults[0]) handleGo(searchResults[0]);
  }

  async function handleLogout() {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    router.push('/login');
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <Image src="/logo.png" alt="Jawanda Cargo" width={44} height={44} className="brand-logo" />
          <span className="brand-name">Jawanda Cargo</span>
        </div>

        {NAV_SECTIONS.map((section) => (
          <div className="nav-section" key={section.title}>
            <p className="nav-label">{section.title}</p>
            <nav className="nav-list">
              {section.items.map((item) => {
                const active = pathname === item.href || (item.href !== '/admin' && pathname.startsWith(item.href));
                return (
                  <Link key={item.href} href={item.href} className={`nav-item${active ? ' active' : ''}`}>
                    <span className="nav-icon">{item.icon}</span>
                    <span>{item.label}</span>
                  </Link>
                );
              })}
            </nav>
          </div>
        ))}

        <div className="sidebar-footer">
          <button onClick={handleLogout} className="ghost-btn" type="button">Logout</button>
        </div>
      </aside>

      <div className="main-wrap">
        <header className="topbar">
          <h2 className="topbar-title">{activeItem?.label || 'Admin'}</h2>
          <form className="searchbox" onSubmit={handleSearchSubmit}>
            <input
              ref={searchInputRef}
              className="topbar-search-input"
              type="search"
              placeholder="Search pages..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <kbd>⌘K</kbd>
            {searchResults.length > 0 && (
              <div className="topbar-search-results" role="listbox">
                {searchResults.slice(0, 8).map((item) => (
                  <button
                    key={item.href}
                    type="button"
                    className="topbar-search-result"
                    onClick={() => handleGo(item)}
                  >
                    <span>{item.label}</span>
                    <small>{item.section}</small>
                  </button>
                ))}
              </div>
            )}
          </form>
          <div className="topbar-actions">
            <button type="button" className="top-icon-btn">◷</button>
            <button type="button" className="top-icon-btn">◌</button>
          </div>
        </header>

        <main className="page-content">{children}</main>
      </div>
    </div>
  );
}
