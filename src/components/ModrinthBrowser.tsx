import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Search, Loader2, Download, Ban, Check, AlertCircle, RefreshCw,
  Unlock, ChevronDown, Package, ArrowDownToLine, ShieldAlert,
} from 'lucide-react';
import type { Key, T } from '../i18n';

/**
 * Backend contract (Tauri commands):
 *  - modrinth_search({ query, gameVersion, loader, categories, index, offset, limit })
 *      -> { hits: ModrinthHit[], totalHits, offset, limit }
 *  - modrinth_install_mod({ gameDir, projectId, gameVersion, loader }) -> string (installed filename)
 *  - get_extra_mods_state() -> { installed: string[], blocked: string[] }
 *  - set_mod_blocked({ projectId, blocked }) -> void
 * Project ids are Modrinth project ids; installed/blocked lists hold project ids.
 */
interface ModrinthHit {
  projectId: string;
  slug: string;
  title: string;
  description: string;
  author: string;
  iconUrl?: string | null;
  downloads: number;
  follows: number;
  categories: string[];
  clientSide?: string | null;
  serverSide?: string | null;
  dateModified?: string | null;
}

interface ModrinthSearchResponse {
  hits: ModrinthHit[];
  totalHits: number;
  offset: number;
  limit: number;
}

interface ExtraModsState {
  installed: string[];
  blocked: string[];
}

type SortIndex = 'relevance' | 'downloads' | 'newest';

type Props = { t: T; gameDir: string; gameVersion: string; loader: string };

const CATEGORIES: { id: string; key: Key }[] = [
  { id: 'optimization', key: 'catOptimization' },
  { id: 'utility', key: 'catUtility' },
  { id: 'decoration', key: 'catDecoration' },
  { id: 'adventure', key: 'catAdventure' },
  { id: 'magic', key: 'catMagic' },
  { id: 'technology', key: 'catTechnology' },
  { id: 'storage', key: 'catStorage' },
  { id: 'worldgen', key: 'catWorldgen' },
  { id: 'mobs', key: 'catMobs' },
  { id: 'library', key: 'catLibrary' },
];

const PAGE_SIZE = 20;
const TITLES_KEY = 'gorizont-modrinth-titles';

/** Remember project titles locally so the blocked list shows names instead of raw ids. */
function loadTitles(): Record<string, string> {
  try {
    const parsed = JSON.parse(localStorage.getItem(TITLES_KEY) || '{}');
    return parsed && typeof parsed === 'object' ? parsed as Record<string, string> : {};
  } catch { return {}; }
}

function rememberTitle(projectId: string, title: string) {
  try {
    const titles = loadTitles();
    if (titles[projectId] === title) return;
    titles[projectId] = title;
    localStorage.setItem(TITLES_KEY, JSON.stringify(titles));
  } catch { /* ignore quota errors */ }
}

function formatDownloads(count: number): string {
  if (count >= 1_000_000) return `${(count / 1_000_000).toFixed(1)}M`;
  if (count >= 1000) return `${(count / 1000).toFixed(1)}K`;
  return String(count);
}

export default function ModrinthBrowser({ t, gameDir, gameVersion, loader }: Props) {
  const [query, setQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [categories, setCategories] = useState<string[]>([]);
  const [sort, setSort] = useState<SortIndex>('relevance');

  const [hits, setHits] = useState<ModrinthHit[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');

  const [installed, setInstalled] = useState<Set<string>>(new Set());
  const [blocked, setBlocked] = useState<Set<string>>(new Set());
  const [busyId, setBusyId] = useState<string | null>(null);
  const [modError, setModError] = useState<Record<string, string>>({});
  const [showBlocked, setShowBlocked] = useState(false);
  const [titles, setTitles] = useState<Record<string, string>>(() => loadTitles());

  const loadState = useCallback(async () => {
    try {
      const state = await invoke<ExtraModsState>('get_extra_mods_state');
      setInstalled(new Set(state.installed ?? []));
      setBlocked(new Set(state.blocked ?? []));
    } catch {
      // Older build without the command: behave as if nothing is installed or blocked.
    }
  }, []);

  useEffect(() => { loadState(); }, [loadState]);

  const search = useCallback(async (offset: number, append: boolean) => {
    if (append) setLoadingMore(true); else setLoading(true);
    setError('');
    try {
      const response = await invoke<ModrinthSearchResponse>('modrinth_search', {
        query: submittedQuery,
        gameVersion,
        loader,
        categories,
        index: sort,
        offset,
        limit: PAGE_SIZE,
      });
      const fresh = (response.hits ?? []).filter(hit => !blocked.has(hit.projectId));
      setHits(prev => (append ? [...prev, ...fresh] : fresh));
      setTotal(response.totalHits ?? 0);
    } catch (e) {
      if (!append) setHits([]);
      setError(String(e));
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, [submittedQuery, gameVersion, loader, categories, sort, blocked]);

  // Initial load and re-search whenever filters change.
  useEffect(() => { search(0, false); }, [search]);

  const toggleCategory = (id: string) => {
    setCategories(prev => (prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]));
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setSubmittedQuery(query.trim());
  };

  const install = async (hit: ModrinthHit) => {
    setBusyId(hit.projectId);
    setModError(prev => ({ ...prev, [hit.projectId]: '' }));
    try {
      await invoke<string>('modrinth_install_mod', {
        gameDir,
        projectId: hit.projectId,
        gameVersion,
        loader,
      });
      setInstalled(prev => new Set(prev).add(hit.projectId));
    } catch (e) {
      setModError(prev => ({ ...prev, [hit.projectId]: String(e) }));
    } finally {
      setBusyId(null);
    }
  };

  const setBlockedState = async (projectId: string, next: boolean, title?: string) => {
    setBusyId(projectId);
    setModError(prev => ({ ...prev, [projectId]: '' }));
    try {
      await invoke('set_mod_blocked', { projectId, blocked: next });
      if (next && title) {
        rememberTitle(projectId, title);
        setTitles(prev => ({ ...prev, [projectId]: title }));
      }
      setBlocked(prev => {
        const copy = new Set(prev);
        if (next) copy.add(projectId); else copy.delete(projectId);
        return copy;
      });
      if (next) setHits(prev => prev.filter(hit => hit.projectId !== projectId));
    } catch (e) {
      setModError(prev => ({ ...prev, [projectId]: String(e) }));
    } finally {
      setBusyId(null);
    }
  };

  const blockedCount = blocked.size;
  const visibleBlocked = useMemo(() => Array.from(blocked), [blocked]);
  const canLoadMore = hits.length < total;

  return (
    <div className="mr-browser">
      <div className="mr-header">
        <div>
          <h2>{t('mrTitle')}</h2>
          <p className="mr-desc">{t('mrDesc')}</p>
        </div>
        <a
          className="mr-external"
          href="https://modrinth.com/discover/mods?v=1.21.1&g=categories:neoforge&e=client"
          onClick={event => { event.preventDefault(); invoke('open_external_url', { url: 'https://modrinth.com/discover/mods?v=1.21.1&g=categories:neoforge&e=client' }).catch(() => undefined); }}
        >
          {t('mrOpenModrinth')}
        </a>
      </div>

      <form className="mr-search" onSubmit={submit}>
        <div className="mr-search-field">
          <Search size={16} className="mr-search-icon" />
          <input
            className="mr-search-input"
            placeholder={t('mrSearchPlaceholder')}
            value={query}
            onChange={event => setQuery(event.target.value)}
          />
        </div>
        <button className="mr-search-btn" type="submit" disabled={loading}>
          {loading ? <Loader2 size={16} className="spin" /> : <Search size={16} />}
          {t('mrSearch')}
        </button>
        <label className="mr-sort">
          <span>{t('mrSort')}</span>
          <select value={sort} onChange={event => setSort(event.target.value as SortIndex)}>
            <option value="relevance">{t('mrSortRelevance')}</option>
            <option value="downloads">{t('mrSortDownloads')}</option>
            <option value="newest">{t('mrSortNewest')}</option>
          </select>
        </label>
      </form>

      <div className="mr-chips">
        {CATEGORIES.map(category => (
          <button
            key={category.id}
            type="button"
            className={`mr-chip ${categories.includes(category.id) ? 'active' : ''}`}
            onClick={() => toggleCategory(category.id)}
            aria-pressed={categories.includes(category.id)}
          >
            {t(category.key)}
          </button>
        ))}
        {categories.length > 0 && (
          <button type="button" className="mr-chip clear" onClick={() => setCategories([])}>{t('mrClearFilters')}</button>
        )}
      </div>

      {error && (
        <div className="mr-error">
          <AlertCircle size={15} />
          <span>{t('mrSearchFailed')}: {error}</span>
          <button type="button" className="mr-retry" onClick={() => search(0, false)}>
            <RefreshCw size={14} /> {t('mrRetry')}
          </button>
        </div>
      )}

      {loading && hits.length === 0 && (
        <div className="mr-loading">
          <Loader2 size={26} className="spin" />
          <span>{t('mrLoading')}</span>
        </div>
      )}

      {!loading && !error && hits.length === 0 && (
        <div className="mr-empty">
          <Package size={46} />
          <p>{t('mrEmpty')}</p>
          <small>{t('mrEmptyHint')}</small>
        </div>
      )}

      {hits.length > 0 && (
        <div className="mr-grid">
          {hits.map(hit => {
            const isBusy = busyId === hit.projectId;
            const isInstalled = installed.has(hit.projectId);
            return (
              <article key={hit.projectId} className={`mr-card ${isInstalled ? 'installed' : ''}`}>
                <div className="mr-card-top">
                  {hit.iconUrl
                    ? <img className="mr-icon" src={hit.iconUrl} alt="" loading="lazy" />
                    : <div className="mr-icon placeholder"><Package size={20} /></div>}
                  <div className="mr-card-head">
                    <h3 title={hit.title}>{hit.title}</h3>
                    <span className="mr-author">{hit.author}</span>
                  </div>
                </div>

                <p className="mr-card-desc">{hit.description}</p>

                <div className="mr-card-meta">
                  <span className="mr-downloads"><ArrowDownToLine size={12} /> {formatDownloads(hit.downloads)}</span>
                  {hit.categories.slice(0, 3).map(name => (
                    <span key={name} className="mr-tag">{name}</span>
                  ))}
                  {isInstalled && <span className="mr-badge installed"><Check size={11} /> {t('mrInstalled')}</span>}
                </div>

                {modError[hit.projectId] && (
                  <p className="mr-card-error">{modError[hit.projectId]}</p>
                )}

                <div className="mr-card-actions">
                  <button
                    className="mr-btn primary"
                    onClick={() => install(hit)}
                    disabled={isBusy || isInstalled}
                  >
                    {isBusy ? <Loader2 size={14} className="spin" /> : isInstalled ? <Check size={14} /> : <Download size={14} />}
                    {isBusy ? t('mrInstalling') : isInstalled ? t('mrInstalled') : t('mrInstall')}
                  </button>
                  <button
                    className="mr-btn danger"
                    onClick={() => setBlockedState(hit.projectId, true, hit.title)}
                    disabled={isBusy}
                    title={t('mrBlockHint')}
                  >
                    <Ban size={14} /> {t('mrBlock')}
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {canLoadMore && !loading && (
        <button className="mr-more" onClick={() => search(hits.length, true)} disabled={loadingMore}>
          {loadingMore ? <Loader2 size={15} className="spin" /> : <ChevronDown size={15} />}
          {t('mrLoadMore')} ({hits.length}/{total})
        </button>
      )}

      <div className="mr-blocked-section">
        <button className="mr-blocked-toggle" onClick={() => setShowBlocked(v => !v)} aria-expanded={showBlocked}>
          <ShieldAlert size={15} />
          {t('mrBlockedTitle')} ({blockedCount})
          <ChevronDown size={15} className={showBlocked ? 'rotated' : ''} />
        </button>

        {showBlocked && (
          blockedCount === 0 ? (
            <p className="mr-blocked-empty">{t('mrBlockedEmpty')}</p>
          ) : (
            <div className="mr-blocked-list">
              {visibleBlocked.map(projectId => (
                <div key={projectId} className="mr-blocked-item">
                  <span className="mr-blocked-id" title={projectId}>{titles[projectId] || projectId}</span>
                  <button
                    className="mr-btn"
                    onClick={() => setBlockedState(projectId, false)}
                    disabled={busyId === projectId}
                  >
                    {busyId === projectId ? <Loader2 size={14} className="spin" /> : <Unlock size={14} />}
                    {t('mrUnblock')}
                  </button>
                </div>
              ))}
            </div>
          )
        )}
      </div>

      <p className="mr-footer">{t('mrFooter')}</p>
    </div>
  );
}