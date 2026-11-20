import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Download, Loader2, Package, Check, AlertCircle, RefreshCw } from 'lucide-react';
import type { T } from '../i18n';

/** Catalog entry as returned by the backend (serde camelCase). */
interface ExtraModState {
  id: string;
  name: string;
  version?: string | null;
  description?: string | null;
  filename: string;
  url: string;
  sha256?: string | null;
  size?: number | null;
  minecraftVersion?: string | null;
  loader?: string | null;
  installed: boolean;
  outdated: boolean;
  inModpack: boolean;
}

interface ExtraModsResponse {
  source: string;
  mods: ExtraModState[];
  error?: string | null;
}

type Props = { t: T; gameDir: string };

function formatSize(bytes?: number | null): string {
  if (!bytes || bytes <= 0) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function ExtraMods({ t, gameDir }: Props) {
  const [mods, setMods] = useState<ExtraModState[]>([]);
  const [source, setSource] = useState('');
  const [catalogError, setCatalogError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [modErrors, setModErrors] = useState<Record<string, string>>({});

  const loadCatalog = useCallback(async () => {
    setLoading(true);
    setCatalogError('');
    try {
      const response = await invoke<ExtraModsResponse>('get_extra_mods_catalog', { gameDir });
      setMods(response.mods ?? []);
      setSource(response.source ?? '');
      if (response.error) setCatalogError(response.error);
    } catch (e) {
      setMods([]);
      setSource('');
      setCatalogError(String(e));
    } finally {
      setLoading(false);
    }
  }, [gameDir]);

  useEffect(() => { loadCatalog(); }, [loadCatalog]);

  const download = async (mod: ExtraModState) => {
    setBusyId(mod.id);
    setModErrors(prev => ({ ...prev, [mod.id]: '' }));
    try {
      // ExtraModSpec is deserialized by serde without rename_all, so its keys are snake_case.
      await invoke<ExtraModState>('download_extra_mod', {
        gameDir,
        spec: {
          id: mod.id,
          name: mod.name,
          version: mod.version ?? null,
          description: mod.description ?? null,
          filename: mod.filename,
          url: mod.url,
          sha256: mod.sha256 ?? null,
          size: mod.size ?? null,
          minecraft_version: mod.minecraftVersion ?? null,
          loader: mod.loader ?? null,
        },
        overwrite: mod.outdated,
      });
      await loadCatalog();
    } catch (e) {
      setModErrors(prev => ({ ...prev, [mod.id]: String(e) }));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="extra-mods">
      <div className="extra-mods-header">
        <div>
          <h2>{t('extraModsTitle')}</h2>
          <p className="extra-mods-desc">{t('extraModsDesc')}</p>
        </div>
        <button className="user-mods-scan-btn" onClick={loadCatalog} disabled={loading}>
          {loading ? <Loader2 size={16} className="spin" /> : <RefreshCw size={16} />}
          {t('extraModsRefresh')}
        </button>
      </div>

      {catalogError && (
        <div className="extra-mods-warn">
          <AlertCircle size={14} />
          <span>{t('extraModsCatalogUnavailable')}: {catalogError}</span>
        </div>
      )}

      {loading && mods.length === 0 && (
        <div className="user-mods-loading">
          <Loader2 size={24} className="spin" />
          <span>{t('extraModsLoading')}</span>
        </div>
      )}

      {!loading && mods.length === 0 && (
        <div className="user-mods-empty">
          <Package size={48} />
          <p>{t('extraModsEmpty')}</p>
        </div>
      )}

      {mods.length > 0 && (
        <div className="extra-mods-list">
          {mods.map(mod => {
            const busy = busyId === mod.id;
            const size = formatSize(mod.size);
            return (
              <div key={mod.id} className={`extra-mod-card ${mod.installed ? 'installed' : ''}`}>
                <div className="extra-mod-icon"><Package size={18} /></div>

                <div className="extra-mod-body">
                  <div className="extra-mod-title">
                    <strong>{mod.name}</strong>
                    {mod.version && <span className="extra-mod-version">v{mod.version}</span>}
                    {mod.inModpack && <span className="extra-mod-badge pack">{t('extraModsInPack')}</span>}
                    {mod.installed && <span className="extra-mod-badge installed"><Check size={11} /> {t('extraModsInstalled')}</span>}
                  </div>

                  {mod.description && <p className="extra-mod-text">{mod.description}</p>}

                  <div className="extra-mod-meta">
                    <span className="extra-mod-file">{mod.filename}</span>
                    {size && <span>{size}</span>}
                    {mod.minecraftVersion && <span>MC {mod.minecraftVersion}</span>}
                    {mod.sha256 && <span className="extra-mod-hash" title={mod.sha256}>sha256: {mod.sha256.slice(0, 12)}…</span>}
                  </div>

                  {modErrors[mod.id] && (
                    <p className="extra-mod-text" style={{ color: '#fca5a5' }}>{modErrors[mod.id]}</p>
                  )}
                </div>

                <div className="extra-mod-action">
                  {mod.inModpack ? null : mod.installed ? null : (
                    <button className="extra-mod-btn" onClick={() => download(mod)} disabled={busy || busyId !== null}>
                      {busy ? <Loader2 size={15} className="spin" /> : <Download size={15} />}
                      {busy ? t('extraModsDownloading') : mod.outdated ? t('extraModsUpdate') : t('extraModsDownload')}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <p className="extra-mods-footer">{t('extraModsFooter')}</p>
      {source && <p className="extra-mods-source">{t('extraModsSource')}: {source}</p>}
    </div>
  );
}