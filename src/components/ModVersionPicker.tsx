import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Loader2, Package, Check, Download, X, Star } from 'lucide-react';
import type { T } from '../i18n';

interface ModVersion {
  id: string;
  versionNumber: string;
  name: string;
  channel: string;
  datePublished: string;
  filename: string;
  size: number;
  latest: boolean;
  installed: boolean;
}

type Props = {
  t: T;
  gameDir: string;
  gameVersion: string;
  loader: string;
  projectId: string;
  title: string;
  iconUrl?: string | null;
  /** The mod is installed already: the chosen version replaces it. */
  replacing: boolean;
  asModerator?: boolean;
  onClose: () => void;
  onDone: () => void;
};

function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} МБ`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} КБ`;
  return bytes > 0 ? `${bytes} Б` : '';
}

function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString();
}

/**
 * "Which version?": the versions that fit the pack (Minecraft + loader), newest first and marked.
 * For a mod that is already installed the chosen version replaces it (older or newer).
 */
export default function ModVersionPicker({ t, gameDir, gameVersion, loader, projectId, title, iconUrl, replacing, asModerator, onClose, onDone }: Props) {
  const [versions, setVersions] = useState<ModVersion[] | null>(null);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    invoke<ModVersion[]>('modrinth_mod_versions', { projectId, gameVersion, loader })
      .then(list => { if (!cancelled) setVersions(list); })
      .catch(e => { if (!cancelled) { setVersions([]); setError(String(e)); } });
    return () => { cancelled = true; };
  }, [projectId, gameVersion, loader]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape' && !busyId) onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [busyId, onClose]);

  const choose = async (version: ModVersion) => {
    setBusyId(version.id);
    setError('');
    try {
      await invoke<string>('modrinth_install_mod', {
        gameDir, projectId, gameVersion, loader,
        versionId: version.id,
        replace: replacing,
        asModerator: !!asModerator,
      });
      onDone();
    } catch (e) {
      setError(String(e));
      setBusyId(null);
    }
  };

  const channelLabel = (channel: string) => (channel === 'beta' ? t('mvBeta') : channel === 'alpha' ? t('mvAlpha') : t('mvRelease'));

  return (
    <div className="mv-overlay" onMouseDown={event => { if (event.target === event.currentTarget && !busyId) onClose(); }}>
      <div className="mv-dialog" role="dialog" aria-modal="true" aria-label={title}>
        <header className="mv-head">
          {iconUrl ? <img className="mr-icon" src={iconUrl} alt="" /> : <div className="mr-icon placeholder"><Package size={20} /></div>}
          <div className="mv-head-text">
            <h3>{replacing ? t('mvChangeTitle') : t('mvTitle')}</h3>
            <span>{title} · Minecraft {gameVersion}</span>
          </div>
          <button className="mv-close" onClick={onClose} disabled={!!busyId} aria-label={t('mvCancel')}><X size={16} /></button>
        </header>

        {error && <p className="mv-error">{error}</p>}

        {versions === null && (
          <div className="mv-state"><Loader2 size={22} className="spin" /><span>{t('mvLoading')}</span></div>
        )}
        {versions !== null && versions.length === 0 && !error && <div className="mv-state"><span>{t('mvNone')}</span></div>}

        {versions !== null && versions.length > 0 && (
          <ul className="mv-list">
            {versions.map(version => (
              <li key={version.id} className={`mv-item ${version.installed ? 'current' : ''}`}>
                <div className="mv-item-main">
                  <div className="mv-item-title">
                    <strong>{version.versionNumber}</strong>
                    {version.latest && <span className="mv-chip latest"><Star size={10} /> {t('mvLatest')}</span>}
                    {version.installed && <span className="mv-chip current"><Check size={10} /> {t('mvInstalledNow')}</span>}
                    {version.channel !== 'release' && <span className={`mv-chip ${version.channel}`}>{channelLabel(version.channel)}</span>}
                  </div>
                  <span className="mv-item-sub">{[formatDate(version.datePublished), formatSize(version.size), version.filename].filter(Boolean).join(' · ')}</span>
                </div>
                <button
                  className={`mr-btn ${version.latest && !version.installed ? 'primary' : ''}`}
                  onClick={() => choose(version)}
                  disabled={!!busyId || version.installed}
                >
                  {busyId === version.id ? <Loader2 size={14} className="spin" /> : version.installed ? <Check size={14} /> : <Download size={14} />}
                  {version.installed ? t('mvInstalledNow') : busyId === version.id ? t('mrInstalling') : replacing ? t('mvSwitch') : t('mrInstall')}
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="mv-foot">{replacing ? t('mvReplaceNote') : t('mvFitNote')}</p>
      </div>
    </div>
  );
}
