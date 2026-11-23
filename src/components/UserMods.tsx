import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Eye, EyeOff, RefreshCw, Trash2, FileText, Loader2, Package, Repeat, FolderInput } from 'lucide-react';
import type { T } from '../i18n';
import ModVersionPicker from './ModVersionPicker';

interface UserMod {
  id: string;
  filename: string;
  hash: string;
  enabled: boolean;
  display_name?: string;
  version?: string;
  project_id?: string;
  title?: string;
  description?: string;
  icon_url?: string;
  manual?: boolean;
}

interface UserModsManifest {
  mods: Record<string, UserMod>;
}

type Props = {
  t: T;
  gameDir: string;
  gameVersion: string;
  loader: string;
};

/**
 * "My mods": only the mods the player downloaded from the "Extra mods" section.
 * Modpack mods are not listed. These mods are set aside while the modpack is updated and put back afterwards.
 */
export default function UserMods({ t, gameDir, gameVersion, loader }: Props) {
  const [changing, setChanging] = useState<UserMod | null>(null);
  const [mods, setMods] = useState<UserMod[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');

  const sorted = (manifest: UserModsManifest) => Object.values(manifest.mods).sort((a, b) => a.filename.localeCompare(b.filename));

  const loadMods = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setMods(sorted(await invoke<UserModsManifest>('get_user_mods', { gameDir })));
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, [gameDir]);

  const scanMods = useCallback(async () => {
    setScanning(true);
    setError('');
    try {
      setMods(sorted(await invoke<UserModsManifest>('scan_user_mods_cmd', { gameDir })));
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }, [gameDir]);

  const toggleEnabled = async (modId: string, enabled: boolean) => {
    setError('');
    try {
      setMods(sorted(await invoke<UserModsManifest>('toggle_user_mod', { gameDir, modId, enabled })));
    } catch (e) {
      setError(String(e));
    }
  };

  const removeMod = async (modId: string) => {
    setError('');
    try {
      setMods(sorted(await invoke<UserModsManifest>('remove_user_mod_tracking', { gameDir, modId })));
    } catch (e) {
      setError(String(e));
    }
  };

  // Opening the section also checks the mods folder: a mod put there by hand is recognised on Modrinth.
  useEffect(() => {
    loadMods().then(() => scanMods());
  }, [loadMods, scanMods]);

  const displayName = (mod: UserMod) => mod.title || mod.display_name || mod.filename.replace('.jar', '');

  return (
    <div className="user-mods">
      <div className="user-mods-header">
        <h2>{t('userModsTitle')}</h2>
        <p className="user-mods-desc">{t('userModsDesc')}</p>
      </div>

      {error && <div className="user-mods-error">{error}</div>}

      <div className="user-mods-toolbar">
        <button
          className="user-mods-scan-btn"
          onClick={scanMods}
          disabled={scanning || loading}
        >
          {scanning ? (
            <>
              <Loader2 size={16} className="spin" />
              {t('userModsScanning')}
            </>
          ) : (
            <>
              <RefreshCw size={16} />
              {t('userModsScan')}
            </>
          )}
        </button>
      </div>

      {loading && mods.length === 0 && (
        <div className="user-mods-loading">
          <Loader2 size={24} className="spin" />
          <span>{t('loading')}</span>
        </div>
      )}

      {!loading && mods.length === 0 && (
        <div className="user-mods-empty">
          <FileText size={48} />
          <p>{t('userModsEmpty')}</p>
        </div>
      )}

      {!loading && mods.length > 0 && (
        <div className="user-mods-list">
          {mods.map(mod => (
            <article key={mod.id} className={`um-card ${!mod.enabled ? 'off' : ''}`}>
              <div className="um-top">
                {mod.icon_url
                  ? <img className="mr-icon" src={mod.icon_url} alt="" loading="lazy" />
                  : <div className="mr-icon placeholder"><Package size={20} /></div>}
                <div className="um-head">
                  <h3 title={mod.filename}>{displayName(mod)}</h3>
                  <div className="um-sub">
                    {mod.version && <span className="um-ver">{mod.version}</span>}
                    <span className={`mr-badge ${mod.enabled ? 'installed' : 'blocked'}`}>{mod.enabled ? t('userModsEnabled') : t('userModsDisabled')}</span>
                    {mod.manual && <span className="mr-tag"><FolderInput size={10} /> {t('userModsManual')}</span>}
                  </div>
                </div>
              </div>
              {mod.description && <p className="um-desc">{mod.description}</p>}
              <div className="um-actions">
                {mod.project_id && (
                  <button className="mr-btn" onClick={() => setChanging(mod)}>
                    <Repeat size={14} /> {t('userModsChange')}
                  </button>
                )}
                <button
                  className={`mod-action-btn ${mod.enabled ? 'active' : ''}`}
                  onClick={() => toggleEnabled(mod.id, !mod.enabled)}
                  title={mod.enabled ? t('userModsDisable') : t('userModsEnable')}
                >
                  {mod.enabled ? <Eye size={16} /> : <EyeOff size={16} />}
                </button>
                <button className="mod-action-btn danger" onClick={() => removeMod(mod.id)} title={t('userModsRemove')}>
                  <Trash2 size={16} />
                </button>
              </div>
            </article>
          ))}
        </div>
      )}

      {changing?.project_id && (
        <ModVersionPicker
          t={t}
          gameDir={gameDir}
          gameVersion={gameVersion}
          loader={loader}
          projectId={changing.project_id}
          title={displayName(changing)}
          iconUrl={changing.icon_url}
          replacing
          onClose={() => setChanging(null)}
          onDone={() => { setChanging(null); scanMods(); }}
        />
      )}
    </div>
  );
}
