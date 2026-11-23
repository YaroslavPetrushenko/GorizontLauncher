import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Check, X, Eye, EyeOff, RefreshCw, Trash2, FileText, Loader2 } from 'lucide-react';
import type { T } from '../i18n';

interface UserMod {
  id: string;
  filename: string;
  hash: string;
  enabled: boolean;
  display_name?: string;
  version?: string;
}

interface UserModsManifest {
  mods: Record<string, UserMod>;
}

type Props = {
  t: T;
  gameDir: string;
};

/**
 * "My mods": only the mods the player downloaded from the "Extra mods" section.
 * Modpack mods are not listed. These mods are set aside while the modpack is updated and put back afterwards.
 */
export default function UserMods({ t, gameDir }: Props) {
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

  useEffect(() => {
    loadMods();
  }, [loadMods]);

  const displayName = (mod: UserMod) => mod.display_name || mod.filename.replace('.jar', '');

  const shortHash = (hash: string) => hash.slice(0, 16) + '...';

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
            <div key={mod.id} className={`user-mod-item ${!mod.enabled ? 'disabled' : ''}`}>
              <div className="mod-info">
                <div className="mod-main">
                  <span className="mod-name">{displayName(mod)}</span>
                  <span className="mod-filename">{mod.filename}</span>
                </div>
                <div className="mod-meta">
                  <span className="mod-hash"><FileText size={12} /> {t('userModsHash')} {shortHash(mod.hash)}</span>
                  {mod.version && <span className="mod-version"><FileText size={12} /> {t('userModsVersion')} {mod.version}</span>}
                </div>
              </div>

              <div className="mod-status">
                <span className={`mod-badge ${mod.enabled ? 'enabled' : 'disabled'}`}>
                  {mod.enabled ? <Check size={12} /> : <X size={12} />}
                  {mod.enabled ? t('userModsEnabled') : t('userModsDisabled')}
                </span>
              </div>

              <div className="mod-actions">
                <button
                  className={`mod-action-btn ${mod.enabled ? 'active' : ''}`}
                  onClick={() => toggleEnabled(mod.id, !mod.enabled)}
                  title={mod.enabled ? t('userModsDisable') : t('userModsEnable')}
                >
                  {mod.enabled ? <Eye size={16} /> : <EyeOff size={16} />}
                </button>
                <button
                  className="mod-action-btn danger"
                  onClick={() => removeMod(mod.id)}
                  title={t('userModsRemove')}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
