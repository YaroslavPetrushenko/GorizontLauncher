import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Check, X, Eye, EyeOff, RefreshCw, Trash2, ShieldCheck, ShieldAlert, FileText, Loader2 } from 'lucide-react';
import type { T } from '../i18n';
import { isModerator } from '../config';

interface UserMod {
  id: string;
  filename: string;
  hash: string;
  enabled: boolean;
  approved: boolean;
  display_name?: string;
  version?: string;
}

interface UserModsManifest {
  mods: Record<string, UserMod>;
}

type Props = {
  t: T;
  gameDir: string;
  username: string;
  askPassword: () => Promise<string | null>;
  forgetPassword: () => void;
};

export default function UserMods({ t, gameDir, username, askPassword, forgetPassword }: Props) {
  const moderator = isModerator(username);
  const [mods, setMods] = useState<UserMod[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');

  const loadMods = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const manifest = await invoke<UserModsManifest>('get_user_mods', { gameDir });
      const modsList = Object.values(manifest.mods).sort((a, b) => a.filename.localeCompare(b.filename));
      setMods(modsList);
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
      const manifest = await invoke<UserModsManifest>('scan_user_mods_cmd', { gameDir });
      const modsList = Object.values(manifest.mods).sort((a, b) => a.filename.localeCompare(b.filename));
      setMods(modsList);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }, [gameDir]);

  const toggleEnabled = async (modId: string, enabled: boolean) => {
    setError('');
    try {
      await invoke<UserModsManifest>('toggle_user_mod', { gameDir, modId, enabled });
      setMods(prev => prev.map(m => m.id === modId ? { ...m, enabled } : m));
    } catch (e) {
      setError(String(e));
    }
  };

  // Approval is decided by the moderator and kept on the server for every player; the server checks the
  // moderator account's password, so hiding the button for others is only a convenience.
  const toggleApproved = async (modId: string, approved: boolean) => {
    if (!moderator) return;
    const target = mods.find(m => m.id === modId);
    if (!target) return;
    setError('');
    try {
      const password = await askPassword();
      if (!password) return;
      try {
        await invoke('moderate_mod', { nickname: username, password, action: approved ? 'approve' : 'unapprove', key: target.hash, title: target.filename });
      } catch (e) {
        forgetPassword();
        throw e;
      }
      const manifest = await invoke<UserModsManifest>('approve_user_mod', { gameDir, modId, approved });
      setMods(Object.values(manifest.mods).sort((a, b) => a.filename.localeCompare(b.filename)));
    } catch (e) {
      setError(String(e));
    }
  };

  const removeMod = async (modId: string) => {
    setError('');
    try {
      await invoke<UserModsManifest>('remove_user_mod_tracking', { gameDir, modId });
      setMods(prev => prev.filter(m => m.id !== modId));
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
          <span>Загрузка модов...</span>
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
            <div key={mod.id} className={`user-mod-item ${!mod.enabled ? 'disabled' : ''} ${mod.approved ? 'approved' : ''}`}>
              <div className="mod-info">
                <div className="mod-main">
                  <span className="mod-name">{displayName(mod)}</span>
                  <span className="mod-filename">{mod.filename}</span>
                </div>
                <div className="mod-meta">
                  <span className="mod-hash"><FileText size={12} /> {t('userModsHash')} {shortHash(mod.hash)}</span>
                  {mod.version && <span className="mod-version"><FileText size={12} /> {t('userModsVersion')} {mod.version}</span>}
                  {!mod.hash && <span className="mod-missing"><FileText size={12} /> {t('userModsFileMissing')}</span>}
                </div>
              </div>

              <div className="mod-status">
                <span className={`mod-badge ${mod.enabled ? 'enabled' : 'disabled'}`}>
                  {mod.enabled ? <Check size={12} /> : <X size={12} />}
                  {mod.enabled ? t('userModsEnabled') : t('userModsDisabled')}
                </span>
                <span className={`mod-badge ${mod.approved ? 'approved' : 'not-approved'}`}>
                  {mod.approved ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                  {mod.approved ? t('userModsApproved') : t('userModsNotApproved')}
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
                {moderator && <button
                  className={`mod-action-btn ${mod.approved ? 'active approved' : ''}`}
                  onClick={() => toggleApproved(mod.id, !mod.approved)}
                  title={mod.approved ? t('userModsUnapprove') : t('userModsApprove')}
                >
                  {mod.approved ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
                </button>}
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

          <div className="user-mods-legend">
            <div className="legend-item">
              <span className="legend-badge approved"><ShieldCheck size={12} /></span>
              <span>{t('userModsApprovedDesc')}</span>
            </div>
            <div className="legend-item">
              <span className="legend-badge not-approved"><ShieldAlert size={12} /></span>
              <span>{t('userModsNotApprovedDesc')}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}