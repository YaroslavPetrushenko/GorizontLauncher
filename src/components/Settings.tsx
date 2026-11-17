import { useState } from 'react';
import { LogOut } from 'lucide-react';
import type { Settings as SettingsType } from '../types';
import type { Lang, T } from '../i18n';

type Props = { t: T; settings: SettingsType; lang: Lang; username: string; onSave: (s: SettingsType) => void; onLogout: () => void; onClose: () => void };

export default function Settings({ t, settings, lang, username, onSave, onLogout, onClose }: Props) {
  const [draft, setDraft] = useState<SettingsType>({ ...settings, lang });
  const logout = () => { if (window.confirm(t('logoutConfirm'))) onLogout(); };
  return <div className="modal-backdrop"><section className="modal">
    <div className="modal-title"><h2>{t('settings')}</h2><button className="icon-button" onClick={onClose} aria-label={t('close')}>×</button></div>

    <div className="account-box">
      <div><small>{t('signedInAs')}</small><strong>{username}</strong></div>
      <button className="danger-button" onClick={logout}><LogOut size={15} /> {t('logout')}</button>
    </div>

    <label className="setting-label">{t('language')}</label>
    <div className="segmented">
      {(['ru', 'en'] as Lang[]).map(code => <button key={code} className={draft.lang === code ? 'active' : ''} onClick={() => setDraft({ ...draft, lang: code })}>{code === 'ru' ? 'Русский' : 'English'}</button>)}
    </div>

    <label className="setting-label">{t('ram')} <strong>{draft.ram / 1024} {t('gb')}</strong></label>
    <input type="range" min="2048" max="8192" step="1024" value={draft.ram} onChange={e => setDraft({ ...draft, ram: Number(e.target.value) })} />
    <div className="range-labels"><span>2 {t('gb')}</span><span>8 {t('gb')}</span></div>

    <label className="setting-label">{t('gameDir')}</label>
    <input className="text-input" value={draft.gameDir} onChange={e => setDraft({ ...draft, gameDir: e.target.value })} />
    <label className="setting-label">{t('mcVersion')}</label>
    <input className="text-input" value={draft.minecraftVersion || ''} placeholder="1.21.1" onChange={e => setDraft({ ...draft, minecraftVersion: e.target.value || undefined })} />
    <label className="setting-label">{t('loaderType')}</label>
    <input className="text-input" value={draft.loaderType || ''} placeholder="neoforge" onChange={e => setDraft({ ...draft, loaderType: e.target.value || undefined })} />
    <label className="setting-label">{t('loaderVersion')}</label>
    <input className="text-input" value={draft.loaderVersion || ''} placeholder="248" onChange={e => setDraft({ ...draft, loaderVersion: e.target.value || undefined })} />
    <button className="primary-button" onClick={() => { onSave(draft); onClose(); }}>{t('save')}</button>
  </section></div>;
}
