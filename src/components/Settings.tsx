import { useState } from 'react';
import { LogOut } from 'lucide-react';
import type { Settings as SettingsType } from '../types';
import type { Lang, T } from '../i18n';
import { effectiveRam, gb, ramLimits, withFallback, type SystemMemory } from '../ram';

type Props = { memory: SystemMemory | null; t: T; settings: SettingsType; lang: Lang; username: string; onSave: (s: SettingsType) => void; onLogout: () => void; onClose: () => void };

export default function Settings({ memory, t, settings, lang, username, onSave, onLogout, onClose }: Props) {
  const [draft, setDraft] = useState<SettingsType>({ ...settings, lang });
  const limits = ramLimits(memory);
  const auto = draft.ramAuto !== false;
  const ram = effectiveRam(draft, memory);
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

    <label className="setting-label">{t('ram')} <strong>{gb(ram)} {t('gb')}</strong></label>
    <label className="check-row"><input type="checkbox" checked={auto} onChange={e => setDraft({ ...draft, ramAuto: e.target.checked, ram: e.target.checked ? draft.ram : ram })} /> {t('ramAuto')} <small>({t('ramRecommended')}: {gb(limits.recommended)} {t('gb')})</small></label>
    <input type="range" disabled={auto} min={limits.min} max={limits.max} step="512" value={ram} onChange={e => setDraft({ ...draft, ram: Number(e.target.value) })} />
    <div className="range-labels"><span>{gb(limits.min)} {t('gb')}</span><span>{t('ramTotal')}: {gb(withFallback(memory).totalMb)} {t('gb')}</span><span>{gb(limits.max)} {t('gb')}</span></div>
    {!auto && ram > withFallback(memory).totalMb * 0.6 && <div className="form-error">{t('ramWarn')}</div>}

    <label className="setting-label">{t('gameDir')}</label>
    <input className="text-input" value={draft.gameDir} onChange={e => setDraft({ ...draft, gameDir: e.target.value })} />
    <button className="primary-button" onClick={() => { onSave(draft); onClose(); }}>{t('save')}</button>
  </section></div>;
}
