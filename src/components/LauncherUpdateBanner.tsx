import { Download, Sparkles, X } from 'lucide-react';
import type { T } from '../i18n';

type Props = { t: T; update: { version: string; url: string; size: number }; onClose: () => void; onInstall: () => void };
export default function LauncherUpdateBanner({ t, update, onClose, onInstall }: Props) {
  return <div className="launcher-update-backdrop"><div className="launcher-update-card"><button className="update-close" onClick={onClose}><X size={18} /></button><div className="update-icon"><Sparkles size={30} /></div><div className="update-eyebrow">GORIZONT LAUNCHER <span>•</span> NEW VERSION</div><h2>{t('launcherUpdatedTitle')}</h2><p>{t('launcherUpdateText', { version: update.version })}</p><button className="primary-button" onClick={onInstall}><Download size={17} /> {t('downloadUpdate')}</button><small>{t('installer')}: {(update.size / 1024 / 1024).toFixed(1)} MB</small></div></div>;
}
