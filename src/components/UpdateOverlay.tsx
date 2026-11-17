import { Download, FileArchive, Sparkles, X } from 'lucide-react';
import type { DownloadProgress } from '../types';
import type { T } from '../i18n';

type Props = { t: T; progress: DownloadProgress; onClose?: () => void };

export default function UpdateOverlay({ t, progress, onClose }: Props) {
  const percent = Math.max(0, Math.min(100, progress.percent));
  const downloading = progress.stage.includes('Скачивание');
  const unpacking = progress.stage.includes('Распаковка');
  const done = progress.stage === 'Готово';
  return <div className="update-overlay" role="status" aria-live="polite">
    <div className="update-orbit update-orbit-one" /><div className="update-orbit update-orbit-two" />
    <div className="update-panel">
      {onClose && !done && <button className="update-close" onClick={onClose} aria-label={t('close')}><X size={18} /></button>}
      <div className="update-icon"><div className="update-icon-glow" />{done ? <Sparkles size={31} /> : unpacking ? <FileArchive size={31} /> : <Download size={31} />}</div>
      <div className="update-eyebrow">GORIZONT NETWORK <span>•</span> SYSTEM UPDATE</div>
      <h2>{done ? t('ovDone') : unpacking ? t('ovUnpacking') : t('ovNew')}</h2>
      <p className="update-description">{done ? t('ovDoneDesc') : downloading ? t('ovDownloadingDesc') : t('ovWaitDesc')}</p>
      <div className="update-progress-meta"><span>{progress.stage}</span><strong>{Math.round(percent)}%</strong></div>
      <div className="update-progress-track"><div className="update-progress-fill" style={{ width: `${percent}%` }} /><div className="update-progress-shine" /></div>
      <div className="update-stats"><span><b>{progress.total ? `${(progress.downloaded / 1024 / 1024).toFixed(1)} MB` : t('ovConnecting')}</b><small>{t('ovDownloaded')}</small></span><span><b>{done ? t('ovInstalled') : unpacking ? t('ovUnzip') : t('ovUpdating')}</b><small>{t('ovStatus')}</small></span></div>
      <div className="update-dots"><i /><i /><i /></div>
    </div>
  </div>;
}
