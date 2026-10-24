import { Download, FileArchive, Sparkles, X } from 'lucide-react';
import type { DownloadProgress } from '../types';

type Props = { progress: DownloadProgress; onClose?: () => void };

export default function UpdateOverlay({ progress, onClose }: Props) {
  const percent = Math.max(0, Math.min(100, progress.percent));
  const downloading = progress.stage.includes('Скачивание');
  const unpacking = progress.stage.includes('Распаковка');
  const done = progress.stage === 'Готово';
  return <div className="update-overlay" role="status" aria-live="polite">
    <div className="update-orbit update-orbit-one" /><div className="update-orbit update-orbit-two" />
    <div className="update-panel">
      {onClose && !done && <button className="update-close" onClick={onClose} aria-label="Закрыть"><X size={18} /></button>}
      <div className="update-icon"><div className="update-icon-glow" />{done ? <Sparkles size={31} /> : unpacking ? <FileArchive size={31} /> : <Download size={31} />}</div>
      <div className="update-eyebrow">GORIZONT NETWORK <span>•</span> SYSTEM UPDATE</div>
      <h2>{done ? 'Сборка готова' : unpacking ? 'Устанавливаем обновление' : 'Вышла новая сборка'}</h2>
      <p className="update-description">{done ? 'Всё готово. Можно возвращаться в игру.' : downloading ? 'Скачиваем свежую сборку прямо из GitHub Releases.' : 'Не закрывайте лаунчер, пока обновление не завершится.'}</p>
      <div className="update-progress-meta"><span>{progress.stage}</span><strong>{Math.round(percent)}%</strong></div>
      <div className="update-progress-track"><div className="update-progress-fill" style={{ width: `${percent}%` }} /><div className="update-progress-shine" /></div>
      <div className="update-stats"><span><b>{progress.total ? `${(progress.downloaded / 1024 / 1024).toFixed(1)} MB` : 'Подключение...'}</b><small>загружено</small></span><span><b>{done ? 'Установлено' : unpacking ? 'Распаковка ZIP' : 'Обновление сборки'}</b><small>статус</small></span></div>
      <div className="update-dots"><i /><i /><i /></div>
    </div>
  </div>;
}
