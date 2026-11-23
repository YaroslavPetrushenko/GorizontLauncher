import { formatSpeed } from '../format';

type Props = { percent: number; label: string; hidden?: boolean; speed?: number };
export default function ProgressBar({ percent, label, hidden, speed }: Props) {
  if (hidden) return null;
  return <div className="progress-wrap"><div className="progress-head"><span>{label}</span><b>{speed ? `${formatSpeed(speed)} · ` : ''}{Math.round(percent)}%</b></div><div className="progress-track"><div className="progress-fill" style={{ width: `${Math.min(100, percent)}%` }} /></div></div>;
}
