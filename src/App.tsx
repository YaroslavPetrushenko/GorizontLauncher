import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Settings as SettingsIcon, Play, Zap, ShieldCheck, Download } from 'lucide-react';
import LoginForm from './components/LoginForm';
import ProgressBar from './components/ProgressBar';
import UpdateOverlay from './components/UpdateOverlay';
import SettingsPanel from './components/Settings';
import News from './components/News';
import type { DownloadProgress, Settings } from './types';

const defaults: Settings = { ram: 4096, gameDir: '%APPDATA%/.minecraft', localVersion: '0.0.0' };
export default function App() {
  const [username, setUsername] = useState(''); const [password, setPassword] = useState('');
  const [settings, setSettings] = useState<Settings>(() => { try { return { ...defaults, ...JSON.parse(localStorage.getItem('gorizont-settings') || '{}') }; } catch { return defaults; } });
  const [progress, setProgress] = useState<DownloadProgress | null>(null); const [status, setStatus] = useState('Готов к запуску'); const [showSettings, setShowSettings] = useState(false); const [busy, setBusy] = useState(false);
  useEffect(() => { const unlisten = listen<DownloadProgress>('download-progress', e => { setProgress(e.payload); setStatus(e.payload.stage); }); return () => { unlisten.then(f => f()); }; }, []);
  const saveSettings = (next: Settings) => { setSettings(next); localStorage.setItem('gorizont-settings', JSON.stringify(next)); };
  const play = async () => { if (!username.trim() || busy) return; setBusy(true); setStatus('Проверка обновлений...'); try { const installedVersion = await invoke<string>('check_and_update_modpack', { localVersion: settings.localVersion, targetDir: settings.gameDir }); if (installedVersion !== settings.localVersion) { const nextSettings = { ...settings, localVersion: installedVersion }; setSettings(nextSettings); localStorage.setItem('gorizont-settings', JSON.stringify(nextSettings)); } setStatus('Запуск...'); await invoke('launch_minecraft', { username: username.trim(), ramMb: settings.ram, gameDir: settings.gameDir }); if (password.trim()) await invoke('link_ip_to_account', { username: username.trim() }); setStatus('Игра запущена'); } catch (e) { setStatus(String(e)); } finally { setBusy(false); } };
  return <div className="app-shell"><header className="topbar"><div className="brand"><div className="brand-mark"><Zap size={20} fill="currentColor" /></div><div><strong>GORIZONT</strong><span>NETWORK</span></div></div><div className="top-actions"><span className="online-dot" /> СЕРВЕР ОНЛАЙН <button className="settings-button" onClick={() => setShowSettings(true)}><SettingsIcon size={19} /></button></div></header><main className="content"><section className="hero"><div className="hero-kicker"><span /> NEOFORGE EDITION</div><h1>МИР ЖДЁТ.<br /><em>ВРЕМЯ ИГРАТЬ.</em></h1><p className="hero-copy">Окунись в уникальную вселенную Gorizont.<br />Твой прогресс. Твои правила.</p><LoginForm username={username} password={password} setUsername={setUsername} setPassword={setPassword} /><button className="play-button" onClick={play} disabled={busy || !username.trim()}><Play size={21} fill="currentColor" />{busy ? 'ЗАГРУЗКА...' : 'ИГРАТЬ'}<span /></button>{progress && <ProgressBar percent={progress.percent} label={status} />}<div className="security-note"><ShieldCheck size={16} /> Пароль проверяется сервером AuthMe. Для первого входа используйте <b>/login</b>.</div></section><News /></main><footer><span>GORIZONT LAUNCHER <b>v0.1.0</b></span><span><Download size={14} /> Автообновление модпака включено</span></footer>{showSettings && <SettingsPanel settings={settings} onSave={saveSettings} onClose={() => setShowSettings(false)} />}{progress && busy && <UpdateOverlay progress={progress} />}</div>;
}
