import { useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getVersion } from '@tauri-apps/api/app';
import { Settings as SettingsIcon, Play, Zap, ShieldCheck, Download } from 'lucide-react';
import AuthScreen from './components/AuthScreen';
import ProgressBar from './components/ProgressBar';
import UpdateOverlay from './components/UpdateOverlay';
import LauncherUpdateBanner from './components/LauncherUpdateBanner';
import SettingsPanel from './components/Settings';
import News, { ServerCard, useServerStatus } from './components/News';
import { clearAccount, loadAccount, saveAccount, type Account } from './account';
import { detectLang, makeT, type Lang } from './i18n';
import { effectiveRam, type SystemMemory } from './ram';
import type { DownloadProgress, Settings } from './types';

type LauncherUpdate = { version: string; url: string; size: number };

const defaults: Settings = { ram: 4096, ramAuto: true, gameDir: '%APPDATA%/.GorizontLauncher', localVersion: '0.0.0' };
const SETTINGS_KEY = 'gorizont-settings';

export default function App() {
  const [account, setAccount] = useState<Account | null>(() => loadAccount());
  const [settings, setSettings] = useState<Settings>(() => { try { return { ...defaults, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; } catch { return defaults; } });
  const [progress, setProgress] = useState<DownloadProgress | null>(null);
  const [launcherUpdate, setLauncherUpdate] = useState<LauncherUpdate | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState('1.0.12');
  const [memory, setMemory] = useState<SystemMemory | null>(null);

  const lang: Lang = settings.lang ?? detectLang();
  const t = useMemo(() => makeT(lang), [lang]);
  const server = useServerStatus();

  useEffect(() => {
    invoke<SystemMemory>('get_system_memory').then(setMemory).catch(() => undefined);
    getVersion().then(setVersion).catch(() => undefined);
    invoke<LauncherUpdate | null>('check_launcher_update').then(update => { if (update) setLauncherUpdate(update); }).catch(() => undefined);
    const unlisten = listen<DownloadProgress>('download-progress', e => { setProgress(e.payload); setStatus(e.payload.stage); });
    const unlistenExit = listen('minecraft-exited', () => { setBusy(false); setStatus(null); setProgress(null); });
    return () => { unlisten.then(f => f()); unlistenExit.then(f => f()); };
  }, []);

  const persistSettings = (next: Settings) => { setSettings(next); try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch { /* ignore */ } };
  const logout = () => { clearAccount(); setAccount(null); setShowSettings(false); setStatus(null); };

  // Checks the modpack release, installs/updates it and downloads missing libraries and assets.
  const prepare = async (): Promise<boolean> => {
    setStatus(t('checkingUpdates'));
    try {
      const installedVersion = await invoke<string>('check_and_update_modpack', { localVersion: settings.localVersion, targetDir: settings.gameDir });
      if (installedVersion !== settings.localVersion) persistSettings({ ...settings, localVersion: installedVersion });
      await invoke('prepare_game_files', { gameDir: settings.gameDir });
      setProgress(null); setStatus(t('ready'));
      return true;
    } catch (e) { setProgress(null); setStatus(String(e)); return false; }
  };

  const play = async () => {
    if (!account || busy) return;
    setBusy(true);
    try {
      if (!(await prepare())) return;
      setStatus(t('launching'));
      await invoke('launch_minecraft', { username: account.username, ramMb: effectiveRam(settings, memory), gameDir: settings.gameDir });
      invoke('link_ip_to_account', { username: account.username }).catch(() => undefined);
      setStatus(t('gameStarted'));
    } catch (e) { setStatus(String(e)); } finally { setBusy(false); }
  };

  // Check the modpack automatically once the launcher is opened with a saved profile.
  const startupChecked = useRef(false);
  useEffect(() => {
    if (!account || startupChecked.current) return;
    startupChecked.current = true;
    setBusy(true);
    prepare().finally(() => setBusy(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account]);

  const installLauncherUpdate = () => {
    if (!launcherUpdate) return;
    setBusy(true);
    setProgress({ downloaded: 0, total: launcherUpdate.size, percent: 0, stage: t('preparingLauncherUpdate') });
    invoke('download_launcher_update', { url: launcherUpdate.url })
      .then(() => { setStatus(t('launcherUpdated')); setBusy(false); })
      .catch(e => { setStatus(String(e)); setBusy(false); });
  };

  const serverLabel = server.status === 'online' ? t('serverOnline') : server.status === 'offline' ? t('serverOffline') : t('serverChecking');

  return <div className="app-shell">
    <header className="topbar">
      <div className="brand"><div className="brand-mark"><Zap size={20} fill="currentColor" /></div><div><strong>GORIZONT</strong><span>NETWORK</span></div></div>
      <div className="top-actions">
        <span className={`online-dot ${server.status}`} /> {serverLabel}
        {account && <button className="settings-button" onClick={() => setShowSettings(true)} aria-label={t('settings')}><SettingsIcon size={19} /></button>}
      </div>
    </header>

    {!account ? <main className="content auth-content"><AuthScreen t={t} onDone={next => { saveAccount(next); setAccount(next); }} /></main> :
      <main className="content">
        <section className="hero">
          <div className="hero-kicker"><span /> {t('heroKicker')}</div>
          <h1>{t('heroTitle1')}<br /><em>{t('heroTitle2')}</em></h1>
          <p className="hero-copy">{t('heroCopy')}</p>
          <div className="welcome-chip"><span className="avatar">{account.uuid ? <img src={`https://mc-heads.net/avatar/${account.uuid}/36`} alt="" /> : account.username.slice(0, 1).toUpperCase()}</span><div><small>{t('welcome')}</small><strong>{account.username}</strong></div></div>
          <div className="pack-line">{t('packVersion')}: <b>{settings.localVersion === '0.0.0' ? '—' : `v${settings.localVersion}`}</b></div>
          <button className="play-button" onClick={play} disabled={busy}><Play size={21} fill="currentColor" />{busy ? t('loading') : t('play')}<span /></button>
          <ProgressBar percent={progress?.percent ?? 0} label={status ?? t('ready')} hidden={!progress && !status} />
          <div className="security-note"><ShieldCheck size={16} /> {t('authNote')}</div>
        </section>
        <aside className="news">
          <ServerCard t={t} server={server} />
          <News t={t} lang={lang} />
        </aside>
      </main>}

    <footer><span>GORIZONT LAUNCHER <b>v{version}</b></span><span><Download size={14} /> {t('autoUpdate')}</span></footer>
    {showSettings && account && <SettingsPanel memory={memory} t={t} lang={lang} settings={settings} username={account.username} onSave={persistSettings} onLogout={logout} onClose={() => setShowSettings(false)} />}
    {progress && busy && <UpdateOverlay t={t} progress={progress} />}
    {launcherUpdate && !busy && <LauncherUpdateBanner t={t} update={launcherUpdate} onClose={() => setLauncherUpdate(null)} onInstall={installLauncherUpdate} />}
  </div>;
}
