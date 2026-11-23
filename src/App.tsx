import { useEffect, useMemo, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getVersion } from '@tauri-apps/api/app';
import { Settings as SettingsIcon, Play, Zap, ShieldCheck, Download, Loader2, Puzzle, FolderOpen } from 'lucide-react';
import AuthScreen from './components/AuthScreen';
import ProgressBar from './components/ProgressBar';
import UpdateOverlay from './components/UpdateOverlay';
import LauncherUpdateBanner from './components/LauncherUpdateBanner';
import SettingsPanel from './components/Settings';
import News, { ServerCard, useServerStatus } from './components/News';
import UserMods from './components/UserMods';
import ExtraMods from './components/ExtraMods';
import ModrinthBrowser from './components/ModrinthBrowser';
import { useModeratorPassword } from './components/ModeratorPassword';
import PlayerAvatar from './components/PlayerAvatar';
import { clearAccount, loadAccount, saveAccount, type Account } from './account';
import { saveAuthResponse, clearAuth, tryAutoLogin, type AuthResponse } from './api';
import { detectLang, makeT, type Lang } from './i18n';
import { effectiveRam, type SystemMemory } from './ram';
import type { DownloadProgress, Settings } from './types';

type LauncherUpdate = { version: string; url: string; size: number };

const defaults: Settings = { ram: 4096, ramAuto: true, gameDir: '%APPDATA%/.GorizontLauncher', localVersion: '0.0.0' };
const SETTINGS_KEY = 'gorizont-settings';

export default function App() {
  const [account, setAccount] = useState<Account | null>(null);
  const [settings, setSettings] = useState<Settings>(() => { try { return { ...defaults, ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}') }; } catch { return defaults; } });
  const [progress, setProgress] = useState<DownloadProgress | null>(null);
  const [launcherUpdate, setLauncherUpdate] = useState<LauncherUpdate | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [busy, setBusy] = useState(false);
  const [version, setVersion] = useState('1.3.2');
  const [memory, setMemory] = useState<SystemMemory | null>(null);
  const gameRunning = useRef(false);
  const busyRef = useRef(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [activeTab, setActiveTab] = useState<'main' | 'mods' | 'extra'>('main');
  busyRef.current = busy;

  const lang: Lang = settings.lang ?? detectLang();
  const t = useMemo(() => makeT(lang), [lang]);
  const moderator = useModeratorPassword(t);
  const server = useServerStatus();

  // Auto-login on startup
  useEffect(() => {
    let cancelled = false;
    
    const checkAuth = async () => {
      // First try to load legacy account
      const legacyAccount = loadAccount();
      if (legacyAccount) {
        if (!cancelled) setAccount(legacyAccount);
      }
      
      // Then try auto-login with stored tokens
      if (!cancelled) {
        setBusy(true);
        try {
          const response = await tryAutoLogin();
          if (response && !cancelled) {
            setAccount({
              username: response.user.nickname,
              uuid: response.user.id,
              passHash: response.access_token,
            });
          }
        } catch (e) {
          // Auto-login failed, will show auth screen
        } finally {
          if (!cancelled) {
            setBusy(false);
            setAuthChecked(true);
          }
        }
      } else if (!cancelled) {
        setAuthChecked(true);
      }
    };
    
    checkAuth();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!authChecked) return;
    invoke<SystemMemory>('get_system_memory').then(setMemory).catch(() => undefined);
    getVersion().then(setVersion).catch(() => undefined);
    invoke<LauncherUpdate | null>('check_launcher_update').then(update => { if (update) setLauncherUpdate(update); }).catch(() => undefined);
    const unlisten = listen<DownloadProgress>('download-progress', e => { setProgress(e.payload); setStatus(e.payload.stage); });
    const unlistenExit = listen('minecraft-exited', () => { gameRunning.current = false; setBusy(false); setStatus(null); setProgress(null); });
    return () => { unlisten.then(f => f()); unlistenExit.then(f => f()); };
  }, [authChecked]);

  const persistSettings = (next: Settings) => { setSettings(next); try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(next)); } catch { /* ignore */ } };
  const logout = () => { clearAccount(); clearAuth(); setAccount(null); setShowSettings(false); setStatus(null); };

  // Checks the modpack release, installs/updates it and downloads missing libraries and assets.
  const prepare = async (): Promise<boolean> => {
    setStatus(t('checkingUpdates'));
    try {
      const installedVersion = await invoke<string>('check_and_update_modpack', { localVersion: settings.localVersion, targetDir: settings.gameDir });
      if (installedVersion !== settings.localVersion) persistSettings({ ...settings, localVersion: installedVersion });
      setStatus(t('preparingLauncherUpdate'));
      await invoke('prepare_game_files', { gameDir: settings.gameDir });
      setProgress(null); setStatus(t('ready'));
      return true;
    } catch (e) { setProgress(null); setStatus(String(e)); return false; }
  };

  const play = async () => {
    if (!account || busy) return;
    setBusy(true);
    setStatus(t('checkingUpdates'));
    try {
      if (!(await prepare())) return;
      setStatus(t('launching'));
      await invoke('launch_minecraft', { username: account.username, ramMb: effectiveRam(settings, memory), gameDir: settings.gameDir, accessToken: account.passHash });
      invoke('link_ip_to_account', { username: account.username }).catch(() => undefined);
      gameRunning.current = true;
      setStatus(t('gameStarted'));
    } catch (e) { setStatus(String(e)); } finally { setBusy(false); }
  };

  // Live updates: re-check the launcher and the modpack every few minutes while the launcher is open.
  // Nothing is installed while the game is running or another action is in progress.
  const periodicCheck = useRef<() => void>(() => undefined);
  periodicCheck.current = () => {
    if (busyRef.current || gameRunning.current) return;
    invoke<LauncherUpdate | null>('check_launcher_update').then(update => { if (update) setLauncherUpdate(update); }).catch(() => undefined);
    if (!account) return;
    setBusy(true);
    prepare().finally(() => setBusy(false));
  };
  useEffect(() => {
    const id = window.setInterval(() => periodicCheck.current(), 5 * 60 * 1000);
    return () => window.clearInterval(id);
  }, []);

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
        <nav className="main-tabs" role="tablist">
          <button
            role="tab"
            aria-selected={activeTab === 'main'}
            onClick={() => setActiveTab('main')}
            className={`main-tab ${activeTab === 'main' ? 'active' : ''}`}
          >
            <Zap size={18} /> {t('heroKicker').replace('NEOFORGE EDITION', '').trim() || 'ГЛАВНАЯ'}
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'mods'}
            onClick={() => setActiveTab('mods')}
            className={`main-tab ${activeTab === 'mods' ? 'active' : ''}`}
          >
            <Puzzle size={18} /> {t('userMods')}
          </button>
          <button
            role="tab"
            aria-selected={activeTab === 'extra'}
            onClick={() => setActiveTab('extra')}
            className={`main-tab ${activeTab === 'extra' ? 'active' : ''}`}
          >
            <FolderOpen size={18} /> {t('extraMods')}
          </button>
        </nav>

        {activeTab === 'main' && (
          <section className="hero">
            <div className="hero-kicker"><span /> {t('heroKicker')}</div>
            <h1>{t('heroTitle1')}<br /><em>{t('heroTitle2')}</em></h1>
            <p className="hero-copy">{t('heroCopy')}</p>
            <div className="welcome-chip"><span className="avatar"><PlayerAvatar username={account.username} uuid={account.uuid} /></span><div><small>{t('welcome')}</small><strong>{account.username}</strong></div></div>
            <div className="pack-line">{t('packVersion')}: <b>{!settings.localVersion || settings.localVersion === '0.0.0' ? '—' : `v${settings.localVersion}`}</b></div>
            <button className="play-button" onClick={play} disabled={busy} aria-busy={busy}>
              {busy ? <Loader2 size={21} className="spin" /> : <Play size={21} fill="currentColor" />}
              {busy ? t('loading') : t('play')}<span />
            </button>
            {(progress || status) && <ProgressBar percent={progress?.percent ?? 0} label={status ?? t('ready')} />}
            <div className="security-note"><ShieldCheck size={16} /> {t('authNote')}</div>
          </section>
        )}

        {activeTab === 'mods' && (
          <section className="mods-section">
            <UserMods t={t} gameDir={settings.gameDir} />
          </section>
        )}

        {activeTab === 'extra' && (
          <section className="mods-section">
            <ModrinthBrowser t={t} gameDir={settings.gameDir} gameVersion="1.21.1" loader="neoforge" username={account.username} askPassword={moderator.ask} forgetPassword={moderator.forget} />
          </section>
        )}

        {activeTab === 'main' && (
          <aside className="news">
            <ServerCard t={t} server={server} />
            <News t={t} lang={lang} />
          </aside>
        )}
      </main>}

    <footer><span>GORIZONT LAUNCHER <b>v{version}</b></span><span><Download size={14} /> {t('autoUpdate')}</span></footer>
    {moderator.dialog}
    {showSettings && account && <SettingsPanel memory={memory} t={t} lang={lang} settings={settings} username={account.username} onSave={persistSettings} onLogout={logout} onClose={() => setShowSettings(false)} />}
    {progress && busy && <UpdateOverlay t={t} progress={progress} />}
    {launcherUpdate && !busy && <LauncherUpdateBanner t={t} update={launcherUpdate} onClose={() => setLauncherUpdate(null)} onInstall={installLauncherUpdate} />}
  </div>;
}
