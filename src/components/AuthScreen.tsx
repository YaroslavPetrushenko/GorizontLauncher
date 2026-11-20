import { useEffect, useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldCheck, UserRound, Lock, AlertCircle, Eye, EyeOff, Loader2, Github, Chrome } from 'lucide-react';
import type { T } from '../i18n';
import { validNick, type Account } from '../account';

type AuthMode = 'login' | 'register' | 'forgot';
type OAuthProvider = 'google' | 'microsoft';

interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    nickname: string;
    created_at: string;
    email_verified: boolean;
  };
}

interface LoginRequest {
  nickname: string;
  password: string;
  remember: boolean;
  device_fp: string;
}

interface RegisterRequest {
  nickname: string;
  password: string;
  device_fp: string;
}

interface ForgotPasswordRequest {
  nickname: string;
}

interface OAuthRequest {
  provider: string;
  code: string;
  device_fp: string;
}

type Props = { t: T; onDone: (account: Account) => void };

// Generate or retrieve device fingerprint
function getDeviceFingerprint(): string {
  let fp = localStorage.getItem('gorizont-device-fp');
  if (!fp) {
    fp = 'fp-' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
    localStorage.setItem('gorizont-device-fp', fp);
  }
  return fp;
}

export default function AuthScreen({ t, onDone }: Props) {
  const [mode, setMode] = useState<AuthMode>('login');
  const [nickname, setNickname] = useState('');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<{ id: string; name: string } | null>(null);
  const [lookup, setLookup] = useState<'idle' | 'checking' | 'premium' | 'free' | 'error'>('idle');
  const deviceFp = getDeviceFingerprint();

  // Check Mojang profile for nickname (register mode)
  useEffect(() => {
    if (mode !== 'register') { setProfile(null); setLookup('idle'); return; }
    const nick = nickname.trim();
    setProfile(null);
    if (!validNick(nick)) { setLookup('idle'); return; }
    setLookup('checking');
    let cancelled = false;
    const timer = setTimeout(() => {
      invoke<{ id: string; name: string } | null>('lookup_mojang_profile', { username: nick })
        .then(found => { if (cancelled) return; setProfile(found); setLookup(found ? 'premium' : 'free'); })
        .catch(() => { if (!cancelled) setLookup('error'); });
    }, 600);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [nickname, mode]);

  const validatePassword = useCallback((p: string) => p.length >= 8, []);
  const validateNickname = useCallback((n: string) => validNick(n), []);

  const switchMode = useCallback((newMode: AuthMode) => {
    setMode(newMode);
    setError('');
    setSuccess('');
    setNickname('');
    setPassword('');
    setPasswordConfirm('');
  }, []);

  const handleAuthSuccess = useCallback((response: AuthResponse) => {
    // Save tokens to localStorage for auto-login
    localStorage.setItem('gorizont-access-token', response.access_token);
    localStorage.setItem('gorizont-refresh-token', response.refresh_token);
    localStorage.setItem('gorizont-user-id', response.user.id);
    localStorage.setItem('gorizont-user-nickname', response.user.nickname);

    // Call onDone with account info compatible with existing Account type
    // Using access_token as passHash for now (backwards compatibility)
    onDone({
      username: response.user.nickname,
      uuid: response.user.id,
      passHash: response.access_token,
    });
  }, [onDone]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setSuccess('');

    if (mode === 'login') {
      if (!validateNickname(nickname)) return setError(t('errNick'));
      if (!validatePassword(password)) return setError(t('authErrorInvalidCredentials'));
      setBusy(true);
      try {
        const request: LoginRequest = { nickname, password, remember: rememberMe, device_fp: deviceFp };
        const response = await invoke<AuthResponse>('auth_login', { request });
        handleAuthSuccess(response);
        setSuccess(t('authSuccess'));
      } catch (e) {
        const err = String(e);
        if (err.includes('Invalid credentials') || err.includes('invalid credentials') || err.includes('not found')) {
          setError(t('authErrorInvalidCredentials'));
        } else if (err.includes('network') || err.includes('Network') || err.includes('fetch')) {
          setError(t('authErrorNetwork'));
        } else {
          setError(t('authErrorServer'));
        }
      } finally { setBusy(false); }
    }

    if (mode === 'register') {
      if (!validateNickname(nickname)) return setError(t('errNick'));
      if (!validatePassword(password)) return setError(t('authErrorWeakPassword'));
      if (password !== passwordConfirm) return setError(t('errMismatch'));
      setBusy(true);
      try {
        const request: RegisterRequest = { nickname, password, device_fp: deviceFp };
        const response = await invoke<AuthResponse>('auth_register', { request });
        handleAuthSuccess(response);
        setSuccess(t('authSuccess'));
      } catch (e) {
        const err = String(e);
        if (err.includes('already exists') || err.includes('Already exists')) {
          setError(t('authErrorUserExists'));
        } else if (err.includes('network') || err.includes('Network') || err.includes('fetch')) {
          setError(t('authErrorNetwork'));
        } else {
          setError(t('authErrorServer'));
        }
      } finally { setBusy(false); }
    }

    if (mode === 'forgot') {
      if (!validateNickname(nickname)) return setError(t('errNick'));
      setBusy(true);
      try {
        const request: ForgotPasswordRequest = { nickname };
        await invoke('auth_forgot_password', { request });
        setSuccess(t('authForgotSuccess'));
      } catch (e) {
        const err = String(e);
        if (err.includes('network') || err.includes('Network') || err.includes('fetch')) {
          setError(t('authErrorNetwork'));
        } else {
          setError(t('authErrorServer'));
        }
      } finally { setBusy(false); }
    }
  };

  const handleOAuth = async (provider: OAuthProvider) => {
    setBusy(true);
    setError('');
    try {
      // For OAuth, we need to open a popup/window and get the auth code
      // This is a placeholder - full OAuth flow needs a webview or popup
      const request: OAuthRequest = { provider, code: '', device_fp: deviceFp };
      const response = await invoke<AuthResponse>('auth_oauth', { request });
      handleAuthSuccess(response);
      setSuccess(t('authSuccess'));
    } catch (e) {
      const err = String(e);
      if (err.includes('network') || err.includes('Network') || err.includes('fetch')) {
        setError(t('authErrorNetwork'));
      } else {
        setError(t('authErrorServer'));
      }
    } finally { setBusy(false); }
  };

  const renderLoginForm = () => (
    <>
      <label>
        {t('authNickname')}
        <div className="input-wrapper">
          <UserRound size={16} className="input-icon" />
          <input
            className="text-input"
            autoFocus
            autoComplete="username"
            placeholder={t('authNicknamePlaceholder')}
            value={nickname}
            maxLength={16}
            onChange={e => { setNickname(e.target.value); setError(''); }}
          />
        </div>
      </label>
      <label>
        {t('authPassword')}
        <div className="input-wrapper">
          <Lock size={16} className="input-icon" />
          <input
            className="text-input"
            type={showPassword ? 'text' : 'password'}
            autoComplete="current-password"
            placeholder={t('authPasswordPlaceholder')}
            value={password}
            onChange={e => { setPassword(e.target.value); setError(''); }}
          />
          <button type="button" className="icon-button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
      </label>
      <div className="login-options">
        <label className="check-row">
          <input type="checkbox" checked={rememberMe} onChange={e => setRememberMe(e.target.checked)} />
          <span>{t('authRememberMe')}</span>
        </label>
        <button type="button" className="link-button" onClick={() => switchMode('forgot')}>{t('authForgotPassword')}</button>
      </div>
      {error && <div className="form-error" role="alert"><AlertCircle size={14} /> {error}</div>}
      <button className="primary-button" type="submit" disabled={busy}>
        {busy ? <Loader2 size={18} className="spin" /> : t('authSubmitLogin')}
      </button>
      <div className="divider"><span>{t('authDivider')}</span></div>
      <div className="oauth-buttons">
        <button type="button" className="oauth-button" onClick={() => handleOAuth('google')} disabled={busy}>
          <Chrome size={18} /> {t('authOAuthGoogle')}
        </button>
        <button type="button" className="oauth-button" onClick={() => handleOAuth('microsoft')} disabled={busy}>
          <Github size={18} /> {t('authOAuthMicrosoft')}
        </button>
      </div>
      <p className="auth-switch">{t('authBackToRegister')} <button type="button" className="link-button" onClick={() => switchMode('register')}>{t('authRegister')}</button></p>
    </>
  );

  const renderRegisterForm = () => (
    <>
      <label>
        {t('authNickname')}
        <div className="input-wrapper">
          <UserRound size={16} className="input-icon" />
          <input
            className="text-input"
            autoFocus
            autoComplete="username"
            placeholder={t('authNicknameRegisterPlaceholder')}
            value={nickname}
            maxLength={16}
            onChange={e => { setNickname(e.target.value); setError(''); }}
          />
        </div>
      </label>
      {lookup !== 'idle' && <div className={`nick-check ${lookup}`}>{lookup === 'checking' ? t('nickChecking') : lookup === 'premium' ? <><img src={`https://mc-heads.net/avatar/${profile?.id}/20`} alt="" />{t('nickPremium', { name: profile?.name ?? '' })}</> : lookup === 'free' ? t('nickFree') : t('nickError')}</div>}
      <label>
        {t('authPassword')}
        <div className="input-wrapper">
          <Lock size={16} className="input-icon" />
          <input
            className="text-input"
            type={showPassword ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder={t('authPasswordPlaceholder')}
            value={password}
            onChange={e => { setPassword(e.target.value); setError(''); }}
          />
          <button type="button" className="icon-button" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
            {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
      </label>
      <label>
        {t('authPasswordConfirm')}
        <div className="input-wrapper">
          <Lock size={16} className="input-icon" />
          <input
            className="text-input"
            type={showPasswordConfirm ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder={t('authPasswordConfirmPlaceholder')}
            value={passwordConfirm}
            onChange={e => { setPasswordConfirm(e.target.value); setError(''); }}
          />
          <button type="button" className="icon-button" onClick={() => setShowPasswordConfirm(!showPasswordConfirm)} aria-label={showPasswordConfirm ? 'Hide password' : 'Show password'}>
            {showPasswordConfirm ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>
      </label>
      {error && <div className="form-error" role="alert"><AlertCircle size={14} /> {error}</div>}
      <button className="primary-button" type="submit" disabled={busy}>
        {busy ? <Loader2 size={18} className="spin" /> : t('authSubmitRegister')}
      </button>
      <div className="divider"><span>{t('authDivider')}</span></div>
      <div className="oauth-buttons">
        <button type="button" className="oauth-button" onClick={() => handleOAuth('google')} disabled={busy}>
          <Chrome size={18} /> {t('authOAuthGoogle')}
        </button>
        <button type="button" className="oauth-button" onClick={() => handleOAuth('microsoft')} disabled={busy}>
          <Github size={18} /> {t('authOAuthMicrosoft')}
        </button>
      </div>
      <p className="auth-switch">{t('authBackToLogin')} <button type="button" className="link-button" onClick={() => switchMode('login')}>{t('authLogin')}</button></p>
    </>
  );

  const renderForgotForm = () => (
    <>
      <p className="auth-subtitle">{t('authForgotDesc')}</p>
      <label>
        {t('authNickname')}
        <div className="input-wrapper">
          <UserRound size={16} className="input-icon" />
          <input
            className="text-input"
            autoFocus
            autoComplete="username"
            placeholder={t('authNicknamePlaceholder')}
            value={nickname}
            maxLength={16}
            onChange={e => { setNickname(e.target.value); setError(''); }}
          />
        </div>
      </label>
      {error && <div className="form-error" role="alert"><AlertCircle size={14} /> {error}</div>}
      {success && <div className="form-success" role="status"><ShieldCheck size={14} /> {success}</div>}
      <button className="primary-button" type="submit" disabled={busy || success !== ''}>
        {busy ? <Loader2 size={18} className="spin" /> : t('authSubmitForgot')}
      </button>
      <p className="auth-switch">{t('authBackToLogin')} <button type="button" className="link-button" onClick={() => switchMode('login')}>{t('authLogin')}</button></p>
    </>
  );

  const renderSuccess = () => (
    <div className="auth-success">
      <div className="success-icon"><ShieldCheck size={32} /></div>
      <h3>{t('authSuccess')}</h3>
      <p>{t('authWelcome', { name: nickname })}</p>
    </div>
  );

  return (
    <form className="auth-card" onSubmit={handleSubmit}>
      <div className="auth-icon"><UserRound size={26} /></div>
      <h2>{mode === 'login' ? t('authLogin') : mode === 'register' ? t('authRegister') : t('authForgotPassword')}</h2>
      <p className="auth-subtitle">
        {mode === 'login' ? t('authSubtitle') : mode === 'register' ? 'Создайте аккаунт для входа в Gorizont' : ''}
      </p>

      <div className="auth-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          className={`auth-tab ${mode === 'login' ? 'active' : ''}`}
          onClick={() => switchMode('login')}
          aria-selected={mode === 'login'}
        >{t('authLogin')}</button>
        <button
          type="button"
          role="tab"
          className={`auth-tab ${mode === 'register' ? 'active' : ''}`}
          onClick={() => switchMode('register')}
          aria-selected={mode === 'register'}
        >{t('authRegister')}</button>
      </div>

      {success && mode === 'forgot' ? renderSuccess() : (
        <>
          {mode === 'login' && renderLoginForm()}
          {mode === 'register' && renderRegisterForm()}
          {mode === 'forgot' && renderForgotForm()}
        </>
      )}

      <div className="security-note"><ShieldCheck size={16} /> {t('authStored')}</div>
    </form>
  );
}