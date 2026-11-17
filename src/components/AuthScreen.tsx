import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldCheck, UserRound } from 'lucide-react';
import type { T } from '../i18n';
import { hashPassword, validNick, type Account } from '../account';

type Props = { t: T; onDone: (account: Account) => void };

export default function AuthScreen({ t, onDone }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<{ id: string; name: string } | null>(null);
  const [lookup, setLookup] = useState<'idle' | 'checking' | 'premium' | 'free' | 'error'>('idle');

  useEffect(() => {
    const nick = username.trim();
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
  }, [username]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const nick = username.trim();
    if (!validNick(nick)) return setError(t('errNick'));
    if (password.length < 4) return setError(t('errPassword'));
    if (password !== repeat) return setError(t('errMismatch'));
    setBusy(true);
    try { onDone({ username: nick, uuid: profile?.id, passHash: await hashPassword(nick, password) }); } finally { setBusy(false); }
  };

  return <form className="auth-card" onSubmit={submit}>
    <div className="auth-icon"><UserRound size={26} /></div>
    <h2>{t('authTitle')}</h2>
    <p className="auth-subtitle">{t('authSubtitle')}</p>
    <label>{t('nick')}<input className="text-input" autoFocus autoComplete="username" placeholder={t('nickPlaceholder')} value={username} maxLength={16} onChange={e => { setUsername(e.target.value); setError(''); }} /></label>
    {lookup !== 'idle' && <div className={`nick-check ${lookup}`}>{lookup === 'checking' ? t('nickChecking') : lookup === 'premium' ? <><img src={`https://mc-heads.net/avatar/${profile?.id}/20`} alt="" />{t('nickPremium', { name: profile?.name ?? '' })}</> : lookup === 'free' ? t('nickFree') : t('nickError')}</div>}
    <label>{t('password')}<input className="text-input" type="password" autoComplete="new-password" placeholder={t('passwordPlaceholder')} value={password} onChange={e => { setPassword(e.target.value); setError(''); }} /></label>
    <label>{t('passwordRepeat')}<input className="text-input" type="password" autoComplete="new-password" value={repeat} onChange={e => { setRepeat(e.target.value); setError(''); }} /></label>
    {error && <div className="form-error" role="alert">{error}</div>}
    <button className="primary-button" type="submit" disabled={busy}>{t('authSubmit')}</button>
    <div className="security-note"><ShieldCheck size={16} /> {t('authStored')}</div>
  </form>;
}
