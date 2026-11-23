import { useCallback, useRef, useState, type ReactNode } from 'react';
import { ShieldCheck, X } from 'lucide-react';
import type { T } from '../i18n';

/**
 * Moderation (blocking mods, approving files) is checked on the server against the moderator account's
 * password. The launcher asks for it once, keeps it in memory only (never on disk) and forgets it when the
 * server says it is wrong.
 */
export type ModeratorPassword = {
  ask: () => Promise<string | null>;
  forget: () => void;
  dialog: ReactNode;
};

export function useModeratorPassword(t: T): ModeratorPassword {
  const remembered = useRef<string | null>(null);
  const resolver = useRef<((password: string | null) => void) | null>(null);
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState('');

  const ask = useCallback(() => {
    if (remembered.current) return Promise.resolve(remembered.current);
    return new Promise<string | null>(resolve => {
      resolver.current = resolve;
      setValue('');
      setOpen(true);
    });
  }, []);

  const forget = useCallback(() => { remembered.current = null; }, []);

  const finish = (password: string | null) => {
    setOpen(false);
    if (password) remembered.current = password;
    resolver.current?.(password);
    resolver.current = null;
  };

  const dialog = open ? (
    <div className="modal-backdrop" role="dialog" aria-modal="true">
      <form className="modal" onSubmit={event => { event.preventDefault(); if (value) finish(value); }}>
        <div className="modal-title">
          <h2><ShieldCheck size={18} /> {t('moderatorPasswordTitle')}</h2>
          <button type="button" className="icon-button" onClick={() => finish(null)} aria-label={t('close')}><X size={18} /></button>
        </div>
        <p className="auth-subtitle">{t('moderatorPasswordHint')}</p>
        <input
          className="text-input"
          type="password"
          autoFocus
          autoComplete="current-password"
          value={value}
          onChange={event => setValue(event.target.value)}
        />
        <button className="primary-button" type="submit" disabled={!value}>{t('moderatorConfirm')}</button>
      </form>
    </div>
  ) : null;

  return { ask, forget, dialog };
}
