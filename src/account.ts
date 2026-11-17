export type Account = { username: string; passHash: string };
const KEY = 'gorizont-account';

export function loadAccount(): Account | null {
  try {
    const value = JSON.parse(localStorage.getItem(KEY) || 'null');
    return value && typeof value.username === 'string' && typeof value.passHash === 'string' ? value : null;
  } catch { return null; }
}
export function saveAccount(account: Account) { try { localStorage.setItem(KEY, JSON.stringify(account)); } catch { /* ignore */ } }
export function clearAccount() { try { localStorage.removeItem(KEY); } catch { /* ignore */ } }

export async function hashPassword(username: string, password: string): Promise<string> {
  const data = new TextEncoder().encode(`gorizont:${username.toLowerCase()}:${password}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export const validNick = (nick: string) => /^[A-Za-z0-9_]{3,16}$/.test(nick);
