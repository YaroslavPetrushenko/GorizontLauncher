import { useEffect, useState } from 'react';
import { Copy, Check, Users } from 'lucide-react';
import type { T } from '../i18n';
import { GITHUB_OWNER, GITHUB_REPO, SERVER_ADDRESS, SERVER_PORT } from '../config';

export type ServerState = { status: 'checking' | 'online' | 'offline'; players?: number; max?: number };
type NewsItem = { id: string; date: string; tag: string; title: string; text: string; url?: string };

export function useServerStatus(): ServerState {
  const [state, setState] = useState<ServerState>({ status: 'checking' });
  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const response = await fetch(`https://api.mcsrvstat.us/3/${SERVER_ADDRESS}:${SERVER_PORT}`);
        const data = await response.json();
        if (!cancelled) setState(data.online ? { status: 'online', players: data.players?.online, max: data.players?.max } : { status: 'offline' });
      } catch { if (!cancelled) setState({ status: 'offline' }); }
    };
    check();
    const timer = setInterval(check, 60_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);
  return state;
}

export function ServerCard({ t, server }: { t: T; server: ServerState }) {
  const [copied, setCopied] = useState(false);
  const address = `${SERVER_ADDRESS}:${SERVER_PORT}`;
  const copy = () => { navigator.clipboard?.writeText(address).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }).catch(() => undefined); };
  return <div className="server-card">
    <div className="section-kicker">{t('server')}</div>
    <div className="server-row"><span className={`online-dot ${server.status}`} /><code>{address}</code></div>
    <div className="server-meta">
      <span><Users size={13} /> {server.status === 'online' ? `${server.players ?? 0}${server.max ? ` / ${server.max}` : ''} ${t('players')}` : server.status === 'checking' ? t('serverChecking') : t('serverOffline')}</span>
      <button className="link-button" onClick={copy}>{copied ? <><Check size={13} /> {t('copied')}</> : <><Copy size={13} /> {t('copyAddress')}</>}</button>
    </div>
  </div>;
}

const clip = (text: string, max = 110) => { const clean = text.replace(/https?:\/\/\S+/g, '').replace(/Full Changelog:?/gi, '').replace(/[#*`>_\[\]]/g, '').replace(/\s+/g, ' ').trim(); return clean.length > max ? `${clean.slice(0, max)}…` : clean; };

export default function News({ t, lang }: { t: T; lang: string }) {
  const [items, setItems] = useState<NewsItem[] | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases?per_page=6`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error(String(r.status))))
      .then((releases: any[]) => {
        if (cancelled) return;
        const mapped = releases.filter(r => !r.draft).map(r => ({
          id: String(r.id),
          date: new Date(r.published_at || r.created_at).toLocaleDateString(lang === 'ru' ? 'ru-RU' : 'en-GB'),
          tag: String(r.tag_name).startsWith('launcher-v') ? 'launcher' : 'modpack',
          title: r.name || r.tag_name,
          text: clip(r.body || ''),
          url: r.html_url,
        }));
        setItems(mapped);
      })
      .catch(() => { if (!cancelled) setItems([]); });
    return () => { cancelled = true; };
  }, [lang]);

  const fallback: NewsItem[] = [
    { id: 'welcome', date: '', tag: 'news', title: t('welcomeNewsTitle'), text: t('welcomeNewsText') },
    { id: 'neoforge', date: '', tag: 'modpack', title: t('neoforgeNewsTitle'), text: t('neoforgeNewsText') },
  ];
  const list = items && items.length ? items : fallback;
  const tagLabel = (tag: string) => tag === 'launcher' ? t('tagLauncher') : tag === 'modpack' ? t('tagModpack') : t('tagNews');
  return <div className="news-list">
    <div className="section-kicker">{t('news')}</div>
    {items === null && <div className="news-empty">{t('newsLoading')}</div>}
    {items !== null && list.map(item => <article className="news-card" key={item.id}>
      <div className="news-meta"><span className={`news-tag ${item.tag}`}>{tagLabel(item.tag)}</span>{item.date && <span>{item.date}</span>}</div>
      <h3>{item.title}</h3>{item.text && <p>{item.text}</p>}
    </article>)}
  </div>;
}
