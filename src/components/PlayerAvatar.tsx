import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';

/**
 * Head of the player's skin for the header ("С возвращением").
 *
 * Source order, so that something sensible is always shown:
 *  1. the skin fetched from Mojang by the launcher itself and cached on disk (works offline after the first start,
 *     does not depend on a third-party image service);
 *  2. an image from mc-heads.net, only when the launcher has no skin for this nickname;
 *  3. the first letter of the nickname.
 */
type Source = 'loading' | 'skin' | 'remote' | 'letter';

/** Cuts the face (and the hat layer on top of it) out of a 64x64 / 64x32 skin: an 8x8 image, scaled up by CSS. */
function drawHead(skinDataUrl: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 8;
      canvas.height = 8;
      const context = canvas.getContext('2d');
      if (!context) { reject(new Error('no canvas')); return; }
      context.imageSmoothingEnabled = false;
      context.drawImage(image, 8, 8, 8, 8, 0, 0, 8, 8);   // face
      // The hat layer exists only in 64x64 skins. Old 64x32 skins store opaque filler there, which the game itself
      // ignores: drawing it would cover the face with a black square.
      if (image.naturalHeight === 64) context.drawImage(image, 40, 8, 8, 8, 0, 0, 8, 8);
      resolve(canvas.toDataURL('image/png'));
    };
    image.onerror = () => reject(new Error('bad skin image'));
    image.src = skinDataUrl;
  });
}

export default function PlayerAvatar({ username, uuid }: { username: string; uuid?: string }) {
  const [source, setSource] = useState<Source>('loading');
  const [head, setHead] = useState('');

  useEffect(() => {
    let cancelled = false;
    setSource('loading');
    setHead('');
    invoke<string | null>('get_player_skin', { username })
      .then(skin => (skin ? drawHead(skin) : null))
      .then(face => {
        if (cancelled) return;
        if (face) { setHead(face); setSource('skin'); } else { setSource('remote'); }
      })
      .catch(() => { if (!cancelled) setSource('remote'); });
    return () => { cancelled = true; };
  }, [username]);

  const letter = username.slice(0, 1).toUpperCase();
  if (source === 'skin') return <img className="avatar-head" src={head} alt="" />;
  if (source === 'remote') {
    return <img className="avatar-head" src={`https://mc-heads.net/avatar/${uuid || username}/36`} alt="" onError={() => setSource('letter')} />;
  }
  return <>{letter}</>;
}
