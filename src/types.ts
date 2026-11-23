import type { Lang } from './i18n';
export type DownloadProgress = { downloaded: number; total?: number; percent: number; stage: string; speed?: number };
export type Settings = {
  ram: number;
  gameDir: string;
  localVersion: string;
  lang?: Lang;
  ramAuto?: boolean;
};
