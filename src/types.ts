import type { Lang } from './i18n';
export type DownloadProgress = { downloaded: number; total?: number; percent: number; stage: string };
export type Settings = {
  ram: number;
  gameDir: string;
  localVersion: string;
  lang?: Lang;
  minecraftVersion?: string;
  loaderType?: string;
  loaderVersion?: string;
};
