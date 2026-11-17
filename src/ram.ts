export type SystemMemory = { totalMb: number; availableMb: number };

const FALLBACK: SystemMemory = { totalMb: 16384, availableMb: 8192 };
export const withFallback = (memory: SystemMemory | null) => memory ?? FALLBACK;

/** Leave 2 GB for Windows and other apps. */
export function ramLimits(memory: SystemMemory | null) {
  const total = withFallback(memory).totalMb;
  const max = Math.max(2048, Math.floor((total - 2048) / 512) * 512);
  const recommended = Math.min(max, Math.max(4096, Math.min(8192, Math.round(total / 4 / 1024) * 1024)));
  return { min: 2048, max, recommended };
}

export function effectiveRam(settings: { ram: number; ramAuto?: boolean }, memory: SystemMemory | null) {
  const { min, max, recommended } = ramLimits(memory);
  return settings.ramAuto === false ? Math.min(max, Math.max(min, settings.ram)) : recommended;
}

export const gb = (mb: number) => `${Math.round((mb / 1024) * 10) / 10}`;
