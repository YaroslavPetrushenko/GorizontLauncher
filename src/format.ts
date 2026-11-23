/** Download speed from bytes per second, for example "3,4 МБ/с". */
export function formatSpeed(bytesPerSecond: number): string {
  if (bytesPerSecond >= 1024 * 1024) return `${(bytesPerSecond / 1024 / 1024).toFixed(1)} МБ/с`;
  if (bytesPerSecond >= 1024) return `${Math.round(bytesPerSecond / 1024)} КБ/с`;
  return `${bytesPerSecond} Б/с`;
}
