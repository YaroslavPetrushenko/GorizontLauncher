// Keep in sync with launcher.config.json.
export const SERVER_ADDRESS = 'mc.gorizont.fun';
export const SERVER_PORT = 20054;
export const GITHUB_OWNER = 'YaroslavPetrushenko';
export const GITHUB_REPO = 'GorizontLauncher';
// Accounts that may block mods and approve mod files. The game server enforces this with the account's
// password (auth.moderators in the plugin config); here it only decides who sees the controls.
export const MODERATORS = ['OgonickYT'];
export const isModerator = (username?: string) => !!username && MODERATORS.some(m => m.toLowerCase() === username.toLowerCase());
