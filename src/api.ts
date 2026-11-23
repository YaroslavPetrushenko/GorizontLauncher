import { invoke } from '@tauri-apps/api/core';

export interface UserResponse {
  id: string;
  nickname: string;
  created_at: string;
  email_verified: boolean;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: UserResponse;
}

export interface LoginRequest {
  nickname: string;
  password: string;
  remember: boolean;
  device_fp: string;
}

export interface RegisterRequest {
  nickname: string;
  password: string;
  device_fp: string;
}

export interface RefreshRequest {
  refresh_token: string;
  device_fp: string;
}

export interface LogoutRequest {
  refresh_token: string;
}

export interface ForgotPasswordRequest {
  nickname: string;
}

// Auth API functions
export async function authLogin(request: LoginRequest): Promise<AuthResponse> {
  return invoke<AuthResponse>('auth_login', { request });
}

export async function authRegister(request: RegisterRequest): Promise<AuthResponse> {
  return invoke<AuthResponse>('auth_register', { request });
}

export async function authRefresh(request: RefreshRequest): Promise<AuthResponse> {
  return invoke<AuthResponse>('auth_refresh', { request });
}

export async function authLogout(request: LogoutRequest): Promise<void> {
  return invoke('auth_logout', { request });
}

export async function authMe(accessToken: string): Promise<UserResponse> {
  return invoke<UserResponse>('auth_me', { access_token: accessToken });
}

export async function authForgotPassword(request: ForgotPasswordRequest): Promise<void> {
  return invoke('auth_forgot_password', { request });
}

// Token management
const ACCESS_TOKEN_KEY = 'gorizont-access-token';
const REFRESH_TOKEN_KEY = 'gorizont-refresh-token';
const USER_ID_KEY = 'gorizont-user-id';
const USER_NICKNAME_KEY = 'gorizont-user-nickname';
const DEVICE_FP_KEY = 'gorizont-device-fp';

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function getUserId(): string | null {
  return localStorage.getItem(USER_ID_KEY);
}

export function getUserNickname(): string | null {
  return localStorage.getItem(USER_NICKNAME_KEY);
}

export function getDeviceFingerprint(): string {
  let fp = localStorage.getItem(DEVICE_FP_KEY);
  if (!fp) {
    fp = 'fp-' + Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
    localStorage.setItem(DEVICE_FP_KEY, fp);
  }
  return fp;
}

export function saveAuthResponse(response: AuthResponse): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, response.access_token);
  localStorage.setItem(REFRESH_TOKEN_KEY, response.refresh_token);
  localStorage.setItem(USER_ID_KEY, response.user.id);
  localStorage.setItem(USER_NICKNAME_KEY, response.user.nickname);
}

export function clearAuth(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(USER_ID_KEY);
  localStorage.removeItem(USER_NICKNAME_KEY);
}

export function hasValidSession(): boolean {
  const accessToken = getAccessToken();
  const refreshToken = getRefreshToken();
  return !!(accessToken && refreshToken);
}

// Check if access token is expired (simple check without decoding)
export function isAccessTokenExpired(): boolean {
  const accessToken = getAccessToken();
  if (!accessToken) return true;
  
  try {
    const payload = JSON.parse(atob(accessToken.split('.')[1]));
    const exp = payload.exp * 1000; // Convert to milliseconds
    return Date.now() >= exp;
  } catch {
    return true;
  }
}

// Auto-login: try to refresh token on startup
export async function tryAutoLogin(): Promise<AuthResponse | null> {
  const refreshToken = getRefreshToken();
  const deviceFp = getDeviceFingerprint();
  
  if (!refreshToken) return null;
  
  try {
    const response = await authRefresh({ refresh_token: refreshToken, device_fp: deviceFp });
    saveAuthResponse(response);
    return response;
  } catch (e) {
    // Refresh failed - clear tokens and require re-login
    clearAuth();
    return null;
  }
}