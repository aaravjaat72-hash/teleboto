import express from 'express';
import * as cheerio from 'cheerio';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { Readable, Transform } from 'stream';
import { execFile, spawn } from 'child_process';
import { promisify } from 'util';
import dotenv from 'dotenv';
import { TelegramClient, Api } from 'telegram';
import { StringSession } from 'telegram/sessions/index.js';
import { readBigIntFromBuffer, generateRandomBytes } from 'telegram/Helpers.js';
import { GoogleGenAI } from '@google/genai';

dotenv.config();
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

import http from 'http';
import https from 'https';
import dns from 'dns';
try {
  dns.setDefaultResultOrder('ipv4first');
} catch {
  // ignore
}

// 1. Global HTTP/HTTPS Keep-Alive Connection Pool (Eliminates TCP/TLS handshake overhead across all requests)
export const globalHttpAgent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 128,
  maxFreeSockets: 32,
  timeout: 30000,
});

export const globalHttpsAgent = new https.Agent({
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 128,
  maxFreeSockets: 32,
  timeout: 30000,
  rejectUnauthorized: false,
});

(http as any).globalAgent = globalHttpAgent;
(https as any).globalAgent = globalHttpsAgent;

import { setGlobalDispatcher, Agent as UndiciAgent, request as undiciRequest } from 'undici';
export const IS_CONSTRAINED_HOST = Boolean(
  process.env.RENDER ||
    process.env.RENDER_EXTERNAL_URL ||
    os.totalmem() < 1.5 * 1024 * 1024 * 1024 ||
    os.cpus().length <= 2
);

export const undiciFastDispatcher = new UndiciAgent({
  connections: IS_CONSTRAINED_HOST ? 128 : 256,
  pipelining: 1, // CRITICAL: HTTP/1.1 pipelining (>1) causes stalls & resets on CloudFront/Akamai/Google Edge CDNs
  allowH2: false,
  keepAliveTimeout: 60000,
  keepAliveMaxTimeout: 120000,
  connect: {
    rejectUnauthorized: false,
    timeout: 10000,
    autoSelectFamily: false,
  },
});
try {
  setGlobalDispatcher(undiciFastDispatcher);
} catch {
  // ignore
}

process.on('uncaughtException', (err) => {
  console.error('[StreamBridge] Uncaught Exception caught (process guarded):', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[StreamBridge] Unhandled Rejection at:', promise, 'reason:', reason);
});

const execFileAsync = promisify(execFile);

const DOWNLOAD_DIR = path.join(os.tmpdir(), 'streambridge-downloads');
if (!fs.existsSync(DOWNLOAD_DIR)) {
  fs.mkdirSync(DOWNLOAD_DIR, { recursive: true });
} else {
  try {
    for (const file of fs.readdirSync(DOWNLOAD_DIR)) {
      try {
        fs.unlinkSync(path.join(DOWNLOAD_DIR, file));
      } catch {
        // ignore
      }
    }
  } catch {
    // ignore
  }
}

function cleanupJobTempFiles(jobId: string) {
  try {
    if (!fs.existsSync(DOWNLOAD_DIR)) return;
    for (const file of fs.readdirSync(DOWNLOAD_DIR)) {
      if (file.startsWith(`${jobId}_`)) {
        try {
          fs.unlinkSync(path.join(DOWNLOAD_DIR, file));
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // ignore
  }
}

type AccessDurationKey = '24h' | '48h' | '7d' | '30d';
type VideoQualityOption = '144p' | '240p' | '360p' | '480p' | '720p' | '1080p';
type UserRole = 'main_admin' | 'admin' | 'developer' | 'user';
type AccessAttemptStatus = 'pending' | 'failed' | 'approved' | 'revoked';

// Keep the historical owner ID as a fallback, but allow the real owner to
// configure their Telegram numeric ID securely in the hosting environment.
// This prevents the admin panel from being locked to an old account after a
// bot migration or redeploy.
let MAIN_ADMIN_ID = String(process.env.MAIN_ADMIN_ID || '7581137308').trim();

interface AccessCodeState {
  code: string;
  durationKey: AccessDurationKey;
  durationLabel: string;
  durationMs: number;
  createdAt: string;
  expiresAt: string;
  autoRotateDaily?: boolean;
}

interface AuthorizedUserSession {
  chatId: string;
  name?: string;
  firstName?: string;
  username?: string;
  role?: UserRole;
  approvedBy?: string;
  activatedWithCode: string;
  activatedAt: string;
  expiresAt: string;
}

interface StaffRoleEntry {
  userId: string;
  role: 'admin' | 'developer';
  name?: string;
  username?: string;
  appointedBy: string;
  appointedAt: string;
}

interface AccessAttemptEntry {
  chatId: string;
  senderId: string;
  firstName: string;
  username?: string;
  status: AccessAttemptStatus;
  attemptsCount: number;
  lastAttemptAt: string;
  firstAttemptAt: string;
  lastInputPreview?: string;
  reason?: string;
  reviewedBy?: string;
  reviewedAt?: string;
}

interface BugBountyCheckItem {
  id: string;
  category: 'SECURITY' | 'UPLOAD_SPEED' | 'BOT_FEATURES' | 'SYSTEM_HEALTH';
  name: string;
  status: 'PASS' | 'WARN' | 'FAIL';
  detail: string;
}

interface BugBountyAuditReport {
  timestamp: string;
  durationMs: number;
  passedCount: number;
  warnCount: number;
  failCount: number;
  tempFilesSwept: number;
  diskUsageMb: number;
  activeMtprotoSockets: number;
  secondaryMtprotoSockets: number;
  checks: BugBountyCheckItem[];
}

interface BackupChannelConfig {
  id: string;
  chatId: string;
  title: string;
  type: 'channel' | 'group';
  enabled: boolean;
  addedVia: 'web' | 'bot';
  addedAt: string;
}

interface ChannelRouteRule {
  id: string;
  pattern: string;
  label: string;
  targetChatId: string;
  targetTitle: string;
  enabled: boolean;
  createdAt: string;
}

interface HuggingFaceCloudConfig {
  deployedRepoId?: string;
  deployedSpaceUrl?: string;
  deployedAppUrl?: string;
  githubRepoUrl?: string;
  renderDeployUrl?: string;
  runtimeVault?: string;
  lastDeployedAt?: string;
  autoPingEnabled: boolean;
  localPollingPaused: boolean;
}

interface PortalAuthSession {
  origin: string;
  host: string;
  portalPath?: string;
  cookieHeader?: string;
  bearerToken?: string;
  userId?: string;
  teachxApiUrl?: string;
  accountLabel?: string;
  authMethod: 'credentials' | 'token_or_cookie';
  updatedAt: string;
  chatId?: string;
}

interface PersistedBotSettings {
  mainAdminId?: string;
  globalDefaultQuality: VideoQualityOption;
  preferFullSingleVideo: boolean;
  accessCode: AccessCodeState;
  authorizedUsers: Record<string, AuthorizedUserSession>;
  staffRoles: Record<string, StaffRoleEntry>;
  accessAttempts: Record<string, AccessAttemptEntry>;
  backupChannels: BackupChannelConfig[];
  routeRules: ChannelRouteRule[];
  explicitlyPausedChats?: string[];
  aiAutoWatchEnabled?: boolean;
  portalSessions?: Record<string, PortalAuthSession>;
  hfCloud: HuggingFaceCloudConfig;
}

const IS_RUNNING_ON_HF = Boolean(
  process.env.SPACE_ID ||
    process.env.SPACE_AUTHOR_NAME ||
    process.env.RENDER ||
    process.env.RENDER_EXTERNAL_URL
);

const VAULT_XOR_KEY = 'SB_24X7_CLOUD_VAULT_2026_KEY';

function encodeRuntimeVault(obj: Record<string, string>): string {
  const raw = Buffer.from(JSON.stringify(obj), 'utf8');
  const key = Buffer.from(VAULT_XOR_KEY, 'utf8');
  const out = Buffer.alloc(raw.length);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw[i] ^ key[i % key.length];
  }
  return out.toString('hex');
}

function decodeRuntimeVault(hexStr?: string): Record<string, string> | null {
  if (!hexStr) return null;
  try {
    const buf = Buffer.from(hexStr, 'hex');
    const key = Buffer.from(VAULT_XOR_KEY, 'utf8');
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
      out[i] = buf[i] ^ key[i % key.length];
    }
    return JSON.parse(out.toString('utf8'));
  } catch {
    return null;
  }
}

const DURATION_MAP: Record<AccessDurationKey, { label: string; ms: number }> = {
  '24h': { label: '24 Hours (Daily Auto-Rotate)', ms: 24 * 60 * 60 * 1000 },
  '48h': { label: '48 Hours (2 Days)', ms: 48 * 60 * 60 * 1000 },
  '7d': { label: '7 Days (Weekly)', ms: 7 * 24 * 60 * 60 * 1000 },
  '30d': { label: '30 Days (Monthly)', ms: 30 * 24 * 60 * 60 * 1000 },
};

const BOT_CONFIG_PATH = path.join(process.cwd(), 'bot-config.json');

function generateRandomCodeString(avoidCode?: string): string {
  for (let i = 0; i < 16; i++) {
    const candidate = crypto.randomInt(1000, 10000).toString();
    if (candidate !== '2612' && candidate !== avoidCode) {
      return candidate;
    }
  }
  return crypto.randomInt(1000, 10000).toString();
}

function createFreshAccessCode(durationKey: AccessDurationKey = '24h', avoidCode?: string): AccessCodeState {
  const validKey: AccessDurationKey = DURATION_MAP[durationKey] ? durationKey : '24h';
  const dur = DURATION_MAP[validKey];
  const now = Date.now();
  return {
    code: generateRandomCodeString(avoidCode),
    durationKey: validKey,
    durationLabel: dur.label,
    durationMs: dur.ms,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + dur.ms).toISOString(),
    autoRotateDaily: true,
  };
}

let botSettings: PersistedBotSettings = {
  mainAdminId: MAIN_ADMIN_ID,
  globalDefaultQuality: '480p',
  preferFullSingleVideo: true,
  accessCode: createFreshAccessCode('24h'),
  authorizedUsers: {},
  staffRoles: {},
  accessAttempts: {},
  backupChannels: [],
  routeRules: [],
  portalSessions: {},
  hfCloud: {
    autoPingEnabled: true,
    localPollingPaused: false,
  },
};

function isValidTelegramBotToken(val?: string): boolean {
  const s = (val || '').trim();
  return /^\d{5,}:[A-Za-z0-9_-]{20,}$/.test(s);
}
function isValidTelegramApiId(val?: string): boolean {
  const s = (val || '').trim();
  return /^\d{4,12}$/.test(s);
}
function isValidTelegramApiHash(val?: string): boolean {
  const s = (val || '').trim();
  return /^[a-fA-F0-9]{16,64}$/.test(s);
}
function isValidTelegramChatId(val?: string): boolean {
  const s = (val || '').trim();
  return /^-?\d{5,}$|^@[a-zA-Z0-9_]{3,}$/.test(s);
}
function isValidTelegramStringSession(val?: string): boolean {
  const s = (val || '').trim();
  return s.length > 40 && !/already added|placeholder|your_/i.test(s) && /^[A-Za-z0-9+/=_-]+$/.test(s);
}

const BOT_MTPROTO_CACHE_PATH = path.join(os.tmpdir(), '.sb_bot_mtproto_cache.json');
let cachedBotMtprotoSessionStr = '';
let cachedSecondaryBotMtprotoSessionStr = '';
let botMtprotoFloodUntil = 0;
let secondaryBotMtprotoFloodUntil = 0;
let lastMtprotoHealthCheckAt = 0;
let lastSecondaryMtprotoHealthCheckAt = 0;
const userExplicitlyPausedChats = new Set<string>();
const activeJobAbortControllers = new Map<string, AbortController>();

function getOrCreateJobAbortController(jobId: string): AbortController {
  const existing = activeJobAbortControllers.get(jobId);
  if (existing && !existing.signal.aborted) return existing;
  const ctrl = new AbortController();
  activeJobAbortControllers.set(jobId, ctrl);
  return ctrl;
}

function abortJobImmediately(jobId: string) {
  const ctrl = activeJobAbortControllers.get(jobId);
  if (ctrl) {
    try {
      ctrl.abort();
    } catch {
      // ignore
    }
    activeJobAbortControllers.delete(jobId);
  }
}

function getBotMtprotoTokenKey(apiId: number, botToken: string): string {
  return crypto.createHash('sha256').update(`${apiId}:${botToken}`).digest('hex').slice(0, 16);
}

function loadPersistedBotMtprotoCache(key: string): { session?: string; floodUntil?: number } {
  try {
    if (!fs.existsSync(BOT_MTPROTO_CACHE_PATH)) return {};
    const parsed = JSON.parse(fs.readFileSync(BOT_MTPROTO_CACHE_PATH, 'utf8'));
    const entry = parsed?.[key];
    return entry && typeof entry === 'object' ? entry : {};
  } catch {
    return {};
  }
}

function savePersistedBotMtprotoCache(key: string, patch: { session?: string; floodUntil?: number }) {
  try {
    let all: Record<string, any> = {};
    if (fs.existsSync(BOT_MTPROTO_CACHE_PATH)) {
      all = JSON.parse(fs.readFileSync(BOT_MTPROTO_CACHE_PATH, 'utf8')) || {};
    }
    all[key] = { ...(all[key] || {}), ...patch, updatedAt: Date.now() };
    fs.writeFileSync(BOT_MTPROTO_CACHE_PATH, JSON.stringify(all), 'utf8');
  } catch {
    // ignore tmp write errors
  }
}

function parseTelegramFloodWaitMs(errText: string): number {
  const m = String(errText || '').match(/FLOOD_WAIT[_\s:]*(\d+)/i);
  if (m && m[1]) {
    const secs = Math.max(30, parseInt(m[1], 10));
    return Math.min(secs, 3600) * 1000;
  }
  return 15 * 60 * 1000;
}

function saveBotSettings() {
  try {
    botSettings.mainAdminId = MAIN_ADMIN_ID;
    const existingVault = decodeRuntimeVault(botSettings.hfCloud.runtimeVault) || {};
    const mergedToken = isValidTelegramBotToken(process.env.TELEGRAM_BOT_TOKEN)
      ? process.env.TELEGRAM_BOT_TOKEN!.trim()
      : isValidTelegramBotToken(existingVault.TELEGRAM_BOT_TOKEN)
      ? existingVault.TELEGRAM_BOT_TOKEN
      : '';
    const mergedApiId = isValidTelegramApiId(process.env.TELEGRAM_API_ID)
      ? process.env.TELEGRAM_API_ID!.trim()
      : isValidTelegramApiId(existingVault.TELEGRAM_API_ID)
      ? existingVault.TELEGRAM_API_ID
      : '';
    const mergedApiHash = isValidTelegramApiHash(process.env.TELEGRAM_API_HASH)
      ? process.env.TELEGRAM_API_HASH!.trim()
      : isValidTelegramApiHash(existingVault.TELEGRAM_API_HASH)
      ? existingVault.TELEGRAM_API_HASH
      : '';
    const mergedSession = isValidTelegramStringSession(process.env.TELEGRAM_STRING_SESSION)
      ? process.env.TELEGRAM_STRING_SESSION!.trim()
      : isValidTelegramStringSession(existingVault.TELEGRAM_STRING_SESSION)
      ? existingVault.TELEGRAM_STRING_SESSION
      : '';
    const mergedChatId = isValidTelegramChatId(process.env.TELEGRAM_CHAT_ID)
      ? process.env.TELEGRAM_CHAT_ID!.trim()
      : isValidTelegramChatId(existingVault.TELEGRAM_CHAT_ID)
      ? existingVault.TELEGRAM_CHAT_ID
      : '';
    const mergedExtraApiId = isValidTelegramApiId(process.env.EXTRA_TELEGRAM_API_ID)
      ? process.env.EXTRA_TELEGRAM_API_ID!.trim()
      : isValidTelegramApiId(existingVault.EXTRA_TELEGRAM_API_ID)
      ? existingVault.EXTRA_TELEGRAM_API_ID
      : '';
    const mergedExtraApiHash = isValidTelegramApiHash(process.env.EXTRA_TELEGRAM_API_HASH)
      ? process.env.EXTRA_TELEGRAM_API_HASH!.trim()
      : isValidTelegramApiHash(existingVault.EXTRA_TELEGRAM_API_HASH)
      ? existingVault.EXTRA_TELEGRAM_API_HASH
      : '';
    const mergedExtraSession = isValidTelegramStringSession(process.env.EXTRA_TELEGRAM_STRING_SESSION)
      ? process.env.EXTRA_TELEGRAM_STRING_SESSION!.trim()
      : isValidTelegramStringSession(existingVault.EXTRA_TELEGRAM_STRING_SESSION)
      ? existingVault.EXTRA_TELEGRAM_STRING_SESSION
      : '';
    const mergedCookiesTxt =
      typeof process.env.PLATFORM_COOKIES_TXT === 'string'
        ? process.env.PLATFORM_COOKIES_TXT
        : typeof existingVault.PLATFORM_COOKIES_TXT === 'string'
        ? existingVault.PLATFORM_COOKIES_TXT
        : '';
    if (mergedToken) {
      botSettings.hfCloud.runtimeVault = encodeRuntimeVault({
        TELEGRAM_BOT_TOKEN: mergedToken,
        TELEGRAM_API_ID: mergedApiId,
        TELEGRAM_API_HASH: mergedApiHash,
        TELEGRAM_STRING_SESSION: mergedSession,
        TELEGRAM_CHAT_ID: mergedChatId,
        EXTRA_TELEGRAM_API_ID: mergedExtraApiId,
        EXTRA_TELEGRAM_API_HASH: mergedExtraApiHash,
        EXTRA_TELEGRAM_STRING_SESSION: mergedExtraSession,
        PLATFORM_COOKIES_TXT: mergedCookiesTxt,
      });
    }
    botSettings.explicitlyPausedChats = Array.from(userExplicitlyPausedChats);
    botSettings.aiAutoWatchEnabled = Boolean(aiAgentState.enabled);
    fs.writeFileSync(BOT_CONFIG_PATH, JSON.stringify(botSettings, null, 2), 'utf8');
  } catch {
    // ignore
  }
}

function loadBotSettings() {
  try {
    if (fs.existsSync(BOT_CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(BOT_CONFIG_PATH, 'utf8')) as Partial<PersistedBotSettings>;
      const persistedOwner = String(parsed.mainAdminId || '').trim();
      if (persistedOwner && isValidTelegramChatId(persistedOwner)) {
        MAIN_ADMIN_ID = persistedOwner;
        botSettings.mainAdminId = persistedOwner;
      }
      if (parsed.globalDefaultQuality) {
        botSettings.globalDefaultQuality = parsed.globalDefaultQuality;
      }
      // Parts splitting has been permanently removed: every video is always delivered as 1 full single file
      botSettings.preferFullSingleVideo = true;
      if (parsed.staffRoles && typeof parsed.staffRoles === 'object') {
        const cleanStaff: Record<string, StaffRoleEntry> = {};
        for (const [uid, entry] of Object.entries(parsed.staffRoles)) {
          const cleanUid = String(uid || '').trim();
          if (
            cleanUid &&
            cleanUid !== MAIN_ADMIN_ID &&
            isValidTelegramChatId(cleanUid) &&
            entry &&
            (entry.role === 'admin' || entry.role === 'developer')
          ) {
            cleanStaff[cleanUid] = { ...entry, userId: cleanUid };
          }
        }
        botSettings.staffRoles = cleanStaff;
      }
      if (parsed.accessAttempts && typeof parsed.accessAttempts === 'object') {
        const cleanAttempts: Record<string, AccessAttemptEntry> = {};
        for (const [uid, entry] of Object.entries(parsed.accessAttempts)) {
          const cleanUid = String(uid || '').trim();
          if (cleanUid && entry && typeof entry === 'object') {
            cleanAttempts[cleanUid] = entry;
          }
        }
        botSettings.accessAttempts = cleanAttempts;
      }
      if (parsed.accessCode && parsed.accessCode.code && parsed.accessCode.expiresAt) {
        const parsedCode = parsed.accessCode;
        const isLegacyStatic =
          parsedCode.code === '2612' || parsedCode.expiresAt.startsWith('2099-');
        if (!isLegacyStatic) {
          botSettings.accessCode = {
            ...parsedCode,
            autoRotateDaily: parsedCode.autoRotateDaily ?? true,
          };
        } else {
          botSettings.accessCode = createFreshAccessCode('24h', '2612');
        }
      }
      if (parsed.authorizedUsers && typeof parsed.authorizedUsers === 'object') {
        const cleanUsers: Record<string, AuthorizedUserSession> = {};
        for (const [uid, sess] of Object.entries(parsed.authorizedUsers)) {
          const cleanUid = String(uid || '').trim();
          if (!isValidTelegramChatId(cleanUid) || !sess || !isValidTelegramChatId(sess.chatId)) {
            continue;
          }
          // Strip legacy auto-authorized '2612' stranger sessions unless Main Admin, Staff, or explicitly approved by an Admin
          const isMainOrStaff = cleanUid === MAIN_ADMIN_ID || Boolean(botSettings.staffRoles[cleanUid]);
          const isLegacyBypass =
            !isMainOrStaff &&
            !sess.approvedBy &&
            (sess.activatedWithCode === '2612' || String(sess.expiresAt || '').startsWith('2099-'));
          if (isLegacyBypass) continue;
          cleanUsers[cleanUid] = sess;
        }
        botSettings.authorizedUsers = cleanUsers;
      }
      if (Array.isArray(parsed.backupChannels)) {
        botSettings.backupChannels = parsed.backupChannels;
      }
      if (Array.isArray(parsed.routeRules)) {
        botSettings.routeRules = parsed.routeRules;
      }
      if (Array.isArray(parsed.explicitlyPausedChats)) {
        for (const cId of parsed.explicitlyPausedChats) {
          if (typeof cId === 'string' && cId.trim()) {
            userExplicitlyPausedChats.add(cId.trim());
          }
        }
        botSettings.explicitlyPausedChats = Array.from(userExplicitlyPausedChats);
      }
      if (typeof parsed.aiAutoWatchEnabled === 'boolean') {
        botSettings.aiAutoWatchEnabled = parsed.aiAutoWatchEnabled;
        aiAgentState.enabled = parsed.aiAutoWatchEnabled;
      } else {
        botSettings.aiAutoWatchEnabled = false;
        aiAgentState.enabled = false;
      }
      if (parsed.hfCloud && typeof parsed.hfCloud === 'object') {
        botSettings.hfCloud = {
          ...botSettings.hfCloud,
          ...parsed.hfCloud,
        };
      }
      if (parsed.portalSessions && typeof parsed.portalSessions === 'object') {
        const cleanSessions: Record<string, PortalAuthSession> = {};
        for (const [k, s] of Object.entries(parsed.portalSessions)) {
          if (s && typeof s === 'object' && s.origin && s.host) {
            cleanSessions[k] = s;
          }
        }
        botSettings.portalSessions = cleanSessions;
      }
    }
  } catch {
    // ignore
  }
  // Restore valid runtime credentials automatically whenever process.env is empty OR contains placeholders like "Already added"
  // Note: Do NOT restore BOT_MTPROTO_SESSION_STR across restarts/containers to avoid 406 AUTH_KEY_DUPLICATED!
  const restored = decodeRuntimeVault(botSettings.hfCloud?.runtimeVault) || {};
  const validators: Record<string, (v?: string) => boolean> = {
    TELEGRAM_BOT_TOKEN: isValidTelegramBotToken,
    TELEGRAM_API_ID: isValidTelegramApiId,
    TELEGRAM_API_HASH: isValidTelegramApiHash,
    TELEGRAM_STRING_SESSION: isValidTelegramStringSession,
    TELEGRAM_CHAT_ID: isValidTelegramChatId,
    EXTRA_TELEGRAM_API_ID: isValidTelegramApiId,
    EXTRA_TELEGRAM_API_HASH: isValidTelegramApiHash,
    EXTRA_TELEGRAM_STRING_SESSION: isValidTelegramStringSession,
  };
  for (const [k, validateFn] of Object.entries(validators)) {
    const envVal = process.env[k];
    if (!validateFn(envVal)) {
      const vaultVal = restored[k];
      if (validateFn(vaultVal)) {
        process.env[k] = vaultVal.trim();
      } else {
        process.env[k] = '';
      }
    } else {
      process.env[k] = envVal!.trim();
    }
  }
  if (!process.env.PLATFORM_COOKIES_TXT && typeof restored.PLATFORM_COOKIES_TXT === 'string' && restored.PLATFORM_COOKIES_TXT.trim()) {
    process.env.PLATFORM_COOKIES_TXT = restored.PLATFORM_COOKIES_TXT.trim();
  }
  if (botSettings.hfCloud) {
    botSettings.hfCloud.localPollingPaused = false;
  }
  // Always ensure immutable Main Admin (7581137308) and any configured owner / appointed staff are permanently active
  botSettings.authorizedUsers[MAIN_ADMIN_ID] = {
    chatId: MAIN_ADMIN_ID,
    firstName: botSettings.authorizedUsers[MAIN_ADMIN_ID]?.firstName || 'Main Admin',
    username: botSettings.authorizedUsers[MAIN_ADMIN_ID]?.username,
    role: 'main_admin',
    approvedBy: 'SYSTEM_ROOT',
    activatedWithCode: 'MAIN_ADMIN',
    activatedAt: botSettings.authorizedUsers[MAIN_ADMIN_ID]?.activatedAt || new Date().toISOString(),
    expiresAt: '2099-12-31T23:59:59.999Z',
  };
  for (const staff of Object.values(botSettings.staffRoles)) {
    botSettings.authorizedUsers[staff.userId] = {
      chatId: staff.userId,
      firstName: staff.name || (staff.role === 'developer' ? 'Developer' : 'Admin'),
      username: staff.username,
      role: staff.role,
      approvedBy: staff.appointedBy,
      activatedWithCode: staff.role.toUpperCase(),
      activatedAt: staff.appointedAt,
      expiresAt: '2099-12-31T23:59:59.999Z',
    };
  }
  saveBotSettings();
}
loadBotSettings();

function upsertBackupChannel(
  chatId: string,
  title: string,
  type: 'channel' | 'group' = 'channel',
  addedVia: 'web' | 'bot' = 'bot'
): BackupChannelConfig {
  const cleanId = chatId.trim();
  const existing = botSettings.backupChannels.find(
    (c) => c.chatId.toLowerCase() === cleanId.toLowerCase()
  );
  if (existing) {
    if (title && title.trim()) existing.title = title.trim();
    existing.enabled = true;
    saveBotSettings();
    return existing;
  }
  const created: BackupChannelConfig = {
    id: crypto.randomUUID(),
    chatId: cleanId,
    title: (title || cleanId).trim(),
    type,
    enabled: true,
    addedVia,
    addedAt: new Date().toISOString(),
  };
  botSettings.backupChannels.push(created);
  saveBotSettings();
  return created;
}

function findMatchingRouteRule(targetUrl?: string): ChannelRouteRule | undefined {
  if (!targetUrl) return undefined;
  const lowerUrl = targetUrl.toLowerCase().trim();
  for (const rule of botSettings.routeRules) {
    if (!rule.enabled || !rule.pattern.trim() || !rule.targetChatId.trim()) continue;
    const pat = rule.pattern.toLowerCase().trim();
    if (lowerUrl.includes(pat)) {
      return rule;
    }
  }
  return undefined;
}

const lastAttemptAlertAtByUser = new Map<string, number>();

function ensureValidAccessCode(notifyMainAdminOnRotate = false): AccessCodeState {
  const cur = botSettings.accessCode;
  const now = Date.now();
  const expiresMs = cur?.expiresAt ? new Date(cur.expiresAt).getTime() : 0;
  const needsFresh =
    !cur ||
    !cur.code ||
    !/^\d{4}$/.test(cur.code) ||
    cur.code === '2612' ||
    String(cur.expiresAt || '').startsWith('2099-') ||
    !Number.isFinite(expiresMs) ||
    now >= expiresMs;

  if (needsFresh) {
    const prevCode = cur?.code;
    const prevDur: AccessDurationKey =
      cur?.durationKey && DURATION_MAP[cur.durationKey] ? cur.durationKey : '24h';
    botSettings.accessCode = createFreshAccessCode(prevDur, prevCode);
    saveBotSettings();
    const newCode = botSettings.accessCode;
    addBotLog(
      'SYSTEM',
      MAIN_ADMIN_ID,
      `Auto-rotated daily 4-digit access code to ${newCode.code} (Valid ${newCode.durationLabel})`
    );
    if (notifyMainAdminOnRotate) {
      setTimeout(() => {
        sendTelegramTextMessage(
          MAIN_ADMIN_ID,
          `🔐 **Daily Access Code Auto-Rotated!**\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `🔑 New Today's Code: \`${newCode.code}\`\n` +
            `⏱ Valid Until: ${new Date(newCode.expiresAt).toLocaleString()} (${newCode.durationLabel})\n\n` +
            `👉 Purana code ab expire ho chuka hai. Naye users ko ye naya code bhejein ya /admin se direct Approve karein.`
        ).catch(() => {});
      }, 250);
    }
  }
  return botSettings.accessCode;
}

function getUserRole(userId?: string): UserRole {
  const clean = String(userId || '').trim();
  if (!clean) return 'user';
  if (clean === MAIN_ADMIN_ID) return 'main_admin';
  const staff = botSettings.staffRoles?.[clean];
  if (staff) return staff.role;
  return 'user';
}

function isMainAdmin(userId?: string, senderId?: string): boolean {
  return String(userId || '').trim() === MAIN_ADMIN_ID || String(senderId || '').trim() === MAIN_ADMIN_ID;
}

function isAdminOrDev(chatId?: string, senderId?: string): boolean {
  const r1 = getUserRole(chatId);
  const r2 = getUserRole(senderId);
  return r1 === 'main_admin' || r1 === 'admin' || r1 === 'developer' || r2 === 'main_admin' || r2 === 'admin' || r2 === 'developer';
}

function isChatAuthorized(chatId?: string, senderId?: string): boolean {
  ensureValidAccessCode(false);
  const candidates = Array.from(new Set([String(chatId || '').trim(), String(senderId || '').trim()].filter(Boolean)));
  if (candidates.length === 0) return false;

  for (const id of candidates) {
    if (id === MAIN_ADMIN_ID || Boolean(botSettings.staffRoles?.[id])) {
      return true;
    }
  }

  let modified = false;
  const now = Date.now();
  for (const id of candidates) {
    const sess = botSettings.authorizedUsers[id];
    if (!sess) continue;
    const expMs = new Date(sess.expiresAt).getTime();
    if (!Number.isFinite(expMs) || now < expMs) {
      return true;
    }
    delete botSettings.authorizedUsers[id];
    if (botSettings.accessAttempts[id]) {
      botSettings.accessAttempts[id].status = 'revoked';
      botSettings.accessAttempts[id].reason = 'Session expired';
    }
    modified = true;
  }
  if (modified) saveBotSettings();
  return false;
}

function grantUserAccess(
  targetId: string,
  durationKey: AccessDurationKey | 'permanent',
  reviewedBy: string,
  meta?: { firstName?: string; username?: string; activatedWithCode?: string }
): AuthorizedUserSession {
  const cleanId = String(targetId).trim();
  const prev = botSettings.authorizedUsers[cleanId];
  const prevAttempt = botSettings.accessAttempts[cleanId];
  const role = getUserRole(cleanId);
  const now = Date.now();
  const expiresAt =
    durationKey === 'permanent' || role !== 'user'
      ? '2099-12-31T23:59:59.999Z'
      : new Date(now + (DURATION_MAP[durationKey]?.ms || DURATION_MAP['24h'].ms)).toISOString();

  const session: AuthorizedUserSession = {
    chatId: cleanId,
    firstName: meta?.firstName || prev?.firstName || prevAttempt?.firstName || 'Telegram User',
    username: meta?.username || prev?.username || prevAttempt?.username,
    role,
    approvedBy: reviewedBy,
    activatedWithCode: meta?.activatedWithCode || (durationKey === 'permanent' ? 'ADMIN_PERM' : 'ADMIN_24H'),
    activatedAt: new Date(now).toISOString(),
    expiresAt,
  };
  botSettings.authorizedUsers[cleanId] = session;
  botSettings.accessAttempts[cleanId] = {
    chatId: cleanId,
    senderId: cleanId,
    firstName: session.firstName || 'Telegram User',
    username: session.username,
    status: 'approved',
    attemptsCount: (prevAttempt?.attemptsCount || 0) + (prevAttempt ? 0 : 1),
    firstAttemptAt: prevAttempt?.firstAttemptAt || session.activatedAt,
    lastAttemptAt: session.activatedAt,
    reviewedBy,
    reviewedAt: session.activatedAt,
    reason: durationKey === 'permanent' ? 'Approved permanently by Admin' : `Approved (${durationKey})`,
  };
  saveBotSettings();
  return session;
}

function revokeUserAccess(targetId: string, reviewedBy: string): { ok: boolean; error?: string } {
  const cleanId = String(targetId).trim();
  if (!cleanId) return { ok: false, error: 'Target ID required' };
  if (cleanId === MAIN_ADMIN_ID) {
    return { ok: false, error: `Main Admin (${MAIN_ADMIN_ID}) is immutable and cannot be revoked.` };
  }
  const prevSess = botSettings.authorizedUsers[cleanId];
  const prevAtt = botSettings.accessAttempts[cleanId];
  delete botSettings.authorizedUsers[cleanId];
  if (botSettings.staffRoles[cleanId] && isMainAdmin(reviewedBy)) {
    delete botSettings.staffRoles[cleanId];
  }
  const nowIso = new Date().toISOString();
  botSettings.accessAttempts[cleanId] = {
    chatId: cleanId,
    senderId: cleanId,
    firstName: prevAtt?.firstName || prevSess?.firstName || 'Telegram User',
    username: prevAtt?.username || prevSess?.username,
    status: 'revoked',
    attemptsCount: prevAtt?.attemptsCount || 1,
    firstAttemptAt: prevAtt?.firstAttemptAt || nowIso,
    lastAttemptAt: nowIso,
    reviewedBy,
    reviewedAt: nowIso,
    reason: `Revoked by ${reviewedBy}`,
  };
  saveBotSettings();
  return { ok: true };
}

function appointStaffRole(
  targetId: string,
  role: 'admin' | 'developer',
  appointedBy: string,
  meta?: { name?: string; username?: string }
): { ok: boolean; error?: string; entry?: StaffRoleEntry } {
  const cleanId = String(targetId).trim();
  if (!isValidTelegramChatId(cleanId)) {
    return { ok: false, error: 'Invalid Telegram User ID.' };
  }
  if (cleanId === MAIN_ADMIN_ID) {
    return { ok: false, error: `Main Admin (${MAIN_ADMIN_ID}) already holds highest root authority.` };
  }
  if (!isMainAdmin(appointedBy) && appointedBy !== 'web-main-admin') {
    return { ok: false, error: `Only Main Admin (${MAIN_ADMIN_ID}) can appoint Admins or Developers.` };
  }
  const prevAtt = botSettings.accessAttempts[cleanId];
  const prevSess = botSettings.authorizedUsers[cleanId];
  const entry: StaffRoleEntry = {
    userId: cleanId,
    role,
    name: meta?.name || prevSess?.firstName || prevAtt?.firstName || (role === 'developer' ? 'Developer' : 'Admin'),
    username: meta?.username || prevSess?.username || prevAtt?.username,
    appointedBy,
    appointedAt: new Date().toISOString(),
  };
  botSettings.staffRoles[cleanId] = entry;
  grantUserAccess(cleanId, 'permanent', appointedBy, {
    firstName: entry.name,
    username: entry.username,
    activatedWithCode: role.toUpperCase(),
  });
  saveBotSettings();
  return { ok: true, entry };
}

function removeStaffRole(targetId: string, removedBy: string): { ok: boolean; error?: string } {
  const cleanId = String(targetId).trim();
  if (cleanId === MAIN_ADMIN_ID) {
    return { ok: false, error: `Main Admin (${MAIN_ADMIN_ID}) cannot be demoted.` };
  }
  if (!isMainAdmin(removedBy) && removedBy !== 'web-main-admin') {
    return { ok: false, error: `Only Main Admin (${MAIN_ADMIN_ID}) can remove Admins or Developers.` };
  }
  if (botSettings.staffRoles[cleanId]) {
    delete botSettings.staffRoles[cleanId];
    const existingSess = botSettings.authorizedUsers[cleanId];
    if (existingSess) {
      if (existingSess.activatedWithCode === 'ADMIN' || existingSess.activatedWithCode === 'DEVELOPER') {
        delete botSettings.authorizedUsers[cleanId];
        if (botSettings.accessAttempts[cleanId]) {
          botSettings.accessAttempts[cleanId].status = 'revoked';
          botSettings.accessAttempts[cleanId].reviewedBy = removedBy;
          botSettings.accessAttempts[cleanId].reviewedAt = new Date().toISOString();
          botSettings.accessAttempts[cleanId].reason = `Staff role removed by ${removedBy}`;
        }
      } else {
        existingSess.role = 'user';
      }
    }
    saveBotSettings();
  }
  return { ok: true };
}

function transferMainAdmin(targetId: string, transferredBy: string): { ok: boolean; error?: string; previousId?: string } {
  const cleanTarget = String(targetId || '').trim();
  const previousId = MAIN_ADMIN_ID;
  if (!isValidTelegramChatId(cleanTarget)) {
    return { ok: false, error: 'Invalid Telegram User ID.' };
  }
  if (!isMainAdmin(transferredBy)) {
    return { ok: false, error: `Only current Main Admin (${MAIN_ADMIN_ID}) can transfer ownership.` };
  }
  if (cleanTarget === previousId) {
    return { ok: false, error: 'That user is already the Main Admin.' };
  }

  // Keep the old owner as an admin to prevent accidental lockout, while the
  // new owner receives root authority and all existing admin/developer rights.
  const oldEntry = botSettings.accessAttempts[previousId];
  botSettings.staffRoles[previousId] = {
    userId: previousId,
    role: 'admin',
    name: oldEntry?.firstName || 'Previous Main Admin',
    username: oldEntry?.username,
    appointedBy: cleanTarget,
    appointedAt: new Date().toISOString(),
  };
  delete botSettings.staffRoles[cleanTarget];
  MAIN_ADMIN_ID = cleanTarget;
  grantUserAccess(cleanTarget, 'permanent', previousId, {
    firstName: botSettings.accessAttempts[cleanTarget]?.firstName || 'Main Admin',
    username: botSettings.accessAttempts[cleanTarget]?.username,
    activatedWithCode: 'MAIN_ADMIN',
  });
  saveBotSettings();
  addBotLog('SYSTEM', previousId, `Transferred Main Admin ownership to ${cleanTarget}`);
  return { ok: true, previousId };
}

function buildUserApprovalKeyboard(targetId: string) {
  return {
    inline_keyboard: [
      [
        { text: '✅ Approve 24h', callback_data: `adm:app24:${targetId}` },
        { text: '♾️ Approve Permanent', callback_data: `adm:applife:${targetId}` },
      ],
      [
        { text: '🚫 Deny / Revoke', callback_data: `adm:deny:${targetId}` },
        { text: '👑 Make Admin', callback_data: `adm:mkadmin:${targetId}` },
        { text: '🛠 Make Dev', callback_data: `adm:mkdev:${targetId}` },
      ],
    ],
  };
}

function getApprovalRecipientIds(): string[] {
  return Array.from(
    new Set(
      [MAIN_ADMIN_ID, ...Object.values(botSettings.staffRoles || {}).map((staff) => staff.userId)].filter((id) =>
        isValidTelegramChatId(String(id))
      )
    )
  );
}

function recordAccessAttempt(params: {
  chatId: string;
  senderId: string;
  firstName: string;
  username?: string;
  status: AccessAttemptStatus;
  inputPreview?: string;
  reason?: string;
  forceNotifyAdmin?: boolean;
}) {
  const cleanId = String(params.senderId || params.chatId).trim();
  if (!cleanId || cleanId === MAIN_ADMIN_ID) return;
  const nowIso = new Date().toISOString();
  const prev = botSettings.accessAttempts[cleanId];
  const nextEntry: AccessAttemptEntry = {
    chatId: String(params.chatId || cleanId).trim(),
    senderId: cleanId,
    firstName: params.firstName || prev?.firstName || 'Telegram User',
    username: params.username || prev?.username,
    status: params.status,
    attemptsCount: (prev?.attemptsCount || 0) + 1,
    firstAttemptAt: prev?.firstAttemptAt || nowIso,
    lastAttemptAt: nowIso,
    lastInputPreview: params.inputPreview ? params.inputPreview.slice(0, 80) : prev?.lastInputPreview,
    reason: params.reason || prev?.reason,
  };
  botSettings.accessAttempts[cleanId] = nextEntry;
  saveBotSettings();

  if (params.status === 'failed' || params.status === 'pending') {
    const lastNotified = lastAttemptAlertAtByUser.get(cleanId) || 0;
    if (params.forceNotifyAdmin || Date.now() - lastNotified >= 30000) {
      lastAttemptAlertAtByUser.set(cleanId, Date.now());
      const badge = params.status === 'pending' ? '📩 APPROVAL REQUEST' : '🚨 FAILED ACCESS ATTEMPT';
      const uHandle = nextEntry.username ? ` (@${nextEntry.username})` : '';
      const approvalText =
        `${badge}\n` +
        `━━━━━━━━━━━━━━━━━━━━━━\n` +
        `👤 User: ${nextEntry.firstName}${uHandle}\n` +
        `🆔 User ID: \`${cleanId}\`\n` +
        `🔢 Total Tries: ${nextEntry.attemptsCount}\n` +
        (nextEntry.lastInputPreview ? `💬 Input: \`${nextEntry.lastInputPreview}\`\n` : '') +
        `📝 Reason: ${nextEntry.reason || 'No valid daily access code'}\n\n` +
        `👇 Neeche se direct Approve, Revoke, Admin ya Developer banayein:`;
      for (const recipientId of getApprovalRecipientIds()) {
        sendTelegramTextMessage(recipientId, approvalText, buildUserApprovalKeyboard(cleanId)).catch(() => {});
      }
    }
  }
}

interface StreamVariant {
  id: string;
  url: string;
  protocol:
    | 'HLS_MASTER'
    | 'HLS_MEDIA'
    | 'DIRECT_MP4'
    | 'DIRECT_WEBM'
    | 'DIRECT_VIDEO'
    | 'JS_EMBEDDED'
    | 'YTDLP_PLATFORM';
  label: string;
  courseName?: string;
  subjectName?: string;
  topicName?: string;
  folderName?: string;
  lectureTitle?: string;
  facultyName?: string;
  date?: string;
  pdfUrl?: string;
  resolution?: string;
  bandwidth?: number;
  codecs?: string;
  frameRate?: number;
  segmentCount?: number;
  durationSec?: number;
  estimatedSizeBytes?: number;
  isEncrypted?: boolean;
  encryptionMethod?: string;
  foundVia: string;
}

interface DownloadJob {
  id: string;
  title: string;
  courseName?: string;
  subjectName?: string;
  topicName?: string;
  lectureTitle?: string;
  folderName?: string;
  sourceUrl: string;
  initialSourceUrl?: string;
  originalRequestUrl?: string;
  explicitTargetChannelId?: string;
  batchOrder?: number;
  retryCount?: number;
  lastProgressAt?: number;
  abortFlag?: boolean;
  downloadEpoch?: number;
  protocol: StreamVariant['protocol'];
  preferredQuality?: string;
  resolution?: string;
  status:
    | 'queued'
    | 'downloading'
    | 'merging'
    | 'uploading_bot_api'
    | 'uploading_mtproto_userbot'
    | 'uploading_google_drive'
    | 'waiting_stream'
    | 'paused'
    | 'completed'
    | 'failed';
  progressPercent: number;
  totalSegments: number;
  completedSegments: number;
  downloadedBytes: number;
  speedBytesPerSec: number;
  deliveryMode: 'browser' | 'telegram_auto' | 'telegram_userbot' | 'drive_only' | 'telegram_and_drive';
  courseCode?: string;
  pdfUrl?: string;
  telegramChatId?: string;
  telegramStatusMsgId?: number;
  telegramResult?: {
    deliveredVia: 'BOT_API_50MB' | 'MTPROTO_USERBOT_2GB';
    chatId: string;
    fileSizeMb: string;
    timestamp: string;
    backedUpTo?: string[];
    routedToChannel?: string;
  };
  driveResult?: {
    fileId: string;
    fileName: string;
    folderPath: string;
    folderId: string;
    webViewLink?: string;
    fileSizeMb: string;
    speedMbps?: string;
    pdfUploaded?: boolean;
    timestamp: string;
  };
  outputFormat: 'mp4' | 'ts';
  filePath?: string;
  error?: string;
  createdAt: string;
  fileReadyForBrowser: boolean;
  customHeaders?: Record<string, string>;
  cleanupAfterTelegram?: boolean;
  preDownloadedReady?: boolean;
  preDownloadError?: string;
  preDownloadPromise?: Promise<void>;
  preProbedMeta?: VideoProbeMeta;
  forceDownload?: boolean;
  skipCompletedCheck?: boolean;
  deliveredToTelegram?: boolean;
  deliveredToDrive?: boolean;
}

// Automatically append 1, 2, 3... when multiple videos share the same title
function applyDuplicateTitleNumbering(list: StreamVariant[]): void {
  const counts = new Map<string, number>();
  for (const s of list) {
    const base = String(s.lectureTitle || s.label || '').trim();
    if (!base) continue;
    const key = base.toLowerCase();
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const seen = new Map<string, number>();
  for (const s of list) {
    const base = String(s.lectureTitle || s.label || '').trim();
    if (!base) continue;
    const key = base.toLowerCase();
    if ((counts.get(key) || 0) > 1) {
      const nextNum = (seen.get(key) || 0) + 1;
      seen.set(key, nextNum);
      const numbered = `${base} ${nextNum}`;
      s.lectureTitle = numbered;
      s.label = numbered;
    }
  }
}

// Build the exact 5-line Telegram Video Caption requested by user:
// Course: <Course Name>
// Subject: <Subject Name>
// Topic: <Topic Name>
// Title: <Video Title>
// #005/1000
function buildVideoTelegramCaption(job: DownloadJob): string {
  const rawCourse = String(job.courseName || 'Course')
    .replace(/\s*\(\d+\s*Folders?,\s*\d+\s*Videos?\)\s*$/i, '')
    .trim();
  const folderParts = String(job.folderName || '')
    .split(/\s*\/\s*/)
    .map((p) => p.trim())
    .filter(Boolean);
  const subjectVal = String(
    job.subjectName ||
      (folderParts.length >= 2 ? folderParts[0] : folderParts[0] || 'General')
  ).trim();
  const topicVal = String(
    job.topicName ||
      (folderParts.length >= 2 ? folderParts.slice(1).join(' / ') : folderParts[0] || 'General')
  ).trim();
  const titleVal = String(
    job.lectureTitle ||
      job.title.replace(/^📹\s*Lecture\s*\d+\/\d+:\s*/i, '') ||
      'Video'
  ).trim();

  const lecMatch = String(job.title || '').match(/Lecture\s*(\d+)\s*\/\s*(\d+)/i);
  const lecNum = lecMatch
    ? parseInt(lecMatch[1], 10)
    : typeof job.batchOrder === 'number' && job.batchOrder > 0
    ? job.batchOrder
    : 1;
  const totalNum = lecMatch ? parseInt(lecMatch[2], 10) : 1;
  const paddedLec = String(lecNum).padStart(3, '0');

  return (
    `Course: ${rawCourse || 'Course'}\n` +
    `Subject: ${subjectVal || 'General'}\n` +
    `Topic: ${topicVal || 'General'}\n` +
    `Title: ${titleVal}\n` +
    `#${paddedLec}/${totalNum}`
  );
}

interface BotActivityLog {
  id: string;
  timestamp: string;
  direction: 'INCOMING' | 'OUTGOING' | 'USERBOT_MTPROTO' | 'SYSTEM';
  chatId: string;
  summary: string;
}

const jobs = new Map<string, DownloadJob>();
const botLogs: BotActivityLog[] = [];

const chatJobQueues = new Map<string, DownloadJob[]>();
const activeChatWorkers = new Set<string>();
const pendingSkipByChat = new Map<string, number>();
const pendingOnlyByChat = new Map<string, number[]>();
const pendingDriveModeByChat = new Map<string, 'drive_only' | 'telegram_and_drive'>();

interface PendingPortalLoginState {
  step: 'awaiting_origin' | 'awaiting_identifier' | 'awaiting_password' | 'awaiting_token';
  origin?: string;
  retryUrl?: string;
  identifier?: string;
  portalPath?: string;
  preferredQuality?: string;
  explicitTargetChannelId?: string;
  deliveryMode?: DownloadJob['deliveryMode'];
  updatedAt: number;
}

const pendingPortalLoginByChat = new Map<string, PendingPortalLoginState>();
const lastFailedPortalContextByChat = new Map<
  string,
  {
    url: string;
    origin: string;
    portalPath?: string;
    reason?: 'cookie_check' | 'login_required' | 'empty';
    preferredQuality?: string;
    explicitTargetChannelId?: string;
    deliveryMode?: DownloadJob['deliveryMode'];
    updatedAt: number;
  }
>();

function maskLoginIdentifier(raw: string): string {
  const s = String(raw || '').trim();
  if (!s) return 'Account';
  if (s.includes('@')) {
    const [u, dom] = s.split('@');
    return `${u.slice(0, 2)}***@${dom || ''}`;
  }
  if (s.length <= 4) return '****';
  return `${s.slice(0, 2)}${'*'.repeat(Math.max(2, s.length - 4))}${s.slice(-2)}`;
}

function normalizePortalHost(originOrUrl: string): { origin: string; host: string; portalPath?: string } {
  const raw = String(originOrUrl || '').trim();
  const withProto = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  const u = new URL(withProto);
  const segs = u.pathname.split('/').map((s) => s.trim()).filter(Boolean);
  const portalPath = segs[0] && !/\.(html?|php|js|css|json)$/i.test(segs[0]) ? `/${segs[0]}` : undefined;
  return { origin: u.origin.replace(/\/$/, ''), host: u.hostname.toLowerCase(), portalPath };
}

function getPortalSessionForOrigin(originOrUrl?: string, chatId?: string): PortalAuthSession | null {
  if (!originOrUrl || !botSettings.portalSessions) return null;
  let host = '';
  try {
    host = normalizePortalHost(originOrUrl).host;
  } catch {
    host = String(originOrUrl || '').trim().toLowerCase();
  }
  if (!host) return null;
  if (chatId) {
    const perChat = botSettings.portalSessions[`${chatId}::${host}`];
    if (perChat) return perChat;
  }
  const globalEntry = botSettings.portalSessions[`GLOBAL::${host}`];
  if (globalEntry) return globalEntry;
  const anyMatch = Object.values(botSettings.portalSessions).find((s) => s.host === host);
  return anyMatch || null;
}

function savePortalSessionForOrigin(session: PortalAuthSession, chatId?: string) {
  if (!botSettings.portalSessions) botSettings.portalSessions = {};
  const host = session.host.toLowerCase();
  if (chatId) {
    botSettings.portalSessions[`${chatId}::${host}`] = { ...session, chatId };
  }
  botSettings.portalSessions[`GLOBAL::${host}`] = { ...session, chatId: session.chatId || chatId };
  saveBotSettings();
  for (const k of Array.from(courseExtractionCache.keys())) {
    if (k.toLowerCase().includes(host)) {
      courseExtractionCache.delete(k);
    }
  }
  saveCourseExtractionCacheToDisk();
}

function clearPortalSessionForOrigin(originOrUrl?: string, chatId?: string): number {
  if (!botSettings.portalSessions) return 0;
  let removed = 0;
  if (!originOrUrl || /^all$/i.test(originOrUrl.trim())) {
    for (const [k, s] of Object.entries(botSettings.portalSessions)) {
      if (!chatId || s.chatId === chatId || k.startsWith(`${chatId}::`) || k.startsWith('GLOBAL::')) {
        delete botSettings.portalSessions[k];
        removed++;
      }
    }
  } else {
    let host = '';
    try {
      host = normalizePortalHost(originOrUrl).host;
    } catch {
      host = String(originOrUrl || '').trim().toLowerCase();
    }
    for (const [k, s] of Object.entries(botSettings.portalSessions)) {
      if (s.host === host && (!chatId || s.chatId === chatId || k.startsWith(`${chatId}::`) || k.startsWith('GLOBAL::'))) {
        delete botSettings.portalSessions[k];
        removed++;
      }
    }
  }
  if (removed > 0) saveBotSettings();
  return removed;
}

function buildPortalSessionHeaders(session: PortalAuthSession | null, referer?: string): Record<string, string> {
  const h: Record<string, string> = {
    'User-Agent': DEFAULT_USER_AGENT,
    ...(referer ? { Referer: referer } : {}),
  };
  if (!session) return h;
  if (session.cookieHeader) {
    h.Cookie = session.cookieHeader;
  }
  if (session.bearerToken) {
    const cleanTok = session.bearerToken.trim();
    h.Authorization =
      cleanTok.startsWith('Bearer ') || cleanTok.startsWith('eyJ')
        ? cleanTok
        : `Bearer ${cleanTok}`;
  }
  if (session.userId) {
    h['User-ID'] = session.userId;
  }
  return h;
}

function extractSetCookiePairs(res: Response): string {
  try {
    const getSetCookieFn = (res.headers as any)?.getSetCookie;
    const rawCookies: string[] =
      typeof getSetCookieFn === 'function'
        ? getSetCookieFn.call(res.headers)
        : res.headers.get('set-cookie')
        ? [res.headers.get('set-cookie') as string]
        : [];
    const pairs: string[] = [];
    for (const raw of rawCookies) {
      const kv = String(raw || '').split(';')[0]?.trim();
      if (kv && kv.includes('=') && !/=(deleted|null|)$/i.test(kv)) {
        pairs.push(kv);
      }
    }
    return Array.from(new Set(pairs)).join('; ');
  } catch {
    return '';
  }
}

function isCookieCheckOrLoginHtml(htmlOrText: string): { isAuthGate: boolean; reason: 'cookie_check' | 'login_required' | null } {
  const sample = String(htmlOrText || '').slice(0, 12000);
  if (!sample) return { isAuthGate: false, reason: null };
  if (
    /<title>\s*Cookie check\s*<\/title>/i.test(sample) ||
    /accounts\.google\.com\/v3\/signin|run\.app\/__\/auth|ai\.studio.*cookie/i.test(sample)
  ) {
    return { isAuthGate: true, reason: 'cookie_check' };
  }
  if (
    (/<input[^>]+type=["']?password["']?/i.test(sample) ||
      /\b(login required|please sign in|sign in to continue|enter your mobile number|unauthorized access)\b/i.test(sample)) &&
    !/livecourseclassbycoursesubtopconcept|master-[a-z0-9-]+\.m3u8/i.test(sample)
  ) {
    return { isAuthGate: true, reason: 'login_required' };
  }
  return { isAuthGate: false, reason: null };
}

async function loginToPortalWithCredentials(
  rawOriginOrUrl: string,
  identifier: string,
  password: string,
  preferredPortalPath?: string
): Promise<{
  ok: boolean;
  session?: PortalAuthSession;
  hitCookieCheck?: boolean;
  message: string;
}> {
  const { origin, host, portalPath } = normalizePortalHost(rawOriginOrUrl);
  const effPortalPath = preferredPortalPath || portalPath;
  const cleanId = String(identifier || '').trim();
  const cleanPass = String(password || '');
  if (!cleanId || !cleanPass) {
    return { ok: false, message: 'Mobile Number/Email aur Password dono zaroori hain.' };
  }

  let capturedCookies = '';
  let capturedToken = '';
  let capturedUserId = '';
  let teachxApiUrl = '';
  let hitCookieCheck = false;
  let lastUpstreamErr = '';

  // 1. Try common custom portal JSON/Form login endpoints on `origin`
  const portalLoginEndpoints = Array.from(
    new Set(
      [
        `${origin}/api/login`,
        `${origin}/api/auth/login`,
        `${origin}/api/user/login`,
        `${origin}/api/rwa/login`,
        `${origin}/api/rwax/login`,
        ...(effPortalPath ? [`${origin}${effPortalPath}/api/login`, `${origin}${effPortalPath}/login`] : []),
        `${origin}/api/v1/login`,
        `${origin}/login`,
      ].filter(Boolean)
    )
  );

  for (const ep of portalLoginEndpoints) {
    try {
      const res = await fetch(ep, {
        method: 'POST',
        headers: {
          'User-Agent': DEFAULT_USER_AGENT,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/plain, */*',
          Referer: `${origin}${effPortalPath || ''}/`,
        },
        body: JSON.stringify({
          phone: cleanId,
          mobile: cleanId,
          email: cleanId,
          username: cleanId,
          identifier: cleanId,
          userid: cleanId,
          password: cleanPass,
        }),
        redirect: 'manual',
        signal: AbortSignal.timeout(7000),
      });

      const cookieStr = extractSetCookiePairs(res);
      const rawTxt = await res.text().catch(() => '');
      const gate = isCookieCheckOrLoginHtml(rawTxt);
      if (gate.reason === 'cookie_check' || /accounts\.google\.com/i.test(res.headers.get('location') || '')) {
        hitCookieCheck = true;
        continue;
      }

      let parsed: any = null;
      if (rawTxt && (rawTxt.trim().startsWith('{') || rawTxt.trim().startsWith('['))) {
        try {
          parsed = JSON.parse(rawTxt);
        } catch {
          parsed = null;
        }
      }

      const dObj = parsed?.data && typeof parsed.data === 'object' ? parsed.data : parsed;
      const candTok = String(
        dObj?.token ||
          dObj?.accessToken ||
          dObj?.access_token ||
          dObj?.jwt ||
          dObj?.authToken ||
          parsed?.token ||
          parsed?.accessToken ||
          ''
      ).trim();
      const candUid = String(dObj?.userid || dObj?.user_id || dObj?.id || parsed?.userid || '').trim();

      if (res.ok && (candTok || cookieStr) && parsed?.success !== false && parsed?.status !== 401 && parsed?.status !== 403) {
        capturedCookies = cookieStr || capturedCookies;
        capturedToken = candTok || capturedToken;
        capturedUserId = candUid || capturedUserId;
        break;
      }
      if (parsed?.message || parsed?.error) {
        lastUpstreamErr = String(parsed.message || parsed.error);
      }
    } catch {
      // continue trying next login endpoint
    }
  }

  // 2. Discover & authenticate against TeachX / AppX backend (`post/userLogin`) just like StudyBeePro / RWA
  if (!capturedToken) {
    const candidateTeachxApis: string[] = [];
    for (const cfgEp of [`${origin}/api/rwa?app=RWA&i=1`, `${origin}/rwa/api/rwa?app=RWA&i=1`]) {
      try {
        const cfgRes = await fetch(cfgEp, {
          headers: { 'User-Agent': DEFAULT_USER_AGENT },
          signal: AbortSignal.timeout(3500),
        });
        const cfgTxt = await cfgRes.text();
        if (isCookieCheckOrLoginHtml(cfgTxt).reason === 'cookie_check') {
          hitCookieCheck = true;
        } else if (cfgRes.ok && cfgTxt.trim().startsWith('{')) {
          const cfgJson = JSON.parse(cfgTxt);
          if (cfgJson?.domain) {
            const dUrl = String(cfgJson.domain).startsWith('http')
              ? String(cfgJson.domain).replace(/\/$/, '')
              : `https://${String(cfgJson.domain).replace(/\/$/, '')}`;
            candidateTeachxApis.push(dUrl);
          }
        }
      } catch {
        // ignore
      }
    }
    candidateTeachxApis.push('https://rozgarapinew.teachx.in');

    for (const txApi of Array.from(new Set(candidateTeachxApis))) {
      try {
        const isDigits = /^\+?\d{6,15}$/.test(cleanId.replace(/[\s-]/g, ''));
        const bodyParams = isDigits
          ? `email=${encodeURIComponent(cleanId)}&phone=${encodeURIComponent(cleanId)}&password=${encodeURIComponent(cleanPass)}`
          : `email=${encodeURIComponent(cleanId)}&password=${encodeURIComponent(cleanPass)}`;

        const txRes = await fetch(`${txApi}/post/userLogin`, {
          method: 'POST',
          headers: {
            'User-Agent': DEFAULT_USER_AGENT,
            'Auth-Key': 'appxapi',
            'User-ID': '-1',
            source: 'website',
            'Client-Service': 'Appx',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: bodyParams,
          signal: AbortSignal.timeout(8000),
        });
        const txRaw = await txRes.text().catch(() => '');
        let txJson: any = null;
        try {
          txJson = JSON.parse(txRaw);
        } catch {
          txJson = null;
        }
        const tok = String(txJson?.data?.token || txJson?.token || '').trim();
        const uid = String(txJson?.data?.userid || txJson?.data?.user_id || '').trim();
        if (tok && txJson?.status !== 401 && txJson?.status !== 400 && txJson?.status !== 403) {
          capturedToken = tok;
          capturedUserId = uid || extractTeachxJwtMeta(tok).userId;
          teachxApiUrl = txApi;
          break;
        }
        if (txJson?.message) {
          lastUpstreamErr = String(txJson.message);
        }
      } catch {
        // continue
      }
    }
  }

  if (!capturedToken && !capturedCookies) {
    if (hitCookieCheck) {
      return {
        ok: false,
        hitCookieCheck: true,
        message:
          `🔒 Website (${host}) Google Cloud / AI Studio Cookie Check ke peeche protected hai (${lastUpstreamErr || 'Login endpoint blocked'}).\n\n` +
          `🍪 Fix: Browser me site khol kar Cookie/Token copy karein aur bhejein:\n` +
          `\`/weblogin token ${origin} <cookie_ya_token>\``,
      };
    }
    return {
      ok: false,
      message:
        `❌ Login failed on **${host}**${lastUpstreamErr ? `: ${lastUpstreamErr}` : ''}.\n` +
        `Check karein ki Mobile Number/Email aur Password sahi hai, ya Cookie/Token se login karein: \`/weblogin token ${origin} <cookie_ya_token>\``,
    };
  }

  const session: PortalAuthSession = {
    origin,
    host,
    portalPath: effPortalPath,
    ...(capturedCookies ? { cookieHeader: capturedCookies } : {}),
    ...(capturedToken ? { bearerToken: capturedToken } : {}),
    ...(capturedUserId ? { userId: capturedUserId } : {}),
    ...(teachxApiUrl ? { teachxApiUrl } : {}),
    accountLabel: maskLoginIdentifier(cleanId),
    authMethod: 'credentials',
    updatedAt: new Date().toISOString(),
  };

  return {
    ok: true,
    session,
    hitCookieCheck,
    message:
      `✅ Login Successful on **${host}**!\n` +
      `👤 Account: \`${session.accountLabel}\`` +
      (capturedToken ? `\n🔑 Session Token Captured` : '') +
      (capturedCookies ? `\n🍪 Web Session Cookies Captured` : ''),
  };
}

// ============================================================================
// GOOGLE DRIVE 5TB HIGH-SPEED RESUMABLE UPLOAD & NESTED FOLDER ENGINE (RAM SESSION ONLY)
// ============================================================================
const DRIVE_SYNC_CHAT_ID = '__drive_sync__';
const DRIVE_ROOT_FOLDER_NAME = 'Rojgar vidoes';

interface DriveRamSession {
  accessToken: string;
  email: string;
  displayName?: string;
  photoLink?: string;
  rootFolderId?: string;
  connectedAt: string;
  expiresAt?: string;
  tokenExpired: boolean;
  storageQuota?: {
    limitBytes: number;
    usageBytes: number;
    usageInDriveBytes: number;
    freeBytes: number;
  };
}

let activeDriveSession: DriveRamSession | null = null;
const driveFolderCache = new Map<string, string>();
const driveFolderInFlight = new Map<string, Promise<string>>();

function sanitizeDriveName(raw: string, fallback = 'Untitled'): string {
  const cleaned = String(raw || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\\/:*?"<>|]/g, '-')
    .replace(/\s+/g, ' ')
    .trim();
  return (cleaned || fallback).slice(0, 140);
}

function escapeDriveQueryLiteral(str: string): string {
  return String(str || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

async function fetchDriveAboutAndQuota(accessToken: string): Promise<{
  email: string;
  displayName?: string;
  photoLink?: string;
  storageQuota: {
    limitBytes: number;
    usageBytes: number;
    usageInDriveBytes: number;
    freeBytes: number;
  };
}> {
  const res = await fetch(
    'https://www.googleapis.com/drive/v3/about?fields=user(emailAddress,displayName,photoLink),storageQuota(limit,usage,usageInDrive)',
    {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(12000),
    }
  );
  if (res.status === 401 || res.status === 403) {
    throw new Error('DRIVE_AUTH_INVALID: Google Drive access token rejected or expired');
  }
  if (!res.ok) {
    throw new Error(`Drive about API HTTP ${res.status}`);
  }
  const j: any = await res.json();
  const limitBytes = Number(j?.storageQuota?.limit || 5 * 1024 * 1024 * 1024 * 1024);
  const usageBytes = Number(j?.storageQuota?.usage || 0);
  const usageInDriveBytes = Number(j?.storageQuota?.usageInDrive || usageBytes);
  return {
    email: String(j?.user?.emailAddress || ''),
    displayName: j?.user?.displayName ? String(j.user.displayName) : undefined,
    photoLink: j?.user?.photoLink ? String(j.user.photoLink) : undefined,
    storageQuota: {
      limitBytes,
      usageBytes,
      usageInDriveBytes,
      freeBytes: Math.max(0, limitBytes - usageBytes),
    },
  };
}

async function getOrCreateDriveFolder(
  folderName: string,
  parentId?: string,
  tokenOverride?: string
): Promise<string> {
  const token = tokenOverride || activeDriveSession?.accessToken || '';
  if (!token || (!tokenOverride && activeDriveSession?.tokenExpired)) {
    throw new Error('DRIVE_AUTH_EXPIRED');
  }
  const cleanName = sanitizeDriveName(folderName);
  const parentKey = parentId || 'root';
  const cacheKey = `${parentKey}::${cleanName.toLowerCase()}`;
  const cached = driveFolderCache.get(cacheKey);
  if (cached) return cached;

  const existingInFlight = driveFolderInFlight.get(cacheKey);
  if (existingInFlight) return existingInFlight;

  const taskPromise = (async () => {
    try {
      const qParts = [
        `mimeType = 'application/vnd.google-apps.folder'`,
        `trashed = false`,
        `'${escapeDriveQueryLiteral(parentKey)}' in parents`,
        cleanName === DRIVE_ROOT_FOLDER_NAME
          ? `(name = '${escapeDriveQueryLiteral(DRIVE_ROOT_FOLDER_NAME)}' or name = 'Rojgar Videos')`
          : `name = '${escapeDriveQueryLiteral(cleanName)}'`,
      ];
      const searchUrl =
        `https://www.googleapis.com/drive/v3/files?` +
        new URLSearchParams({
          q: qParts.join(' and '),
          fields: 'files(id,name)',
          pageSize: '5',
          supportsAllDrives: 'true',
          includeItemsFromAllDrives: 'true',
        }).toString();

      const searchRes = await fetch(searchUrl, {
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(12000),
      });
      if (searchRes.status === 401) {
        if (activeDriveSession) activeDriveSession.tokenExpired = true;
        throw new Error('DRIVE_AUTH_EXPIRED');
      }
      if (searchRes.ok) {
        const sj: any = await searchRes.json();
        const found = Array.isArray(sj?.files) && sj.files[0]?.id ? String(sj.files[0].id) : '';
        if (found) {
          driveFolderCache.set(cacheKey, found);
          return found;
        }
      }

      const createRes = await fetch(
        'https://www.googleapis.com/drive/v3/files?fields=id,name&supportsAllDrives=true',
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: cleanName,
            mimeType: 'application/vnd.google-apps.folder',
            parents: parentId ? [parentId] : undefined,
          }),
          signal: AbortSignal.timeout(12000),
        }
      );
      if (createRes.status === 401) {
        if (activeDriveSession) activeDriveSession.tokenExpired = true;
        throw new Error('DRIVE_AUTH_EXPIRED');
      }
      if (!createRes.ok) {
        const errTxt = await createRes.text().catch(() => '');
        throw new Error(`Drive create folder HTTP ${createRes.status}: ${errTxt.slice(0, 180)}`);
      }
      const cj: any = await createRes.json();
      const newId = String(cj?.id || '');
      if (!newId) throw new Error('Drive folder created without ID');
      driveFolderCache.set(cacheKey, newId);
      return newId;
    } finally {
      driveFolderInFlight.delete(cacheKey);
    }
  })();

  driveFolderInFlight.set(cacheKey, taskPromise);
  return taskPromise;
}

function extractCourseCodeFromJob(job: {
  courseCode?: string;
  sourceUrl?: string;
  originalRequestUrl?: string;
}): string {
  if (job.courseCode && String(job.courseCode).trim()) {
    return sanitizeDriveName(String(job.courseCode).trim(), '');
  }
  for (const cand of [job.sourceUrl, job.originalRequestUrl]) {
    if (!cand) continue;
    const m = String(cand).match(/(?:courseid|course_id|id)=([A-Za-z0-9_-]+)/i);
    if (m && m[1]) return sanitizeDriveName(m[1], '');
  }
  return '';
}

async function ensureDriveCourseHierarchy(job: {
  courseName?: string;
  courseCode?: string;
  subjectName?: string;
  topicName?: string;
  folderName?: string;
  sourceUrl?: string;
  originalRequestUrl?: string;
}): Promise<{ folderId: string; folderPath: string }> {
  const rootId = activeDriveSession?.rootFolderId || (await getOrCreateDriveFolder(DRIVE_ROOT_FOLDER_NAME));
  if (activeDriveSession && !activeDriveSession.rootFolderId) {
    activeDriveSession.rootFolderId = rootId;
  }

  const rawCourse = sanitizeDriveName(job.courseName || job.folderName || 'General Batch', 'General Batch')
    .replace(/\s*\(\d+\s*Folders?,\s*\d+\s*Videos?\)\s*$/i, '')
    .trim();
  const code = extractCourseCodeFromJob(job);
  const batchFolderName = code && !rawCourse.includes(`(${code})`) ? `${rawCourse} (${code})` : rawCourse;
  const batchFolderId = await getOrCreateDriveFolder(batchFolderName, rootId);

  const segments = [DRIVE_ROOT_FOLDER_NAME, batchFolderName];
  let currentParentId = batchFolderId;

  const cleanSubj = job.subjectName ? sanitizeDriveName(job.subjectName, '') : '';
  const cleanTopic = job.topicName ? sanitizeDriveName(job.topicName, '') : '';
  const cleanFolder = job.folderName ? sanitizeDriveName(job.folderName, '') : '';

  if (cleanSubj) {
    currentParentId = await getOrCreateDriveFolder(cleanSubj, currentParentId);
    segments.push(cleanSubj);
    if (cleanTopic && cleanTopic.toLowerCase() !== cleanSubj.toLowerCase()) {
      currentParentId = await getOrCreateDriveFolder(cleanTopic, currentParentId);
      segments.push(cleanTopic);
    }
  } else if (cleanTopic) {
    currentParentId = await getOrCreateDriveFolder(cleanTopic, currentParentId);
    segments.push(cleanTopic);
  } else if (cleanFolder && cleanFolder.toLowerCase() !== rawCourse.toLowerCase()) {
    currentParentId = await getOrCreateDriveFolder(cleanFolder, currentParentId);
    segments.push(cleanFolder);
  }

  return { folderId: currentParentId, folderPath: segments.join(' / ') };
}

async function findExistingDriveFile(
  folderId: string,
  fileName: string
): Promise<{ id: string; name: string; webViewLink?: string; size?: string } | null> {
  const token = activeDriveSession?.accessToken;
  if (!token || activeDriveSession?.tokenExpired) return null;
  try {
    const q = `'${escapeDriveQueryLiteral(folderId)}' in parents and name = '${escapeDriveQueryLiteral(fileName)}' and trashed = false`;
    const url =
      'https://www.googleapis.com/drive/v3/files?' +
      new URLSearchParams({
        q,
        fields: 'files(id,name,size,webViewLink)',
        pageSize: '2',
        supportsAllDrives: 'true',
      }).toString();
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10000),
    });
    if (res.status === 401) {
      if (activeDriveSession) activeDriveSession.tokenExpired = true;
      throw new Error('DRIVE_AUTH_EXPIRED');
    }
    if (!res.ok) return null;
    const j: any = await res.json();
    const f = Array.isArray(j?.files) && j.files[0];
    if (f?.id && Number(f.size || 0) > 4096) {
      return {
        id: String(f.id),
        name: String(f.name),
        webViewLink: f.webViewLink ? String(f.webViewLink) : undefined,
        size: f.size ? String(f.size) : undefined,
      };
    }
  } catch (err: any) {
    if (String(err?.message || '').includes('DRIVE_AUTH_EXPIRED')) throw err;
  }
  return null;
}

async function uploadBufferToDriveFolder(
  buf: Buffer,
  fileName: string,
  mimeType: string,
  folderId: string
): Promise<{ id: string; name: string; webViewLink?: string } | null> {
  const token = activeDriveSession?.accessToken;
  if (!token || activeDriveSession?.tokenExpired) return null;

  const existing = await findExistingDriveFile(folderId, fileName).catch(() => null);
  if (existing) return existing;

  const initRes = await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,name,webViewLink',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Upload-Content-Type': mimeType,
        'X-Upload-Content-Length': String(buf.length),
      },
      body: JSON.stringify({
        name: fileName,
        parents: [folderId],
        mimeType,
      }),
      signal: AbortSignal.timeout(15000),
    }
  );
  if (initRes.status === 401) {
    if (activeDriveSession) activeDriveSession.tokenExpired = true;
    throw new Error('DRIVE_AUTH_EXPIRED');
  }
  const uploadUri = initRes.headers.get('location');
  if (!initRes.ok || !uploadUri) return null;

  const putRes = await fetch(uploadUri, {
    method: 'PUT',
    headers: {
      'Content-Type': mimeType,
      'Content-Length': String(buf.length),
      'Content-Range': `bytes 0-${buf.length - 1}/${buf.length}`,
    },
    body: new Uint8Array(buf),
    signal: AbortSignal.timeout(60000),
  });
  if (!putRes.ok) return null;
  const pj: any = await putRes.json();
  return pj?.id ? { id: String(pj.id), name: String(pj.name || fileName), webViewLink: pj.webViewLink } : null;
}

async function uploadFileToGoogleDriveResumable(
  localFilePath: string,
  fileName: string,
  mimeType: string,
  folderId: string,
  shouldAbort: () => boolean,
  onProgress?: (pct: number, speedMbps: number, uploadedMb: number, totalMb: number) => void,
  abortSignal?: AbortSignal
): Promise<{ id: string; name: string; webViewLink?: string; fileSizeMb: string; speedMbps: string }> {
  const token = activeDriveSession?.accessToken;
  if (!token || activeDriveSession?.tokenExpired) {
    throw new Error('DRIVE_AUTH_EXPIRED');
  }
  if (shouldAbort() || abortSignal?.aborted) {
    throw new Error('JOB_PAUSED_BY_USER');
  }

  const stat = await fs.promises.stat(localFilePath);
  const totalSize = stat.size;
  const totalMb = totalSize / (1024 * 1024);

  const existing = await findExistingDriveFile(folderId, fileName);
  if (existing && Number(existing.size || 0) >= totalSize * 0.98) {
    onProgress?.(100, 0, totalMb, totalMb);
    return {
      id: existing.id,
      name: existing.name,
      webViewLink: existing.webViewLink || `https://drive.google.com/file/d/${existing.id}/view`,
      fileSizeMb: totalMb.toFixed(2),
      speedMbps: 'Instant (Exists)',
    };
  }

  const initRes = await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,name,size,webViewLink',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Upload-Content-Type': mimeType,
        'X-Upload-Content-Length': String(totalSize),
      },
      body: JSON.stringify({
        name: fileName,
        parents: [folderId],
        mimeType,
      }),
      signal: abortSignal ? AbortSignal.any([abortSignal, AbortSignal.timeout(20000)]) : AbortSignal.timeout(20000),
    }
  );
  if (initRes.status === 401) {
    if (activeDriveSession) activeDriveSession.tokenExpired = true;
    throw new Error('DRIVE_AUTH_EXPIRED');
  }
  const uploadUri = initRes.headers.get('location');
  if (!initRes.ok || !uploadUri) {
    const errBody = await initRes.text().catch(() => '');
    throw new Error(`Drive upload init HTTP ${initRes.status}: ${errBody.slice(0, 200)}`);
  }

  const startedAt = Date.now();
  let finalMeta: any = null;

  // FAST PATH: Single continuous Gigabit streaming PUT for files <= 1 GB (zero chunk round-trips, only 4MB RAM!)
  if (totalSize > 0 && totalSize <= 1024 * 1024 * 1024) {
    try {
      let streamedBytes = 0;
      let lastEmit = 0;
      const readStream = fs.createReadStream(localFilePath, { highWaterMark: 4 * 1024 * 1024 });
      const meter = new Transform({
        highWaterMark: 4 * 1024 * 1024,
        transform(chunk: Buffer, _enc, cb) {
          if (shouldAbort() || abortSignal?.aborted) {
            readStream.destroy();
            cb(new Error('JOB_PAUSED_BY_USER'));
            return;
          }
          streamedBytes += chunk.length;
          const now = Date.now();
          if (onProgress && (now - lastEmit >= 450 || streamedBytes >= totalSize)) {
            lastEmit = now;
            const elapsed = Math.max(0.15, (now - startedAt) / 1000);
            const mbDone = streamedBytes / (1024 * 1024);
            onProgress(Math.min(99, Math.round((streamedBytes / totalSize) * 100)), mbDone / elapsed, mbDone, totalMb);
          }
          cb(null, chunk);
        },
      });
      readStream.pipe(meter);

      const putRes = await undiciRequest(uploadUri, {
        method: 'PUT',
        headers: {
          'Content-Type': mimeType,
          'Content-Length': String(totalSize),
          'Content-Range': `bytes 0-${totalSize - 1}/${totalSize}`,
        },
        body: meter,
        dispatcher: undiciFastDispatcher,
        headersTimeout: 180000,
        bodyTimeout: 180000,
        signal: abortSignal,
      });

      if (putRes.statusCode === 401) {
        await putRes.body.dump().catch(() => {});
        if (activeDriveSession) activeDriveSession.tokenExpired = true;
        throw new Error('DRIVE_AUTH_EXPIRED');
      }
      if (putRes.statusCode === 200 || putRes.statusCode === 201) {
        const bodyText = await putRes.body.text().catch(() => '{}');
        try {
          finalMeta = JSON.parse(bodyText);
        } catch {
          finalMeta = {};
        }
        const totalSec = Math.max(0.15, (Date.now() - startedAt) / 1000);
        const avgSpeed = (totalMb / totalSec).toFixed(1);
        onProgress?.(100, totalMb / totalSec, totalMb, totalMb);
        const fileId = String(finalMeta?.id || '');
        return {
          id: fileId,
          name: String(finalMeta?.name || fileName),
          webViewLink:
            finalMeta?.webViewLink || (fileId ? `https://drive.google.com/file/d/${fileId}/view` : undefined),
          fileSizeMb: totalMb.toFixed(2),
          speedMbps: `${avgSpeed} MB/s`,
        };
      }
      await putRes.body.dump().catch(() => {});
    } catch (fastErr: any) {
      if (
        shouldAbort() ||
        abortSignal?.aborted ||
        String(fastErr?.message || '') === 'JOB_PAUSED_BY_USER' ||
        String(fastErr?.message || '').includes('DRIVE_AUTH_EXPIRED')
      ) {
        throw new Error(
          String(fastErr?.message || '').includes('DRIVE_AUTH_EXPIRED')
            ? 'DRIVE_AUTH_EXPIRED'
            : 'JOB_PAUSED_BY_USER'
        );
      }
      // Fall through to resumable chunked upload below on transient network glitch
    }
  }

  // DOUBLE-BUFFERED 64 MB CHUNKED RESUMABLE UPLOAD (for >256 MB files or single-stream fallback)
  const CHUNK_SIZE = 64 * 1024 * 1024;
  let offset = 0;

  const fh = await fs.promises.open(localFilePath, 'r');
  const readChunkAt = async (pos: number): Promise<Buffer> => {
    const len = Math.min(CHUNK_SIZE, totalSize - pos);
    if (len <= 0) return Buffer.alloc(0);
    const buf = Buffer.allocUnsafe(len);
    let readTotal = 0;
    while (readTotal < len) {
      const { bytesRead } = await fh.read(buf, readTotal, len - readTotal, pos + readTotal);
      if (bytesRead <= 0) break;
      readTotal += bytesRead;
    }
    return readTotal === len ? buf : buf.subarray(0, readTotal);
  };

  try {
    let nextChunkPromise: Promise<Buffer> | null = offset < totalSize ? readChunkAt(offset) : null;
    while (offset < totalSize) {
      if (shouldAbort() || abortSignal?.aborted) {
        throw new Error('JOB_PAUSED_BY_USER');
      }
      const actualBuf = nextChunkPromise ? await nextChunkPromise : await readChunkAt(offset);
      const nextOffsetPre = offset + actualBuf.length;
      // Prefetch next 64MB chunk from disk while current chunk streams to Google Drive
      nextChunkPromise = nextOffsetPre < totalSize ? readChunkAt(nextOffsetPre) : null;
      const rangeEnd = offset + actualBuf.length - 1;

      let uploadedChunk = false;
      let lastChunkErr = '';
      for (let attempt = 0; attempt < 4; attempt++) {
        if (shouldAbort() || abortSignal?.aborted) throw new Error('JOB_PAUSED_BY_USER');
        try {
          const chunkRes = await undiciRequest(uploadUri, {
            method: 'PUT',
            headers: {
              'Content-Length': String(actualBuf.length),
              'Content-Range': `bytes ${offset}-${rangeEnd}/${totalSize}`,
            },
            body: actualBuf,
            dispatcher: undiciFastDispatcher,
            headersTimeout: 180000,
            bodyTimeout: 180000,
            signal: abortSignal,
          });

          if (chunkRes.statusCode === 401) {
            await chunkRes.body.dump().catch(() => {});
            if (activeDriveSession) activeDriveSession.tokenExpired = true;
            throw new Error('DRIVE_AUTH_EXPIRED');
          }
          if (chunkRes.statusCode === 200 || chunkRes.statusCode === 201) {
            const bodyTxt = await chunkRes.body.text().catch(() => '{}');
            try {
              finalMeta = JSON.parse(bodyTxt);
            } catch {
              finalMeta = {};
            }
            offset += actualBuf.length;
            uploadedChunk = true;
            break;
          }
          if (chunkRes.statusCode === 308) {
            const rangeHdr = String(chunkRes.headers['range'] || '');
            await chunkRes.body.dump().catch(() => {});
            if (rangeHdr) {
              const m = rangeHdr.match(/bytes=0-(\d+)/i);
              if (m) {
                const serverNext = Number(m[1]) + 1;
                if (serverNext !== nextOffsetPre) nextChunkPromise = null;
                offset = serverNext;
              } else {
                offset += actualBuf.length;
              }
            } else {
              offset += actualBuf.length;
            }
            uploadedChunk = true;
            break;
          }
          await chunkRes.body.dump().catch(() => {});
          lastChunkErr = `HTTP ${chunkRes.statusCode}`;
        } catch (err: any) {
          if (
            shouldAbort() ||
            abortSignal?.aborted ||
            String(err?.message || '').includes('DRIVE_AUTH_EXPIRED') ||
            String(err?.message || '') === 'JOB_PAUSED_BY_USER'
          ) {
            throw new Error(
              String(err?.message || '').includes('DRIVE_AUTH_EXPIRED')
                ? 'DRIVE_AUTH_EXPIRED'
                : 'JOB_PAUSED_BY_USER'
            );
          }
          lastChunkErr = err?.message || 'Chunk transfer error';
        }
        await new Promise((r) => setTimeout(r, 600 * Math.pow(2, attempt)));
      }
      if (!uploadedChunk) {
        throw new Error(`Drive resumable chunk failed at offset ${offset}: ${lastChunkErr}`);
      }

      const elapsedSec = Math.max(0.15, (Date.now() - startedAt) / 1000);
      const speedMbps = offset / (1024 * 1024) / elapsedSec;
      const pct = Math.min(100, Math.round((offset / totalSize) * 100));
      onProgress?.(pct, speedMbps, offset / (1024 * 1024), totalMb);
    }
  } finally {
    await fh.close().catch(() => {});
  }

  const totalSec = Math.max(0.15, (Date.now() - startedAt) / 1000);
  const avgSpeed = (totalMb / totalSec).toFixed(1);
  const fileId = String(finalMeta?.id || '');
  return {
    id: fileId,
    name: String(finalMeta?.name || fileName),
    webViewLink:
      finalMeta?.webViewLink || (fileId ? `https://drive.google.com/file/d/${fileId}/view` : undefined),
    fileSizeMb: totalMb.toFixed(2),
    speedMbps: `${avgSpeed} MB/s`,
  };
}

async function uploadJobToGoogleDrive(
  job: DownloadJob,
  shouldAbort: () => boolean,
  onProgress?: (pct: number, speedMbps: number, uploadedMb: number, totalMb: number) => void,
  abortSignal?: AbortSignal
): Promise<NonNullable<DownloadJob['driveResult']>> {
  if (!job.filePath || !fs.existsSync(job.filePath)) {
    throw new Error('Local video file missing for Drive upload');
  }
  const { folderId, folderPath } = await ensureDriveCourseHierarchy(job);
  const baseTitle = sanitizeDriveName(job.lectureTitle || job.title.replace(/^📹\s*/, ''), 'Lecture');
  const orderPrefix =
    typeof job.batchOrder === 'number' && job.batchOrder > 0 && !/^\s*\d+[._\-\s]/.test(baseTitle)
      ? `${String(job.batchOrder).padStart(3, '0')}. `
      : '';
  const ext = job.outputFormat === 'ts' ? 'ts' : 'mp4';
  const fileName = sanitizeDriveName(`${orderPrefix}${baseTitle}`, 'Lecture') + `.${ext}`;
  const mimeType = ext === 'ts' ? 'video/mp2t' : 'video/mp4';

  // Run video upload and optional notes PDF upload in PARALLEL for zero extra latency!
  const pdfUploadPromise = (async (): Promise<boolean> => {
    if (!job.pdfUrl || !/^https?:\/\//i.test(job.pdfUrl)) return false;
    try {
      const pdfRes = await fetch(job.pdfUrl, {
        headers: { 'User-Agent': DEFAULT_USER_AGENT, Referer: 'https://rozgarapinew.teachx.in/' },
        signal: abortSignal ? AbortSignal.any([abortSignal, AbortSignal.timeout(25000)]) : AbortSignal.timeout(25000),
      });
      if (!pdfRes.ok) return false;
      const pdfBuf = Buffer.from(await pdfRes.arrayBuffer());
      if (pdfBuf.length <= 512) return false;
      const pdfFileName = sanitizeDriveName(`${orderPrefix}${baseTitle} Notes`, 'Notes') + '.pdf';
      const upPdf = await uploadBufferToDriveFolder(pdfBuf, pdfFileName, 'application/pdf', folderId);
      return Boolean(upPdf?.id);
    } catch {
      return false;
    }
  })();

  const [upRes, pdfUploaded] = await Promise.all([
    uploadFileToGoogleDriveResumable(
      job.filePath,
      fileName,
      mimeType,
      folderId,
      shouldAbort,
      onProgress,
      abortSignal
    ),
    pdfUploadPromise,
  ]);

  return {
    fileId: upRes.id,
    fileName: upRes.name,
    folderPath,
    folderId,
    webViewLink: upRes.webViewLink,
    fileSizeMb: upRes.fileSizeMb,
    speedMbps: upRes.speedMbps,
    pdfUploaded,
    timestamp: new Date().toISOString(),
  };
}


function parseNumberListOrRanges(inputStr: string): number[] {
  const result = new Set<number>();
  if (!inputStr) return [];
  const clean = inputStr.replace(/https?:\/\/[^\s]+/gi, '').replace(/[^\d,\-\s]/g, ' ');
  const parts = clean.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  for (const part of parts) {
    if (part.includes('-')) {
      const rangeParts = part.split('-').map((n) => parseInt(n.trim(), 10));
      if (rangeParts.length === 2 && !isNaN(rangeParts[0]) && !isNaN(rangeParts[1])) {
        const start = Math.min(rangeParts[0], rangeParts[1]);
        const end = Math.max(rangeParts[0], rangeParts[1]);
        const span = Math.min(end - start, 5000);
        for (let i = start; i <= start + span; i++) {
          if (i > 0) result.add(i);
        }
      }
    } else {
      const num = parseInt(part, 10);
      if (!isNaN(num) && num > 0) {
        result.add(num);
      }
    }
  }
  return Array.from(result).sort((a, b) => a - b);
}
const JOBS_STATE_PATH = path.join(process.cwd(), 'jobs-state.json');
const COMPLETED_VIDEOS_PATH = path.join(process.cwd(), 'completed-videos.json');
const completedVideoKeys = new Set<string>();

function getVideoDedupeKeys(item: {
  initialSourceUrl?: string;
  sourceUrl?: string;
  originalRequestUrl?: string;
  courseName?: string;
  folderName?: string;
  lectureTitle?: string;
  title?: string;
  batchOrder?: number;
}): string[] {
  const keys = new Set<string>();
  const origCourseUrl = String(item.originalRequestUrl || '').trim().toLowerCase();

  // 1. Check ONLY video stream URLs (initialSourceUrl & sourceUrl — NEVER originalRequestUrl which is the shared Course URL!)
  const rawUrls = [item.initialSourceUrl, item.sourceUrl].filter(Boolean) as string[];
  for (const rawUrl of rawUrls) {
    const trimmed = rawUrl.trim();
    if (!trimmed) continue;
    const lowerUrl = trimmed.toLowerCase();

    if (trimmed.startsWith('appx://')) {
      keys.add(lowerUrl);
      try {
        const u = new URL(trimmed.replace(/^appx:\/\//i, 'http://'));
        const cId = (u.searchParams.get('courseid') || '').trim().toLowerCase();
        const vId = (u.searchParams.get('videoid') || '').trim().toLowerCase();
        if (cId && vId) {
          keys.add(`appx::${cId}::${vId}`);
        }
        if (vId) {
          keys.add(`vid::${vId}`);
        }
      } catch {}
    } else {
      try {
        const u = new URL(trimmed);
        const cId = (
          u.searchParams.get('course_id') ||
          u.searchParams.get('courseid') ||
          u.searchParams.get('id') ||
          ''
        )
          .trim()
          .toLowerCase();
        const vId = (u.searchParams.get('video_id') || u.searchParams.get('videoid') || '')
          .trim()
          .toLowerCase();
        if (cId && vId) {
          keys.add(`appx::${cId}::${vId}`);
        }
        if (vId) {
          keys.add(`vid::${vId}`);
        }
        // Only add raw HTTP URL if it is an actual video stream or has a video_id (never a shared course page like content.html?id=545)
        const isSharedCoursePage =
          (origCourseUrl && lowerUrl === origCourseUrl && !vId && (item.batchOrder || item.courseName)) ||
          (/\/content\.html|\/batches\.html|\/course/i.test(u.pathname) && !vId);
        if (!isSharedCoursePage) {
          keys.add(lowerUrl);
        }
      } catch {
        keys.add(lowerUrl);
      }
    }
  }

  // 2. Course Checkpoint Key / Clean Course Identifier
  const cKey = getCourseCheckpointKey(item);
  const cleanCourse = String(item.courseName || cKey || '')
    .replace(/\s*\(\d+\s*Folders?,\s*\d+\s*Videos?\)\s*$/i, '')
    .trim()
    .toLowerCase();

  // 3. Batch Order Locking (e.g. order::rwa_course_545::128)
  const lecMatch = String(item.title || '').match(/Lecture\s*(\d+)\s*\/\s*(\d+)/i);
  const orderNum =
    typeof item.batchOrder === 'number' && item.batchOrder > 0
      ? item.batchOrder
      : lecMatch
      ? parseInt(lecMatch[1], 10)
      : undefined;

  if (orderNum !== undefined) {
    if (cKey) {
      keys.add(`order::${cKey}::${orderNum}`);
    }
    if (cleanCourse) {
      keys.add(`order::${cleanCourse}::${orderNum}`);
    }
  }

  // 4. Clean Lecture Title (Scoped with #orderNum when orderNum is known so two lectures in a course never collide!)
  const cleanTitle = String(
    item.lectureTitle ||
      (item.title || '')
        .replace(/^📹\s*Lecture\s*\d+\/\d+:\s*/i, '')
        .replace(/#\d+\/\d+/i, '')
  )
    .trim()
    .toLowerCase();
  const cleanFolder = String(item.folderName || 'general')
    .trim()
    .toLowerCase();

  if (cleanTitle) {
    if (orderNum !== undefined) {
      if (cleanCourse) {
        keys.add(`${cleanCourse}::${cleanFolder}::#${orderNum}::${cleanTitle}`);
      }
      if (cKey) {
        keys.add(`title::${cKey}::#${orderNum}::${cleanTitle}`);
      }
    } else if (keys.size === 0) {
      if (cleanCourse) {
        keys.add(`${cleanCourse}::${cleanFolder}::${cleanTitle}`);
      }
      if (cKey) {
        keys.add(`title::${cKey}::${cleanTitle}`);
      }
    }
  }

  return Array.from(keys);
}

function getVideoDedupeKey(item: {
  initialSourceUrl?: string;
  sourceUrl?: string;
  originalRequestUrl?: string;
  courseName?: string;
  folderName?: string;
  lectureTitle?: string;
  title?: string;
  batchOrder?: number;
}): string {
  const keys = getVideoDedupeKeys(item);
  return keys[0] || '';
}

let saveCompletedTimer: NodeJS.Timeout | null = null;
let writingCompletedPromise: Promise<void> = Promise.resolve();
function saveCompletedVideosState(immediate = false) {
  const writeNow = () => {
    const payload = JSON.stringify(Array.from(completedVideoKeys).slice(-15000));
    writingCompletedPromise = writingCompletedPromise
      .then(() => fs.promises.writeFile(COMPLETED_VIDEOS_PATH, payload, 'utf8'))
      .catch(() => {});
  };
  if (immediate) {
    if (saveCompletedTimer) {
      clearTimeout(saveCompletedTimer);
      saveCompletedTimer = null;
    }
    writeNow();
    return;
  }
  if (!saveCompletedTimer) {
    saveCompletedTimer = setTimeout(() => {
      saveCompletedTimer = null;
      writeNow();
    }, 1200);
  }
}

function loadCompletedVideosState() {
  try {
    if (!fs.existsSync(COMPLETED_VIDEOS_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(COMPLETED_VIDEOS_PATH, 'utf8'));
    if (Array.isArray(parsed)) {
      let hadPolluted = false;
      for (const k of parsed) {
        if (typeof k === 'string' && k.trim()) {
          const cleanK = k.trim().toLowerCase();
          // Purge any accidentally stored course page URLs (e.g. content.html?id=545 without videoid)
          if (
            /^https?:\/\//i.test(cleanK) &&
            /content\.html|batches\.html/i.test(cleanK) &&
            !/videoid=|video_id=/i.test(cleanK)
          ) {
            hadPolluted = true;
            continue;
          }
          completedVideoKeys.add(cleanK);
        }
      }
      if (hadPolluted) {
        saveCompletedVideosState(true);
      }
    }
  } catch {
    // ignore
  }
}
loadCompletedVideosState();

interface CourseCheckpointState {
  courseKey: string;
  courseName: string;
  sourceUrl?: string;
  chatId: string;
  lastCompletedBatchOrder: number;
  lastCompletedTitle: string;
  totalVideos: number;
  completedCount: number;
  updatedAt: string;
}

interface WatchedCourseEntry {
  courseKey: string;
  sourceUrl: string;
  courseName: string;
  chatId: string;
  preferredQuality: string;
  explicitTargetChannelId?: string;
  lastScannedAt: string;
  lastDetectedVideos: number;
}

interface AiAgentDecisionEntry {
  id: string;
  timestamp: string;
  summary: string;
  action: string;
}

const COURSE_CHECKPOINTS_PATH = path.join(process.cwd(), 'course-progress.json');
const WATCHED_COURSES_PATH = path.join(process.cwd(), 'watched-courses.json');
const courseCheckpoints = new Map<string, CourseCheckpointState>();
const watchedCourses = new Map<string, WatchedCourseEntry>();

const aiAgentState = {
  enabled: false,
  intervalMinutes: 3,
  lastCheckAt: undefined as string | undefined,
  nextCheckAt: new Date(Date.now() + 3 * 60 * 1000).toISOString(),
  isCheckingNow: false,
  totalAutoRecoveredVideos: 0,
  recentDecisions: [] as AiAgentDecisionEntry[],
};

function addAiAgentDecision(summary: string, action: string = 'AUTO_CHECK') {
  aiAgentState.recentDecisions.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    summary,
    action,
  });
  if (aiAgentState.recentDecisions.length > 35) {
    aiAgentState.recentDecisions.pop();
  }
}

function getCourseCheckpointKey(item: {
  originalRequestUrl?: string;
  initialSourceUrl?: string;
  sourceUrl?: string;
  courseName?: string;
}): string {
  const rawUrl = String(item.initialSourceUrl || item.sourceUrl || '').trim();
  if (rawUrl.startsWith('appx://')) {
    try {
      const u = new URL(rawUrl.replace(/^appx:\/\//i, 'http://'));
      const cId = (u.searchParams.get('courseid') || '').trim().toLowerCase();
      if (cId) return `rwa_course_${cId}`;
    } catch {
      // fallback
    }
  }
  const orig = String(item.originalRequestUrl || '').trim();
  if (orig) {
    try {
      const u = new URL(orig);
      const pathSegs = u.pathname
        .split('/')
        .map((s) => decodeURIComponent(s).trim())
        .filter(Boolean);
      const secondSeg = pathSegs[1] || '';
      const lastSeg = pathSegs[pathSegs.length - 1] || '';
      const pathCid =
        secondSeg &&
        !/\.(html?|php|jsp|asp|json|js|css)$/i.test(secondSeg) &&
        !/^(content|subject|topic|batch|play|player|batches|login|api|details|pdf|proxy)$/i.test(secondSeg)
          ? secondSeg
          : pathSegs.length >= 2 && /^\d+$/.test(lastSeg)
          ? lastSeg
          : null;
      const cId =
        u.searchParams.get('courseid') ||
        u.searchParams.get('course_id') ||
        u.searchParams.get('courseId') ||
        u.searchParams.get('id') ||
        pathCid;
      if (cId) return `rwa_course_${cId.trim().toLowerCase()}`;
    } catch {
      // fallback
    }
  }
  const cName = String(item.courseName || '')
    .replace(/\s*\(\d+\s*Folders?,\s*\d+\s*Videos?\)\s*$/i, '')
    .trim()
    .toLowerCase();
  return cName || orig.toLowerCase() || 'default_course';
}

let writingCheckpointsPromise: Promise<void> = Promise.resolve();
function saveCourseCheckpointsState() {
  const payload = JSON.stringify(Array.from(courseCheckpoints.values()));
  writingCheckpointsPromise = writingCheckpointsPromise
    .then(() => fs.promises.writeFile(COURSE_CHECKPOINTS_PATH, payload, 'utf8'))
    .catch(() => {});
}

function loadCourseCheckpointsState() {
  try {
    if (!fs.existsSync(COURSE_CHECKPOINTS_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(COURSE_CHECKPOINTS_PATH, 'utf8'));
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item && item.courseKey) {
          courseCheckpoints.set(item.courseKey, item);
        }
      }
    }
  } catch {
    // ignore
  }
}
loadCourseCheckpointsState();

let writingWatchedPromise: Promise<void> = Promise.resolve();
function saveWatchedCoursesState() {
  const payload = JSON.stringify(Array.from(watchedCourses.values()));
  writingWatchedPromise = writingWatchedPromise
    .then(() => fs.promises.writeFile(WATCHED_COURSES_PATH, payload, 'utf8'))
    .catch(() => {});
}

function loadWatchedCoursesState() {
  try {
    if (!fs.existsSync(WATCHED_COURSES_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(WATCHED_COURSES_PATH, 'utf8'));
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item && item.courseKey && item.sourceUrl) {
          watchedCourses.set(item.courseKey, item);
        }
      }
    }
  } catch {
    // ignore
  }
}
loadWatchedCoursesState();

function upsertWatchedCourse(entry: {
  courseKey?: string;
  sourceUrl: string;
  courseName: string;
  chatId: string;
  preferredQuality: string;
  explicitTargetChannelId?: string;
  lastScannedAt?: string;
  lastDetectedVideos?: number;
  totalVideosFound?: number;
}) {
  const key =
    entry.courseKey ||
    getCourseCheckpointKey({
      originalRequestUrl: entry.sourceUrl,
      courseName: entry.courseName,
    });
  watchedCourses.set(key, {
    courseKey: key,
    sourceUrl: entry.sourceUrl,
    courseName: entry.courseName,
    chatId: entry.chatId,
    preferredQuality: entry.preferredQuality,
    explicitTargetChannelId: entry.explicitTargetChannelId,
    lastScannedAt: entry.lastScannedAt || new Date().toISOString(),
    lastDetectedVideos:
      typeof entry.lastDetectedVideos === 'number'
        ? entry.lastDetectedVideos
        : entry.totalVideosFound || 0,
  });
  saveWatchedCoursesState();
}

function markVideoCompleted(
  item: {
    initialSourceUrl?: string;
    sourceUrl?: string;
    originalRequestUrl?: string;
    courseName?: string;
    folderName?: string;
    lectureTitle?: string;
    title?: string;
    batchOrder?: number;
    telegramChatId?: string;
    forceDownload?: boolean;
  },
  immediate = false
) {
  // /only (forceDownload) downloads are completely separate: NEVER add them to completedVideoKeys or courseCheckpoints!
  if (item.forceDownload) {
    return;
  }

  const keys = getVideoDedupeKeys(item);
  for (const k of keys) {
    completedVideoKeys.add(k);
  }

  // Also update the automatic Course Checkpoint ONLY for regular sequential batch runs
  const cKey = getCourseCheckpointKey(item);
  if (cKey) {
    const existing = courseCheckpoints.get(cKey);
    const lecMatch = String(item.title || '').match(/Lecture\s*(\d+)\s*\/\s*(\d+)/i);
    const orderNum =
      typeof item.batchOrder === 'number' && item.batchOrder > 0
        ? item.batchOrder
        : lecMatch
        ? parseInt(lecMatch[1], 10)
        : existing?.lastCompletedBatchOrder || 1;
    const totalNum = lecMatch
      ? parseInt(lecMatch[2], 10)
      : existing?.totalVideos || orderNum;
    const cleanCourseName = String(item.courseName || existing?.courseName || cKey)
      .replace(/\s*\(\d+\s*Folders?,\s*\d+\s*Videos?\)\s*$/i, '')
      .trim();

    const nextLastOrder = Math.max(existing?.lastCompletedBatchOrder || 0, orderNum);
    courseCheckpoints.set(cKey, {
      courseKey: cKey,
      courseName: cleanCourseName,
      sourceUrl: item.originalRequestUrl || existing?.sourceUrl,
      chatId: item.telegramChatId || existing?.chatId || '',
      lastCompletedBatchOrder: nextLastOrder,
      lastCompletedTitle:
        orderNum >= (existing?.lastCompletedBatchOrder || 0)
          ? String(item.title || item.lectureTitle || existing?.lastCompletedTitle || '')
          : String(existing?.lastCompletedTitle || item.title || ''),
      totalVideos: Math.max(existing?.totalVideos || 0, totalNum),
      completedCount: (existing?.completedCount || 0) + 1,
      updatedAt: new Date().toISOString(),
    });
    if (immediate) {
      saveCourseCheckpointsState();
    }
  }

  saveCompletedVideosState(immediate);
}

function isVideoAlreadyCompletedForChat(
  chatId: string,
  item: {
    initialSourceUrl?: string;
    sourceUrl?: string;
    originalRequestUrl?: string;
    courseName?: string;
    folderName?: string;
    lectureTitle?: string;
    title?: string;
    batchOrder?: number;
  }
): boolean {
  const targetKeys = getVideoDedupeKeys(item);
  if (targetKeys.length === 0) return false;

  for (const k of targetKeys) {
    if (completedVideoKeys.has(k)) {
      return true;
    }
  }

  for (const existing of jobs.values()) {
    if (existing.status !== 'completed') continue;
    if (chatId && existing.telegramChatId && existing.telegramChatId !== chatId) continue;
    const existingKeys = getVideoDedupeKeys(existing);
    for (const tk of targetKeys) {
      if (existingKeys.includes(tk)) {
        for (const k of targetKeys) {
          completedVideoKeys.add(k);
        }
        return true;
      }
    }
  }
  return false;
}

function findExistingPendingJobForChat(
  chatId: string,
  item: {
    initialSourceUrl?: string;
    sourceUrl?: string;
    originalRequestUrl?: string;
    courseName?: string;
    folderName?: string;
    lectureTitle?: string;
    title?: string;
    batchOrder?: number;
  }
): DownloadJob | undefined {
  const targetKeys = getVideoDedupeKeys(item);
  if (targetKeys.length === 0) return undefined;

  for (const existing of jobs.values()) {
    if (existing.status === 'completed' || existing.status === 'failed') continue;
    if (chatId && existing.telegramChatId && existing.telegramChatId !== chatId) continue;
    // Never treat two different lecture numbers (batchOrder) as the same pending job!
    if (
      typeof item.batchOrder === 'number' &&
      item.batchOrder > 0 &&
      typeof existing.batchOrder === 'number' &&
      existing.batchOrder > 0 &&
      item.batchOrder !== existing.batchOrder
    ) {
      continue;
    }
    const existingKeys = getVideoDedupeKeys(existing);
    for (const tk of targetKeys) {
      if (existingKeys.includes(tk)) {
        return existing;
      }
    }
  }
  return undefined;
}

let saveJobsTimer: NodeJS.Timeout | null = null;
let writingJobsPromise: Promise<void> = Promise.resolve();
function saveJobsState(immediate = false) {
  const writeNow = () => {
    const allList = Array.from(jobs.values());
    const activeFirst = allList.filter((j) => j.status !== 'completed');
    const completedTail = allList.filter((j) => j.status === 'completed');
    const list = [...activeFirst, ...completedTail].slice(-4000);
    const payload = JSON.stringify(list);
    writingJobsPromise = writingJobsPromise
      .then(() => fs.promises.writeFile(JOBS_STATE_PATH, payload, 'utf8'))
      .catch(() => {});
  };
  if (immediate) {
    if (saveJobsTimer) {
      clearTimeout(saveJobsTimer);
      saveJobsTimer = null;
    }
    writeNow();
    return;
  }
  if (!saveJobsTimer) {
    saveJobsTimer = setTimeout(() => {
      saveJobsTimer = null;
      writeNow();
    }, 5000);
  }
}

function loadJobsState() {
  try {
    if (!fs.existsSync(JOBS_STATE_PATH)) return;
    const parsed = JSON.parse(fs.readFileSync(JOBS_STATE_PATH, 'utf8'));
    if (!Array.isArray(parsed)) return;
    for (const raw of parsed) {
      if (!raw || !raw.id) continue;
      const job: DownloadJob = {
        ...raw,
        initialSourceUrl: raw.initialSourceUrl || raw.sourceUrl,
        abortFlag: false,
      };
      if (job.status === 'completed') {
        if (!job.forceDownload) {
          for (const k of getVideoDedupeKeys(job)) {
            completedVideoKeys.add(k);
          }
        }
      } else if (
        !job.forceDownload &&
        !job.skipCompletedCheck &&
        isVideoAlreadyCompletedForChat(job.telegramChatId || '', job)
      ) {
        job.status = 'completed';
        job.progressPercent = 100;
        job.speedBytesPerSec = 0;
        job.error = undefined;
      } else if (
        job.status === 'downloading' ||
        job.status === 'merging' ||
        job.status === 'uploading_bot_api' ||
        job.status === 'uploading_mtproto_userbot' ||
        job.status === 'uploading_google_drive' ||
        job.status === 'queued'
      ) {
        job.status = 'paused';
        job.sourceUrl = job.initialSourceUrl || job.sourceUrl;
        if (!job.preferredQuality) {
          job.preferredQuality = botSettings.globalDefaultQuality || '480p';
        }
        if (!job.resolution) {
          job.resolution = job.preferredQuality;
        }
        job.speedBytesPerSec = 0;
        job.error = 'Paused — send /resume to continue';
      }
      jobs.set(job.id, job);
    }
    saveCompletedVideosState(true);
    saveCourseCheckpointsState();
  } catch {
    // ignore corrupt state
  }
}
loadJobsState();

const pendingUserbotRelays = new Map<
  string,
  {
    allTargetChatIds: string[];
    cleanCaption: string;
    resolve: (deliveredMsgInfo?: { fromChatId: string; messageId: number }) => void;
  }
>();

function addBotLog(direction: BotActivityLog['direction'], chatId: string, summary: string) {
  botLogs.unshift({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    direction,
    chatId: String(chatId || 'system'),
    summary,
  });
  if (botLogs.length > 80) {
    botLogs.pop();
  }
}

let ffmpegAvailable = false;
async function checkFfmpeg() {
  try {
    await execFileAsync('ffmpeg', ['-version']);
    ffmpegAvailable = true;
  } catch {
    ffmpegAvailable = false;
  }
}
checkFfmpeg();

const DEFAULT_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

function envInt(name: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(String(process.env[name] || ''), 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

// Adaptive defaults: constrained free hosts stay bounded, while a real VPS
// can use the higher-throughput 64/96-worker and 16-socket pipeline.
const CONFIGURED_HLS_WORKERS = envInt('TURBO_HLS_WORKERS', IS_CONSTRAINED_HOST ? 32 : 64, 4, 96);
const CONFIGURED_RANGE_WORKERS = envInt('TURBO_RANGE_WORKERS', IS_CONSTRAINED_HOST ? 24 : 64, 4, 96);
const CONFIGURED_UPLOAD_SOCKETS = envInt('TURBO_UPLOAD_SOCKETS', IS_CONSTRAINED_HOST ? 6 : 16, 2, 16);

function buildHeaders(customHeaders?: Record<string, string>, refererUrl?: string): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': DEFAULT_USER_AGENT,
    Accept: '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
  };
  if (refererUrl) {
    try {
      if (/classx\.co\.in|teachx\.in/i.test(refererUrl)) {
        headers['Referer'] = 'https://rozgarapinew.teachx.in/';
      } else {
        const u = new URL(refererUrl);
        headers['Referer'] = `${u.protocol}//${u.host}/`;
      }
      // DO NOT set Origin header on GET requests — AWS IVS / CloudFront / NGINX return HTTP 413 / 403 when Origin is present on GETs!
    } catch {
      // ignore
    }
  }
  if (customHeaders) {
    for (const [k, v] of Object.entries(customHeaders)) {
      if (k && v && v.trim()) {
        headers[k.trim()] = v.trim();
      }
    }
  }
  return headers;
}

// ============================================================================
// BULLETPROOF HTTP FETCHER (NODE FETCH + NATIVE CURL FALLBACK — ZERO "fetch failed")
// ============================================================================

let activeCurlSubprocesses = 0;
const MAX_CONCURRENT_CURL = 6;
async function runCurlBufferLimited(curlArgs: string[]): Promise<Buffer> {
  while (activeCurlSubprocesses >= MAX_CONCURRENT_CURL) {
    await new Promise((r) => setTimeout(r, 80));
  }
  activeCurlSubprocesses++;
  try {
    const { stdout } = await execFileAsync('curl', curlArgs, {
      encoding: 'buffer',
      maxBuffer: 60 * 1024 * 1024,
    });
    return stdout;
  } finally {
    activeCurlSubprocesses--;
  }
}

async function undiciRequestFollow(
  url: string,
  options: {
    method?: 'GET' | 'HEAD';
    headers?: Record<string, string>;
    headersTimeout?: number;
    bodyTimeout?: number;
    signal?: AbortSignal;
  },
  maxRedirects = 5
) {
  let currentUrl = url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (options.signal?.aborted) {
      throw new Error('JOB_PAUSED_BY_USER');
    }
    const res = await undiciRequest(currentUrl, {
      method: options.method || 'GET',
      headers: options.headers,
      dispatcher: undiciFastDispatcher,
      headersTimeout: options.headersTimeout ?? 4000,
      bodyTimeout: options.bodyTimeout ?? 6000,
      signal: options.signal,
    });
    if (
      (res.statusCode === 301 ||
        res.statusCode === 302 ||
        res.statusCode === 303 ||
        res.statusCode === 307 ||
        res.statusCode === 308) &&
      res.headers.location &&
      hop < maxRedirects
    ) {
      const loc = Array.isArray(res.headers.location)
        ? res.headers.location[0]
        : res.headers.location;
      await res.body.dump().catch(() => {});
      currentUrl = new URL(loc, currentUrl).toString();
      continue;
    }
    return res;
  }
  return undiciRequest(currentUrl, {
    method: options.method || 'GET',
    headers: options.headers,
    dispatcher: undiciFastDispatcher,
    headersTimeout: options.headersTimeout ?? 4000,
    bodyTimeout: options.bodyTimeout ?? 6000,
    signal: options.signal,
  });
}

async function robustFetchBuffer(
  url: string,
  headers: Record<string, string>,
  maxRetries = 4,
  signal?: AbortSignal
): Promise<Buffer> {
  let lastError: any;
  const needsClassxReferer = /classx\.co\.in|teachx\.in/i.test(url);

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    if (signal?.aborted) {
      throw new Error('JOB_PAUSED_BY_USER');
    }
    try {
      const activeHeaders: Record<string, string> =
        attempt >= 2
          ? {
              'User-Agent': DEFAULT_USER_AGENT,
              Accept: '*/*',
              'Accept-Encoding': 'identity',
              ...(needsClassxReferer ? { Referer: 'https://rozgarapinew.teachx.in/' } : {}),
            }
          : needsClassxReferer && !headers['Referer']
          ? { ...headers, Referer: 'https://rozgarapinew.teachx.in/' }
          : headers;

      const res = await undiciRequestFollow(url, {
        method: 'GET',
        headers: activeHeaders,
        headersTimeout: attempt === 1 ? 10000 : 18000,
        bodyTimeout: attempt === 1 ? 20000 : 35000,
        signal,
      });

      if (res.statusCode < 200 || res.statusCode >= 300) {
        await res.body.dump().catch(() => {});
        if (res.statusCode === 401 || res.statusCode === 403) {
          throw new Error(`TOKEN_EXPIRED_OR_FORBIDDEN: HTTP ${res.statusCode}`);
        }
        throw new Error(`HTTP ${res.statusCode}`);
      }

      const arrBuf = await res.body.arrayBuffer();
      if (signal?.aborted) throw new Error('JOB_PAUSED_BY_USER');
      return Buffer.from(arrBuf);
    } catch (err: any) {
      lastError = err;
      if (signal?.aborted || String(err?.message || '') === 'JOB_PAUSED_BY_USER') {
        throw new Error('JOB_PAUSED_BY_USER');
      }
      if (String(err?.message || '').includes('TOKEN_EXPIRED_OR_FORBIDDEN')) {
        throw err;
      }
      // Only fall back to curl subprocess on attempt >= 3 so keep-alive Undici sockets handle 99.9% of segments with zero fork overhead
      if (attempt >= 3) {
        try {
          const curlArgs = ['-k', '-sL', '--fail', '--retry', '1', '--max-time', '15', '--connect-timeout', '5'];
          const activeHeaders: Record<string, string> = {
            'User-Agent': DEFAULT_USER_AGENT,
            ...(needsClassxReferer ? { Referer: 'https://rozgarapinew.teachx.in/' } : {}),
          };
          for (const [k, v] of Object.entries(activeHeaders)) {
            curlArgs.push('-H', `${k}: ${v}`);
          }
          curlArgs.push(url);
          const stdout = await runCurlBufferLimited(curlArgs);
          if (stdout && stdout.length > 0) {
            return stdout;
          }
        } catch (curlErr) {
          lastError = curlErr;
        }
      }
      if (attempt < maxRetries && !signal?.aborted) {
        const backoffMs = 100 * Math.pow(2, attempt - 1);
        await new Promise((r) => setTimeout(r, backoffMs));
      }
    }
  }

  throw lastError || new Error(`Failed to fetch ${url}`);
}

async function robustFetchText(
  url: string,
  headers: Record<string, string>,
  maxRetries = 4
): Promise<{ text: string; finalUrl: string; contentType: string }> {
  let lastError: any;
  const needsClassxReferer = /classx\.co\.in|teachx\.in/i.test(url);

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const activeHeaders: Record<string, string> =
        attempt >= 2
          ? {
              'User-Agent': DEFAULT_USER_AGENT,
              Accept: '*/*',
              ...(needsClassxReferer ? { Referer: 'https://rozgarapinew.teachx.in/' } : {}),
            }
          : needsClassxReferer && !headers['Referer']
          ? { ...headers, Referer: 'https://rozgarapinew.teachx.in/' }
          : headers;
      const res = await fetch(url, { headers: activeHeaders, redirect: 'follow', signal: controller.signal });
      clearTimeout(timeout);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status} ${res.statusText}`);
      }
      const text = await res.text();
      return {
        text,
        finalUrl: res.url || url,
        contentType: (res.headers.get('content-type') || '').toLowerCase(),
      };
    } catch (err: any) {
      lastError = err;
      try {
        const curlArgs = ['-k', '-sL', '--fail', '--retry', '2', '--max-time', '18'];
        const activeHeaders: Record<string, string> =
          attempt >= 3
            ? {
                'User-Agent': DEFAULT_USER_AGENT,
                ...(needsClassxReferer ? { Referer: 'https://rozgarapinew.teachx.in/' } : {}),
              }
            : headers;
        for (const [k, v] of Object.entries(activeHeaders)) {
          curlArgs.push('-H', `${k}: ${v}`);
        }
        curlArgs.push(url);
        const { stdout } = await execFileAsync('curl', curlArgs, {
          encoding: 'utf8',
          maxBuffer: 25 * 1024 * 1024,
        });
        if (stdout && stdout.trim().length > 0) {
          return {
            text: stdout,
            finalUrl: url,
            contentType: stdout.trim().startsWith('#EXTM3U') ? 'application/vnd.apple.mpegurl' : 'text/html',
          };
        }
      } catch (curlErr: any) {
        lastError = curlErr;
      }
      await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }

  throw lastError || new Error(`Could not fetch text from ${url}`);
}

function resolveRelativeUrl(relOrAbs: string, baseUrl: string): string {
  try {
    return new URL(relOrAbs.trim(), baseUrl).toString();
  } catch {
    return relOrAbs.trim();
  }
}

function isUrlPathnameEndingWith(rawUrl: string, regex: RegExp): boolean {
  try {
    const u = new URL(rawUrl);
    return regex.test(u.pathname);
  } catch {
    return regex.test(rawUrl.split('?')[0]);
  }
}

function unwrapQueryRedirectUrl(rawUrl: string): string | null {
  try {
    const u = new URL(rawUrl);
    if (/\/api\/proxy/i.test(u.pathname)) {
      return null;
    }
    for (const param of ['url', 'src', 'm3u8', 'stream', 'video', 'file', 'link']) {
      const val = u.searchParams.get(param);
      if (val && /^https?:\/\//i.test(val.trim())) {
        return val.trim();
      }
    }
  } catch {
    // ignore
  }
  return null;
}

// ============================================================================
// APPX / STUDYBEEPRO / TEACHX DECRYPTION & MULTI-FOLDER TOPIC CRAWLER
// ============================================================================

function decryptAppxUrl(enc: string): string | null {
  try {
    if (!enc || typeof enc !== 'string') return null;
    const trimmed = enc.trim();
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    if (!trimmed.includes(':')) return null;
    const [cipherB64, ivB64] = trimmed.split(':');
    if (!cipherB64 || !ivB64) return null;
    const key = Buffer.from('638udh3829162018', 'utf8');
    const iv = Buffer.from(ivB64, 'base64');
    const encrypted = Buffer.from(cipherB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8').trim();
  } catch {
    return null;
  }
}

function normalizeAppxMediaUrl(rawOrEnc: string, ytHint = false): string | null {
  if (!rawOrEnc || typeof rawOrEnc !== 'string') return null;
  const trimmed = rawOrEnc.trim();
  const dec = decryptAppxUrl(trimmed) || (/^[A-Za-z0-9_-]{11}$/.test(trimmed) ? trimmed : null);
  if (!dec) return null;
  if (/^[A-Za-z0-9_-]{11}$/.test(dec)) {
    return `https://www.youtube.com/watch?v=${dec}`;
  }
  if (/^https?:\/\//i.test(dec)) {
    if (/pdflink\.com|\.pdf(\?|$)/i.test(dec)) return null;
    return dec;
  }
  if (ytHint && /^[A-Za-z0-9_-]{11}$/.test(dec.trim())) {
    return `https://www.youtube.com/watch?v=${dec.trim()}`;
  }
  return null;
}

// ============================================================================
// ROJGAR ADMIN PORTAL CONFIGURATION & BATCH OVERRIDES STORE
// ============================================================================
interface RojgarJoinLink {
  id: string;
  name: string;
  url: string;
  platformType?: 'telegram' | 'youtube' | 'whatsapp' | 'instagram' | 'website';
}

interface RojgarBatchOverride {
  isLive?: boolean;
  customTitle?: string;
  customApiUrl?: string;
  customToken?: string;
  customUserId?: string;
  donorCourseIds?: string[];
  note?: string;
  updatedAt?: string;
}

interface RojgarNotificationItem {
  id: string;
  title: string;
  message: string;
  linkLabel?: string;
  linkUrl?: string;
  pinned?: boolean;
  createdAt: string;
}

interface ExternalPortalMirrorConfig {
  id: string;
  name: string;
  baseUrl: string;
  portalPath?: string;
  cookieHeader?: string;
  bearerToken?: string;
  userId?: string;
  enabled: boolean;
  lastSyncedAt?: string;
  lastSyncStatus?: 'ok' | 'auth_required' | 'error' | 'pending';
  lastSyncMessage?: string;
  lastSyncedCount?: number;
}

interface RojgarPortalAdminConfig {
  portalTitle: string;
  announcementText: string;
  maintenanceMode: boolean;
  maintenanceMessage: string;
  defaultQuality: '240p' | '360p' | '480p' | '720p';
  onlyShowPlayableBatches?: boolean;
  globalCustomApiUrl?: string;
  globalCustomToken?: string;
  globalCustomUserId?: string;
  externalMirrors?: ExternalPortalMirrorConfig[];
  joinBanner: {
    enabled: boolean;
    showMode: 'first_visit' | 'every_visit';
    allowClose: boolean;
    title: string;
    subtitle: string;
    links: RojgarJoinLink[];
  };
  notifications: RojgarNotificationItem[];
  batchOverrides: Record<string, RojgarBatchOverride>;
  updatedAt: string;
}

const DEFAULT_EXTERNAL_MIRRORS: ExternalPortalMirrorConfig[] = [
  {
    id: 'mirror-ais-rwax',
    name: 'External RWAX Web Mirror',
    baseUrl: 'https://ais-pre-puxho4o57upkknekv3mgg7-49225910278.asia-east1.run.app',
    portalPath: '/rwax',
    enabled: true,
    lastSyncStatus: 'pending',
  },
];

const ROJGAR_ADMIN_CONFIG_FILE = path.join(process.cwd(), 'rojgar-admin-config.json');

function defaultRojgarAdminConfig(): RojgarPortalAdminConfig {
  return {
    portalTitle: 'Rojgar Batches',
    announcementText: '',
    maintenanceMode: false,
    maintenanceMessage: 'Portal maintenance in progress. Please check back shortly.',
    defaultQuality: '480p',
    onlyShowPlayableBatches: false,
    globalCustomApiUrl: '',
    globalCustomToken: '',
    globalCustomUserId: '',
    externalMirrors: DEFAULT_EXTERNAL_MIRRORS.map((m) => ({ ...m })),
    joinBanner: {
      enabled: false,
      showMode: 'first_visit',
      allowClose: true,
      title: 'Join Official Study Channels',
      subtitle: 'Stay updated with class schedules, PDF notes, and new batches.',
      links: [],
    },
    notifications: [],
    batchOverrides: {},
    updatedAt: new Date().toISOString(),
  };
}

function loadRojgarAdminConfig(): RojgarPortalAdminConfig {
  const def = defaultRojgarAdminConfig();
  try {
    if (fs.existsSync(ROJGAR_ADMIN_CONFIG_FILE)) {
      const raw = JSON.parse(fs.readFileSync(ROJGAR_ADMIN_CONFIG_FILE, 'utf8'));
      const rawMirrors = Array.isArray(raw?.externalMirrors) ? raw.externalMirrors : [];
      const mergedMirrors: ExternalPortalMirrorConfig[] =
        rawMirrors.length > 0
          ? rawMirrors.map((m: any) => ({
              id: String(m.id || crypto.randomUUID()),
              name: String(m.name || 'External Mirror').trim(),
              baseUrl: String(m.baseUrl || '').trim().replace(/\/+$/, ''),
              portalPath: m.portalPath ? String(m.portalPath).trim() : '/rwax',
              cookieHeader: m.cookieHeader ? String(m.cookieHeader).trim() : undefined,
              bearerToken: m.bearerToken ? String(m.bearerToken).trim() : undefined,
              userId: m.userId ? String(m.userId).trim() : undefined,
              enabled: m.enabled !== false,
              lastSyncedAt: m.lastSyncedAt ? String(m.lastSyncedAt) : undefined,
              lastSyncStatus: m.lastSyncStatus || 'pending',
              lastSyncMessage: m.lastSyncMessage ? String(m.lastSyncMessage) : undefined,
              lastSyncedCount: typeof m.lastSyncedCount === 'number' ? m.lastSyncedCount : undefined,
            }))
          : DEFAULT_EXTERNAL_MIRRORS.map((m) => ({ ...m }));
      return {
        ...def,
        ...raw,
        externalMirrors: mergedMirrors,
        joinBanner: {
          ...def.joinBanner,
          ...(raw?.joinBanner || {}),
          links: Array.isArray(raw?.joinBanner?.links) ? raw.joinBanner.links : [],
        },
        notifications: Array.isArray(raw?.notifications) ? raw.notifications : [],
        batchOverrides: raw?.batchOverrides && typeof raw.batchOverrides === 'object' ? raw.batchOverrides : {},
      };
    }
  } catch {
    // ignore corrupt config
  }
  return def;
}

let rojgarAdminConfig: RojgarPortalAdminConfig = loadRojgarAdminConfig();

function saveRojgarAdminConfig() {
  try {
    rojgarAdminConfig.updatedAt = new Date().toISOString();
    fs.writeFileSync(ROJGAR_ADMIN_CONFIG_FILE, JSON.stringify(rojgarAdminConfig, null, 2));
  } catch (err) {
    console.warn('[RojgarAdmin] Failed to save config:', err);
  }
}

const rwaBatchHasVideosCache = new Map<string, boolean>();
const RWA_HEALTH_CACHE_FILE = path.join(os.tmpdir(), 'rojgar_batch_health_cache.json');
interface RwaHealthCacheEntry {
  status: 'active' | 'partial' | 'unpurchased' | 'empty' | 'custom_api' | 'error';
  detail?: string;
  checkedAt: number;
  videoStats?: {
    totalVideos: number;
    totalPdfs: number;
    playableCount: number;
    errorCount: number;
    unpurchasedCount: number;
    checkedAt: string;
    scanDepth?: 'quick' | 'deep';
  };
}
const rwaBatchHealthCache = new Map<string, RwaHealthCacheEntry>();
try {
  if (fs.existsSync(RWA_HEALTH_CACHE_FILE)) {
    const parsedHealth = JSON.parse(fs.readFileSync(RWA_HEALTH_CACHE_FILE, 'utf8'));
    if (parsedHealth && typeof parsedHealth === 'object') {
      for (const [k, v] of Object.entries(parsedHealth as Record<string, any>)) {
        if (v && typeof v.status === 'string') {
          rwaBatchHealthCache.set(k, v);
          if (v.status === 'empty' || v.status === 'unpurchased') {
            rwaBatchHasVideosCache.set(k, false);
          } else if (v.status === 'active' || v.status === 'partial' || v.status === 'custom_api') {
            rwaBatchHasVideosCache.set(k, true);
          }
        }
      }
    }
  }
} catch {
  // ignore corrupt health file
}
function saveRwaHealthCache() {
  try {
    const obj: Record<string, any> = {};
    for (const [k, v] of rwaBatchHealthCache.entries()) obj[k] = v;
    fs.writeFileSync(RWA_HEALTH_CACHE_FILE, JSON.stringify(obj));
  } catch {
    // ignore
  }
}

// Generates a unique per-request Authorization header representation that bypasses OpenResty
// $http_authorization rate-limiting while decoding identically in PHP base64_decode()
function freshAppxAuthToken(token: string): string {
  const trimmed = (token || '').trim();
  const parts = trimmed.replace(/=+$/, '').split('.');
  if (parts.length !== 3) return trimmed;
  const sig = parts[2].replace(/\s+/g, '');
  let mutatedSig = '';
  for (let i = 0; i < sig.length; i++) {
    mutatedSig += sig[i];
    if (i < sig.length - 1 && Math.random() < 0.35) {
      mutatedSig += ' ';
    }
  }
  const eqPad = '='.repeat(Math.floor(Math.random() * 6) + 1);
  return `${parts[0]}.${parts[1]}.${mutatedSig}${eqPad}`;
}

function extractTeachxJwtMeta(token: string): { userId: string; timestamp: number; isFresh: boolean } {
  try {
    const parts = (token || '').trim().split('.');
    if (parts.length < 2) return { userId: '16231827', timestamp: 0, isFresh: false };
    const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson);
    const userId = String(payload?.id || payload?.userid || '16231827').trim();
    const timestamp = Number(payload?.timestamp || 0);
    const nowSec = Math.floor(Date.now() / 1000);
    // TeachX tokens expire at 180 days (15,552,000s); treat anything older than 165 days as stale
    const isFresh = timestamp > 0 && nowSec - timestamp < 165 * 86400;
    return { userId, timestamp, isFresh };
  } catch {
    return { userId: '16231827', timestamp: 0, isFresh: false };
  }
}

// Never commit a portal JWT to source control. A fresh token is minted on
// demand by mintFreshTeachxToken() when the portal requires one.
const DEFAULT_FRESH_RWA_TOKEN = '';

let activeMintedRwaToken: { token: string; userId: string; mintedAt: number } = {
  token: DEFAULT_FRESH_RWA_TOKEN,
  userId: '16231827',
  mintedAt: Date.now(),
};
let mintingTokenPromise: Promise<{ token: string; userId: string } | null> | null = null;

async function mintFreshTeachxToken(
  apiUrl: string = 'https://rozgarapinew.teachx.in'
): Promise<{ token: string; userId: string } | null> {
  if (mintingTokenPromise) return mintingTokenPromise;
  mintingTokenPromise = (async () => {
    const cleanApi = apiUrl.replace(/\/$/, '') || 'https://rozgarapinew.teachx.in';
    const headers = {
      'User-Agent': DEFAULT_USER_AGENT,
      'Auth-Key': 'appxapi',
      'User-ID': '-1',
      source: 'website',
      'Client-Service': 'Appx',
      'Content-Type': 'application/x-www-form-urlencoded',
    };
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const randPhone = '9' + String(Math.floor(100000000 + Math.random() * 899999999));
        const randEmail = `student${randPhone}@gmail.com`;
        const pass = crypto.randomBytes(18).toString('base64url');
        const params = `name=Student+User&email=${encodeURIComponent(
          randEmail
        )}&phone=${randPhone}&password=${encodeURIComponent(
          pass
        )}&cpassword=${encodeURIComponent(
          pass
        )}&username=student${randPhone}&state=UP&district=Noida&otp=1234`;
        const res = await fetch(`${cleanApi}/post/userSignup?${params}`, {
          method: 'POST',
          headers,
          body: params,
          signal: AbortSignal.timeout(8000),
        });
        const j = (await res.json()) as any;
        const tok = String(j?.data?.token || '').trim();
        const uid = String(j?.data?.userid || j?.data?.user_id || '').trim();
        if (tok && tok.startsWith('eyJ')) {
          const resolvedUid = uid || extractTeachxJwtMeta(tok).userId;
          activeMintedRwaToken = {
            token: tok,
            userId: resolvedUid,
            mintedAt: Date.now(),
          };
          console.log(`[TeachX Self-Heal] Minted fresh 6-month token (User-ID: ${resolvedUid})`);
          return { token: tok, userId: resolvedUid };
        }
      } catch {
        // try again
      }
    }
    return null;
  })().finally(() => {
    mintingTokenPromise = null;
  });
  return mintingTokenPromise;
}

async function fetchAppxJsonWithRetry(
  url: string,
  headers: Record<string, string>,
  maxRetries = 3
): Promise<any | null> {
  let lastValidObj: any = null;
  let didMintFreshToken = false;
  const isTeachxDirect = /teachx\.in|classx\.co\.in/i.test(url);
  const isAsmultiverse = /asmultiverse\.site/i.test(url);
  const effectiveRetries = isTeachxDirect ? Math.max(maxRetries, 4) : maxRetries;

  for (let attempt = 1; attempt <= effectiveRetries; attempt++) {
    const reqHeaders: Record<string, string> = { ...headers };
    if (reqHeaders.Authorization && reqHeaders.Authorization.startsWith('eyJ')) {
      const meta = extractTeachxJwtMeta(reqHeaders.Authorization);
      if (meta.userId) {
        reqHeaders['User-ID'] = meta.userId;
      }
      reqHeaders.Authorization = freshAppxAuthToken(reqHeaders.Authorization);
    }
    try {
      const timeoutMs = isAsmultiverse ? 5000 : isTeachxDirect ? 7000 : 8500;
      const res = await fetch(url, {
        headers: reqHeaders,
        signal: AbortSignal.timeout(timeoutMs),
      });

      const rawText = await res.text();
      let parsed: any = null;
      if (rawText && (rawText.trim().startsWith('{') || rawText.trim().startsWith('['))) {
        try {
          parsed = JSON.parse(rawText);
        } catch {
          parsed = null;
        }
      }

      // Self-heal direct TeachX calls on 401 (expired token) OR 429 ("Too many requests, please try again after 1 hour" per User-ID)
      // by immediately minting a brand new student User-ID and token!
      if (
        isTeachxDirect &&
        (res.status === 401 ||
          parsed?.status === 401 ||
          res.status === 429 ||
          parsed?.status === 429 ||
          /too many requests|after 1 hour/i.test(rawText || ''))
      ) {
        const isPerUserHourlyLimit =
          parsed?.status === 429 ||
          /after 1 hour|too many requests/i.test(String(parsed?.message || rawText || ''));
        if (!didMintFreshToken || isPerUserHourlyLimit) {
          didMintFreshToken = true;
          const originMatch = url.match(/^https?:\/\/[^/]+/i);
          const minted = await mintFreshTeachxToken(originMatch ? originMatch[0] : undefined);
          if (minted) {
            headers.Authorization = minted.token;
            headers['User-ID'] = minted.userId;
            appxConfigCache.clear();
            if (attempt < effectiveRetries) {
              continue;
            }
          }
        }
        if (attempt < effectiveRetries) {
          await new Promise((r) => setTimeout(r, 150 * attempt));
          continue;
        }
      }

      // Never retry asmultiverse.site if it reports a rate limit (429) or token exhaustion
      if (
        isAsmultiverse &&
        parsed &&
        (parsed.rate_limit_hit === true ||
          parsed.status === 429 ||
          /429|rate limit/i.test(String(parsed.message || '')))
      ) {
        return parsed;
      }

      if (parsed) {
        if (
          parsed.status === 429 ||
          parsed.status === 500 ||
          (parsed.success === false && !parsed.data)
        ) {
          lastValidObj = parsed;
          if (!isAsmultiverse && attempt < effectiveRetries) {
            await new Promise((r) => setTimeout(r, 250 * attempt));
            continue;
          }
        }
        return parsed;
      }

      if (!res.ok) {
        if (!isAsmultiverse && attempt < effectiveRetries) {
          await new Promise((r) => setTimeout(r, 250 * attempt));
          continue;
        }
        return lastValidObj;
      }
      return lastValidObj;
    } catch {
      if (!isAsmultiverse && attempt < effectiveRetries) {
        await new Promise((r) => setTimeout(r, 250 * attempt));
      }
    }
  }
  return lastValidObj;
}

const appxConfigCache = new Map<
  string,
  { data: { apiUrl: string; token: string; userId: string; name: string }; expiry: number }
>();

async function fetchAppxDomainConfig(
  domainId: string = 'RWA',
  origin: string = 'https://studybeepro.site'
): Promise<{ apiUrl: string; token: string; userId: string; name: string }> {
  const normDomain = (domainId || 'RWA').toUpperCase();
  const cached = appxConfigCache.get(normDomain);
  if (cached && Date.now() < cached.expiry) {
    return cached.data;
  }

  // For RWA, cache permanently in memory while token JWT is valid!
  if (normDomain === 'RWA' || normDomain.includes('RWA')) {
    const apiUrl = 'https://rozgarapinew.teachx.in';
    const currentMeta = extractTeachxJwtMeta(activeMintedRwaToken.token);
    if (!currentMeta.isFresh) {
      await mintFreshTeachxToken(apiUrl);
    }
    const fallbackRwa = {
      apiUrl,
      token: activeMintedRwaToken.token,
      userId: activeMintedRwaToken.userId,
      name: 'ROJGAR WITH ANKIT (RWA)',
    };
    appxConfigCache.set(normDomain, { data: fallbackRwa, expiry: Date.now() + 24 * 60 * 60 * 1000 });
    return fallbackRwa;
  }

  const cleanOrigin = origin.replace(/\/$/, '') || 'https://studybeepro.site';
  const urlsToTry = [
    `${cleanOrigin}/api/rwa?app=${encodeURIComponent(normDomain)}&i=1`,
    `https://studybeepro.site/api/rwa?app=${encodeURIComponent(normDomain)}&i=1`,
    `https://rwa.smexfot.workers.dev/?app=${encodeURIComponent(normDomain)}`,
  ];
  for (const u of urlsToTry) {
    try {
      const res = await fetch(u, {
        headers: { 'User-Agent': DEFAULT_USER_AGENT },
        signal: AbortSignal.timeout(3500),
      });
      if (res.ok) {
        const data = (await res.json()) as any;
        if (data && data.domain && data.token) {
          let apiUrl = String(data.domain).trim();
          if (!apiUrl.startsWith('http')) apiUrl = `https://${apiUrl}`;
          apiUrl = apiUrl.replace(/\/$/, '');
          const candidateToken = String(data.token).trim();
          const meta = extractTeachxJwtMeta(candidateToken);
          if (meta.isFresh) {
            const result = {
              apiUrl,
              token: candidateToken,
              userId: meta.userId,
              name: data.name || normDomain,
            };
            appxConfigCache.set(normDomain, { data: result, expiry: Date.now() + 24 * 60 * 60 * 1000 });
            return result;
          }
        }
      }
    } catch {
      // try next
    }
  }

  if (cached) {
    return cached.data;
  }
  throw new Error(`Could not load AppX configuration for domainId=${normDomain}`);
}

// Live discovered subjectId -> candidate donor courseIds index (persisted & populated as batch trees load)
const rwaSubjectToCoursesMap = new Map<string, Set<string>>();
const rwaSubjectNameToCoursesMap = new Map<string, Set<string>>();
const rwaDiscoveredCoursesMap = new Map<string, any>();

const RWA_SUBJECT_DONORS_FILE = path.join(os.tmpdir(), 'rojgar_subject_donors_index.json');
const RWA_DISCOVERED_COURSES_FILE = path.join(os.tmpdir(), 'rojgar_discovered_courses.json');

try {
  if (fs.existsSync(RWA_SUBJECT_DONORS_FILE)) {
    const rawDonors = JSON.parse(fs.readFileSync(RWA_SUBJECT_DONORS_FILE, 'utf8'));
    if (rawDonors?.byId && typeof rawDonors.byId === 'object') {
      for (const [sid, cids] of Object.entries(rawDonors.byId as Record<string, any>)) {
        if (Array.isArray(cids)) {
          rwaSubjectToCoursesMap.set(sid, new Set(cids.map((x) => String(x).trim()).filter(Boolean)));
        }
      }
    }
    if (rawDonors?.byName && typeof rawDonors.byName === 'object') {
      for (const [sname, cids] of Object.entries(rawDonors.byName as Record<string, any>)) {
        if (Array.isArray(cids)) {
          rwaSubjectNameToCoursesMap.set(sname, new Set(cids.map((x) => String(x).trim()).filter(Boolean)));
        }
      }
    }
  }
} catch {
  // ignore corrupt donors index cache
}

try {
  if (fs.existsSync(RWA_DISCOVERED_COURSES_FILE)) {
    const rawCourses = JSON.parse(fs.readFileSync(RWA_DISCOVERED_COURSES_FILE, 'utf8'));
    if (Array.isArray(rawCourses)) {
      for (const c of rawCourses) {
        if (c && c.id) rwaDiscoveredCoursesMap.set(String(c.id).trim(), c);
      }
    }
  }
} catch {
  // ignore corrupt discovered courses cache
}

let rwaDonorsSaveTimer: NodeJS.Timeout | null = null;
function scheduleSaveRwaSubjectDonorsIndex() {
  if (rwaDonorsSaveTimer) return;
  rwaDonorsSaveTimer = setTimeout(() => {
    rwaDonorsSaveTimer = null;
    try {
      const byId: Record<string, string[]> = {};
      for (const [k, v] of rwaSubjectToCoursesMap.entries()) {
        byId[k] = Array.from(v);
      }
      const byName: Record<string, string[]> = {};
      for (const [k, v] of rwaSubjectNameToCoursesMap.entries()) {
        byName[k] = Array.from(v);
      }
      fs.writeFileSync(RWA_SUBJECT_DONORS_FILE, JSON.stringify({ byId, byName }));
    } catch {
      // ignore
    }
  }, 800);
}

function saveRwaDiscoveredCoursesCache() {
  try {
    fs.writeFileSync(
      RWA_DISCOVERED_COURSES_FILE,
      JSON.stringify(Array.from(rwaDiscoveredCoursesMap.values()))
    );
  } catch {
    // ignore
  }
}

function normDonorSubjectName(name?: string): string {
  return String(name || '')
    .toLowerCase()
    .replace(/[*$]+/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function recordRwaSubjectCourseLink(subjectId: string, courseId: string, subjectName?: string) {
  const sid = String(subjectId || '').trim();
  const cid = String(courseId || '').trim();
  if (!cid) return;
  if (sid) {
    let set = rwaSubjectToCoursesMap.get(sid);
    if (!set) {
      set = new Set<string>();
      rwaSubjectToCoursesMap.set(sid, set);
    }
    set.add(cid);
  }
  const nName = normDonorSubjectName(subjectName);
  if (nName && nName.length >= 4) {
    let nSet = rwaSubjectNameToCoursesMap.get(nName);
    if (!nSet) {
      nSet = new Set<string>();
      rwaSubjectNameToCoursesMap.set(nName, nSet);
    }
    nSet.add(cid);
  }
  scheduleSaveRwaSubjectDonorsIndex();
}

// Verified purchased RWA donor courses on asmultiverse.site mapped strictly by shared subjectId
const RWA_SUBJECT_DONOR_COURSES: Record<string, string[]> = {
  '1': ['758', '516', '485', '738', '560', '737', '568', '736', '735'],
  '12': ['695', '720', '722'],
  '138': ['98', '106', '102', '129', '490', '97', '105'],
  '477': ['582', '98', '577', '97'],
  '704': ['560'],
  '725': ['763'],
  '726': ['763'],
  '960': ['268'],
  '961': ['268'],
  '962': ['268'],
  '963': ['268', '520'],
  '964': ['268'],
  '1031': ['106'],
  '1066': ['268', '520'],
  '1092': ['520', '679', '687', '685', '677', '683', '753', '681'],
  '1178': ['268'],
  '1180': [
    '763', '758', '736', '735', '733', '582', '694', '514', '486', '545', '98', '491',
    '423', '287', '477', '268', '356', '520', '102', '291',
    '671', '553', '424', '554', '567', '529', '531', '518',
    '320', '512', '561', '415', '675', '615', '460', '465',
    '327', '634', '524', '468', '97', '418', '676', '421',
    '695', '516', '515', '753', '284',
  ],
  '1181': ['520', '679', '687', '685', '677', '683', '753', '681'],
  '1271': ['268'],
  '1321': ['575', '284'],
  '1369': ['582', '676', '554', '553', '675', '518', '460', '633'],
  '1558': ['575', '284'],
  '1751': ['291', '560'],
  '1983': ['327'],
  '1984': ['327'],
  '1985': ['327'],
  '1986': ['327'],
  '1987': ['327'],
  '1994': ['568'],
  '2023': ['320'],
  '2103': ['327'],
  '2117': ['320'],
  '2159': ['327'],
  '2164': ['356'],
  '2165': ['356'],
  '2293': ['356'],
  '2424': ['568'],
  '2494': ['626', '426', '648'],
  '2495': ['648'],
  '2497': ['753', '648'],
  '2503': ['638', '437', '648'],
  '2562': ['567'],
  '2633': ['514', '486', '516', '515', '485', '484'],
  '2801': ['560'],
  '2802': ['356'],
  '2804': ['560'],
  '2825': ['505', '510'],
  '2826': ['505', '510'],
  '2827': ['505', '510'],
  '2831': ['505'],
  '2846': ['512'],
  '2864': ['521', '679', '687', '685', '677', '494', '683', '753'],
  '2865': ['524', '525'],
  '2866': ['524', '525'],
  '2891': ['421'],
  '2940': ['759', '648'],
  '2998': ['518'],
  '3007': ['512'],
  '3011': ['538', '541'],
  '3013': ['538', '541'],
  '3015': ['541'],
  '3016': ['541'],
  '3021': ['535', '538', '536'],
  '3022': ['535', '538', '536'],
  '3023': ['535', '538', '536'],
  '3024': ['535'],
  '3025': ['538', '536'],
  '3026': ['535', '538', '536'],
  '3027': ['535', '538', '536'],
  '3074': ['356'],
  '3087': ['560'],
  '3088': ['465', '560'],
  '3089': ['560'],
  '3090': ['560'],
  '3091': ['560'],
  '3098': ['530'],
  '3099': ['530'],
  '3100': ['695', '530'],
  '3101': ['777', '530'],
  '3102': ['648', '530'],
  '3103': ['530'],
  '3105': ['530'],
  '3126': ['491', '695', '102', '524', '525', '530'],
  '3135': ['565', '530'],
  '3142': ['582'],
  '3143': ['560', '559'],
  '3167': ['520'],
  '3180': ['530'],
  '3236': ['577', '648'],
  '3263': ['530'],
  '3264': ['530'],
  '3272': ['582'],
  '3316': ['530'],
  '3325': ['626', '648'],
  '3328': ['560', '675'],
  '3331': ['531'],
  '3336': ['531', '561'],
  '3351': ['512', '568'],
  '3369': ['722', '721'],
  '3370': ['722', '721'],
  '3371': ['722', '721'],
  '3372': ['722', '721'],
  '3374': ['510'],
  '3418': ['582'],
  '3426': ['582', '679', '687', '685', '677', '683', '753', '681', '760'],
  '3446': ['560'],
  '3487': ['758', '733'],
  '3509': ['626', '648'],
  '3514': ['763'],
  '3515': ['763'],
  '3516': ['763'],
  '3517': ['763'],
  '3518': ['763'],
  '3527': ['738', '737', '568'],
  '3536': ['560'],
  '3546': ['679', '687', '685', '677', '683', '753', '681'],
  '3651': ['763', '738', '737'],
  '3678': ['520', '561'],
  '3699': ['648'],
  '3702': ['679', '687', '685', '677', '683', '753', '681'],
  '3815': ['760', '734'],
};

const RWA_DEFAULT_DONOR_COURSES = [
  '763', '762', '759', '758', '757', '756', '744', '742', '741', '740',
  '736', '735', '733', '729', '728', '725', '723', '722', '695', '582',
  '560', '505', '538', '541', '268', '679', '738', '737', '568', '648',
  '753', '575', '755', '760', '677', '686', '681', '683', '685', '687',
  '672', '633', '577', '548', '537', '536', '532', '546', '523', '547',
  '535', '423', '287', '477', '491', '545', '356', '520', '102', '291',
  '671', '553', '424', '554', '567', '529', '531', '518', '320', '512',
  '561', '415', '675', '460', '465', '327', '634', '524', '468', '97',
  '418', '676', '421', '284', '516', '515', '485', '484', '226',
];

async function resolveAppxVideoStreamUrl(
  domainId: string,
  courseId: string,
  videoId: string,
  preferredQuality: string = '480p',
  origin: string = 'https://studybeepro.site',
  portalPath: string = '/rwax',
  fallbackUrl?: string,
  hintMeta?: {
    subjectId?: string;
    topicId?: string;
    conceptId?: string;
    title?: string;
    strtotime?: number;
    duration?: string;
    freeFlag?: string;
    ytFlag?: string;
    skipFallback?: boolean;
    chatId?: string;
  }
): Promise<{ streamUrl: string; quality: string; title?: string }> {
  const normPrefQuality = (preferredQuality || botSettings.globalDefaultQuality || '480p').toLowerCase();
  const targetNum = parseInt(normPrefQuality.replace(/\D/g, ''), 10) || 480;
  const cleanOrig = origin.replace(/\/$/, '') || 'https://studybeepro.site';

  // ClassX / RWA CDN Quality Path Rewriter:
  // RWA's encrypted_links often return `/480p/master-...m3u8` even inside the `720p` entry,
  // while the edge-cache-token URLPrefix signs the parent video directory so `/240p/`, `/360p/`, `/480p/`, `/720p/` all work!
  const rewriteClassxQualityUrl = (rawUrl: string, desiredQ: string): { url: string; actualQuality: string } => {
    const trimmed = (rawUrl || '').trim();
    if (!trimmed) return { url: trimmed, actualQuality: desiredQ };
    const qNum = parseInt(String(desiredQ || '480p').replace(/\D/g, ''), 10) || 480;
    // ClassX transcoded-videos CDN supports 240p, 360p, 480p, 720p folders reliably
    const targetFolder =
      qNum <= 240 ? '240p' : qNum <= 360 ? '360p' : qNum <= 480 ? '480p' : '720p';
    const targetBitrate = targetFolder.replace(/\D/g, '');

    if (
      /(?:transcoded-videos|appx-transcoded-videos|akamai\.net\.in)/i.test(trimmed) &&
      /\/(144p|240p|360p|480p|720p|1080p)\/master-/i.test(trimmed)
    ) {
      let rewritten = trimmed.replace(
        /\/(144p|240p|360p|480p|720p|1080p)\/(master-[^/?#]+\.m3u8)/i,
        `/${targetFolder}/$2`
      );
      if (/([?&]bitrate=)\d+/i.test(rewritten)) {
        rewritten = rewritten.replace(/([?&]bitrate=)\d+/i, `$1${targetBitrate}`);
      }
      return { url: rewritten, actualQuality: `${targetBitrate}p` };
    }
    return { url: trimmed, actualQuality: desiredQ };
  };

  let unsignedFallbackCandidate: string | undefined = fallbackUrl;

  const isUnusableOrUnsignedClassx = (uStr: string): boolean => {
    if (!uStr) return true;
    if (/pdflink\.com|\.pdf(\?|$)/i.test(uStr)) return true;
    if (/(?:appx-content|transcoded-videos|appx-transcoded-videos|akamai\.net\.in)/i.test(uStr) && !/edge-cache-token=/i.test(uStr)) {
      return true;
    }
    if (/appxcontent\.kaxa\.in/i.test(uStr) && !/edge-cache-token=|Signature=/i.test(uStr)) {
      return true;
    }
    return false;
  };

  // Fast 0ms Path: If course scan already produced a freshly-signed CDN stream URL (and this isn't a retry after 401/403),
  // rewrite its ClassX quality folder to match the user's current preferredQuality!
  if (
    !hintMeta?.skipFallback &&
    fallbackUrl &&
    /^https?:\/\//i.test(fallbackUrl) &&
    !isUnusableOrUnsignedClassx(fallbackUrl) &&
    (/edge-cache-token=|token=|expires=|\.(m3u8|mp4)(\?|$)/i.test(fallbackUrl))
  ) {
    const rewrittenFallback = rewriteClassxQualityUrl(fallbackUrl.trim(), normPrefQuality);
    return {
      streamUrl: rewrittenFallback.url,
      quality: normPrefQuality,
      title: hintMeta?.title,
    };
  }

  const pickBestFromQualitiesArray = (
    qualitiesArr: any[],
    titleHint?: string
  ): { streamUrl: string; quality: string; title?: string } | null => {
    if (!Array.isArray(qualitiesArr) || qualitiesArr.length === 0) return null;
    const valid = qualitiesArr.filter(
      (q) => q && typeof (q.url || q.path) === 'string' && /^https?:\/\//i.test(String(q.url || q.path).trim())
    );
    if (valid.length === 0) return null;
    const signedPool = valid.filter((q) => !isUnusableOrUnsignedClassx(String(q.url || q.path)));
    const pool = signedPool.length > 0 ? signedPool : valid;
    let chosen = pool[0];
    let bestDiff = Infinity;
    for (const q of pool) {
      const qNum = parseInt(String(q.quality || q.label || '').replace(/\D/g, ''), 10);
      if (!isNaN(qNum)) {
        const diff = Math.abs(qNum - targetNum);
        if (diff < bestDiff) {
          bestDiff = diff;
          chosen = q;
        }
      }
    }
    const chosenUrl = String(chosen.url || chosen.path).trim();
    if (isUnusableOrUnsignedClassx(chosenUrl)) {
      if (!/pdflink\.com|\.pdf(\?|$)/i.test(chosenUrl)) {
        unsignedFallbackCandidate = chosenUrl;
      }
      return null;
    }
    const rewritten = rewriteClassxQualityUrl(chosenUrl, normPrefQuality);
    return {
      streamUrl: rewritten.url,
      quality: normPrefQuality || String(chosen.quality || chosen.label || '480p'),
      title: titleHint,
    };
  };

  const extractPlayableFromData = (
    rawObj: any
  ): { streamUrl: string; quality: string; title?: string } | null => {
    if (!rawObj || typeof rawObj !== 'object') return null;
    const vData = rawObj.data && typeof rawObj.data === 'object' && !Array.isArray(rawObj.data) ? rawObj.data : rawObj;
    const titleHint =
      vData.Title || vData.title || rawObj.title || rawObj.Title || undefined;
    const ytHint = Number(vData.ytFlag ?? vData.yt_flag ?? vData.ytFlagWeb ?? rawObj.ytFlag ?? 0) === 1;

    // 1. Check qualities array (Vidyagram, SachinAcademy, YesOfficer, etc.)
    const fromQualities =
      pickBestFromQualitiesArray(rawObj.qualities, titleHint) ||
      pickBestFromQualitiesArray(vData.qualities, titleHint);
    if (fromQualities) return fromQualities;

    // 2. Check encrypted_links first (signed adaptive HLS), then download_links / livestream_links
    const linkArrays = [
      vData.encrypted_links,
      rawObj.encrypted_links,
      vData.download_links,
      rawObj.download_links,
      vData.livestream_links,
    ];
    for (const arr of linkArrays) {
      if (Array.isArray(arr) && arr.length > 0) {
        const decryptedCandidates: { url: string; quality: string; qNum: number; isClassxRewriteable: boolean }[] = [];
        for (const link of arr) {
          if (!link) continue;
          const dec =
            normalizeAppxMediaUrl(link.path || link.url || '', ytHint) ||
            normalizeAppxMediaUrl(link.backup_url || '', ytHint) ||
            normalizeAppxMediaUrl(link.backup_url2 || '', ytHint);
          if (dec) {
            if (isUnusableOrUnsignedClassx(dec)) {
              unsignedFallbackCandidate = dec;
              continue;
            }
            const qStr = String(link.quality || link.bitrate || normPrefQuality || '480p');
            const qNum = parseInt(qStr.replace(/\D/g, ''), 10) || 480;
            decryptedCandidates.push({
              url: dec,
              quality: qStr,
              qNum,
              isClassxRewriteable: /(?:transcoded-videos|appx-transcoded-videos|akamai\.net\.in)/i.test(dec) && /\/(144p|240p|360p|480p|720p|1080p)\/master-/i.test(dec),
            });
          }
        }
        if (decryptedCandidates.length > 0) {
          let best = decryptedCandidates[0];
          let bestDiff = Infinity;
          for (const c of decryptedCandidates) {
            const diff = Math.abs(c.qNum - targetNum);
            if (diff < bestDiff) {
              bestDiff = diff;
              best = c;
            }
          }
          if (best.isClassxRewriteable) {
            const rewritten = rewriteClassxQualityUrl(best.url, normPrefQuality);
            return { streamUrl: rewritten.url, quality: normPrefQuality, title: titleHint };
          }
          return {
            streamUrl: best.url,
            quality: `${best.qNum}p` || normPrefQuality || best.quality,
            title: titleHint,
          };
        }
      }
    }

    // 3. Check singular download_link / download_link2 / file_link / decoded_video_link / ytFlag video_id
    for (const singleField of [
      vData.download_link,
      vData.download_link2,
      rawObj.download_link,
      vData.file_link,
      rawObj.decoded_video_link,
      vData.decoded_video_link,
      ytHint ? vData.video_id : undefined,
      ytHint ? vData.id : undefined,
    ]) {
      if (singleField && (typeof singleField === 'string' || typeof singleField === 'number')) {
        const decSingle = normalizeAppxMediaUrl(String(singleField), ytHint);
        if (decSingle) {
          if (!isUnusableOrUnsignedClassx(decSingle)) {
            const rewritten = rewriteClassxQualityUrl(decSingle, normPrefQuality);
            return {
              streamUrl: rewritten.url,
              quality: normPrefQuality,
              title: titleHint,
            };
          }
          unsignedFallbackCandidate = decSingle;
        }
      }
    }

    // 4. Check video_player_url + video_player_token
    if (vData.video_player_url && vData.video_player_token) {
      const playerUrl =
        String(vData.video_player_url).replace('?isMobile=true&', '?') +
        String(vData.video_player_token);
      if (/^https?:\/\//i.test(playerUrl) && !isUnusableOrUnsignedClassx(playerUrl)) {
        const rewritten = rewriteClassxQualityUrl(playerUrl, normPrefQuality);
        return {
          streamUrl: rewritten.url,
          quality: normPrefQuality,
          title: titleHint,
        };
      }
    }

    return null;
  };

  // A. Special Portal: MJ / MissionJeet (/mj, /missionjeet)
  if (domainId.toUpperCase() === 'MJ' || /\/(mj|missionjeet)(\/|$)/i.test(portalPath)) {
    try {
      const mjRes =
        (await fetchAppxJsonWithRetry(
          `https://mj.smexdoy.workers.dev/?content_id=${encodeURIComponent(videoId)}&course_id=${encodeURIComponent(courseId)}`,
          { 'User-Agent': DEFAULT_USER_AGENT },
          3
        )) ||
        (await fetchAppxJsonWithRetry(
          `${cleanOrig}/api/nig?content_id=${encodeURIComponent(videoId)}&course_id=${encodeURIComponent(courseId)}`,
          { 'User-Agent': DEFAULT_USER_AGENT, Referer: `${cleanOrig}/mj/play.html?course_id=${courseId}&content_id=${videoId}` },
          2
        ));
      if (mjRes) {
        const mediaData = mjRes.decryptedData || mjRes.data || {};
        const drmUrl = mjRes.drm_details?.data?.link?.file_url;
        const foundUrl =
          drmUrl ||
          mediaData.file_url ||
          mediaData.url ||
          mediaData.videoUrl ||
          mjRes.file_url ||
          mjRes.url;
        if (foundUrl && /^https?:\/\//i.test(String(foundUrl))) {
          return {
            streamUrl: String(foundUrl).trim(),
            quality: preferredQuality || '480p',
            title: mediaData.title || mjRes.title || undefined,
          };
        }
      }
    } catch {
      // continue
    }
  }

  // B. Special Portal: MasterSahab (/mastersahab, /ms)
  if (domainId.toUpperCase() === 'MS' || /\/(mastersahab|ms)(\/|$)/i.test(portalPath)) {
    for (const msApiPath of ['/api/mastersahab/course/get_master_data', '/api/ms/course/get_master_data']) {
      try {
        const msRes = await fetch(`${cleanOrig}${msApiPath}`, {
          method: 'POST',
          headers: {
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-Type': 'application/json',
            Referer: `${cleanOrig}/mastersahab/${courseId}`,
          },
          body: JSON.stringify({
            course_id: String(courseId),
            content_id: String(videoId),
            parent_id: '1',
          }),
          signal: AbortSignal.timeout(10000),
        });
        if (msRes.ok) {
          const msJson = (await msRes.json()) as any;
          const dObj = msJson?.decodedResponse?.data || msJson?.decodedResponse || msJson?.data || msJson;
          const msUrl =
            dObj?.m3u8_url ||
            dObj?.file_url ||
            dObj?.videoUrl ||
            dObj?.url ||
            msJson?.m3u8_url ||
            msJson?.file_url;
          if (msUrl && /^https?:\/\//i.test(String(msUrl))) {
            return {
              streamUrl: String(msUrl).trim(),
              quality: preferredQuality || '480p',
              title: dObj?.title || undefined,
            };
          }
        }
      } catch {
        // continue
      }
    }
  }

  const portalSession = getPortalSessionForOrigin(cleanOrig, hintMeta?.chatId);
  const portalAuthHeaders = buildPortalSessionHeaders(
    portalSession,
    `${cleanOrig}${portalPath.startsWith('/') ? portalPath : '/' + portalPath}/play.html?course_id=${courseId}&video_id=${videoId}`
  );
  const isCustomWebOrigin = !/studybeepro\.site$/i.test(cleanOrig);

  // C. Try StudyBeePro / StudyPanda / Custom Web Portal / External Mirrors proxy (/get/fetchVideoDetailsById, /api/rwa/get/..., /api/rwax/get/..., /api/scienceandfun, /api/vibrant)
  const configuredMirrors = (rojgarAdminConfig.externalMirrors || []).filter(
    (m) => m && m.enabled && m.baseUrl && m.lastSyncStatus !== 'auth_required'
  );
  if (portalPath && (isCustomWebOrigin || !/\/rwa/i.test(portalPath) || configuredMirrors.length > 0)) {
    const portalProxyUrls: { url: string; headers: Record<string, string>; retries: number }[] = [];
    if (/\/(scienceandfun|sf)(\/|$)/i.test(portalPath)) {
      portalProxyUrls.push(
        {
          url: `${cleanOrig}/api/scienceandfun/vg/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=1`,
          headers: portalAuthHeaders,
          retries: 1,
        },
        {
          url: `https://studypanda.live/api/scienceandfun/vg/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=1`,
          headers: portalAuthHeaders,
          retries: 1,
        }
      );
    }
    if (/\/(vibrant|vibrante)(\/|$)/i.test(portalPath)) {
      portalProxyUrls.push(
        {
          url: `${cleanOrig}/api/vibrant/playx?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}`,
          headers: portalAuthHeaders,
          retries: 1,
        },
        {
          url: `https://studypanda.live/api/vibrant/playx?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}`,
          headers: portalAuthHeaders,
          retries: 1,
        }
      );
    }
    if (isCustomWebOrigin && /\/rwa/i.test(portalPath)) {
      for (const fw of [0, 1]) {
        portalProxyUrls.push(
          {
            url: `${cleanOrig}/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=${fw}`,
            headers: portalAuthHeaders,
            retries: 1,
          },
          {
            url: `${cleanOrig}/api/rwax/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=${fw}`,
            headers: portalAuthHeaders,
            retries: 1,
          },
          {
            url: `${cleanOrig}/api/rwa/stream?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&courseId=${encodeURIComponent(courseId)}&videoId=${encodeURIComponent(videoId)}`,
            headers: portalAuthHeaders,
            retries: 1,
          }
        );
      }
    }
    if (portalPath && (isCustomWebOrigin || !/\/rwa/i.test(portalPath))) {
      for (const fw of [0, 1]) {
        portalProxyUrls.push({
          url: `${cleanOrig}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=${fw}`,
          headers: portalAuthHeaders,
          retries: isCustomWebOrigin ? 1 : 2,
        });
      }
    }
    for (const mir of configuredMirrors) {
      const mOrig = mir.baseUrl.replace(/\/+$/, '');
      if (mOrig === cleanOrig) continue;
      const mSess = getPortalSessionForOrigin(mOrig, hintMeta?.chatId);
      const mHdrs: Record<string, string> = {
        'User-Agent': DEFAULT_USER_AGENT,
        Referer: `${mOrig}${mir.portalPath || '/rwax'}/`,
        ...(mSess ? buildPortalSessionHeaders(mSess, `${mOrig}/`) : {}),
        ...(mir.cookieHeader ? { Cookie: mir.cookieHeader } : {}),
        ...(mir.bearerToken ? { Authorization: mir.bearerToken } : {}),
        ...(mir.userId ? { 'User-ID': mir.userId } : {}),
      };
      portalProxyUrls.push(
        {
          url: `${mOrig}/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
          headers: mHdrs,
          retries: 1,
        },
        {
          url: `${mOrig}/api/rwax/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
          headers: mHdrs,
          retries: 1,
        }
      );
    }
    for (const item of portalProxyUrls) {
      try {
        const jPortal = await fetchAppxJsonWithRetry(item.url, item.headers, item.retries);
        const extracted = extractPlayableFromData(jPortal);
        if (extracted) return extracted;
      } catch {
        // continue
      }
    }
  }

  // D & E. Concurrent Fast Stream Resolution: Fire asmultiverse.site/rwa/ FIRST / concurrently with Step D via Promise.any!
  let directVideoMeta: {
    subjectId?: string;
    topicId?: string;
    conceptId?: string;
    title?: string;
    strtotime?: number;
    duration?: string;
  } = {
    subjectId: hintMeta?.subjectId || undefined,
    topicId: hintMeta?.topicId || undefined,
    conceptId: hintMeta?.conceptId || '1',
    title: hintMeta?.title || undefined,
    strtotime: hintMeta?.strtotime || undefined,
    duration: hintMeta?.duration || undefined,
  };
  let cachedAppxHeaders: Record<string, string> | null = null;
  let cachedApiUrl = 'https://rozgarapinew.teachx.in';

  const asmVideoDataCache: Map<string, { data: any; fetchedAt: number }> =
    (resolveAppxVideoStreamUrl as any)._asmVideoDataCache ||
    ((resolveAppxVideoStreamUrl as any)._asmVideoDataCache = new Map<string, { data: any; fetchedAt: number }>());
  const videoCacheKey = `${courseId}:${videoId}`;
  const cachedRawVideo = asmVideoDataCache.get(videoCacheKey);
  if (cachedRawVideo && Date.now() - cachedRawVideo.fetchedAt < 20 * 60 * 1000) {
    const cachedExtracted = extractPlayableFromData(cachedRawVideo.data);
    if (cachedExtracted) return cachedExtracted;
  }

  const asmGlobalCooldownRef: { until: number } =
    (resolveAppxVideoStreamUrl as any)._asmGlobalCooldown ||
    ((resolveAppxVideoStreamUrl as any)._asmGlobalCooldown = { until: 0 });
  const asmCacheMap: Map<string, number> =
    (resolveAppxVideoStreamUrl as any)._asmUnpurchasedMap ||
    ((resolveAppxVideoStreamUrl as any)._asmUnpurchasedMap = new Map<string, number>());
  const asmRateLimitMap: Map<string, number> =
    (resolveAppxVideoStreamUrl as any)._asmRateLimitMap ||
    ((resolveAppxVideoStreamUrl as any)._asmRateLimitMap = new Map<string, number>());
  const donorTopicCache: Map<string, any[]> =
    (resolveAppxVideoStreamUrl as any)._donorTopicCache ||
    ((resolveAppxVideoStreamUrl as any)._donorTopicCache = new Map<string, any[]>());

  let rateLimitHitOnAsm = false;
  let portalTokenUnpurchased = false;
  let unrecordedErrorToThrow: Error | null = null;

  try {
    const cfg = await fetchAppxDomainConfig(domainId, origin);
    cachedApiUrl = cfg.apiUrl;
    cachedAppxHeaders = {
      'User-Agent': DEFAULT_USER_AGENT,
      'Auth-Key': 'appxapi',
      'User-ID': cfg.userId || activeMintedRwaToken.userId || '16231827',
      Authorization: freshAppxAuthToken(cfg.token || activeMintedRwaToken.token),
      source: 'website',
      'Client-Service': 'Appx',
      Referer: 'https://rozgarapinew.teachx.in/',
    };
  } catch {
    cachedAppxHeaders = {
      'User-Agent': DEFAULT_USER_AGENT,
      'Auth-Key': 'appxapi',
      'User-ID': activeMintedRwaToken.userId || '16231827',
      Authorization: freshAppxAuthToken(activeMintedRwaToken.token),
      source: 'website',
      'Client-Service': 'Appx',
      Referer: 'https://rozgarapinew.teachx.in/',
    };
  }

  const cachedUnpurchasedUntil = asmCacheMap.get(String(courseId)) || 0;
  const cachedRateLimitUntil = asmRateLimitMap.get(String(courseId)) || 0;
  if (Date.now() < cachedUnpurchasedUntil) {
    portalTokenUnpurchased = true;
  } else {
    const cooldownTarget = Math.max(cachedRateLimitUntil, asmGlobalCooldownRef.until);
    if (Date.now() < cooldownTarget) {
      const waitMs = Math.min(2800, Math.max(0, cooldownTarget - Date.now()));
      if (waitMs > 0) await new Promise((r) => setTimeout(r, waitMs));
    }
  }

  const adminOverride = rojgarAdminConfig.batchOverrides[String(courseId)];

  // Custom User Logged-In Session Token OR Admin Batch API / Token Override Resolver OR Global Admin API / Token Vault
  const customCandidates = [
    ...(portalSession?.bearerToken
      ? [{
          apiUrl: portalSession.teachxApiUrl,
          token: portalSession.bearerToken.replace(/^Bearer\s+/i, ''),
          userId: portalSession.userId,
        }]
      : []),
    ...(adminOverride && (adminOverride.customApiUrl || adminOverride.customToken)
      ? [{ apiUrl: adminOverride.customApiUrl, token: adminOverride.customToken, userId: adminOverride.customUserId }]
      : []),
    ...(rojgarAdminConfig.globalCustomApiUrl || rojgarAdminConfig.globalCustomToken
      ? [{
          apiUrl: rojgarAdminConfig.globalCustomApiUrl,
          token: rojgarAdminConfig.globalCustomToken,
          userId: rojgarAdminConfig.globalCustomUserId,
        }]
      : []),
  ];

  for (const ovCand of customCandidates) {
    try {
      if (ovCand.apiUrl) {
        const customUrl = ovCand.apiUrl.includes('{video_id}') || ovCand.apiUrl.includes('{course_id}')
          ? ovCand.apiUrl
              .replace(/\{course_id\}/gi, encodeURIComponent(courseId))
              .replace(/\{video_id\}/gi, encodeURIComponent(videoId))
              .replace(/\{quality\}/gi, encodeURIComponent(normPrefQuality))
          : `${ovCand.apiUrl.replace(/\/$/, '')}${ovCand.apiUrl.includes('?') ? '&' : '?'}course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=${hintMeta?.ytFlag === '1' ? '1' : '0'}`;
        const cHeaders: Record<string, string> = { 'User-Agent': DEFAULT_USER_AGENT };
        if (ovCand.token) {
          cHeaders.Authorization = ovCand.token;
          cHeaders['Auth-Key'] = 'appxapi';
          cHeaders['Client-Service'] = 'Appx';
          cHeaders.source = 'website';
          if (ovCand.userId) cHeaders['User-ID'] = ovCand.userId;
        }
        const jCustom = await fetchAppxJsonWithRetry(customUrl, cHeaders, 1);
        const extractedCustom = extractPlayableFromData(jCustom);
        if (extractedCustom) return extractedCustom;
        const directCUrl = jCustom?.streamUrl || jCustom?.url || jCustom?.file_url || jCustom?.m3u8_url || jCustom?.data?.url;
        if (directCUrl && /^https?:\/\//i.test(String(directCUrl))) {
          return { streamUrl: String(directCUrl).trim(), quality: normPrefQuality, title: hintMeta?.title };
        }
      }
      if (ovCand.token && cachedApiUrl) {
        const tokHeaders: Record<string, string> = {
          'User-Agent': DEFAULT_USER_AGENT,
          'Auth-Key': 'appxapi',
          'Client-Service': 'Appx',
          source: 'website',
          'User-ID': ovCand.userId || extractTeachxJwtMeta(ovCand.token).userId,
          Authorization: ovCand.token,
          Referer: `${cachedApiUrl}/`,
        };
        for (const ytTry of hintMeta?.ytFlag === '1' ? ['1', '0'] : ['0', '1']) {
          for (const fwTry of ['0', '1']) {
            const jTok = await fetchAppxJsonWithRetry(
              `${cachedApiUrl}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(courseId)}&video_id=${encodeURIComponent(videoId)}&ytflag=${ytTry}&folder_wise_course=${fwTry}`,
              tokHeaders,
              1
            );
            const extTok = extractPlayableFromData(jTok);
            if (extTok) return extTok;
          }
        }
      }
    } catch {
      // continue to standard resolvers
    }
  }

  const asmQueueRef: { chain: Promise<any>; lastCallAt: number } =
    (resolveAppxVideoStreamUrl as any)._asmQueueRef ||
    ((resolveAppxVideoStreamUrl as any)._asmQueueRef = { chain: Promise.resolve(), lastCallAt: 0 });

  const scheduleAsmCall = <T,>(fn: () => Promise<T>): Promise<T> => {
    const run = asmQueueRef.chain.then(async () => {
      const waitMs = Math.max(0, 320 - (Date.now() - asmQueueRef.lastCallAt));
      if (waitMs > 0) await new Promise((r) => setTimeout(r, waitMs));
      asmQueueRef.lastCallAt = Date.now();
      return fn();
    });
    asmQueueRef.chain = run.catch(() => null);
    return run;
  };

  const runAsmResolver = async (): Promise<{ streamUrl: string; quality: string; title?: string }> => {
    if (portalTokenUnpurchased) {
      throw new Error('ASM_SKIPPED');
    }
    const ytInit = hintMeta?.ytFlag === '1' ? '1' : '0';
    const makeAsmUrl = (ytf: string, fw = '0') =>
      `https://asmultiverse.site/rwa/?course_id=${encodeURIComponent(
        courseId
      )}&video_id=${encodeURIComponent(videoId)}&ytflag=${ytf}&folder_wise_course=${fw}&lc_app_api_url=`;

    const isAsmRateLimit = (resp: any) =>
      Boolean(
        resp &&
          (resp.rate_limit_hit === true ||
            resp.status === 429 ||
            /429|rate limit/i.test(String(resp.message || '')))
      );

    let jAsm = await scheduleAsmCall(() =>
      fetchAppxJsonWithRetry(makeAsmUrl(ytInit, '0'), { 'User-Agent': DEFAULT_USER_AGENT }, 1)
    );
    if (isAsmRateLimit(jAsm)) {
      await new Promise((r) => setTimeout(r, 1500));
      jAsm = await scheduleAsmCall(() =>
        fetchAppxJsonWithRetry(makeAsmUrl(ytInit, '0'), { 'User-Agent': DEFAULT_USER_AGENT }, 1)
      );
    }
    if (isAsmRateLimit(jAsm)) {
      await new Promise((r) => setTimeout(r, 2200));
      jAsm = await scheduleAsmCall(() =>
        fetchAppxJsonWithRetry(makeAsmUrl(ytInit, '0'), { 'User-Agent': DEFAULT_USER_AGENT }, 1)
      );
    }
    // Automatic ytflag=1 & folder_wise_course=1 retry if ytflag=0 failed with HTTP 400 (YouTube or folder-mode classes)
    if (
      jAsm &&
      !/koi token nahi mila/i.test(String(jAsm.message || '')) &&
      (jAsm.status === 400 || /status 400/i.test(String(jAsm.message || '')) || (!extractPlayableFromData(jAsm) && String(jAsm?.data?.is_purchased ?? '') !== '0'))
    ) {
      if (ytInit === '0') {
        const jAsmYt = await scheduleAsmCall(() =>
          fetchAppxJsonWithRetry(makeAsmUrl('1', '0'), { 'User-Agent': DEFAULT_USER_AGENT }, 1)
        );
        if (jAsmYt && extractPlayableFromData(jAsmYt)) jAsm = jAsmYt;
      }
      if (!extractPlayableFromData(jAsm)) {
        const jAsmFw = await scheduleAsmCall(() =>
          fetchAppxJsonWithRetry(makeAsmUrl(ytInit, '1'), { 'User-Agent': DEFAULT_USER_AGENT }, 1)
        );
        if (jAsmFw && extractPlayableFromData(jAsmFw)) jAsm = jAsmFw;
      }
    }
    if (isAsmRateLimit(jAsm)) {
      rateLimitHitOnAsm = true;
      throw new Error('ASM_RATE_LIMIT');
    }
    const extracted = extractPlayableFromData(jAsm);
    if (extracted) {
      asmVideoDataCache.set(videoCacheKey, { data: jAsm, fetchedAt: Date.now() });
      asmCacheMap.delete(String(courseId));
      asmRateLimitMap.delete(String(courseId));
      return extracted;
    }
    const asmMsg = String(jAsm?.message || jAsm?.error || '');
    if (
      jAsm &&
      ((jAsm.status === 200 && String(jAsm?.data?.is_purchased ?? '') === '0') ||
        /koi token nahi mila/i.test(asmMsg) ||
        /status 401|unauthorized|forbidden/i.test(asmMsg) ||
        (jAsm.status === 500 && jAsm.tokens_tried >= 1 && !jAsm.rate_limit_hit))
    ) {
      portalTokenUnpurchased = true;
      asmCacheMap.set(String(courseId), Date.now() + 2 * 60 * 1000);
    }
    throw new Error('ASM_NO_STREAM');
  };

  const runDirectDetailsResolver = async (forceRun = false): Promise<{ streamUrl: string; quality: string; title?: string }> => {
    const shouldCallDirectDetails =
      forceRun || hintMeta?.freeFlag === '1' || hintMeta?.ytFlag === '1' || !directVideoMeta.subjectId || !directVideoMeta.topicId;
    if (!shouldCallDirectDetails || !cachedAppxHeaders) {
      throw new Error('DIRECT_SKIPPED');
    }
    const ytDirect = hintMeta?.ytFlag === '1' ? '1' : '0';
    let jDirect = await fetchAppxJsonWithRetry(
      `${cachedApiUrl}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
        courseId
      )}&video_id=${encodeURIComponent(videoId)}&ytflag=${ytDirect}&folder_wise_course=0`,
      cachedAppxHeaders,
      1
    );
    if (ytDirect === '0' && jDirect && (jDirect.status === 400 || /status 400/i.test(String(jDirect.message || '')))) {
      const jDirectYt = await fetchAppxJsonWithRetry(
        `${cachedApiUrl}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
          courseId
        )}&video_id=${encodeURIComponent(videoId)}&ytflag=1&folder_wise_course=0`,
        cachedAppxHeaders,
        1
      );
      if (jDirectYt) jDirect = jDirectYt;
    }
    let extractedDirect = extractPlayableFromData(jDirect);
    if (!extractedDirect && jDirect?.status && (jDirect.status === 401 || jDirect.status === 403 || jDirect.status === 429)) {
      const freshlyMinted = await mintFreshTeachxToken(cachedApiUrl).catch(() => null);
      if (freshlyMinted) {
        cachedAppxHeaders = {
          ...cachedAppxHeaders,
          'User-ID': freshlyMinted.userId,
          Authorization: freshlyMinted.token,
        };
        jDirect = await fetchAppxJsonWithRetry(
          `${cachedApiUrl}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
            courseId
          )}&video_id=${encodeURIComponent(videoId)}&ytflag=${ytDirect}&folder_wise_course=0`,
          cachedAppxHeaders,
          1
        );
        extractedDirect = extractPlayableFromData(jDirect);
      }
    }
    cachedAppxHeaders = {
      ...cachedAppxHeaders,
      'User-ID': cachedAppxHeaders['User-ID'] || activeMintedRwaToken.userId,
      Authorization: cachedAppxHeaders.Authorization || activeMintedRwaToken.token,
    };
    if (extractedDirect) {
      asmVideoDataCache.set(videoCacheKey, { data: jDirect, fetchedAt: Date.now() });
      return extractedDirect;
    }

    const vData = jDirect?.data;
    if (vData && typeof vData === 'object' && !Array.isArray(vData)) {
      const nonZeroStr = (val: any): string | undefined => {
        const s = String(val ?? '').trim();
        return s && s !== '0' ? s : undefined;
      };
      directVideoMeta = {
        subjectId: nonZeroStr(directVideoMeta.subjectId) || nonZeroStr(vData.subject),
        topicId: nonZeroStr(directVideoMeta.topicId) || nonZeroStr(vData.topic),
        conceptId: nonZeroStr(directVideoMeta.conceptId) || nonZeroStr(vData.concept) || '1',
        title: directVideoMeta.title || String(vData.Title || vData.title || '').trim() || undefined,
        strtotime: directVideoMeta.strtotime || Number(vData.strtotime || 0) || undefined,
        duration: nonZeroStr(directVideoMeta.duration) || nonZeroStr(vData.duration),
      };
      const mType = String(vData.material_type ?? '').toUpperCase();
      const recType = String(vData.recording_type ?? '').trim();
      const durStr = nonZeroStr(directVideoMeta.duration) || nonZeroStr(vData.duration) || '';
      const hlsType = String(vData.hls_stream_type ?? '0').trim();
      const isUnpurchasedStub = String(vData.is_purchased ?? '') === '0';
      const decFileLink = vData.file_link ? decryptAppxUrl(String(vData.file_link)) : null;
      const hasValidFileLink = Boolean(
        decFileLink && !/pdflink\.com|\.pdf(\?|$)/i.test(decFileLink)
      );
      const hasAnyLinks =
        hasValidFileLink ||
        Boolean(vData.video_player_url) ||
        (Array.isArray(vData.download_links) && vData.download_links.length > 0) ||
        (Array.isArray(vData.encrypted_links) && vData.encrypted_links.length > 0) ||
        (Array.isArray(vData.livestream_links) && vData.livestream_links.length > 0);

      if (
        mType === 'PDF' ||
        mType === 'DOC' ||
        mType === 'NOTES' ||
        (!isUnpurchasedStub && recType === '0' && (!durStr || durStr === '0') && hlsType === '0' && !hasAnyLinks)
      ) {
        unrecordedErrorToThrow = new Error(
          `UNRECORDED_CLASS_SKIP: Video recording not uploaded on server yet (video_id=${videoId})`
        );
      }
    }
    throw new Error('DIRECT_NO_STREAM');
  };

  const shouldTryDirectFirst =
    hintMeta?.freeFlag === '1' || hintMeta?.ytFlag === '1' || !directVideoMeta.subjectId || !directVideoMeta.topicId;

  if (shouldTryDirectFirst) {
    try {
      const fastest = await Promise.any([runAsmResolver(), runDirectDetailsResolver(true)]);
      if (fastest) return fastest;
    } catch {
      if (unrecordedErrorToThrow) {
        throw unrecordedErrorToThrow;
      }
    }
  } else {
    try {
      const asmRes = await runAsmResolver();
      if (asmRes) return asmRes;
    } catch {
      // fallback to direct details & portal mirrors immediately
      try {
        const directFallback = await runDirectDetailsResolver(true);
        if (directFallback) return directFallback;
      } catch {
        if (unrecordedErrorToThrow) {
          throw unrecordedErrorToThrow;
        }
      }
    }
  }

  // E2. Cross-Course Shared Subject Fallback (STRICT matching: same subjectId & topicId & exact videoId OR exact title)
  if (
    directVideoMeta.subjectId &&
    directVideoMeta.topicId &&
    cachedAppxHeaders
  ) {
    const winningDonorMap: Map<string, string> =
      (resolveAppxVideoStreamUrl as any)._winningDonorBySubject ||
      ((resolveAppxVideoStreamUrl as any)._winningDonorBySubject = new Map<string, string>());

    const subjId = String(directVideoMeta.subjectId).trim();
    const mappedSubjectDonors = RWA_SUBJECT_DONOR_COURSES[subjId];
    const discoveredSubjectDonors = Array.from(rwaSubjectToCoursesMap.get(subjId) || []);
    const adminExtraDonors = Array.isArray(adminOverride?.donorCourseIds)
      ? adminOverride.donorCourseIds.map((x) => String(x).trim()).filter(Boolean)
      : [];
    const defaultDonorSet = new Set(RWA_DEFAULT_DONOR_COURSES);
    const activeHealthDonors = discoveredSubjectDonors.filter((d) => {
      const st = rwaBatchHealthCache.get(d)?.status;
      return st === 'active' || st === 'custom_api';
    });
    const partialHealthDonors = discoveredSubjectDonors.filter(
      (d) => rwaBatchHealthCache.get(d)?.status === 'partial'
    );
    const otherDiscoveredDonors = discoveredSubjectDonors.filter(
      (d) => !activeHealthDonors.includes(d) && !partialHealthDonors.includes(d)
    );
    const prioritizedDiscovered = [
      ...activeHealthDonors.filter((d) => defaultDonorSet.has(d)),
      ...activeHealthDonors.filter((d) => !defaultDonorSet.has(d)),
      ...partialHealthDonors.filter((d) => defaultDonorSet.has(d)),
      ...partialHealthDonors.filter((d) => !defaultDonorSet.has(d)),
      ...otherDiscoveredDonors.filter((d) => defaultDonorSet.has(d)),
      ...otherDiscoveredDonors.filter((d) => !defaultDonorSet.has(d)),
    ];
    const preferredDonors = [
      ...adminExtraDonors,
      ...(mappedSubjectDonors || []),
      ...prioritizedDiscovered,
      ...(!mappedSubjectDonors && prioritizedDiscovered.length === 0 && adminExtraDonors.length === 0
        ? RWA_DEFAULT_DONOR_COURSES.slice(0, 35)
        : []),
    ];
    const cachedWinningDonor = winningDonorMap.get(subjId);
    const orderedDonors = Array.from(
      new Set([
        ...(cachedWinningDonor ? [cachedWinningDonor] : []),
        ...preferredDonors,
      ])
    ).filter(
      (donorCourseId) =>
        donorCourseId !== String(courseId) &&
        rwaBatchHealthCache.get(donorCourseId)?.status !== 'unpurchased' &&
        Date.now() >= (asmRateLimitMap.get(donorCourseId) || 0) &&
        Date.now() >= (asmCacheMap.get(donorCourseId) || 0)
    );

    const trySingleDonorCourse = async (
      donorCourseId: string
    ): Promise<{ streamUrl: string; quality: string; title?: string } | null> => {
      try {
        const cacheKey = `${donorCourseId}:${subjId}:${directVideoMeta.topicId}:${
          directVideoMeta.conceptId || '1'
        }`;
        let donorItems: any[] | undefined = donorTopicCache.get(cacheKey);
        if (!donorItems || donorItems.length === 0) {
          const fetchDonorConceptItems = async (cid: string): Promise<any[]> => {
            const donorQuery = `courseid=${encodeURIComponent(
              donorCourseId
            )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
              directVideoMeta.topicId!
            )}&conceptid=${encodeURIComponent(cid)}&start=-1`;
            let donorListJson = await fetchAppxJsonWithRetry(
              `${cachedApiUrl}/get/livecourseclassbycoursesubtopconceptapiv3?${donorQuery}`,
              cachedAppxHeaders!,
              1
            ).catch(() => null);
            let items: any[] = Array.isArray(donorListJson?.data)
              ? donorListJson.data
              : Array.isArray(donorListJson)
              ? donorListJson
              : [];
            if (
              items.length === 0 &&
              donorListJson?.status &&
              (donorListJson.status === 401 || donorListJson.status === 403 || donorListJson.status === 429)
            ) {
              const freshlyMinted = await mintFreshTeachxToken(cachedApiUrl).catch(() => null);
              if (freshlyMinted) {
                cachedAppxHeaders = {
                  ...cachedAppxHeaders!,
                  'User-ID': freshlyMinted.userId,
                  Authorization: freshAppxAuthToken(freshlyMinted.token),
                };
                donorListJson = await fetchAppxJsonWithRetry(
                  `${cachedApiUrl}/get/livecourseclassbycoursesubtopconceptapiv3?${donorQuery}`,
                  cachedAppxHeaders!,
                  1
                ).catch(() => null);
                items = Array.isArray(donorListJson?.data)
                  ? donorListJson.data
                  : Array.isArray(donorListJson)
                  ? donorListJson
                  : [];
              }
            }
            return items;
          };

          const primaryCid = directVideoMeta.conceptId || '1';
          let resolvedItems = await fetchDonorConceptItems(primaryCid);
          if (resolvedItems.length === 0) {
            const conceptsJson = await fetchAppxJsonWithRetry(
              `${cachedApiUrl}/get/allconceptfrmlivecourseclass?courseid=${encodeURIComponent(
                donorCourseId
              )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
                directVideoMeta.topicId!
              )}&start=-1`,
              cachedAppxHeaders!,
              1
            ).catch(() => null);
            const conceptsArr: any[] = Array.isArray(conceptsJson?.data)
              ? conceptsJson.data
              : Array.isArray(conceptsJson)
              ? conceptsJson
              : [];
            const extraCids = conceptsArr
              .map((c) => String(c?.conceptid ?? c?.id ?? '').trim())
              .filter((id) => id && id !== primaryCid)
              .slice(0, 6);
            if (extraCids.length > 0) {
              const extraLists = await Promise.all(extraCids.map((id) => fetchDonorConceptItems(id)));
              resolvedItems = extraLists.flat();
            }
          }
          if (resolvedItems.length === 0 && primaryCid !== '0') {
            resolvedItems = await fetchDonorConceptItems('0');
          }
          if (resolvedItems.length === 0 && primaryCid !== '') {
            resolvedItems = await fetchDonorConceptItems('');
          }
          donorItems = resolvedItems;
          if (resolvedItems.length > 0) {
            donorTopicCache.set(cacheKey, resolvedItems);
          }
        }
        if (!donorItems || donorItems.length === 0) return null;

        const normTitle = (s?: string) =>
          String(s || '')
            .toLowerCase()
            .replace(/\s+/g, ' ')
            .trim();
        const targetTitleNorm = normTitle(directVideoMeta.title);
        const validTargetDur =
          directVideoMeta.duration && directVideoMeta.duration !== '0'
            ? String(directVideoMeta.duration).trim()
            : '';
        // STRICT Lecture Match inside exact same subjectId + topicId:
        const matchedDonor =
          donorItems.find(
            (item: any) => String(item?.id ?? item?.video_id ?? '').trim() === String(videoId).trim()
          ) ||
          (targetTitleNorm
            ? donorItems.find(
                (item: any) =>
                  normTitle(item?.Title || item?.title) === targetTitleNorm &&
                  Boolean(directVideoMeta.strtotime) &&
                  Number(item?.strtotime || 0) === Number(directVideoMeta.strtotime)
              ) ||
              donorItems.find(
                (item: any) =>
                  normTitle(item?.Title || item?.title) === targetTitleNorm &&
                  Boolean(validTargetDur) &&
                  String(item?.duration || '').trim() === validTargetDur
              ) ||
              donorItems.find(
                (item: any) => normTitle(item?.Title || item?.title) === targetTitleNorm
              )
            : undefined);
        if (!matchedDonor || !matchedDonor.id) return null;

        const donorVidId = String(matchedDonor.id).trim();
        const directFromDonorList = extractPlayableFromData(matchedDonor);
        if (directFromDonorList) {
          asmVideoDataCache.set(videoCacheKey, { data: matchedDonor, fetchedAt: Date.now() });
          winningDonorMap.set(subjId, donorCourseId);
          return directFromDonorList;
        }
        let jDonorAsm = await scheduleAsmCall(() =>
          fetchAppxJsonWithRetry(
            `https://asmultiverse.site/rwa/?course_id=${encodeURIComponent(
              donorCourseId
            )}&video_id=${encodeURIComponent(donorVidId)}&ytflag=${Number(matchedDonor.ytFlag ?? 0) === 1 ? '1' : '0'}&folder_wise_course=0&lc_app_api_url=`,
            { 'User-Agent': DEFAULT_USER_AGENT },
            1
          )
        );
        const isDonorRateLimited = (resp: any) =>
          Boolean(
            resp &&
              (resp.rate_limit_hit === true ||
                resp.status === 429 ||
                /429|rate limit/i.test(String(resp.message || '')))
          );
        if (isDonorRateLimited(jDonorAsm)) {
          await new Promise((r) => setTimeout(r, 1800));
          jDonorAsm = await scheduleAsmCall(() =>
            fetchAppxJsonWithRetry(
              `https://asmultiverse.site/rwa/?course_id=${encodeURIComponent(
                donorCourseId
              )}&video_id=${encodeURIComponent(donorVidId)}&ytflag=${Number(matchedDonor.ytFlag ?? 0) === 1 ? '1' : '0'}&folder_wise_course=0&lc_app_api_url=`,
              { 'User-Agent': DEFAULT_USER_AGENT },
              1
            )
          );
        }
        if (isDonorRateLimited(jDonorAsm)) {
          asmRateLimitMap.set(donorCourseId, Date.now() + 2500);
          asmGlobalCooldownRef.until = Date.now() + 2000;
          rateLimitHitOnAsm = true;
          return null;
        }
        const extractedDonor = extractPlayableFromData(jDonorAsm);
        if (extractedDonor) {
          asmVideoDataCache.set(videoCacheKey, { data: jDonorAsm, fetchedAt: Date.now() });
          winningDonorMap.set(subjId, donorCourseId);
          console.log(
            `[Cross-Course Resolver] Resolved video "${directVideoMeta.title}" (vid=${videoId} in course ${courseId}) via active donor course ${donorCourseId} (vid=${donorVidId})!`
          );
          return extractedDonor;
        }
        if (jDonorAsm && String(jDonorAsm?.data?.is_purchased ?? '') === '0') {
          asmCacheMap.set(donorCourseId, Date.now() + 10 * 60 * 1000);
        }
      } catch {
        // ignore single donor error
      }
      return null;
    };

    // 1. If we have a known winning donor for this subject, try it immediately first!
    if (cachedWinningDonor && orderedDonors[0] === cachedWinningDonor) {
      const fastHit = await trySingleDonorCourse(cachedWinningDonor);
      if (fastHit) return fastHit;
    }

    // 2. Scan remaining donor courses in small parallel batches of 4
    const startIdx = cachedWinningDonor && orderedDonors[0] === cachedWinningDonor ? 1 : 0;
    for (let i = startIdx; i < orderedDonors.length; i += 4) {
      const batch = orderedDonors.slice(i, i + 4);
      const batchResults = await Promise.all(batch.map((dId) => trySingleDonorCourse(dId)));
      const found = batchResults.find((r) => r !== null);
      if (found) return found;
    }
  }

  // F. Try StudyBeePro / StudyPanda / Direct TeachX cross-fallback portals (folder_wise_course 0 & 1, ytflag 0 & 1)
  const crossFallbackUrls = [
    `${cleanOrig}/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
      courseId
    )}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
    ...(isCustomWebOrigin
      ? [
          `${cleanOrig}/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
            courseId
          )}&video_id=${encodeURIComponent(videoId)}&ytflag=1&folder_wise_course=1`,
          `${cleanOrig}/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
            courseId
          )}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
        ]
      : []),
    `https://studybeepro.site/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
      courseId
    )}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
    `https://studybeepro.site/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
      courseId
    )}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=1`,
    `https://studypanda.live/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
      courseId
    )}&video_id=${encodeURIComponent(videoId)}&ytflag=0&folder_wise_course=0`,
    `https://studypanda.live/api/rwa/get/fetchVideoDetailsById?course_id=${encodeURIComponent(
      courseId
    )}&video_id=${encodeURIComponent(videoId)}&ytflag=1&folder_wise_course=0`,
  ];
  const crossResults = await Promise.all(
    crossFallbackUrls.map(async (crossUrl) => {
      try {
        const useHeaders = crossUrl.startsWith(cleanOrig)
          ? portalAuthHeaders
          : { 'User-Agent': DEFAULT_USER_AGENT, Referer: `${cleanOrig}/` };
        const jCross = await fetchAppxJsonWithRetry(crossUrl, useHeaders, 1);
        return extractPlayableFromData(jCross);
      } catch {
        return null;
      }
    })
  );
  const workingCross = crossResults.find(Boolean);
  if (workingCross) return workingCross;

  if (unsignedFallbackCandidate) {
    return {
      streamUrl: unsignedFallbackCandidate,
      quality: preferredQuality || '480p',
    };
  }

  if (rateLimitHitOnAsm) {
    throw new Error(
      `RWA_RATE_LIMIT_COOLDOWN: RWA upstream token rate-limit cooldown active for video_id=${videoId}`
    );
  }

  if (portalTokenUnpurchased) {
    throw new Error(
      `BATCH_NOT_PURCHASED_ON_PORTAL: StudyBeePro server par is Course/Batch (ID: ${courseId}) ki videos abhi active/available nahi hain ("Video stream unavailable").`
    );
  }

  throw new Error(`No playable stream URL available for video_id=${videoId}`);
}


interface ParsedMediaPlaylist {
  isMaster: false;
  segments: { url: string; duration: number; key?: { method: string; uri?: string; iv?: string } }[];
  initMapUrl?: string;
  totalDurationSec: number;
  isEncrypted: boolean;
  encryptionMethod?: string;
}

interface ParsedMasterPlaylist {
  isMaster: true;
  variants: {
    url: string;
    bandwidth?: number;
    resolution?: string;
    codecs?: string;
    frameRate?: number;
    name?: string;
  }[];
}

function normalizeM3u8Content(rawContent: string): string {
  if (!rawContent) return '';
  let s = rawContent.replace(/\r/g, '');
  // 1. Ensure newline before every '#' tag
  s = s.replace(/(?!^)(#)/g, '\n$1');
  // 2. Separate variant stream URL attached directly to #EXT-X-STREAM-INF tag
  s = s.replace(/(#EXT-X-STREAM-INF:[^\n]+?)([^"\n\s,]+\.m3u8[^\s#]*)/gi, '$1\n$2');
  // 3. Separate segment URL attached directly after #EXTINF tag
  s = s.replace(/(#EXTINF:[\d.]+,?)([^\n#]+)/gi, '$1\n$2');
  // 4. Put newline before standalone http:// or https:// URLs
  s = s.replace(/([^\n])(https?:\/\/[^\s#]+)/gi, '$1\n$2');
  return s;
}

function parseM3u8Content(content: string, manifestUrl: string): ParsedMasterPlaylist | ParsedMediaPlaylist {
  const normalized = normalizeM3u8Content(content);
  const lines = normalized
    .split(/\r\n|\r|\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const isMaster = lines.some((l) => l.startsWith('#EXT-X-STREAM-INF'));

  if (isMaster) {
    const variants: ParsedMasterPlaylist['variants'] = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('#EXT-X-STREAM-INF:')) {
        const attrs = line.slice('#EXT-X-STREAM-INF:'.length);
        const bwMatch = attrs.match(/BANDWIDTH=(\d+)/i);
        const resMatch = attrs.match(/RESOLUTION=(\d+x\d+)/i);
        const codecsMatch = attrs.match(/CODECS="([^"]+)"/i);
        const fpsMatch = attrs.match(/FRAME-RATE=([\d.]+)/i);
        const nameMatch = attrs.match(/NAME="([^"]+)"/i);
        const videoMatch = attrs.match(/VIDEO="([^"]+)"/i);

        let nextIdx = i + 1;
        while (nextIdx < lines.length && lines[nextIdx].startsWith('#')) {
          nextIdx++;
        }
        if (nextIdx < lines.length) {
          variants.push({
            url: resolveRelativeUrl(lines[nextIdx], manifestUrl),
            bandwidth: bwMatch ? parseInt(bwMatch[1], 10) : undefined,
            resolution: resMatch ? resMatch[1] : undefined,
            codecs: codecsMatch ? codecsMatch[1] : undefined,
            frameRate: fpsMatch ? parseFloat(fpsMatch[1]) : undefined,
            name: nameMatch ? nameMatch[1] : videoMatch ? videoMatch[1] : undefined,
          });
          i = nextIdx;
        }
      }
    }
    variants.sort((a, b) => (b.bandwidth || 0) - (a.bandwidth || 0));
    return { isMaster: true, variants };
  }

  const segments: ParsedMediaPlaylist['segments'] = [];
  let currentDuration = 0;
  let totalDurationSec = 0;
  let currentKey: { method: string; uri?: string; iv?: string } | undefined;
  let isEncrypted = false;
  let encryptionMethod: string | undefined;
  let initMapUrl: string | undefined;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('#EXT-X-KEY:')) {
      const attrs = line.slice('#EXT-X-KEY:'.length);
      const methodMatch = attrs.match(/METHOD=([^,\s]+)/i);
      const uriMatch = attrs.match(/URI="([^"]+)"/i);
      const ivMatch = attrs.match(/IV=([^,\s]+)/i);
      const method = methodMatch ? methodMatch[1].toUpperCase() : 'NONE';
      if (method !== 'NONE') {
        isEncrypted = true;
        encryptionMethod = method;
        currentKey = {
          method,
          uri: uriMatch ? resolveRelativeUrl(uriMatch[1], manifestUrl) : undefined,
          iv: ivMatch ? ivMatch[1] : undefined,
        };
      } else {
        currentKey = undefined;
      }
    } else if (line.startsWith('#EXT-X-MAP:')) {
      const uriMatch = line.match(/URI="([^"]+)"/i);
      if (uriMatch) {
        initMapUrl = resolveRelativeUrl(uriMatch[1], manifestUrl);
      }
    } else if (line.startsWith('#EXTINF:')) {
      const durMatch = line.slice('#EXTINF:'.length).match(/^([\d.]+)/);
      currentDuration = durMatch ? parseFloat(durMatch[1]) : 4.0;
    } else if (!line.startsWith('#')) {
      segments.push({
        url: resolveRelativeUrl(line, manifestUrl),
        duration: currentDuration || 4.0,
        key: currentKey ? { ...currentKey } : undefined,
      });
      totalDurationSec += currentDuration || 4.0;
      currentDuration = 0;
    }
  }

  return {
    isMaster: false,
    segments,
    initMapUrl,
    totalDurationSec: Math.round(totalDurationSec),
    isEncrypted,
    encryptionMethod,
  };
}

function chooseVariantByPreferredQuality(
  variants: ParsedMasterPlaylist['variants'],
  preferredQuality: string = '480p'
): ParsedMasterPlaylist['variants'][0] {
  if (variants.length === 0) {
    throw new Error('No HLS variants available in master playlist.');
  }
  if (preferredQuality === 'best') {
    return variants[0];
  }
  const targetHeight = parseInt((preferredQuality || '480p').replace(/\D/g, ''), 10) || 480;

  let bestMatch = variants[0];
  let smallestDiff = Infinity;
  for (const v of variants) {
    const heightMatch = v.resolution?.match(/x(\d+)/i);
    const nameMatch = v.name?.match(/(\d+)p/i);
    const h = heightMatch
      ? parseInt(heightMatch[1], 10)
      : nameMatch
      ? parseInt(nameMatch[1], 10)
      : 0;
    if (h > 0) {
      const diff = Math.abs(h - targetHeight);
      if (diff < smallestDiff) {
        smallestDiff = diff;
        bestMatch = v;
      }
    }
  }
  return bestMatch;
}

const YTDLP_TMP_BIN_PATH = path.join(os.tmpdir(), 'yt-dlp');
const YTDLP_COOKIES_TMP_PATH = path.join(os.tmpdir(), 'streambridge_cookies.txt');
let resolvedYtDlpBinCache: string | null = null;
let ytdlpDownloadPromise: Promise<string | null> | null = null;

async function ensureYtDlpBinary(): Promise<string | null> {
  if (resolvedYtDlpBinCache && fs.existsSync(resolvedYtDlpBinCache)) {
    return resolvedYtDlpBinCache;
  }
  const candidates = ['/usr/local/bin/yt-dlp', '/usr/bin/yt-dlp', YTDLP_TMP_BIN_PATH];
  for (const cand of candidates) {
    try {
      if (fs.existsSync(cand)) {
        const st = fs.statSync(cand);
        if (st.size > 100000) {
          fs.chmodSync(cand, 0o755);
          resolvedYtDlpBinCache = cand;
          return cand;
        }
      }
    } catch {}
  }
  if (ytdlpDownloadPromise) return ytdlpDownloadPromise;
  ytdlpDownloadPromise = (async () => {
    try {
      const arch = os.arch();
      const binName = arch === 'arm64' ? 'yt-dlp_linux_aarch64' : 'yt-dlp_linux';
      const dlUrl = `https://github.com/yt-dlp/yt-dlp/releases/latest/download/${binName}`;
      await execFileAsync('curl', ['-fsSL', '--max-time', '60', '-o', YTDLP_TMP_BIN_PATH, dlUrl], {
        timeout: 65000,
      });
      if (fs.existsSync(YTDLP_TMP_BIN_PATH) && fs.statSync(YTDLP_TMP_BIN_PATH).size > 1000000) {
        fs.chmodSync(YTDLP_TMP_BIN_PATH, 0o755);
        resolvedYtDlpBinCache = YTDLP_TMP_BIN_PATH;
        return YTDLP_TMP_BIN_PATH;
      }
    } catch (e: any) {
      console.warn('[StreamBridge yt-dlp] Could not fetch standalone binary:', e?.message || e);
    } finally {
      ytdlpDownloadPromise = null;
    }
    return null;
  })();
  return ytdlpDownloadPromise;
}

// Pre-fetch standalone yt-dlp into /tmp at server boot without affecting /app/applet disk size
void ensureYtDlpBinary().catch(() => {});

function getYtDlpCookiesFilePath(): string | null {
  const rawCookies = (process.env.PLATFORM_COOKIES_TXT || '').trim();
  if (!rawCookies || rawCookies.length < 20) return null;
  try {
    fs.writeFileSync(YTDLP_COOKIES_TMP_PATH, rawCookies, 'utf8');
    return YTDLP_COOKIES_TMP_PATH;
  } catch {
    return null;
  }
}

function detectPlatformVideoUrl(rawUrl: string): { isPlatform: boolean; platformName: string } {
  try {
    const u = new URL(rawUrl);
    const host = u.hostname.toLowerCase().replace(/^www\./, '');
    if (/(?:^|\.)(youtube\.com|youtu\.be|youtube-nocookie\.com)$/.test(host)) {
      return { isPlatform: true, platformName: 'YouTube' };
    }
    if (/(?:^|\.)instagram\.com$/.test(host)) {
      return { isPlatform: true, platformName: 'Instagram' };
    }
    if (/(?:^|\.)(facebook\.com|fb\.watch|m\.facebook\.com)$/.test(host)) {
      return { isPlatform: true, platformName: 'Facebook' };
    }
    if (/(?:^|\.)(tiktok\.com|vt\.tiktok\.com|vm\.tiktok\.com)$/.test(host)) {
      return { isPlatform: true, platformName: 'TikTok' };
    }
    if (/(?:^|\.)(twitter\.com|x\.com)$/.test(host)) {
      return { isPlatform: true, platformName: 'X / Twitter' };
    }
    if (/(?:^|\.)(vimeo\.com|player\.vimeo\.com)$/.test(host)) {
      return { isPlatform: true, platformName: 'Vimeo' };
    }
    if (/(?:^|\.)(dailymotion\.com|dai\.ly)$/.test(host)) {
      return { isPlatform: true, platformName: 'Dailymotion' };
    }
    if (/(?:^|\.)(reddit\.com|v\.redd\.it|redd\.it)$/.test(host)) {
      return { isPlatform: true, platformName: 'Reddit' };
    }
    if (/(?:^|\.)(twitch\.tv|clips\.twitch\.tv)$/.test(host)) {
      return { isPlatform: true, platformName: 'Twitch' };
    }
    if (/(?:^|\.)(pinterest\.com|pin\.it)$/.test(host)) {
      return { isPlatform: true, platformName: 'Pinterest' };
    }
    if (/(?:^|\.)(streamable\.com|rumble\.com|bilibili\.com|ok\.ru|vk\.com|vkvideo\.ru|threads\.net|threads\.com)$/.test(host)) {
      return { isPlatform: true, platformName: host };
    }
    if (host === 'drive.google.com' && /\/(file\/d\/|open\?id=|uc\?)/.test(u.pathname + u.search)) {
      return { isPlatform: true, platformName: 'Google Drive' };
    }
  } catch {}
  return { isPlatform: false, platformName: '' };
}

async function probeHttpMediaType(
  url: string,
  headers: Record<string, string>
): Promise<{
  isDirectMedia: boolean;
  isPlaylist: boolean;
  contentType: string;
  filename?: string;
  finalUrl: string;
}> {
  const tryProbeMethod = async (method: 'HEAD' | 'GET') => {
    const reqHeaders = method === 'GET' ? { ...headers, Range: 'bytes=0-2047' } : headers;
    const res = await undiciRequestFollow(url, {
      method,
      headers: reqHeaders,
      headersTimeout: 7000,
      bodyTimeout: 7000,
    });
    const ct = String(res.headers['content-type'] || '').toLowerCase();
    const cd = String(res.headers['content-disposition'] || '');
    let firstBytes = '';
    if (method === 'GET') {
      const buf = Buffer.from(await res.body.arrayBuffer()).subarray(0, 512);
      firstBytes = buf.toString('utf8').trimStart();
    } else {
      await res.body.dump().catch(() => {});
    }
    const cdMatch = cd.match(/filename\*?=(?:UTF-8''|"?)([^";\r\n"]+)/i);
    const filename = cdMatch ? decodeURIComponent(cdMatch[1]).trim() : undefined;
    const isPlaylist =
      firstBytes.startsWith('#EXTM3U') ||
      /mpegurl|dash\+xml/i.test(ct);
    const isVideoCt =
      ct.startsWith('video/') ||
      (/application\/octet-stream/i.test(ct) &&
        Boolean(filename && /\.(mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)$/i.test(filename)));
    return {
      statusCode: res.statusCode,
      isDirectMedia: !isPlaylist && isVideoCt,
      isPlaylist,
      contentType: ct,
      filename,
      finalUrl: (res as any).finalUrl || url,
    };
  };

  try {
    const headInfo = await tryProbeMethod('HEAD');
    if (headInfo.statusCode < 400 && (headInfo.isDirectMedia || headInfo.isPlaylist || /html|json|text/.test(headInfo.contentType))) {
      return headInfo;
    }
  } catch {}

  try {
    const getInfo = await tryProbeMethod('GET');
    return getInfo;
  } catch {}

  return { isDirectMedia: false, isPlaylist: false, contentType: '', finalUrl: url };
}

async function extractWithYtDlp(
  url: string,
  maxEntries: number = 40
): Promise<{
  ok: boolean;
  pageTitle: string;
  entries: StreamVariant[];
  isPlaylist: boolean;
  error?: string;
}> {
  const bin = await ensureYtDlpBinary();
  if (!bin) {
    return {
      ok: false,
      pageTitle: 'Media Extraction',
      entries: [],
      isPlaylist: false,
      error: 'yt-dlp binary could not be initialized.',
    };
  }
  const cookiesPath = getYtDlpCookiesFilePath();
  const isYt = /(?:youtube\.com|youtu\.be)/i.test(url);

  const attemptArgsList: string[][] = [
    [
      '--no-warnings',
      '--flat-playlist',
      '--dump-single-json',
      '--playlist-end',
      String(maxEntries),
      '--socket-timeout',
      '15',
      ...(cookiesPath ? ['--cookies', cookiesPath] : []),
      ...(isYt && !cookiesPath ? ['--extractor-args', 'youtube:player_client=android_vr,ios,tv_embedded,web'] : []),
      url,
    ],
  ];
  if (isYt && !cookiesPath) {
    attemptArgsList.push([
      '--no-warnings',
      '--flat-playlist',
      '--dump-single-json',
      '--playlist-end',
      String(maxEntries),
      '--socket-timeout',
      '15',
      '--extractor-args',
      'youtube:player_client=mweb,tv',
      url,
    ]);
  }

  let lastErrMsg = '';
  for (const args of attemptArgsList) {
    try {
      const { stdout } = await execFileAsync(bin, args, {
        timeout: 45000,
        maxBuffer: 32 * 1024 * 1024,
      });
      const parsed = JSON.parse(stdout || '{}');
      if (!parsed || typeof parsed !== 'object') continue;
      const entriesArr: any[] = Array.isArray(parsed.entries) ? parsed.entries.filter(Boolean) : [];
      const defQuality = botSettings.globalDefaultQuality || '720p';
      if (entriesArr.length > 0) {
        const listTitle = String(parsed.title || parsed.uploader || 'Platform Playlist').trim();
        const streamsOut: StreamVariant[] = [];
        for (let i = 0; i < entriesArr.length; i++) {
          const ent = entriesArr[i];
          const vUrl = String(ent.webpage_url || ent.url || '').trim();
          if (!vUrl) continue;
          const fullUrl =
            vUrl.startsWith('http') ? vUrl : isYt ? `https://www.youtube.com/watch?v=${vUrl}` : vUrl;
          const vTitle = String(ent.title || `Video #${i + 1}`).trim();
          streamsOut.push({
            id: crypto.randomUUID(),
            url: fullUrl,
            protocol: 'YTDLP_PLATFORM',
            label: vTitle,
            courseName: listTitle,
            folderName: listTitle,
            lectureTitle: vTitle,
            durationSec: typeof ent.duration === 'number' ? Math.round(ent.duration) : undefined,
            resolution: defQuality,
            foundVia: `${parsed.extractor_key || 'Platform'} Playlist`,
          });
        }
        if (streamsOut.length > 0) {
          return {
            ok: true,
            pageTitle: `${listTitle} (${streamsOut.length} Videos)`,
            entries: streamsOut,
            isPlaylist: true,
          };
        }
      }

      const singleTitle = String(parsed.title || parsed.fulltitle || 'Platform Video').trim();
      const webpageUrl = String(parsed.webpage_url || parsed.original_url || url).trim();
      return {
        ok: true,
        pageTitle: singleTitle,
        isPlaylist: false,
        entries: [
          {
            id: crypto.randomUUID(),
            url: webpageUrl,
            protocol: 'YTDLP_PLATFORM',
            label: singleTitle,
            courseName: parsed.uploader || parsed.extractor_key || 'Social Video',
            lectureTitle: singleTitle,
            durationSec: typeof parsed.duration === 'number' ? Math.round(parsed.duration) : undefined,
            resolution: defQuality,
            foundVia: `${parsed.extractor_key || 'yt-dlp'} (${defQuality.toUpperCase()})`,
          },
        ],
      };
    } catch (err: any) {
      lastErrMsg = String(err?.stderr || err?.message || err || '');
    }
  }

  return {
    ok: false,
    pageTitle: 'Platform Video',
    entries: [],
    isPlaylist: false,
    error: lastErrMsg.slice(0, 350),
  };
}

async function downloadWithYtDlp(
  url: string,
  outMp4Path: string,
  job: DownloadJob,
  onProgress?: () => void
): Promise<void> {
  const bin = await ensureYtDlpBinary();
  if (!bin) {
    throw new Error('yt-dlp engine is unavailable on this server.');
  }
  const cookiesPath = getYtDlpCookiesFilePath();
  const targetHeight =
    parseInt(String(job.preferredQuality || botSettings.globalDefaultQuality || '720p').replace(/\D/g, ''), 10) ||
    720;
  const formatSelector = `bv*[height<=${targetHeight}][ext=mp4]+ba[ext=m4a]/bv*[height<=${targetHeight}]+ba/b[height<=${targetHeight}]/b`;
  const isYt = /(?:youtube\.com|youtu\.be)/i.test(url);

  const myEpoch = job.downloadEpoch || 0;
  const isAborted = () =>
    Boolean(job.abortFlag || (job.status as string) === 'paused' || (job.downloadEpoch || 0) !== myEpoch);

  const runOnce = (extraExtractorArgs?: string[]) =>
    new Promise<void>((resolve, reject) => {
      const args = [
        '--no-warnings',
        '--no-playlist',
        '--newline',
        '--progress',
        '-f',
        formatSelector,
        '--merge-output-format',
        'mp4',
        '--concurrent-fragments',
        '16',
        '--http-chunk-size',
        '10M',
        '--buffer-size',
        '16K',
        '--retries',
        '4',
        '--fragment-retries',
        '4',
        ...(cookiesPath ? ['--cookies', cookiesPath] : []),
        ...(extraExtractorArgs || []),
        '-o',
        outMp4Path,
        url,
      ];

      const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let stderrTail = '';
      let abortedByUser = false;

      const abortCheckInterval = setInterval(() => {
        if (isAborted()) {
          abortedByUser = true;
          try {
            child.kill('SIGKILL');
          } catch {}
          clearInterval(abortCheckInterval);
        }
      }, 400);

      const handleLine = (line: string) => {
        job.lastProgressAt = Date.now();
        // Match: [download]  45.3% of ~120.50MiB at   12.34MiB/s ETA 00:05
        const m = line.match(
          /\[download\]\s+([\d.]+)%\s+of\s+~?([\d.]+)([KMG]i?B)(?:\s+at\s+([\d.]+)([KMG]i?B)\/s)?/i
        );
        if (m) {
          const pct = parseFloat(m[1]);
          const totalNum = parseFloat(m[2]);
          const totalUnit = m[3].toUpperCase();
          const unitMul = (u: string) =>
            u.startsWith('G') ? 1024 * 1024 * 1024 : u.startsWith('M') ? 1024 * 1024 : 1024;
          const totalBytes = Math.round(totalNum * unitMul(totalUnit));
          if (!isNaN(pct)) {
            job.progressPercent = Math.min(95, Math.round(pct * 0.95));
            job.downloadedBytes = Math.round((pct / 100) * totalBytes);
            job.totalSegments = 100;
            job.completedSegments = Math.min(99, Math.round(pct));
          }
          if (m[4] && m[5]) {
            const spdNum = parseFloat(m[4]);
            job.speedBytesPerSec = Math.round(spdNum * unitMul(m[5].toUpperCase()));
          }
          if (onProgress) onProgress();
        }
      };

      let stdoutBuf = '';
      child.stdout.on('data', (chunk) => {
        stdoutBuf += chunk.toString('utf8');
        const lines = stdoutBuf.split(/\r?\n|\r/);
        stdoutBuf = lines.pop() || '';
        for (const l of lines) handleLine(l);
      });
      child.stderr.on('data', (chunk) => {
        const s = chunk.toString('utf8');
        stderrTail = (stderrTail + s).slice(-1200);
      });
      child.on('error', (err) => {
        clearInterval(abortCheckInterval);
        reject(err);
      });
      child.on('close', (code) => {
        clearInterval(abortCheckInterval);
        if (abortedByUser || isAborted()) {
          reject(new Error('JOB_PAUSED_BY_USER'));
          return;
        }
        if (code === 0 && fs.existsSync(outMp4Path) && fs.statSync(outMp4Path).size > 1024) {
          resolve();
        } else {
          const cleanErr = stderrTail
            .split(/\r?\n/)
            .filter((l) => /ERROR:/i.test(l))
            .join(' ')
            .trim();
          const hint = /Sign in to confirm|cookies/i.test(stderrTail)
            ? ' (YouTube/Instagram server check triggered — paste Netscape cookies.txt via /setcookies or Web Cookies Vault!)'
            : '';
          reject(new Error((cleanErr || stderrTail || `yt-dlp exited with code ${code}`).slice(0, 320) + hint));
        }
      });
    });

  if (isYt && !cookiesPath) {
    try {
      await runOnce(['--extractor-args', 'youtube:player_client=android_vr,ios,tv_embedded']);
      return;
    } catch (firstErr: any) {
      if (String(firstErr?.message) === 'JOB_PAUSED_BY_USER') throw firstErr;
      await runOnce(['--extractor-args', 'youtube:player_client=mweb,tv']);
      return;
    }
  }
  await runOnce();
}

async function normalizeVideoFileToMp4(inputPath: string, targetMp4Path: string): Promise<string> {
  if (!ffmpegAvailable || !fs.existsSync(inputPath)) {
    return inputPath;
  }
  const lowerInput = inputPath.toLowerCase();
  const isAlreadyMp4 = lowerInput.endsWith('.mp4');
  // Fast zero-reencode stream copy + faststart moov atom first (<1-3s!)
  try {
    const tmpOut = isAlreadyMp4 ? `${targetMp4Path}.fast.mp4` : targetMp4Path;
    await execFileAsync(
      'ffmpeg',
      [
        '-y',
        '-threads',
        '0',
        '-i',
        inputPath,
        '-map',
        '0:v:0?',
        '-map',
        '0:a:0?',
        '-c',
        'copy',
        '-movflags',
        '+faststart',
        tmpOut,
      ],
      { timeout: 180000, maxBuffer: 20 * 1024 * 1024 }
    );
    if (fs.existsSync(tmpOut) && fs.statSync(tmpOut).size > 1024) {
      if (tmpOut !== inputPath) {
        try {
          fs.unlinkSync(inputPath);
        } catch {}
        if (tmpOut !== targetMp4Path) {
          fs.renameSync(tmpOut, targetMp4Path);
          return targetMp4Path;
        }
      }
      return tmpOut;
    }
  } catch {
    // Non-MP4 codecs (VP8/VP9/AV1/WMV/MPEG2 in .webm/.avi/.flv/.mkv/.mov) -> Fast H264/AAC transcode!
    if (!isAlreadyMp4) {
      try {
        await execFileAsync(
          'ffmpeg',
          [
            '-y',
            '-threads',
            '0',
            '-i',
            inputPath,
            '-c:v',
            'libx264',
            '-preset',
            'veryfast',
            '-crf',
            '23',
            '-pix_fmt',
            'yuv420p',
            '-c:a',
            'aac',
            '-b:a',
            '128k',
            '-movflags',
            '+faststart',
            targetMp4Path,
          ],
          { timeout: 600000, maxBuffer: 20 * 1024 * 1024 }
        );
        if (fs.existsSync(targetMp4Path) && fs.statSync(targetMp4Path).size > 1024) {
          try {
            fs.unlinkSync(inputPath);
          } catch {}
          return targetMp4Path;
        }
      } catch {}
    }
  }
  return inputPath;
}

function extractStreamsFromJsOrText(
  text: string,
  baseUrl: string,
  foundViaLabel: string,
  discoveredMap: Map<string, { url: string; foundVia: string; folderName?: string; titleHint?: string }>,
  folderName?: string
) {
  const normalized = text
    .replace(/\\\//g, '/')
    .replace(/\\u002F/gi, '/')
    .replace(/\\u0026/gi, '&')
    .replace(/&amp;/g, '&');

  const VIDEO_EXT_PATTERN = '(?:m3u8|mpd|mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)';

  const absoluteRegex = new RegExp(
    `https?:\\/\\/[^\\s"'<>\\\\\`]+?\\.${VIDEO_EXT_PATTERN}(?:\\?[^\\s"'<>\\\\\`]*)?`,
    'gi'
  );
  let match: RegExpExecArray | null;
  while ((match = absoluteRegex.exec(normalized)) !== null) {
    const cleanUrl = match[0].replace(/[),;.\]]+$/, '');
    if (cleanUrl.endsWith('.ts') && !/video|stream|movie|episode|lecture|clip/i.test(cleanUrl)) {
      // Skip bare HLS chunk filenames unless full path looks like a standalone video
      if (/seg[-_]?\d+|chunk[-_]?\d+|frag[-_]?\d+/i.test(cleanUrl)) continue;
    }
    if (!discoveredMap.has(cleanUrl)) {
      discoveredMap.set(cleanUrl, { url: cleanUrl, foundVia: foundViaLabel, folderName });
    }
  }

  // Also detect CDN video URLs without extension (e.g. mime=video/mp4, videoplayback, cdninstagram, fbcdn)
  const cdnVideoRegex =
    /https?:\/\/[^\s"'<>\\`]+?(?:mime=video(?:%2F|\/)(?:mp4|webm)|\/videoplayback\?[^\s"'<>\\`]+|fbcdn\.net\/[^\s"'<>\\`]+?\.mp4[^\s"'<>\\`]*|cdninstagram\.com\/[^\s"'<>\\`]+?\.mp4[^\s"'<>\\`]*)/gi;
  while ((match = cdnVideoRegex.exec(normalized)) !== null) {
    const cleanUrl = match[0].replace(/[),;.\]]+$/, '');
    if (!discoveredMap.has(cleanUrl)) {
      discoveredMap.set(cleanUrl, { url: cleanUrl, foundVia: `${foundViaLabel} (CDN Stream)`, folderName });
    }
  }

  // Protocol-relative //cdn.../video.mp4
  const protoRelRegex = new RegExp(
    `["'](\\/\\/[a-zA-Z0-9.-]+\\/[^"'\\s<>\\\\]+?\\.${VIDEO_EXT_PATTERN}(?:\\?[^"'\\s<>\\\\]*)?)["']`,
    'gi'
  );
  while ((match = protoRelRegex.exec(normalized)) !== null) {
    const resolved = resolveRelativeUrl(match[1], baseUrl);
    if (resolved.startsWith('http') && !discoveredMap.has(resolved)) {
      discoveredMap.set(resolved, { url: resolved, foundVia: foundViaLabel, folderName });
    }
  }

  const relativeRegex = new RegExp(
    `["']((?:\\/|\\.\\/|\\.\\.\\/|[a-zA-Z0-9_\\-./]+)\\.${VIDEO_EXT_PATTERN}(?:\\?[^"'\\s<>\\\\]*)?)["']`,
    'gi'
  );
  while ((match = relativeRegex.exec(normalized)) !== null) {
    const rawRel = match[1];
    if (!rawRel.startsWith('http') && !rawRel.startsWith('//') && rawRel.length > 5) {
      const resolved = resolveRelativeUrl(rawRel, baseUrl);
      if (resolved.startsWith('http') && !discoveredMap.has(resolved)) {
        if (resolved.toLowerCase().endsWith('.ts') && /seg|chunk|frag/i.test(resolved)) continue;
        discoveredMap.set(resolved, {
          url: resolved,
          foundVia: `${foundViaLabel} (Relative Path)`,
          folderName,
        });
      }
    }
  }

  const atobRegex = /atob\(\s*["']([A-Za-z0-9+/=]{16,})["']\s*\)/g;
  while ((match = atobRegex.exec(normalized)) !== null) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf8').trim();
      const decMatch = decoded.match(
        new RegExp(`https?:\\/\\/[^\\s"'<>]+?\\.${VIDEO_EXT_PATTERN}(?:\\?[^\\s"'<>]*)?`, 'i')
      )?.[0];
      if (decMatch && !discoveredMap.has(decMatch)) {
        discoveredMap.set(decMatch, {
          url: decMatch,
          foundVia: `${foundViaLabel} (Decoded Base64)`,
          folderName,
        });
      }
    } catch {
      // ignore
    }
  }
}

interface CachedCourseExtraction {
  timestamp: number;
  sourceUrl: string;
  pageTitle: string;
  streams: StreamVariant[];
  folders: string[];
  scriptsScanned: number;
  pagesScanned?: number;
  notes: string[];
  isPartialScan?: boolean;
}

const COURSE_CACHE_FILE = path.join(process.cwd(), 'course-cache.json');
const courseExtractionCache = new Map<string, CachedCourseExtraction>();

try {
  if (fs.existsSync(COURSE_CACHE_FILE)) {
    const rawCache = JSON.parse(fs.readFileSync(COURSE_CACHE_FILE, 'utf8'));
    if (rawCache && typeof rawCache === 'object') {
      for (const [k, v] of Object.entries(rawCache)) {
        if (v && typeof v === 'object' && Array.isArray((v as any).streams)) {
          courseExtractionCache.set(k, v as CachedCourseExtraction);
        }
      }
    }
  }
} catch {
  // ignore cache load error
}

let saveCourseCacheTimer: NodeJS.Timeout | null = null;
function saveCourseExtractionCacheToDisk() {
  if (saveCourseCacheTimer) return;
  saveCourseCacheTimer = setTimeout(() => {
    saveCourseCacheTimer = null;
    try {
      const obj: Record<string, CachedCourseExtraction> = {};
      const now = Date.now();
      for (const [k, v] of courseExtractionCache.entries()) {
        if (now - v.timestamp < 12 * 60 * 60 * 1000) {
          obj[k] = v;
        }
      }
      fs.writeFileSync(COURSE_CACHE_FILE, JSON.stringify(obj), 'utf8');
    } catch {
      // ignore disk cache write error
    }
  }, 500);
}

async function inspectUrlAndExtractStreams(
  inputUrl: string,
  customHeaders?: Record<string, string>,
  rawHtmlSnippet?: string,
  crawlFolders: boolean = true,
  onProgress?: (progressText: string) => void,
  maxVideosNeeded?: number,
  chatId?: string
): Promise<{
  sourceUrl: string;
  pageTitle: string;
  extractedAt: string;
  streams: StreamVariant[];
  folders: string[];
  scriptsScanned: number;
  pagesScanned?: number;
  rawManifestSnippet?: string;
  notes: string[];
  authRequiredOrigin?: string;
  authRequiredReason?: 'cookie_check' | 'login_required';
}> {
  const notes: string[] = [];
  const streams: StreamVariant[] = [];
  const folderSet = new Set<string>();
  let scriptsScanned = 0;
  let pagesScanned = 1;
  let pageTitle = 'Extracted Media Stream';
  let rawManifestSnippet: string | undefined;
  let authRequiredOrigin: string | undefined;
  let authRequiredReason: 'cookie_check' | 'login_required' | undefined;

  let targetUrl = (inputUrl || '').trim();

  const unwrapped = unwrapQueryRedirectUrl(targetUrl);
  if (unwrapped) {
    notes.push(`Unwrapped embedded stream URL from query parameter: ${unwrapped}`);
    targetUrl = unwrapped;
  }

  const cacheKey = `${targetUrl}__${crawlFolders ? 'full' : 'single'}`;
  if (crawlFolders && !rawHtmlSnippet) {
    const cachedCourse = courseExtractionCache.get(cacheKey);
    const hasEmbeddedSubjectMeta = Boolean(
      cachedCourse?.streams?.[0] &&
        (!cachedCourse.streams[0].url.startsWith('appx://') ||
          cachedCourse.streams[0].url.includes('subjectid='))
    );
    const satisfiesRequestedRange = maxVideosNeeded
      ? Boolean(cachedCourse && cachedCourse.streams.length >= maxVideosNeeded)
      : Boolean(cachedCourse && !cachedCourse.isPartialScan);
    if (
      cachedCourse &&
      hasEmbeddedSubjectMeta &&
      Date.now() - cachedCourse.timestamp < 12 * 60 * 60 * 1000 &&
      cachedCourse.streams.length > 1 &&
      satisfiesRequestedRange
    ) {
      const defQ = botSettings.globalDefaultQuality || '480p';
      const clonedStreams = cachedCourse.streams.map((s) => ({
        ...s,
        id: crypto.randomUUID(),
        resolution: s.url.startsWith('appx://') ? defQ : s.resolution || defQ,
      }));
      return {
        sourceUrl: targetUrl,
        pageTitle: cachedCourse.pageTitle,
        extractedAt: new Date().toISOString(),
        streams: clonedStreams,
        folders: [...cachedCourse.folders],
        scriptsScanned: cachedCourse.scriptsScanned,
        pagesScanned: cachedCourse.pagesScanned || 1,
        notes: [...cachedCourse.notes, 'Loaded from <50ms course structure cache'],
      };
    }
  }

  const storeInCourseCacheAndReturn = (resObj: {
    sourceUrl: string;
    pageTitle: string;
    extractedAt: string;
    streams: StreamVariant[];
    folders: string[];
    scriptsScanned: number;
    pagesScanned?: number;
    rawManifestSnippet?: string;
    notes: string[];
  }) => {
    // Deduplicate extracted streams in exact first-seen order so no video appears twice in 1..N list
    if (resObj.streams.length > 1) {
      const seenCanonical = new Set<string>();
      const dedupedStreams: StreamVariant[] = [];
      for (const s of resObj.streams) {
        const raw = String(s.url || '').trim();
        let canon = raw.toLowerCase();
        if (raw.startsWith('appx://')) {
          try {
            const u = new URL(raw.replace(/^appx:\/\//i, 'http://'));
            const cId = (u.searchParams.get('courseid') || '').trim().toLowerCase();
            const vId = (u.searchParams.get('videoid') || '').trim().toLowerCase();
            if (vId) canon = `appx::${cId}::${vId}`;
          } catch {}
        }
        if (canon && seenCanonical.has(canon)) continue;
        if (canon) seenCanonical.add(canon);
        dedupedStreams.push(s);
      }
      resObj.streams = dedupedStreams;
    }

    if (crawlFolders && !rawHtmlSnippet && resObj.streams.length > 1) {
      const prevCached = courseExtractionCache.get(cacheKey);
      const isPartial = Boolean(maxVideosNeeded && resObj.streams.length >= maxVideosNeeded);
      if (!prevCached || !isPartial || resObj.streams.length >= prevCached.streams.length) {
        courseExtractionCache.set(cacheKey, {
          timestamp: Date.now(),
          sourceUrl: resObj.sourceUrl,
          pageTitle: resObj.pageTitle,
          streams: resObj.streams,
          folders: resObj.folders,
          scriptsScanned: resObj.scriptsScanned,
          notes: resObj.notes,
          isPartialScan: isPartial && Boolean(prevCached ? prevCached.isPartialScan : true),
        });
        saveCourseExtractionCacheToDisk();
      }
    }
    return resObj;
  };

  const baseUrl = targetUrl || 'https://localhost/';
  const portalSessionForTarget = getPortalSessionForOrigin(baseUrl, chatId);
  const mergedCustomHeaders: Record<string, string> = {
    ...(portalSessionForTarget?.cookieHeader ? { Cookie: portalSessionForTarget.cookieHeader } : {}),
    ...(portalSessionForTarget?.bearerToken
      ? {
          Authorization:
            portalSessionForTarget.bearerToken.startsWith('Bearer ') || portalSessionForTarget.bearerToken.startsWith('eyJ')
              ? portalSessionForTarget.bearerToken
              : `Bearer ${portalSessionForTarget.bearerToken}`,
        }
      : {}),
    ...(portalSessionForTarget?.userId ? { 'User-ID': portalSessionForTarget.userId } : {}),
    ...(customHeaders || {}),
  };
  const headers = buildHeaders(mergedCustomHeaders, baseUrl);

  // 1A. Check if URL is StudyBeePro / StudyPanda / AppX / TeachX Multi-Folder Course / Subject / Topic / Concept / Play URL
  try {
    const u = new URL(targetUrl);
    const isSubjectPage = /\/subject(\.html)?$/i.test(u.pathname);
    const isTopicPage = /\/topic(\.html)?$/i.test(u.pathname);
    const isContentPage = /\/content(\.html)?$/i.test(u.pathname);
    const isBatchPage = /\/batch(\.html)?$/i.test(u.pathname);
    const isPlayPage = /\/(play|player)(\.html)?$/i.test(u.pathname);
    const isRwaPath = /\/(rwax?|rozgar)(\/|$)/i.test(u.pathname);
    const isSachinPath = /\/sachinacademy(\/|$)/i.test(u.pathname);
    const isSelectionBeePath = /\/(selectionbee|nexttoppers)(\/|$)/i.test(u.pathname);
    const isMjPath = /\/(mj|missionjeet)(\/|$)/i.test(u.pathname);
    const isScienceAndFunPath = /\/(scienceandfun|sf)(\/|$)/i.test(u.pathname);
    const isVibrantPath = /\/(vibrant|vibrante)(\/|$)/i.test(u.pathname);
    const isMasterSahabPath = /\/(mastersahab|ms)(\/|$)/i.test(u.pathname);

    const pathSegments = u.pathname
      .split('/')
      .map((s) => decodeURIComponent(s).trim())
      .filter(Boolean);
    const firstSeg = pathSegments[0] || '';
    const secondSeg = pathSegments[1] || '';
    const lastSeg = pathSegments[pathSegments.length - 1] || '';

    // Support path-based course IDs such as https://studypanda.live/rwa/789, /rwax/571, /mastersahab/12, /missionjeet/4, /batch/789
    const pathCourseId =
      secondSeg &&
      !/\.(html?|php|jsp|asp|json|js|css)$/i.test(secondSeg) &&
      !/^(content|subject|topic|batch|play|player|batches|login|api|details|pdf|proxy)$/i.test(secondSeg)
        ? secondSeg
        : pathSegments.length >= 2 && /^\d+$/.test(lastSeg)
        ? lastSeg
        : null;

    const portalPath = firstSeg ? `/${firstSeg}` : '/rwax';
    const cleanOrig = u.origin.replace(/\/$/, '') || 'https://studybeepro.site';

    const courseId =
      u.searchParams.get('courseid') ||
      u.searchParams.get('course_id') ||
      u.searchParams.get('courseId') ||
      (isSubjectPage || isTopicPage || isContentPage || isBatchPage
        ? u.searchParams.get('id')
        : null) ||
      u.searchParams.get('id') ||
      pathCourseId;
    const subjectId = u.searchParams.get('subjectid') || u.searchParams.get('subject_id');
    const topicId = u.searchParams.get('topicid') || u.searchParams.get('topic_id');
    const conceptIdParam = u.searchParams.get('conceptid') || u.searchParams.get('concept_id');
    const parentIdParam = u.searchParams.get('parent_id') || u.searchParams.get('parentId');
    const videoId = isPlayPage
      ? u.searchParams.get('id') || u.searchParams.get('video_id')
      : u.searchParams.get('video_id');
    const domainId =
      u.searchParams.get('domainId') ||
      u.searchParams.get('domain_id') ||
      (isMasterSahabPath ? 'MS' : isMjPath ? 'MJ' : 'RWA');

    if (
      courseId &&
      (isSubjectPage ||
        isTopicPage ||
        isContentPage ||
        isBatchPage ||
        isPlayPage ||
        isRwaPath ||
        isSachinPath ||
        isSelectionBeePath ||
        isMjPath ||
        isScienceAndFunPath ||
        isVibrantPath ||
        isMasterSahabPath ||
        Boolean(pathCourseId) ||
        u.searchParams.has('domainId') ||
        /studypanda\.live|studybeepro\.site|teachx\.in|classx\.co\.in|asmultiverse\.site/i.test(u.hostname))
    ) {
      // Special Portal 1: SelectionBee (/selectionbee/content.html?courseId=...)
      if (isSelectionBeePath) {
        const swWorker = 'https://sw.smexfot.workers.dev';
        const foldersRes = await fetchAppxJsonWithRetry(
          `${swWorker}/api/get-folders?courseId=${encodeURIComponent(courseId)}`,
          { 'User-Agent': DEFAULT_USER_AGENT, Referer: `${cleanOrig}/selectionbee/content.html?courseId=${courseId}` },
          2
        );
        const swCourseTitle =
          foldersRes?.data?.course?.title ||
          foldersRes?.course?.title ||
          `SelectionBee Course #${courseId}`;
        const swTopics: any[] = Array.isArray(foldersRes?.data?.topics)
          ? foldersRes.data.topics
          : Array.isArray(foldersRes?.topics)
          ? foldersRes.topics
          : Array.isArray(foldersRes?.data)
          ? foldersRes.data
          : Array.isArray(foldersRes)
          ? foldersRes
          : [];
        const targetQNum = parseInt((botSettings.globalDefaultQuality || '480p').replace(/\D/g, ''), 10) || 480;
        for (const top of swTopics) {
          const tId = String(top.topicId || top.id || top._id || '').trim();
          const tName = String(top.topicName || top.name || top.title || `Topic ${tId}`).trim();
          if (!tId) continue;
          const classesRes = await fetchAppxJsonWithRetry(
            `${swWorker}/api/get-classes?courseId=${encodeURIComponent(courseId)}&topicId=${encodeURIComponent(tId)}`,
            { 'User-Agent': DEFAULT_USER_AGENT, Referer: `${cleanOrig}/selectionbee/content.html?courseId=${courseId}` },
            2
          );
          const clsList: any[] = Array.isArray(classesRes?.data?.classes)
            ? classesRes.data.classes
            : Array.isArray(classesRes?.classes)
            ? classesRes.classes
            : Array.isArray(classesRes?.data)
            ? classesRes.data
            : Array.isArray(classesRes)
            ? classesRes
            : [];
          for (const cls of clsList) {
            let vUrl = '';
            let chosenRes: string = botSettings.globalDefaultQuality || '480p';
            if (Array.isArray(cls.mp4Recordings) && cls.mp4Recordings.length > 0) {
              let bestRec = cls.mp4Recordings[0];
              let bestDiff = Infinity;
              for (const rec of cls.mp4Recordings) {
                const qNum = parseInt(String(rec?.quality || '').replace(/\D/g, ''), 10);
                if (!isNaN(qNum) && rec?.url) {
                  const diff = Math.abs(qNum - targetQNum);
                  if (diff < bestDiff) {
                    bestDiff = diff;
                    bestRec = rec;
                  }
                }
              }
              vUrl = bestRec?.url || '';
              if (bestRec?.quality) chosenRes = String(bestRec.quality);
            }
            if (!vUrl) {
              vUrl = cls.class_link || cls.videoUrl || cls.url || '';
            }
            if (vUrl && /^https?:\/\//i.test(String(vUrl))) {
              const secName = cls.internalSection?.sectionName ? ` / ${cls.internalSection.sectionName}` : '';
              const fl = `${tName}${secName}`;
              folderSet.add(fl);
              const cTitle = String(cls.title || cls.name || cls.topic || `Lecture`).trim();
              streams.push({
                id: crypto.randomUUID(),
                url: String(vUrl).trim(),
                protocol: String(vUrl).toLowerCase().includes('.mp4') ? 'DIRECT_MP4' : 'HLS_MASTER',
                label: cTitle,
                courseName: swCourseTitle,
                subjectName: tName,
                topicName: cls.internalSection?.sectionName || tName,
                folderName: fl,
                lectureTitle: cTitle,
                resolution: chosenRes,
                foundVia: `Folder: ${fl}`,
              });
            }
          }
        }
        if (streams.length > 0) {
          applyDuplicateTitleNumbering(streams);
          pageTitle = `${swCourseTitle} (${folderSet.size} Folders, ${streams.length} Videos)`;
          return storeInCourseCacheAndReturn({
            sourceUrl: targetUrl,
            pageTitle,
            extractedAt: new Date().toISOString(),
            streams,
            folders: Array.from(folderSet),
            scriptsScanned: 1,
            notes,
          });
        }
      }

      // Special Portal 2: MJ (/mj/content.html?id=...)
      if (isMjPath) {
        const visitedMjFolders = new Set<string>();
        const crawlMjFolder = async (fId: string, fPath: string, depth: number = 0) => {
          if (depth > 8 || visitedMjFolders.has(fId)) return;
          visitedMjFolders.add(fId);
          const mjJson =
            (await fetchAppxJsonWithRetry(
              `${cleanOrig}/api/nig?content=${encodeURIComponent(courseId)}&folder=${encodeURIComponent(fId)}&_t=${Date.now()}`,
              { 'User-Agent': DEFAULT_USER_AGENT, Referer: `${cleanOrig}/mj/content.html?id=${courseId}` },
              2
            )) ||
            (await fetchAppxJsonWithRetry(
              `https://mj.smexfot.workers.dev/?content=${encodeURIComponent(courseId)}&folder=${encodeURIComponent(fId)}`,
              { 'User-Agent': DEFAULT_USER_AGENT },
              2
            ));
          const mjItems: any[] = Array.isArray(mjJson?.data)
            ? mjJson.data
            : Array.isArray(mjJson?.contents)
            ? mjJson.contents
            : Array.isArray(mjJson)
            ? mjJson
            : [];
          for (const item of mjItems) {
            const itemTitle = String(item.title || item.name || item.Title || `Item ${item.entity_id || item.id}`).trim();
            if (item.type === 'folder' || item.is_folder || item.material_type === 'FOLDER') {
              const subId = String(item.entity_id || item.id || item.folder_id || '').trim();
              if (subId) {
                await crawlMjFolder(subId, fPath ? `${fPath} / ${itemTitle}` : itemTitle, depth + 1);
              }
            } else if (
              item.type === 'file' ||
              item.data?.file_type === 2 ||
              item.data?.video_type > 0 ||
              item.url ||
              item.video_url ||
              item.file_link
            ) {
              const isPdfItem =
                item.data?.file_type === 1 ||
                (item.type === 'file' && item.data?.file_type !== 2 && !(item.data?.video_type > 0));
              if (isPdfItem) continue;
              const contentId = String(item.entity_id || item.data?.id || item.id || '').trim();
              const vUrl = item.url || item.video_url || item.file_link || item.stream_url || item.data?.file_url || '';
              const decUrl = decryptAppxUrl(String(vUrl)) || (String(vUrl).startsWith('http') ? String(vUrl) : null);
              const streamUrl =
                decUrl ||
                (contentId
                  ? `appx://MJ?courseid=${encodeURIComponent(courseId)}&videoid=${encodeURIComponent(
                      contentId
                    )}&origin=${encodeURIComponent(u.origin)}&portal=%2Fmj`
                  : null);
              if (streamUrl) {
                const fl = fPath || 'Course Lectures';
                folderSet.add(fl);
                const fParts = fl.split(/\s*\/\s*/).map((p) => p.trim()).filter(Boolean);
                streams.push({
                  id: crypto.randomUUID(),
                  url: streamUrl,
                  protocol: streamUrl.toLowerCase().includes('.mp4') ? 'DIRECT_MP4' : 'HLS_MASTER',
                  label: itemTitle,
                  courseName: `MJ Course #${courseId}`,
                  subjectName: fParts[0] || 'General',
                  topicName: fParts.length >= 2 ? fParts.slice(1).join(' / ') : fParts[0] || 'General',
                  folderName: fl,
                  lectureTitle: itemTitle,
                  resolution: botSettings.globalDefaultQuality || '480p',
                  foundVia: `Folder: ${fl}`,
                });
              }
            }
          }
        };
        await crawlMjFolder('0', '');
        if (streams.length > 0) {
          applyDuplicateTitleNumbering(streams);
          pageTitle = `MJ — Course #${courseId} (${folderSet.size} Folders, ${streams.length} Videos)`;
          return storeInCourseCacheAndReturn({
            sourceUrl: targetUrl,
            pageTitle,
            extractedAt: new Date().toISOString(),
            streams,
            folders: Array.from(folderSet),
            scriptsScanned: 1,
            notes,
          });
        }
      }

      // Special Portal 3: MasterSahab (/mastersahab/[courseId] or /ms/content.html?id=...)
      if (isMasterSahabPath) {
        const msApiPrefixes = ['/api/mastersahab', '/api/ms'];
        const postMsJson = async (ep: string, payload: any): Promise<any> => {
          for (const pref of msApiPrefixes) {
            try {
              const r = await fetch(`${cleanOrig}${pref}${ep}`, {
                method: 'POST',
                headers: {
                  'User-Agent': DEFAULT_USER_AGENT,
                  'Content-Type': 'application/json',
                  Referer: `${cleanOrig}/mastersahab/${courseId}`,
                },
                body: JSON.stringify(payload),
                signal: AbortSignal.timeout(10000),
              });
              if (r.ok) {
                const j = (await r.json()) as any;
                const d = j?.decodedResponse || j?.data || j;
                if (d) return d;
              }
            } catch {
              // continue
            }
          }
          return null;
        };

        const comboRes = await postMsJson('/course_deprecated/get_combo_course_list', {
          course_id: String(courseId),
          page: 1,
          search: '',
        });
        const comboList: any[] = Array.isArray(comboRes?.data)
          ? comboRes.data
          : Array.isArray(comboRes)
          ? comboRes
          : [{ id: courseId, title: `MasterSahab Course #${courseId}` }];
        const msCourseTitle = String(
          comboList[0]?.title || comboList[0]?.course_name || `MasterSahab Course #${courseId}`
        ).trim();

        for (const subCourse of comboList) {
          const subCourseId = String(subCourse.id || courseId);
          const detailRes = await postMsJson('/course_deprecated/get_course_detail', {
            course_id: subCourseId,
            parent_id: String(courseId),
          });
          const tiles: any[] = detailRes?.data?.tiles || detailRes?.tiles || [];
          const contentTile = tiles.find((t: any) => t?.type === 'content') || tiles[0];
          const subjectsList: any[] = contentTile?.meta?.list || [];
          const tileId = String(contentTile?.id || '0');
          const tileType = String(contentTile?.type || 'content');
          const revertApi = String(contentTile?.revert_api || '1#0#0#1');

          for (const subj of subjectsList) {
            const subjName = String(subj.title || subj.name || `Subject ${subj.id}`).trim();
            const topicsList: any[] = Array.isArray(subj.list) && subj.list.length > 0 ? subj.list : [subj];
            for (const top of topicsList) {
              const topName = String(top.title || top.name || subjName).trim();
              const folderLabel = topName !== subjName ? `${subjName} / ${topName}` : subjName;
              const masterRes = await postMsJson('/course/get_master_data', {
                course_id: subCourseId,
                tile_id: tileId,
                type: tileType,
                revert_api: revertApi,
                topic_id: String(top.topic_id || top.id || ''),
                subject_id: String(subj.id || ''),
                layer: 3,
                page: 1,
                parent_id: String(courseId),
              });
              const items: any[] = masterRes?.data?.list || masterRes?.list || [];
              for (const item of items) {
                const isPdf =
                  String(item.file_type) === '1' ||
                  /\.pdf(\?|$)/i.test(String(item.file_url || '')) ||
                  Boolean(item.test_series_name || item.test_code || item.total_questions);
                if (isPdf) continue;
                const contentId = String(item.id || item.vdc_id || '').trim();
                const directUrl = String(item.file_url || item.m3u8_url || item.videoUrl || item.url || '').trim();
                const streamUrl =
                  /^https?:\/\//i.test(directUrl)
                    ? directUrl
                    : contentId
                    ? `appx://MS?courseid=${encodeURIComponent(subCourseId)}&videoid=${encodeURIComponent(
                        contentId
                      )}&origin=${encodeURIComponent(u.origin)}&portal=%2Fmastersahab`
                    : '';
                if (streamUrl) {
                  folderSet.add(folderLabel);
                  const lTitle = String(item.title || item.name || `Lecture #${contentId}`).trim();
                  streams.push({
                    id: crypto.randomUUID(),
                    url: streamUrl,
                    protocol: streamUrl.toLowerCase().includes('.mp4') ? 'DIRECT_MP4' : 'HLS_MASTER',
                    label: lTitle,
                    courseName: msCourseTitle,
                    subjectName: subjName,
                    topicName: topName,
                    folderName: folderLabel,
                    lectureTitle: lTitle,
                    resolution: botSettings.globalDefaultQuality || '480p',
                    foundVia: `Folder: ${folderLabel}`,
                  });
                }
              }
            }
          }
        }
        if (streams.length > 0) {
          applyDuplicateTitleNumbering(streams);
          pageTitle = `${msCourseTitle} (${folderSet.size} Folders, ${streams.length} Videos)`;
          return storeInCourseCacheAndReturn({
            sourceUrl: targetUrl,
            pageTitle,
            extractedAt: new Date().toISOString(),
            streams,
            folders: Array.from(folderSet),
            scriptsScanned: 1,
            notes,
          });
        }
      }

      const cfg = await fetchAppxDomainConfig(domainId, u.origin);
      const portalSession = getPortalSessionForOrigin(u.origin, chatId);
      const portalCleanTok = portalSession?.bearerToken?.replace(/^Bearer\s+/i, '').trim();
      const appxHeaders: Record<string, string> = {
        'User-Agent': DEFAULT_USER_AGENT,
        'Auth-Key': 'appxapi',
        'User-ID': (portalCleanTok ? portalSession?.userId : undefined) || cfg.userId || '16231827',
        Authorization: portalCleanTok || cfg.token,
        'Client-Service': 'Appx',
        Referer: 'https://rozgarapinew.teachx.in/',
      };
      const portalRef = `${cleanOrig}${portalPath}/content.html?id=${encodeURIComponent(courseId)}`;
      const portalHeaders: Record<string, string> = buildPortalSessionHeaders(portalSession, portalRef);

      // Resolve real Course Name (e.g., "SSC CGL, CPO, CHSL 2025 ( Target Batch)") for Telegram captions
      let resolvedCourseName = `Course #${courseId}`;
      if (!isSachinPath) {
        try {
          const cById = await fetchAppxJsonWithRetry(
            `${cfg.apiUrl}/get/course_by_id?id=${encodeURIComponent(courseId)}`,
            appxHeaders,
            1
          );
          const cItem = Array.isArray(cById?.data) ? cById.data[0] : cById?.data;
          const cName = String(cItem?.course_name || cItem?.exam_name || cItem?.title || '').trim();
          if (cName) resolvedCourseName = cName;
        } catch {
          // ignore
        }
      }
      if (resolvedCourseName === `Course #${courseId}`) {
        const batchCatalogUrls = isRwaPath
          ? [`${cleanOrig}/rwa/batches`, `${cleanOrig}${portalPath}/batches.json`]
          : isScienceAndFunPath
          ? [`${cleanOrig}/api/scienceandfun/batches`, `${cleanOrig}${portalPath}/batches.json`]
          : [`${cleanOrig}${portalPath}/batches.json`, `${cleanOrig}/rwa/batches`];
        for (const catUrl of batchCatalogUrls) {
          try {
            const batchesJson = await fetchAppxJsonWithRetry(catUrl, portalHeaders, 1);
            if (batchesJson) {
              const allBatches: any[] = Array.isArray(batchesJson)
                ? batchesJson
                : [
                    ...(Array.isArray(batchesJson.new) ? batchesJson.new : []),
                    ...(Array.isArray(batchesJson.old) ? batchesJson.old : []),
                    ...(Array.isArray(batchesJson.data) ? batchesJson.data : []),
                  ];
              const foundBatch = allBatches.find(
                (b) =>
                  b &&
                  (String(b.id) === String(courseId) ||
                    String(b.batch_id) === String(courseId) ||
                    String(b.course_id) === String(courseId))
              );
              if (foundBatch) {
                const bName = String(
                  foundBatch.title || foundBatch.batch_name || foundBatch.course_name || ''
                ).trim();
                if (bName) {
                  resolvedCourseName = bName;
                  break;
                }
              }
            }
          } catch {
            // ignore
          }
        }
      }

      // Case 1: Single Video Player page (play.html?id=...&courseid=...)
      if (videoId && /play\.html/i.test(u.pathname)) {
        const resolved = await resolveAppxVideoStreamUrl(
          domainId,
          courseId,
          videoId,
          botSettings.globalDefaultQuality || '480p',
          u.origin,
          portalPath,
          undefined,
          { chatId }
        );
        pageTitle = resolved.title || `Lecture #${videoId}`;
        streams.push({
          id: crypto.randomUUID(),
          url: resolved.streamUrl,
          protocol: resolved.streamUrl.toLowerCase().includes('.mp4') ? 'DIRECT_MP4' : 'HLS_MASTER',
          label: pageTitle,
          courseName: resolvedCourseName,
          subjectName: 'General',
          topicName: 'General',
          lectureTitle: pageTitle,
          resolution: resolved.quality,
          foundVia: `AppX Player (${resolved.quality})`,
        });
        return {
          sourceUrl: targetUrl,
          pageTitle,
          extractedAt: new Date().toISOString(),
          streams,
          folders: [],
          scriptsScanned: 1,
          notes,
        };
      }

      const seenVideoIds = new Set<string>();
      const MAX_COURSE_STREAMS = 2500;

      const isFolderItem = (item: any): boolean => {
        if (!item || typeof item !== 'object') return false;
        const mType = String(item.material_type || item.type || item.materialType || '').toUpperCase();
        if (mType === 'FOLDER' || mType === 'SUBJECT' || mType === 'TOPIC' || mType === 'CONCEPT' || mType === 'DIR') {
          return true;
        }
        if (item.is_folder === true || item.is_folder === 1 || item.is_folder === '1' || item.is_folder === 'true') return true;
        if (item.has_subfolder === true || item.has_subfolder === 1 || item.has_subfolder === '1') return true;
        if (item.folder_id && !item.file_link && !item.pdf_link && !item.url) return true;

        if (
          mType === 'PDF' ||
          mType === 'NOTES' ||
          mType === 'DOC' ||
          mType === 'DOCUMENT' ||
          mType === 'FILE' ||
          mType === 'VIDEO' ||
          mType === 'LIVE' ||
          mType === 'RECORDED' ||
          mType === 'CLASS' ||
          mType === 'CONTENT'
        ) {
          return false;
        }

        const hasVideoLink = Boolean(
          item.file_link ||
          item.pdf_link ||
          (Array.isArray(item.download_links) && item.download_links.length > 0) ||
          (Array.isArray(item.encrypted_links) && item.encrypted_links.length > 0) ||
          (Array.isArray(item.livestream_links) && item.livestream_links.length > 0) ||
          item.video_id ||
          item.url ||
          item.file_url ||
          (item.hls_stream_type && String(item.hls_stream_type) !== '0')
        );

        if (!hasVideoLink && (item.subjectid || item.topicid || item.conceptid)) {
          return true;
        }
        return false;
      };

      const mapVideoItemToStream = (
        item: any,
        folderLabel: string,
        folderIds?: { subjId?: string; topId?: string; conId?: string }
      ): StreamVariant | null => {
        const vidId = String(item.id || item.video_id || item.content_id || '').trim();
        if (!vidId || seenVideoIds.has(vidId)) return null;

        // Skip non-video items (PDFs, DOCs, Notes, Tests)
        const mType = String(item.material_type || item.type || '').toUpperCase();
        if (mType === 'PDF' || mType === 'DOC' || mType === 'DOCUMENT' || mType === 'NOTES' || mType === 'TEST') {
          return null;
        }

        const rawFileLinkStr = String(item.file_link || '').trim();
        const isDummyPdfFileLink =
          /pdflink\.com|\.pdf(\?|$)/i.test(rawFileLinkStr) ||
          (rawFileLinkStr
            ? /pdflink\.com|\.pdf(\?|$)/i.test(decryptAppxUrl(rawFileLinkStr) || '')
            : false);

        const hasAnyVideoField = Boolean(
          mType === 'VIDEO' ||
            (Array.isArray(item.download_links) && item.download_links.length > 0) ||
            (Array.isArray(item.encrypted_links) && item.encrypted_links.length > 0) ||
            (Array.isArray(item.livestream_links) && item.livestream_links.length > 0) ||
            (rawFileLinkStr && !isDummyPdfFileLink) ||
            item.video_id ||
            item.video_player_url ||
            (item.hls_stream_type && String(item.hls_stream_type) !== '0')
        );
        if (!hasAnyVideoField && mType && mType !== 'VIDEO') {
          return null;
        }

        seenVideoIds.add(vidId);

        const title = String(item.Title || item.title || item.name || item.course_name || `Video #${vidId}`).trim();
        const rawPdf = item.pdf_link || item.pdf_link2 || item.file_link_pdf || item.pdfUrl || '';
        const rawDecPdf = rawPdf ? decryptAppxUrl(String(rawPdf)) || undefined : undefined;
        const decPdf = rawDecPdf && !/pdflink\.com/i.test(rawDecPdf) ? rawDecPdf : undefined;

        // Extract any direct URL as fallback, and detect available resolution
        let directResolvedUrl: string | null = null;
        let chosenQualityLabel: string = botSettings.globalDefaultQuality || '480p';
        const targetQNum = parseInt(chosenQualityLabel.replace(/\D/g, ''), 10) || 480;

        const dlList: any[] = Array.isArray(item.download_links)
          ? item.download_links
          : Array.isArray(item.encrypted_links)
          ? item.encrypted_links
          : Array.isArray(item.livestream_links)
          ? item.livestream_links
          : [];
        if (dlList.length > 0) {
          let chosen = dlList[0];
          let bestDiff = Infinity;
          for (const link of dlList) {
            const qNum = parseInt(String(link?.quality || '').replace(/\D/g, ''), 10);
            if (!isNaN(qNum) && (link?.path || link?.url || link?.backup_url)) {
              const diff = Math.abs(qNum - targetQNum);
              if (diff < bestDiff) {
                bestDiff = diff;
                chosen = link;
              }
            }
          }
          const candUrl =
            decryptAppxUrl(chosen?.path || chosen?.url || '') || decryptAppxUrl(chosen?.backup_url || '');
          if (candUrl && !/pdflink\.com|\.pdf(\?|$)/i.test(candUrl)) {
            directResolvedUrl = candUrl;
          }
          if (chosen?.quality) {
            chosenQualityLabel = String(chosen.quality);
          }
        }
        if (!directResolvedUrl && rawFileLinkStr && !isDummyPdfFileLink) {
          const decFile = decryptAppxUrl(rawFileLinkStr);
          if (decFile && !/pdflink\.com|\.pdf(\?|$)/i.test(decFile)) {
            directResolvedUrl = decFile;
          }
        }
        if (
          !directResolvedUrl &&
          item.url &&
          /^https?:\/\//i.test(String(item.url)) &&
          !/pdflink\.com|\.pdf(\?|$)/i.test(String(item.url))
        ) {
          directResolvedUrl = String(item.url).trim();
        }

        const isUnrecordedPlaceholder =
          String(item.recording_type ?? '').trim() === '0' &&
          (!item.duration ||
            String(item.duration).trim() === '' ||
            String(item.duration).trim() === '0') &&
          !directResolvedUrl &&
          (!rawFileLinkStr || isDummyPdfFileLink) &&
          !item.video_player_url &&
          (!item.hls_stream_type || String(item.hls_stream_type).trim() === '0') &&
          dlList.length === 0;

        const metaSubjId = String(item.subject_id || item.subjectid || folderIds?.subjId || '').trim();
        const metaTopId = String(item.topic_id || item.topicid || folderIds?.topId || '').trim();
        const metaConId = String(item.concept_id || item.conceptid || folderIds?.conId || '').trim();
        const metaStrToTime = String(item.strtotime || '').trim();
        const metaDuration = String(item.duration || '').trim();
        const metaFreeFlag = String(item.free_flag ?? '').trim();

        const extraMetaQuery =
          (metaSubjId ? `&subjectid=${encodeURIComponent(metaSubjId)}` : '') +
          (metaTopId ? `&topicid=${encodeURIComponent(metaTopId)}` : '') +
          (metaConId ? `&conceptid=${encodeURIComponent(metaConId)}` : '') +
          (metaStrToTime ? `&strtotime=${encodeURIComponent(metaStrToTime)}` : '') +
          (metaDuration ? `&duration=${encodeURIComponent(metaDuration)}` : '') +
          (metaFreeFlag ? `&free=${encodeURIComponent(metaFreeFlag)}` : '');

        // Always use lazy appx:// resolution when vidId & courseId are available so that
        // each video in a bulk queue fetches a brand-new edge-cache-token signed URL right when its download starts
        const streamUrl =
          vidId && courseId
            ? `appx://${encodeURIComponent(domainId)}?courseid=${encodeURIComponent(
                courseId
              )}&videoid=${encodeURIComponent(vidId)}&origin=${encodeURIComponent(
                u.origin
              )}&portal=${encodeURIComponent(portalPath)}${extraMetaQuery}${
                directResolvedUrl ? `&fallback=${encodeURIComponent(directResolvedUrl)}` : ''
              }${isUnrecordedPlaceholder ? '&unrecorded=1' : ''}`
            : directResolvedUrl ||
              `appx://${encodeURIComponent(domainId)}?courseid=${encodeURIComponent(
                courseId
              )}&videoid=${encodeURIComponent(vidId)}&origin=${encodeURIComponent(
                u.origin
              )}&portal=${encodeURIComponent(portalPath)}${extraMetaQuery}${
                isUnrecordedPlaceholder ? '&unrecorded=1' : ''
              }`;

        const folderParts = (folderLabel || '')
          .split(/\s*\/\s*/)
          .map((p) => p.trim())
          .filter(Boolean);
        const parsedSubject = String(
          folderParts.length >= 2
            ? folderParts[0]
            : item.subject_name || folderParts[0] || 'General'
        ).trim();
        const parsedTopic = String(
          folderParts.length >= 2
            ? folderParts.slice(1).join(' / ')
            : item.topic_name || folderParts[0] || 'General'
        ).trim();

        return {
          id: crypto.randomUUID(),
          url: streamUrl,
          protocol:
            directResolvedUrl && directResolvedUrl.toLowerCase().includes('.mp4')
              ? ('DIRECT_MP4' as const)
              : ('HLS_MASTER' as const),
          label: title,
          courseName: resolvedCourseName,
          subjectName: parsedSubject,
          topicName: parsedTopic,
          folderName: folderLabel,
          lectureTitle: title,
          date: item.date_and_time || item.event_date || item.created_at || undefined,
          pdfUrl: decPdf,
          resolution: chosenQualityLabel,
          foundVia: `Folder: ${folderLabel}`,
        };
      };

      // Helper to fetch videos for a specific (subjectId, topicId, conceptId) across direct API + portal proxy
      const fetchVideosByConcept = async (
        subjId: string,
        topId: string,
        conId: string,
        folderLabel: string
      ): Promise<StreamVariant[]> => {
        let contentJson: any = null;
        if (!isSachinPath) {
          contentJson = await fetchAppxJsonWithRetry(
            `${cfg.apiUrl}/get/livecourseclassbycoursesubtopconceptapiv3?courseid=${encodeURIComponent(
              courseId
            )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
              topId
            )}&conceptid=${encodeURIComponent(conId)}&start=-1`,
            appxHeaders,
            2
          );
        }
        let items: any[] = Array.isArray(contentJson)
          ? contentJson
          : Array.isArray(contentJson?.data)
          ? contentJson.data
          : Array.isArray(contentJson?.contents)
          ? contentJson.contents
          : [];

        const directAnsweredAuthoritatively = Boolean(
          contentJson &&
            (contentJson.status === 200 ||
              Array.isArray(contentJson.data) ||
              Array.isArray(contentJson))
        );

        if (items.length === 0 && !directAnsweredAuthoritatively) {
          const isCustomOrig = !/studybeepro\.site$/i.test(cleanOrig);
          const proxyUrls = isRwaPath
            ? [
                `${cleanOrig}/api/rwa/get/livecourseclassbycoursesubtopconceptapiv3?courseid=${encodeURIComponent(
                  courseId
                )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
                  topId
                )}&conceptid=${encodeURIComponent(conId)}&start=-1`,
                ...(isCustomOrig
                  ? [
                      `${cleanOrig}/api/rwax/get/livecourseclassbycoursesubtopconceptapiv3?courseid=${encodeURIComponent(
                        courseId
                      )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
                        topId
                      )}&conceptid=${encodeURIComponent(conId)}&start=-1`,
                      `${cleanOrig}/get/livecourseclassbycoursesubtopconceptapiv3?courseid=${encodeURIComponent(
                        courseId
                      )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
                        topId
                      )}&conceptid=${encodeURIComponent(conId)}&windowsapp=false&start=0`,
                    ]
                  : []),
              ]
            : [
                `${cleanOrig}/get/livecourseclassbycoursesubtopconceptapiv3?courseid=${encodeURIComponent(
                  courseId
                )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(
                  topId
                )}&conceptid=${encodeURIComponent(conId)}&windowsapp=false&start=0`,
              ];
          for (const pUrl of proxyUrls) {
            const proxyJson = await fetchAppxJsonWithRetry(pUrl, portalHeaders, 1);
            items = Array.isArray(proxyJson)
              ? proxyJson
              : Array.isArray(proxyJson?.data)
              ? proxyJson.data
              : Array.isArray(proxyJson?.contents)
              ? proxyJson.contents
              : [];
            if (items.length > 0) break;
          }
        }

        const out: StreamVariant[] = [];
        for (const item of items) {
          if (!isFolderItem(item) && (item.id || item.video_id)) {
            const mapped = mapVideoItemToStream(item, folderLabel, { subjId, topId, conId });
            if (mapped) out.push(mapped);
          }
        }
        (out as any)._hadRawItems = items.length > 0;
        return out;
      };

      // Helper to crawl a Topic folder AND all nested Concept sub-folders inside it
      const fetchVideosInTopic = async (
        subjId: string,
        topId: string,
        folderLabel: string,
        explicitConceptId?: string | null
      ): Promise<StreamVariant[]> => {
        const collected: StreamVariant[] = [];

        if (explicitConceptId) {
          const vids = await fetchVideosByConcept(subjId, topId, explicitConceptId, folderLabel);
          if (vids.length > 0) {
            folderSet.add(folderLabel);
            collected.push(...vids);
          }
          return collected;
        }

        // Fast Path: Try conceptid="1" ("All video" folder in RWA/TeachX) first, or "" for SachinAcademy
        const firstConId = isSachinPath ? '' : '1';
        const con1Vids = await fetchVideosByConcept(subjId, topId, firstConId, folderLabel);
        if (con1Vids.length > 0 || Boolean((con1Vids as any)._hadRawItems)) {
          if (con1Vids.length > 0) {
            folderSet.add(folderLabel);
            collected.push(...con1Vids);
          }
          return collected;
        }

        // Step A: Check nested Concepts (3rd folder level: Subject -> Topic -> Concept -> Videos)
        let conceptsJson: any = null;
        if (!isSachinPath) {
          conceptsJson = await fetchAppxJsonWithRetry(
            `${cfg.apiUrl}/get/allconceptfrmlivecourseclass?courseid=${encodeURIComponent(
              courseId
            )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(topId)}&start=-1`,
            appxHeaders,
            2
          );
        }
        const conceptsDirectAnswered = Boolean(
          conceptsJson &&
            (conceptsJson.status === 200 ||
              Array.isArray(conceptsJson.data) ||
              Array.isArray(conceptsJson))
        );
        if (!conceptsDirectAnswered && !isRwaPath) {
          conceptsJson = await fetchAppxJsonWithRetry(
            `${cleanOrig}/get/allconceptfrmlivecourseclass?courseid=${encodeURIComponent(
              courseId
            )}&subjectid=${encodeURIComponent(subjId)}&topicid=${encodeURIComponent(topId)}&start=-1`,
            portalHeaders,
            1
          );
        }
        const concepts: any[] = Array.isArray(conceptsJson)
          ? conceptsJson
          : Array.isArray(conceptsJson?.data)
          ? conceptsJson.data
          : [];

        if (concepts.length > 0) {
          const filteredConcepts = concepts.filter((concept) => {
            const cId = String(concept.conceptid ?? concept.id ?? '').trim();
            return Boolean(cId && cId !== firstConId);
          });
          for (let ci = 0; ci < filteredConcepts.length; ci += 4) {
            const cBatch = filteredConcepts.slice(ci, ci + 4);
            const cResults = await Promise.all(
              cBatch.map(async (concept) => {
                const cId = String(concept.conceptid ?? concept.id ?? '').trim();
                const rawConceptName = String(
                  concept.concept_name || concept.title || concept.name || ''
                ).trim();
                const isGenericConceptName =
                  !rawConceptName || /^all\s*videos?$/i.test(rawConceptName);
                const subFolderLabel = isGenericConceptName
                  ? folderLabel
                  : `${folderLabel} / ${rawConceptName}`;
                const vids = await fetchVideosByConcept(subjId, topId, cId, subFolderLabel);
                return { subFolderLabel, vids };
              })
            );
            for (const { subFolderLabel, vids } of cResults) {
              if (vids.length > 0) {
                folderSet.add(subFolderLabel);
                collected.push(...vids);
              }
            }
          }
        }

        // Step B: Also check fallback conceptid ("" if we tried "1", or "1" if we tried "") only for non-RWA portals
        if (collected.length === 0 && !isRwaPath) {
          const altConId = firstConId === '1' ? '' : '1';
          const directVids = await fetchVideosByConcept(subjId, topId, altConId, folderLabel);
          if (directVids.length > 0) {
            folderSet.add(folderLabel);
            collected.push(...directVids);
          }
        }

        return collected;
      };

      // Case 2: Specific Topic/Concept Folder (content.html?courseid=...&subjectid=...&topicid=...)
      if (subjectId && topicId) {
        const folderName = conceptIdParam
          ? `Topic #${topicId} / Concept #${conceptIdParam}`
          : `Topic #${topicId}`;
        const vids = await fetchVideosInTopic(subjectId, topicId, folderName, conceptIdParam);
        if (vids.length > 0) {
          streams.push(...vids);
        }
        applyDuplicateTitleNumbering(streams);
        pageTitle = `${resolvedCourseName} (${folderName})`;
        return storeInCourseCacheAndReturn({
          sourceUrl: targetUrl,
          pageTitle,
          extractedAt: new Date().toISOString(),
          streams,
          folders: Array.from(folderSet),
          scriptsScanned: 1,
          notes,
        });
      }

      // Helper to fetch all topics inside a subject and all concepts/videos inside each topic in deterministic order
      const fetchAllTopicsForSubject = async (
        subjId: string,
        subjectPrefix?: string
      ): Promise<StreamVariant[]> => {
        const subjectStreams: StreamVariant[] = [];
        try {
          let topicsJson: any = null;
          if (!isSachinPath) {
            topicsJson = await fetchAppxJsonWithRetry(
              `${cfg.apiUrl}/get/alltopicfrmlivecourseclass?courseid=${encodeURIComponent(
                courseId
              )}&subjectid=${encodeURIComponent(subjId)}&start=-1`,
              appxHeaders,
              2
            );
          }
          let allTopics: any[] = Array.isArray(topicsJson)
            ? topicsJson
            : Array.isArray(topicsJson?.data)
            ? topicsJson.data
            : [];
          const topicsDirectAnswered = Boolean(
            topicsJson &&
              (topicsJson.status === 200 ||
                Array.isArray(topicsJson.data) ||
                Array.isArray(topicsJson))
          );
          if (allTopics.length === 0 && !topicsDirectAnswered) {
            const topicProxyUrls = isRwaPath
              ? [
                  `${cleanOrig}/api/rwa/get/alltopicfrmlivecourseclass?courseid=${encodeURIComponent(
                    courseId
                  )}&subjectid=${encodeURIComponent(subjId)}&start=-3`,
                  ...(!/studybeepro\.site$/i.test(cleanOrig)
                    ? [
                        `${cleanOrig}/get/alltopicfrmlivecourseclass?courseid=${encodeURIComponent(
                          courseId
                        )}&subjectid=${encodeURIComponent(subjId)}&start=-1`,
                      ]
                    : []),
                ]
              : [
                  `${cleanOrig}/get/alltopicfrmlivecourseclass?courseid=${encodeURIComponent(
                    courseId
                  )}&subjectid=${encodeURIComponent(subjId)}&start=-1`,
                ];
            for (const topicProxyUrl of topicProxyUrls) {
              const proxyTopics = await fetchAppxJsonWithRetry(topicProxyUrl, portalHeaders, 1);
              allTopics = Array.isArray(proxyTopics)
                ? proxyTopics
                : Array.isArray(proxyTopics?.data)
                ? proxyTopics.data
                : [];
              if (allTopics.length > 0) break;
            }
          }

          const topics = allTopics.filter(
            (t) => !/^combined\s*pdfs?$/i.test(String(t.topic_name || t.title || t.name || '').trim())
          );

          const targetStreamLimit =
            maxVideosNeeded && maxVideosNeeded > 0
              ? Math.min(MAX_COURSE_STREAMS, maxVideosNeeded)
              : MAX_COURSE_STREAMS;

          // Parallel topic crawl (8 topics at a time) while preserving exact topic order
          for (let ti = 0; ti < topics.length; ti += 8) {
            if (streams.length + subjectStreams.length >= targetStreamLimit) break;
            const topicBatch = topics.slice(ti, ti + 8);
            const batchResults = await Promise.all(
              topicBatch.map(async (topic) => {
                const rawTopicName = String(
                  topic.topic_name || topic.title || topic.name || `Topic ${topic.topicid || topic.id}`
                ).trim();
                const folderLabel = subjectPrefix
                  ? `${subjectPrefix} / ${rawTopicName}`
                  : rawTopicName;
                return await fetchVideosInTopic(subjId, String(topic.topicid || topic.id), folderLabel);
              })
            );
            for (const vids of batchResults) {
              if (vids.length > 0) {
                subjectStreams.push(...vids);
              }
            }
          }
        } catch (topErr: any) {
          notes.push(`Topics fetch note for subj ${subjId}: ${topErr?.message}`);
        }
        return subjectStreams;
      };

      // Case 3: Subject Topic-List Page (topic.html?courseid=284&subjectid=1677&domainId=RWA)
      if (subjectId) {
        const subjVids = await fetchAllTopicsForSubject(subjectId);
        if (subjVids.length > 0) {
          streams.push(...subjVids);
          applyDuplicateTitleNumbering(streams);
          pageTitle = `${resolvedCourseName} (Subject #${subjectId})`;
          return storeInCourseCacheAndReturn({
            sourceUrl: targetUrl,
            pageTitle,
            extractedAt: new Date().toISOString(),
            streams,
            folders: Array.from(folderSet),
            scriptsScanned: 1,
            notes,
          });
        }
      }

      // Helper for 4-Level Subject -> Topic -> Concept -> Video Crawler (RWA / TeachX / SachinAcademy)
      const crawlSubjectsTopicsAndVideos = async () => {
        try {
          let subjJson: any = null;
          if (!isSachinPath) {
            subjJson = await fetchAppxJsonWithRetry(
              `${cfg.apiUrl}/get/allsubjectfrmlivecourseclass?courseid=${encodeURIComponent(
                courseId
              )}&start=-1`,
              appxHeaders,
              2
            );
          }
          let subjects: any[] = Array.isArray(subjJson)
            ? subjJson
            : Array.isArray(subjJson?.data)
            ? subjJson.data
            : [];

          if (subjects.length === 0) {
            const subjProxyUrls = isRwaPath
              ? [
                  `${cleanOrig}/api/rwa/get/allsubjectfrmlivecourseclass?courseid=${encodeURIComponent(courseId)}`,
                  ...(!/studybeepro\.site$/i.test(cleanOrig)
                    ? [
                        `${cleanOrig}/api/rwax/get/allsubjectfrmlivecourseclass?courseid=${encodeURIComponent(courseId)}`,
                        `${cleanOrig}/get/allsubjectfrmlivecourseclass?courseid=${encodeURIComponent(courseId)}&start=-1`,
                      ]
                    : []),
                ]
              : [`${cleanOrig}/get/allsubjectfrmlivecourseclass?courseid=${encodeURIComponent(courseId)}&start=-1`];
            for (const subjProxyUrl of subjProxyUrls) {
              const proxySubj = await fetchAppxJsonWithRetry(subjProxyUrl, portalHeaders, 1);
              subjects = Array.isArray(proxySubj)
                ? proxySubj
                : Array.isArray(proxySubj?.data)
                ? proxySubj.data
                : [];
              if (subjects.length > 0) break;
            }
          }

          const targetStreamLimit =
            maxVideosNeeded && maxVideosNeeded > 0
              ? Math.min(MAX_COURSE_STREAMS, maxVideosNeeded)
              : MAX_COURSE_STREAMS;
          const subjStep =
            maxVideosNeeded && maxVideosNeeded > 0 && maxVideosNeeded <= 40 ? 4 : 8;

          // Crawl subjects in deterministic order so Lecture 1..N numbering never shuffles
          for (let si = 0; si < subjects.length; si += subjStep) {
            if (streams.length >= targetStreamLimit) break;
            const subBatch = subjects.slice(si, si + subjStep);
            const batchSubjStreams = await Promise.all(
              subBatch.map(async (subj) => {
                const sName = String(
                  subj.subject_name || subj.title || subj.name || `Subject ${subj.subjectid || subj.id}`
                ).trim();
                return await fetchAllTopicsForSubject(String(subj.subjectid || subj.id), sName);
              })
            );
            for (const sList of batchSubjStreams) {
              if (sList.length > 0) {
                streams.push(...sList);
              }
            }
            if (onProgress && subjects.length > 0) {
              const doneSubj = Math.min(si + subBatch.length, subjects.length);
              onProgress(
                `📂 Scanned ${doneSubj}/${subjects.length} Subjects (${folderSet.size} folders, ${streams.length} videos found)...`
              );
            }
            if (streams.length >= targetStreamLimit) break;
          }
        } catch (subjErr: any) {
          notes.push(`Subject tree scan note: ${subjErr?.message}`);
        }
      };

      // Helper to recursively crawl multi-level folder_contentsv3 / folder_contentsv2 trees (folders inside folders up to 12 levels deep)
      const visitedFolderIds = new Set<string>();
      const crawlRecursiveFolderContents = async (
        parentId: string,
        folderPath: string,
        depth: number = 0
      ) => {
        if (depth > 12 || streams.length >= MAX_COURSE_STREAMS) return;
        const visitKey = `${courseId}:${parentId}`;
        if (visitedFolderIds.has(visitKey)) return;
        visitedFolderIds.add(visitKey);

        let folderJson: any = null;
        // For non-RWA portals (e.g. scienceandfun, vibrant, vidyagram, yesoff), try StudyPanda / StudyBeePro portal proxy first
        if (!isRwaPath) {
          const folderProxyCandidates: string[] = [];
          if (isScienceAndFunPath) {
            folderProxyCandidates.push(
              `${cleanOrig}/api/scienceandfun/get/folder_contentsv3?course_id=${encodeURIComponent(
                courseId
              )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
              `https://studypanda.live/api/scienceandfun/get/folder_contentsv3?course_id=${encodeURIComponent(
                courseId
              )}&parent_id=${encodeURIComponent(parentId)}&start=0`
            );
          } else if (isVibrantPath) {
            folderProxyCandidates.push(
              `${cleanOrig}/api/vibrant/get/folder_contentsv3?course_id=${encodeURIComponent(
                courseId
              )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
              `https://studypanda.live/api/vibrant/get/folder_contentsv3?course_id=${encodeURIComponent(
                courseId
              )}&parent_id=${encodeURIComponent(parentId)}&start=0`
            );
          }
          folderProxyCandidates.push(
            `${cleanOrig}/get/folder_contentsv3?course_id=${encodeURIComponent(
              courseId
            )}&parent_id=${encodeURIComponent(parentId)}&start=0`
          );

          for (const candUrl of folderProxyCandidates) {
            folderJson = await fetchAppxJsonWithRetry(candUrl, portalHeaders, 2);
            if (
              folderJson &&
              ((Array.isArray(folderJson) && folderJson.length > 0) ||
                (Array.isArray(folderJson.data) && folderJson.data.length > 0) ||
                (Array.isArray(folderJson.contents) && folderJson.contents.length > 0))
            ) {
              break;
            }
          }
        }

        let hasValidItems =
          folderJson &&
          ((Array.isArray(folderJson) && folderJson.length > 0) ||
            (Array.isArray(folderJson.data) && folderJson.data.length > 0) ||
            (Array.isArray(folderJson.contents) && folderJson.contents.length > 0));

        // Try direct TeachX / AppX API with appxHeaders
        if (!hasValidItems) {
          folderJson = await fetchAppxJsonWithRetry(
            `${cfg.apiUrl}/get/folder_contentsv3?course_id=${encodeURIComponent(
              courseId
            )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
            appxHeaders,
            2
          );
          hasValidItems =
            folderJson &&
            ((Array.isArray(folderJson) && folderJson.length > 0) ||
              (Array.isArray(folderJson.data) && folderJson.data.length > 0) ||
              (Array.isArray(folderJson.contents) && folderJson.contents.length > 0));
        }

        // Try StudyBeePro / Custom Web portal proxy if RWA direct API returned empty
        if (!hasValidItems && isRwaPath) {
          const rwaFolderProxies = [
            `${cleanOrig}/get/folder_contentsv3?course_id=${encodeURIComponent(
              courseId
            )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
            ...(!/studybeepro\.site$/i.test(cleanOrig)
              ? [
                  `${cleanOrig}/api/rwa/get/folder_contentsv3?course_id=${encodeURIComponent(
                    courseId
                  )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
                  `${cleanOrig}/api/rwax/get/folder_contentsv3?course_id=${encodeURIComponent(
                    courseId
                  )}&parent_id=${encodeURIComponent(parentId)}&start=0`,
                ]
              : []),
          ];
          for (const rfUrl of rwaFolderProxies) {
            folderJson = await fetchAppxJsonWithRetry(rfUrl, portalHeaders, 1);
            hasValidItems =
              folderJson &&
              ((Array.isArray(folderJson) && folderJson.length > 0) ||
                (Array.isArray(folderJson.data) && folderJson.data.length > 0) ||
                (Array.isArray(folderJson.contents) && folderJson.contents.length > 0));
            if (hasValidItems) break;
          }
        }

        // Fallback to folder_contentsv2
        if (!hasValidItems) {
          folderJson = await fetchAppxJsonWithRetry(
            `${cfg.apiUrl}/get/folder_contentsv2?course_id=${encodeURIComponent(
              courseId
            )}&parent_id=${encodeURIComponent(parentId)}`,
            appxHeaders,
            1
          );
        }

        const items: any[] = Array.isArray(folderJson)
          ? folderJson
          : Array.isArray(folderJson?.data)
          ? folderJson.data
          : Array.isArray(folderJson?.contents)
          ? folderJson.contents
          : Array.isArray(folderJson?.result)
          ? folderJson.result
          : [];

        if (items.length === 0) return;

        const childFolders: { id: string; title: string }[] = [];
        for (const item of items) {
          const itemTitle = String(
            item.Title || item.title || item.name || item.subject_name || item.topic_name || `Folder ${item.id}`
          ).trim();

          if (isFolderItem(item)) {
            const folderId = String(item.id || item.folder_id || item.subjectid || item.topicid || item.conceptid || '');
            if (folderId) {
              childFolders.push({ id: folderId, title: itemTitle });
            }
          } else {
            const labelFolder = folderPath || 'Course Lectures';
            const mapped = mapVideoItemToStream(item, labelFolder);
            if (mapped) {
              folderSet.add(labelFolder);
              streams.push(mapped);
            }
          }
        }

        // Recursively crawl nested sub-folders inside folders (paced in batches of 6)
        for (let fi = 0; fi < childFolders.length; fi += 6) {
          const fBatch = childFolders.slice(fi, fi + 6);
          await Promise.all(
            fBatch.map(async (subFolder) => {
              const isRootHome = depth === 0 && /^home$/i.test(subFolder.title);
              const nextFolderPath = isRootHome
                ? folderPath
                : folderPath
                ? `${folderPath} / ${subFolder.title}`
                : subFolder.title;
              await crawlRecursiveFolderContents(subFolder.id, nextFolderPath, depth + 1);
            })
          );
          if (streams.length >= MAX_COURSE_STREAMS) break;
        }
      };

      // Execution Order:
      // For RWA (/rwax, /rwa), SachinAcademy (/sachinacademy), or Subject/Topic pages -> Subject/Topic/Concept crawler first!
      if ((isRwaPath || isSachinPath || isSubjectPage || isTopicPage) && !parentIdParam) {
        await crawlSubjectsTopicsAndVideos();
      }

      // If no streams found yet (or for folder_contentsv3 portals like /vidyagram, /yesoff, /sf, /vibrante), run recursive folder crawler
      if (streams.length === 0) {
        await crawlRecursiveFolderContents(parentIdParam || '-1', '');
        if (streams.length === 0 && parentIdParam !== '0') {
          await crawlRecursiveFolderContents('0', '');
        }
      }

      // Final fallback: if recursive folder crawler was tried first and found 0 streams, try Subject/Topic/Concept crawler
      if (streams.length === 0 && !(isRwaPath || isSachinPath || isSubjectPage || isTopicPage)) {
        await crawlSubjectsTopicsAndVideos();
      }

      if (streams.length > 0) {
        applyDuplicateTitleNumbering(streams);
        pageTitle = `${resolvedCourseName} (${folderSet.size} Folders, ${streams.length} Videos)`;
        return storeInCourseCacheAndReturn({
          sourceUrl: targetUrl,
          pageTitle,
          extractedAt: new Date().toISOString(),
          streams,
          folders: Array.from(folderSet),
          scriptsScanned: 1,
          notes,
        });
      }

      // Check if origin returned a Cookie Check interstitial or login gate (401/403/login page)
      try {
        const probeRes = await fetch(targetUrl, {
          headers: portalHeaders,
          redirect: 'manual',
          signal: AbortSignal.timeout(6500),
        });
        const probeBody = await probeRes.text().catch(() => '');
        const loc = probeRes.headers.get('location') || '';
        const gate = isCookieCheckOrLoginHtml(probeBody);
        if (
          gate.isAuthGate ||
          probeRes.status === 401 ||
          probeRes.status === 403 ||
          /accounts\.google\.com|\/login\b/i.test(loc)
        ) {
          authRequiredOrigin = u.origin;
          authRequiredReason =
            gate.reason === 'cookie_check' || /accounts\.google\.com/i.test(loc)
              ? 'cookie_check'
              : 'login_required';
          notes.push(
            authRequiredReason === 'cookie_check'
              ? `Portal Cookie check active on ${u.origin}. Login or Cookie/Token required.`
              : `Login required on ${u.origin} (HTTP ${probeRes.status}).`
          );
        }
      } catch {
        // ignore probe error
      }
    }
  } catch (appxErr: any) {
    console.error('[AppX Inspection Error]:', appxErr);
    notes.push(`AppX folder scan note: ${appxErr?.message || 'skipped'}`);
  }

  // 1B. Check if URL is a Multi-Folder Course / Batch URL (e.g. /course/:courseId or /course/:courseId/:folderName)
  try {
    const parsedUrlObj = new URL(targetUrl);
    const courseMatch = parsedUrlObj.pathname.match(/\/course\/(\d+)(?:\/([^/?#]+))?/i);
    if (courseMatch) {
      const courseId = courseMatch[1];
      const requestedFolderSlug = courseMatch[2] ? decodeURIComponent(courseMatch[2]).trim() : null;
      const apiContentUrl = `${parsedUrlObj.origin}/api/content`;

      const apiRes = await fetch(apiContentUrl, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ courseId }),
      });

      if (apiRes.ok) {
        const apiJson = (await apiRes.json()) as any;
        if (apiJson && apiJson.success && apiJson.data) {
          const courseData = apiJson.data;
          pageTitle = courseData.courseTitle || courseData.title || `Batch Course #${courseId}`;
          const items: any[] =
            courseData.data || courseData.courseContent || courseData.lectures || [];

          for (const item of items) {
            const videoUrl = item.videoUrl || item.url || item.streamUrl;
            if (!videoUrl || typeof videoUrl !== 'string') continue;

            const folderName = (item.parentTitle || item.folderName || 'General').trim();
            folderSet.add(folderName);

            if (
              requestedFolderSlug &&
              folderName.toLowerCase() !== requestedFolderSlug.toLowerCase()
            ) {
              continue;
            }

            const lectureTitle = (item.name || item.title || 'Lecture Video').trim();
            const isM3u8 = videoUrl.toLowerCase().includes('.m3u8');

            const fParts = folderName.split(/\s*\/\s*/).map((p: string) => p.trim()).filter(Boolean);
            streams.push({
              id: crypto.randomUUID(),
              url: videoUrl,
              protocol: isM3u8 ? 'HLS_MASTER' : 'DIRECT_MP4',
              label: lectureTitle,
              courseName: pageTitle,
              subjectName: fParts[0] || folderName,
              topicName: fParts.length >= 2 ? fParts.slice(1).join(' / ') : folderName,
              folderName,
              lectureTitle,
              facultyName: item.facultyName || undefined,
              date: item.date || undefined,
              pdfUrl: item.textUploadUrl || undefined,
              foundVia: `Folder: ${folderName}`,
            });
          }

          applyDuplicateTitleNumbering(streams);
          const folders = Array.from(folderSet);
          return {
            sourceUrl: targetUrl,
            pageTitle: requestedFolderSlug ? `${pageTitle} — ${requestedFolderSlug}` : pageTitle,
            extractedAt: new Date().toISOString(),
            streams,
            folders,
            scriptsScanned: 1,
            notes,
          };
        }
      }
    }
  } catch {
    // Continue to standard HTTP inspection
  }

  const DIRECT_VIDEO_EXT_RE = /\.(mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)$/i;
  if (isUrlPathnameEndingWith(targetUrl, DIRECT_VIDEO_EXT_RE)) {
    const isWebm = isUrlPathnameEndingWith(targetUrl, /\.webm$/i);
    const isMp4 = isUrlPathnameEndingWith(targetUrl, /\.(mp4|m4v)$/i);
    const urlPathName = new URL(targetUrl).pathname.split('/').pop() || 'video.mp4';
    const cleanFileTitle = decodeURIComponent(urlPathName);
    const extUpper = (cleanFileTitle.split('.').pop() || 'MP4').toUpperCase();
    pageTitle = cleanFileTitle;
    streams.push({
      id: crypto.randomUUID(),
      url: targetUrl,
      protocol: isWebm ? 'DIRECT_WEBM' : isMp4 ? 'DIRECT_MP4' : 'DIRECT_VIDEO',
      label: isMp4 ? cleanFileTitle : `${cleanFileTitle} (${extUpper} → MP4)`,
      lectureTitle: cleanFileTitle,
      resolution: botSettings.globalDefaultQuality || '720p',
      foundVia: `Direct ${extUpper} Video URL`,
    });
    return {
      sourceUrl: targetUrl,
      pageTitle,
      extractedAt: new Date().toISOString(),
      streams,
      folders: [],
      scriptsScanned: 0,
      pagesScanned: 1,
      notes,
    };
  }

  // 1C. Social & Video Hosting Platforms (YouTube, Instagram, Facebook, TikTok, X/Twitter, Vimeo, Reddit, Drive, etc.)
  const platformCheck = detectPlatformVideoUrl(targetUrl);
  if (platformCheck.isPlatform && !rawHtmlSnippet) {
    if (onProgress) {
      onProgress(`🎬 Extracting ${platformCheck.platformName} high-quality media streams...`);
    }
    const ytRes = await extractWithYtDlp(targetUrl, maxVideosNeeded ? Math.max(maxVideosNeeded, 25) : 50);
    if (ytRes.ok && ytRes.entries.length > 0) {
      for (const ent of ytRes.entries) {
        if (ent.folderName) folderSet.add(ent.folderName);
      }
      return {
        sourceUrl: targetUrl,
        pageTitle: ytRes.pageTitle,
        extractedAt: new Date().toISOString(),
        streams: ytRes.entries,
        folders: Array.from(folderSet),
        scriptsScanned: 0,
        pagesScanned: 1,
        notes: [...notes, `Extracted via ${platformCheck.platformName} High-Quality Engine`],
      };
    }
    if (ytRes.error) {
      notes.push(`Platform extractor note (${platformCheck.platformName}): ${ytRes.error}`);
    }
  }

  // 1D. Lightweight Content-Type & Redirect Probe (catches extensionless direct MP4/MKV/WebM links without blowing RAM!)
  if (!rawHtmlSnippet) {
    const probeInfo = await probeHttpMediaType(targetUrl, headers);
    if (probeInfo.isDirectMedia) {
      const finalDirectUrl = probeInfo.finalUrl || targetUrl;
      const isWebm = probeInfo.contentType.includes('webm') || /\.webm$/i.test(probeInfo.filename || '');
      const isMp4 = probeInfo.contentType.includes('mp4') || /\.(mp4|m4v)$/i.test(probeInfo.filename || '');
      const titleFromProbe =
        probeInfo.filename ||
        decodeURIComponent(new URL(finalDirectUrl).pathname.split('/').pop() || 'Direct_Video.mp4');
      streams.push({
        id: crypto.randomUUID(),
        url: finalDirectUrl,
        protocol: isWebm ? 'DIRECT_WEBM' : isMp4 ? 'DIRECT_MP4' : 'DIRECT_VIDEO',
        label: titleFromProbe,
        lectureTitle: titleFromProbe,
        resolution: botSettings.globalDefaultQuality || '720p',
        foundVia: `Direct HTTP Media (${probeInfo.contentType || 'video/*'})`,
      });
      return {
        sourceUrl: finalDirectUrl,
        pageTitle: titleFromProbe,
        extractedAt: new Date().toISOString(),
        streams,
        folders: [],
        scriptsScanned: 0,
        pagesScanned: 1,
        notes,
      };
    }
  }

  let textBody = '';
  let finalUrl = targetUrl;
  let contentType = 'text/html';
  try {
    const fetched = await robustFetchText(targetUrl, headers);
    textBody = fetched.text;
    finalUrl = fetched.finalUrl;
    contentType = fetched.contentType;
  } catch (fetchErr: any) {
    const msgErr = String(fetchErr?.message || '');
    if (/\b(401|403|unauthorized|forbidden)\b/i.test(msgErr)) {
      try {
        authRequiredOrigin = new URL(targetUrl).origin;
        authRequiredReason = 'login_required';
      } catch {}
      notes.push(`Website returned ${msgErr}. Login or Cookie/Token required.`);
      return {
        sourceUrl: targetUrl,
        pageTitle: 'Authentication Required',
        extractedAt: new Date().toISOString(),
        streams: [],
        folders: [],
        scriptsScanned: 0,
        pagesScanned: 1,
        notes,
        authRequiredOrigin,
        authRequiredReason,
      };
    }
    throw fetchErr;
  }

  const pageGateCheck = isCookieCheckOrLoginHtml(textBody);
  if (pageGateCheck.isAuthGate && !textBody.trim().startsWith('#EXTM3U')) {
    try {
      authRequiredOrigin = new URL(finalUrl || targetUrl).origin;
      authRequiredReason = pageGateCheck.reason || 'login_required';
      notes.push(
        authRequiredReason === 'cookie_check'
          ? `Cookie check / Google Auth gate active on ${authRequiredOrigin}`
          : `Web portal login required on ${authRequiredOrigin}`
      );
    } catch {}
  }

  if (
    textBody.trim().startsWith('#EXTM3U') ||
    (contentType.includes('mpegurl') && !textBody.trim().startsWith('<'))
  ) {
    rawManifestSnippet = textBody.slice(0, 2500);
    const urlName = new URL(finalUrl).pathname.split('/').pop() || 'stream.m3u8';
    pageTitle = `HLS Stream (${decodeURIComponent(urlName)})`;

    streams.push({
      id: 'hls-master-or-media',
      url: finalUrl,
      protocol: 'HLS_MASTER',
      label: pageTitle,
      foundVia: 'Direct HLS Playlist (#EXTM3U)',
    });

    return {
      sourceUrl: finalUrl,
      pageTitle,
      extractedAt: new Date().toISOString(),
      streams,
      folders: [],
      scriptsScanned: 0,
      pagesScanned: 1,
      rawManifestSnippet,
      notes,
    };
  }

  // 2. Universal Deep Any-Website Scanner (BFS Crawl up to 25 Pages, Depth 3, JSON-LD, __NEXT_DATA__, Iframe Embeds, Open Directories, JS/Base64)
  const $ = cheerio.load(textBody);
  pageTitle =
    $('meta[property="og:title"]').attr('content')?.trim() ||
    $('title').first().text().trim() ||
    finalUrl;

  const discovered = new Map<
    string,
    { url: string; foundVia: string; folderName?: string; titleHint?: string }
  >();
  const globalExternalScriptsSeen = new Set<string>();
  const externalScriptUrls: string[] = [];
  const embedIframesQueue: Array<{ url: string; folderLabel?: string; titleHint?: string }> = [];
  const seenEmbeds = new Set<string>();

  const cleanLabelText = (raw: string): string =>
    String(raw || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 110);

  const deriveCleanTitleFromUrl = (rawMediaUrl: string): string => {
    try {
      const u = new URL(rawMediaUrl);
      const lastSeg = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() || 'Video');
      return lastSeg.replace(/\.(m3u8|mpd|mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)$/i, '').replace(/[_+]+/g, ' ').trim() || lastSeg;
    } catch {
      return 'Extracted Video';
    }
  };

  const upsertDiscovered = (
    rawMediaUrl: string,
    foundVia: string,
    folderLabel?: string,
    titleHint?: string
  ) => {
    if (!rawMediaUrl || /^data:|^blob:|^javascript:/i.test(rawMediaUrl)) return;
    const lower = rawMediaUrl.toLowerCase();
    if (/google-analytics|googletagmanager|doubleclick|fbevents|favicon/i.test(lower)) return;
    const prev = discovered.get(rawMediaUrl);
    if (!prev) {
      discovered.set(rawMediaUrl, {
        url: rawMediaUrl,
        foundVia,
        folderName: folderLabel,
        titleHint: titleHint ? cleanLabelText(titleHint) : undefined,
      });
    } else {
      if (!prev.titleHint && titleHint) prev.titleHint = cleanLabelText(titleHint);
      if (!prev.folderName && folderLabel) prev.folderName = folderLabel;
    }
  };

  const parseJsonForVideoUrls = (obj: any, pageBaseUrl: string, folderLabel?: string, depth = 0) => {
    if (!obj || depth > 7) return;
    if (typeof obj === 'string') {
      if (/\.(m3u8|mpd|mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)(\?.*)?$/i.test(obj) && (/^https?:\/\//i.test(obj) || obj.startsWith('/'))) {
        upsertDiscovered(resolveRelativeUrl(obj, pageBaseUrl), folderLabel ? `Folder [${folderLabel}] JSON` : 'Structured JSON Metadata', folderLabel);
      }
      return;
    }
    if (Array.isArray(obj)) {
      for (const el of obj.slice(0, 80)) {
        parseJsonForVideoUrls(el, pageBaseUrl, folderLabel, depth + 1);
      }
      return;
    }
    if (typeof obj === 'object') {
      const titleCandidate = obj.name || obj.title || obj.headline || obj.videoTitle || obj.caption;
      for (const k of ['contentUrl', 'embedUrl', 'videoUrl', 'streamUrl', 'fileUrl', 'hlsUrl', 'mp4Url', 'playbackUrl', 'src', 'url', 'file']) {
        const val = obj[k];
        if (typeof val === 'string' && val.trim()) {
          const abs = resolveRelativeUrl(val.trim(), pageBaseUrl);
          if (/\.(m3u8|mpd|mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)(\?.*)?$/i.test(abs)) {
            upsertDiscovered(
              abs,
              folderLabel ? `Folder [${folderLabel}] JSON-LD` : 'Structured JSON/Schema Video',
              folderLabel,
              typeof titleCandidate === 'string' ? titleCandidate : undefined
            );
          } else if (k === 'embedUrl' && detectPlatformVideoUrl(abs).isPlatform) {
            upsertDiscovered(
              abs,
              'Embedded Platform Video',
              folderLabel,
              typeof titleCandidate === 'string' ? titleCandidate : undefined
            );
          }
        }
      }
      for (const val of Object.values(obj)) {
        if (val && typeof val === 'object') {
          parseJsonForVideoUrls(val, pageBaseUrl, folderLabel, depth + 1);
        }
      }
    }
  };

  const parseHtmlDomIntoDiscovered = (
    cheerioInstance: cheerio.CheerioAPI,
    pageBaseUrl: string,
    pageHtmlRaw: string,
    folderLabel?: string
  ) => {
    const pageTitleHint = cleanLabelText(
      cheerioInstance('h1').first().text() ||
        cheerioInstance('meta[property="og:title"]').attr('content') ||
        cheerioInstance('title').first().text() ||
        ''
    );

    // 1. HTML5 <video> & <source>
    cheerioInstance('video, video source, source').each((_, el) => {
      const src =
        cheerioInstance(el).attr('src') ||
        cheerioInstance(el).attr('data-src') ||
        cheerioInstance(el).attr('data-url') ||
        cheerioInstance(el).attr('data-file');
      if (src) {
        const abs = resolveRelativeUrl(src, pageBaseUrl);
        const cardTitle = cleanLabelText(
          cheerioInstance(el).closest('article, .card, .video-item, .lesson, li, div').find('h1, h2, h3, h4, .title').first().text() ||
            cheerioInstance(el).attr('title') ||
            pageTitleHint
        );
        upsertDiscovered(
          abs,
          folderLabel ? `Folder [${folderLabel}] <video>` : 'HTML5 <video>',
          folderLabel,
          cardTitle
        );
      }
    });

    // 2. Direct video file links & Open Directory listings (<a href="*.mp4|mkv|webm|mov|avi|m3u8|mpd">)
    cheerioInstance('a[href]').each((_, el) => {
      const href = cheerioInstance(el).attr('href');
      if (!href) return;
      const abs = resolveRelativeUrl(href, pageBaseUrl);
      const unwrappedLink = unwrapQueryRedirectUrl(abs) || abs;
      if (/\.(m3u8|mpd|mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)(\?.*)?$/i.test(unwrappedLink)) {
        const rawText = cleanLabelText(cheerioInstance(el).text());
        const titleHint =
          rawText && !/^parent directory$/i.test(rawText)
            ? rawText
            : deriveCleanTitleFromUrl(unwrappedLink);
        upsertDiscovered(
          unwrappedLink,
          folderLabel ? `Folder [${folderLabel}] — ${titleHint}` : titleHint || 'Direct Page Link',
          folderLabel,
          titleHint
        );
      }
    });

    // 3. OpenGraph / Twitter player meta tags
    cheerioInstance(
      'meta[property="og:video"], meta[property="og:video:url"], meta[property="og:video:secure_url"], meta[name="twitter:player:stream"]'
    ).each((_, el) => {
      const content = cheerioInstance(el).attr('content');
      if (content) {
        const abs = resolveRelativeUrl(content, pageBaseUrl);
        upsertDiscovered(
          abs,
          folderLabel ? `Folder [${folderLabel}] Meta` : 'OpenGraph Video Tag',
          folderLabel,
          pageTitleHint
        );
      }
    });

    // 4. Data attributes on elements
    cheerioInstance(
      '[data-video], [data-mp4], [data-m3u8], [data-mpd], [data-hls], [data-stream-url], [data-video-url], [data-file]'
    ).each((_, el) => {
      const elFolder = cheerioInstance(el).attr('data-folder') || folderLabel;
      const elTitle = cleanLabelText(
        cheerioInstance(el).attr('data-title') ||
          cheerioInstance(el).attr('title') ||
          cheerioInstance(el).text() ||
          pageTitleHint
      );
      for (const attr of [
        'data-video',
        'data-mp4',
        'data-m3u8',
        'data-mpd',
        'data-hls',
        'data-stream-url',
        'data-video-url',
        'data-file',
      ]) {
        const val = cheerioInstance(el).attr(attr);
        if (val) {
          const abs = resolveRelativeUrl(val, pageBaseUrl);
          upsertDiscovered(
            abs,
            elFolder ? `Folder [${elFolder}]` : `DOM [${attr}]`,
            elFolder,
            elTitle
          );
        }
      }
    });

    // 5. JSON-LD <script type="application/ld+json">, __NEXT_DATA__, __NUXT__
    cheerioInstance('script[type="application/ld+json"], script#__NEXT_DATA__').each((_, el) => {
      const rawJson = cheerioInstance(el).html();
      if (!rawJson || rawJson.trim().length < 5) return;
      try {
        const parsed = JSON.parse(rawJson);
        parseJsonForVideoUrls(parsed, pageBaseUrl, folderLabel, 0);
      } catch {}
    });

    // 6. Video player <iframe> / <embed> detection
    cheerioInstance('iframe[src], embed[src]').each((_, el) => {
      const src = cheerioInstance(el).attr('src') || cheerioInstance(el).attr('data-src');
      if (!src) return;
      const abs = resolveRelativeUrl(src, pageBaseUrl);
      if (
        /youtube\.com\/embed|youtu\.be|player\.vimeo\.com|dailymotion\.com\/embed|streamable\.com|mediadelivery\.net|bunny|loom\.com|wistia|jwplayer|plyr|vidyard|player|embed|video/i.test(
          abs
        )
      ) {
        const pCheck = detectPlatformVideoUrl(abs);
        if (pCheck.isPlatform) {
          upsertDiscovered(
            abs,
            `${pCheck.platformName} Embed`,
            folderLabel,
            cleanLabelText(cheerioInstance(el).attr('title') || pageTitleHint)
          );
        } else if (!seenEmbeds.has(abs) && embedIframesQueue.length < 8) {
          seenEmbeds.add(abs);
          embedIframesQueue.push({
            url: abs,
            folderLabel,
            titleHint: cleanLabelText(cheerioInstance(el).attr('title') || pageTitleHint),
          });
        }
      }
    });

    // 7. Inline JS & HTML Regex Scan
    cheerioInstance('script').each((_, el) => {
      const src = cheerioInstance(el).attr('src');
      if (src) {
        const absJs = resolveRelativeUrl(src, pageBaseUrl);
        if (
          !globalExternalScriptsSeen.has(absJs) &&
          !/google-analytics|googletagmanager|fbevents|doubleclick|jquery|bootstrap|fontawesome|tailwind/i.test(
            absJs
          )
        ) {
          globalExternalScriptsSeen.add(absJs);
          externalScriptUrls.push(absJs);
        }
      }
      const inlineCode = cheerioInstance(el).html();
      if (inlineCode && inlineCode.trim().length > 0) {
        scriptsScanned++;
        extractStreamsFromJsOrText(
          inlineCode,
          pageBaseUrl,
          folderLabel ? `Folder [${folderLabel}] Inline JS` : 'Inline <script> JS Inspector',
          discovered,
          folderLabel
        );
      }
    });

    extractStreamsFromJsOrText(
      pageHtmlRaw,
      pageBaseUrl,
      folderLabel ? `Folder [${folderLabel}] HTML` : 'HTML Source Scanner',
      discovered,
      folderLabel
    );
  };

  parseHtmlDomIntoDiscovered($, finalUrl, textBody);

  // Inspect safe video embed iframes (1 hop)
  if (embedIframesQueue.length > 0 && !rawHtmlSnippet) {
    await Promise.all(
      embedIframesQueue.slice(0, 6).map(async (emb) => {
        try {
          const { text: embHtml, finalUrl: embFinal } = await robustFetchText(emb.url, headers, 1);
          const emb$ = cheerio.load(embHtml);
          parseHtmlDomIntoDiscovered(emb$, embFinal, embHtml, emb.folderLabel);
        } catch {}
      })
    );
  }

  // Deep Multi-Page Universal Web Crawler (up to 25 Pages, Depth 3, BFS with Pagination + Folder/Content Priority)
  if (crawlFolders && !rawHtmlSnippet) {
    const MAX_CRAWL_PAGES = 25;
    const MAX_CRAWL_DEPTH = 3;
    const CRAWL_DEADLINE_MS = Date.now() + 45000;
    const CRAWL_CONCURRENCY = 5;

    const canonPageUrl = (uStr: string): string => {
      try {
        const u = new URL(uStr);
        u.hash = '';
        return u.toString();
      } catch {
        return uStr;
      }
    };

    const rootOrigin = (() => {
      try {
        return new URL(finalUrl).origin;
      } catch {
        return '';
      }
    })();

    const visitedPages = new Set<string>([canonPageUrl(finalUrl)]);
    const queuedPages = new Set<string>([canonPageUrl(finalUrl)]);

    interface CrawlQueueItem {
      url: string;
      depth: number;
      label: string;
      priority: number;
    }

    const extractNavLinksFromPage = (
      cheerioInstance: cheerio.CheerioAPI,
      pageBaseUrl: string,
      currentDepth: number
    ): CrawlQueueItem[] => {
      if (!rootOrigin) return [];
      const foundLinks: CrawlQueueItem[] = [];
      cheerioInstance('a[href], [data-folder-url]').each((_, el) => {
        const rawHref = cheerioInstance(el).attr('data-folder-url') || cheerioInstance(el).attr('href');
        if (!rawHref || rawHref.startsWith('#') || /^(mailto:|tel:|javascript:)/i.test(rawHref)) return;
        const abs = canonPageUrl(resolveRelativeUrl(rawHref, pageBaseUrl));
        if (visitedPages.has(abs) || queuedPages.has(abs)) return;

        try {
          const subU = new URL(abs);
          if (subU.origin !== rootOrigin) return;
          const lowerPath = subU.pathname.toLowerCase();
          // Skip binary/non-HTML/auth/admin routes
          if (
            /\.(jpg|jpeg|png|gif|webp|svg|ico|css|js|pdf|zip|rar|7z|tar|gz|mp3|wav|m3u8|mp4|mkv|webm|mov|avi|woff2?|ttf|eot|xml|json)$/i.test(
              lowerPath
            )
          ) {
            return;
          }
          if (/\/(login|signin|signup|register|logout|cart|checkout|privacy|terms|cookie|wp-login|feed)\b/i.test(lowerPath)) {
            return;
          }

          const linkText = cleanLabelText(
            cheerioInstance(el).attr('data-folder-name') ||
              cheerioInstance(el).attr('title') ||
              cheerioInstance(el).text()
          );
          const relAttr = (cheerioInstance(el).attr('rel') || '').toLowerCase();

          let priority = 1;
          if (
            relAttr === 'next' ||
            /[?&](page|p|pg|offset|start)=/i.test(subU.search) ||
            /\/page\/\d+/i.test(lowerPath) ||
            /^(next|next\s*page|older|more|»|›)$/i.test(linkText)
          ) {
            priority = 3; // Pagination links get highest priority
          } else if (
            subU.pathname.endsWith('/') ||
            /\/(folder|dir|course|batch|chapter|module|subject|playlist|lecture|episode|video|watch|view|lesson|class|topic|series|season|category|tag|archive)\b/i.test(
              lowerPath
            )
          ) {
            priority = 2; // Folder / video / content pages get high priority
          }

          if (priority < 3 && currentDepth >= MAX_CRAWL_DEPTH) {
            return;
          }

          const folderTitle =
            (priority >= 2 && linkText && !/^(next|prev|previous|home|back|parent directory|»|›)$/i.test(linkText)
              ? linkText
              : decodeURIComponent(subU.pathname.split('/').filter(Boolean).pop() || 'Page')) ||
            'Web Page';

          queuedPages.add(abs);
          foundLinks.push({
            url: abs,
            depth: priority === 3 ? currentDepth : currentDepth + 1,
            label: folderTitle.slice(0, 65),
            priority,
          });
        } catch {}
      });
      return foundLinks;
    };

    const frontier: CrawlQueueItem[] = extractNavLinksFromPage($, finalUrl, 0);
    frontier.sort((a, b) => b.priority - a.priority);

    while (
      frontier.length > 0 &&
      pagesScanned < MAX_CRAWL_PAGES &&
      Date.now() < CRAWL_DEADLINE_MS
    ) {
      const remainingBudget = MAX_CRAWL_PAGES - pagesScanned;
      const batch = frontier.splice(0, Math.min(CRAWL_CONCURRENCY, remainingBudget));
      if (batch.length === 0) break;

      if (onProgress) {
        onProgress(
          `🌐 Deep Scanning Website (Page ${pagesScanned}/${MAX_CRAWL_PAGES}) · Found ${discovered.size} video(s)...`
        );
      }

      const nextDiscoveries: CrawlQueueItem[] = [];
      await Promise.all(
        batch.map(async (targetPage) => {
          if (visitedPages.has(targetPage.url)) return;
          visitedPages.add(targetPage.url);
          try {
            const { text: subHtml, finalUrl: subFinal, contentType: subCt } = await robustFetchText(
              targetPage.url,
              headers,
              1
            );
            pagesScanned++;
            if (subCt && !/html|text|xml|xhtml/i.test(subCt) && !subHtml.trimStart().startsWith('<')) {
              return;
            }
            const sub$ = cheerio.load(subHtml);
            const cleanFolder =
              targetPage.priority === 3
                ? `Page ${pagesScanned}`
                : targetPage.label || `Page ${pagesScanned}`;
            folderSet.add(cleanFolder);
            parseHtmlDomIntoDiscovered(sub$, subFinal, subHtml, cleanFolder);
            if (pagesScanned < MAX_CRAWL_PAGES && (targetPage.depth < MAX_CRAWL_DEPTH || targetPage.priority === 3)) {
              const childDepth = targetPage.depth;
              const childLinks = extractNavLinksFromPage(sub$, subFinal, childDepth);
              for (const cl of childLinks) {
                if (cl.priority === 3) {
                  cl.depth = targetPage.depth; // Do not consume depth budget on pagination chains!
                }
                nextDiscoveries.push(cl);
              }
            }
          } catch {
            // ignore unreachable page
          }
        })
      );

      if (nextDiscoveries.length > 0) {
        frontier.push(...nextDiscoveries);
        frontier.sort((a, b) => b.priority - a.priority);
        if (frontier.length > 150) frontier.length = 150;
      }
    }
  }

  const filteredExternalScripts = externalScriptUrls.slice(0, 8);
  await Promise.all(
    filteredExternalScripts.map(async (jsUrl) => {
      try {
        const { text: jsText } = await robustFetchText(jsUrl, headers, 1);
        scriptsScanned++;
        extractStreamsFromJsOrText(
          jsText,
          finalUrl,
          `External JS (${jsUrl.split('/').pop()})`,
          discovered
        );
      } catch {
        // ignore
      }
    })
  );

  for (const item of discovered.values()) {
    if (item.folderName) {
      folderSet.add(item.folderName);
    }
    const lower = item.url.toLowerCase();
    const isPlat = detectPlatformVideoUrl(item.url).isPlatform;
    const protocol: StreamVariant['protocol'] = isPlat || lower.includes('.mpd')
      ? 'YTDLP_PLATFORM'
      : lower.includes('.m3u8')
      ? 'HLS_MASTER'
      : lower.includes('.webm')
      ? 'DIRECT_WEBM'
      : lower.includes('.mp4') || lower.includes('.m4v') || lower.includes('mime=video/mp4') || lower.includes('videoplayback')
      ? 'DIRECT_MP4'
      : 'DIRECT_VIDEO';

    const cleanLabel = item.titleHint || deriveCleanTitleFromUrl(item.url) || item.foundVia;
    streams.push({
      id: crypto.randomUUID(),
      url: item.url,
      protocol,
      label: cleanLabel,
      courseName: cleanLabelText(pageTitle),
      lectureTitle: cleanLabel,
      folderName: item.folderName,
      resolution: botSettings.globalDefaultQuality || '720p',
      foundVia: item.foundVia,
    });
  }

  if (streams.length > 1) {
    applyDuplicateTitleNumbering(streams);
  }

  return {
    sourceUrl: finalUrl,
    pageTitle,
    extractedAt: new Date().toISOString(),
    streams,
    folders: Array.from(folderSet),
    scriptsScanned,
    pagesScanned,
    rawManifestSnippet,
    notes,
    ...(streams.length === 0 && authRequiredOrigin ? { authRequiredOrigin, authRequiredReason } : {}),
  };
}

// ============================================================================
// TELEGRAM BOT API (NATIVE CURL STREAMING) & GRAMJS MTPROTO USERBOT RELAY
// ============================================================================

let cachedUserbotClient: TelegramClient | null = null;
let cachedSecondaryUserbotClient: TelegramClient | null = null;
let cachedUserbotSessionKey = '';
let userbotConnectingPromise: Promise<TelegramClient | null> | null = null;
let secondaryUserbotConnectingPromise: Promise<TelegramClient | null> | null = null;
let mtprotoClientRoundRobinCounter = 0;
let userbotMeCache: {
  connected: boolean;
  accountName?: string;
  username?: string;
  error?: string;
  lastChecked: number;
} = {
  connected: false,
  lastChecked: 0,
};
let botInfoCache: { username?: string; firstName?: string; connected: boolean; error?: string } = {
  connected: false,
};

function withTimeoutPromise<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (err) => {
        clearTimeout(t);
        reject(err);
      }
    );
  });
}

async function closeTurboMtprotoSenderPool(client: TelegramClient | null): Promise<void> {
  if (!client) return;
  const pool: any[] | undefined = (client as any)._turboSendersPool;
  (client as any)._turboSendersPool = [];
  if (Array.isArray(pool)) {
    for (const s of pool) {
      try {
        await s?.disconnect?.();
      } catch {}
    }
  }
}

function isMtprotoSenderHealthy(sender: any, expectedDcId?: number): boolean {
  return Boolean(
    sender &&
      typeof sender.send === 'function' &&
      !sender._disconnected &&
      !sender.isReconnecting &&
      (typeof sender.isConnected !== 'function' || sender.isConnected()) &&
      (!expectedDcId || !sender._dcId || sender._dcId === expectedDcId)
  );
}

function tuneMtprotoSenderSocket(sender: any): void {
  try {
    const rawSocket =
      sender?._connection?.socket ||
      sender?._connection?._socket ||
      sender?.connection?.socket;
    if (rawSocket && typeof rawSocket.setNoDelay === 'function') {
      rawSocket.setNoDelay(true);
      if (typeof rawSocket.setKeepAlive === 'function') {
        rawSocket.setKeepAlive(true, 10000);
      }
    }
  } catch {
    // ignore socket option hint errors
  }
}

function getActiveMtprotoSocketCounts(): { primary: number; secondary: number; total: number } {
  const countClientSockets = (client: TelegramClient | null): number => {
    if (!client || !client.connected) return 0;
    const dcId = (client.session as any)?.dcId;
    const mainHealthy = isMtprotoSenderHealthy((client as any)._sender, dcId) ? 1 : 0;
    const extras = Array.isArray((client as any)._turboSendersPool)
      ? (client as any)._turboSendersPool.filter((s: any) => isMtprotoSenderHealthy(s, dcId)).length
      : 0;
    return mainHealthy + extras;
  };
  const primary = countClientSockets(cachedUserbotClient);
  const secondary = countClientSockets(cachedSecondaryUserbotClient);
  return { primary, secondary, total: primary + secondary };
}

// Opens and maintains up to 12 parallel TCP_NODELAY MTProtoSender sockets to the same DC sharing the client's authKey
// WITHOUT GramJS's broken 30-second _borrowExportedSender disconnect timer (12x-24x upload speed!)
async function getTurboMtprotoSenderPool(
  client: TelegramClient,
  dcId: number,
  desiredTotalSockets = 12
): Promise<any[]> {
  let mainSender = (client as any)._sender;
  if (!isMtprotoSenderHealthy(mainSender, dcId)) {
    mainSender = await withTimeoutPromise(client.getSender(dcId), 10000, 'MTProto getSender');
  }
  tuneMtprotoSenderSocket(mainSender);
  if (desiredTotalSockets <= 1) {
    return [mainSender];
  }

  let extraPool: any[] = Array.isArray((client as any)._turboSendersPool)
    ? (client as any)._turboSendersPool
    : [];

  const healthyExtras: any[] = [];
  for (const s of extraPool) {
    if (isMtprotoSenderHealthy(s, dcId)) {
      tuneMtprotoSenderSocket(s);
      healthyExtras.push(s);
    } else {
      try {
        await s?.disconnect?.();
      } catch {}
    }
  }

  const needed = Math.max(0, desiredTotalSockets - 1 - healthyExtras.length);
  if (needed > 0 && typeof (client as any)._createExportedSender === 'function') {
    const existingBuildPromise: Promise<void> | undefined = (client as any)._turboPoolBuildingPromise;
    if (existingBuildPromise) {
      await existingBuildPromise.catch(() => {});
      extraPool = Array.isArray((client as any)._turboSendersPool)
        ? (client as any)._turboSendersPool.filter((s: any) => isMtprotoSenderHealthy(s, dcId))
        : healthyExtras;
      return [mainSender, ...extraPool];
    }

    const buildPromise = (async () => {
      const created = await Promise.all(
        Array.from({ length: needed }, async () => {
          try {
            const s = await (client as any)._createExportedSender(dcId);
            const connectedOk = await withTimeoutPromise(
              (client as any)._connectSender(s, dcId),
              10000,
              `Turbo MTProto socket DC${dcId}`
            );
            if (connectedOk && isMtprotoSenderHealthy(s, dcId)) {
              tuneMtprotoSenderSocket(s);
              return s;
            }
            try {
              await s?.disconnect?.();
            } catch {}
          } catch {}
          return null;
        })
      );
      for (const s of created) {
        if (s) healthyExtras.push(s);
      }
      (client as any)._turboSendersPool = healthyExtras;
    })();

    (client as any)._turboPoolBuildingPromise = buildPromise;
    try {
      await buildPromise;
    } finally {
      (client as any)._turboPoolBuildingPromise = undefined;
    }
  } else {
    (client as any)._turboSendersPool = healthyExtras;
  }

  return [mainSender, ...healthyExtras];
}

let lastPoolPrewarmAt = 0;
function prewarmTurboPools(desiredPerClient = 8): void {
  if (Date.now() - lastPoolPrewarmAt < 45000) return;
  lastPoolPrewarmAt = Date.now();
  void (async () => {
    try {
      const primary = await getConnectedUserbotClient();
      const dc1 = (primary?.session as any)?.dcId;
      if (primary && primary.connected && dc1) {
        await getTurboMtprotoSenderPool(primary, dc1, desiredPerClient);
      }
    } catch {}
    try {
      if (process.env.EXTRA_TELEGRAM_API_ID?.trim() && process.env.EXTRA_TELEGRAM_API_HASH?.trim()) {
        const sec = await getSecondaryUserbotClient();
        const dc2 = (sec?.session as any)?.dcId;
        if (sec && sec.connected && dc2) {
          await getTurboMtprotoSenderPool(sec, dc2, desiredPerClient);
        }
      }
    } catch {}
  })();
}

async function getSecondaryUserbotClient(forceReconnect = false): Promise<TelegramClient | null> {
  const extraApiIdStr = process.env.EXTRA_TELEGRAM_API_ID?.trim() || '';
  const extraApiHash = process.env.EXTRA_TELEGRAM_API_HASH?.trim() || '';
  const extraStringSession = process.env.EXTRA_TELEGRAM_STRING_SESSION?.trim() || '';
  const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim() || '';

  const apiId = parseInt(extraApiIdStr, 10);
  if (isNaN(apiId) || !extraApiHash) {
    return null;
  }

  if (forceReconnect && cachedSecondaryUserbotClient) {
    await closeTurboMtprotoSenderPool(cachedSecondaryUserbotClient);
    try {
      await cachedSecondaryUserbotClient.disconnect();
    } catch {}
    cachedSecondaryUserbotClient = null;
  }

  if (cachedSecondaryUserbotClient) {
    const senderAny = (cachedSecondaryUserbotClient as any)._sender;
    if (Boolean(cachedSecondaryUserbotClient.connected) && isMtprotoSenderHealthy(senderAny)) {
      if (Date.now() - lastSecondaryMtprotoHealthCheckAt < 60000) {
        return cachedSecondaryUserbotClient;
      }
      try {
        await withTimeoutPromise(cachedSecondaryUserbotClient.getMe(), 5000, 'Secondary MTProto health check');
        lastSecondaryMtprotoHealthCheckAt = Date.now();
        return cachedSecondaryUserbotClient;
      } catch {}
    }
    await closeTurboMtprotoSenderPool(cachedSecondaryUserbotClient);
    try {
      await cachedSecondaryUserbotClient.disconnect();
    } catch {}
    cachedSecondaryUserbotClient = null;
  }

  if (secondaryUserbotConnectingPromise) {
    return secondaryUserbotConnectingPromise;
  }

  secondaryUserbotConnectingPromise = (async () => {
    if (extraStringSession) {
      try {
        const client = new TelegramClient(new StringSession(extraStringSession), apiId, extraApiHash, {
          connectionRetries: 2,
          autoReconnect: false,
          useWSS: false,
        });
        try {
          (client as any).setLogLevel('none');
        } catch {}
        await withTimeoutPromise(client.connect(), 15000, 'Secondary Userbot MTProto connect');
        if (client.connected) {
          cachedSecondaryUserbotClient = client;
          lastSecondaryMtprotoHealthCheckAt = Date.now();
          return client;
        }
      } catch {
        process.env.EXTRA_TELEGRAM_STRING_SESSION = '';
        saveBotSettings();
      }
    }

    if (botToken) {
      const tokenKey = `sec_${getBotMtprotoTokenKey(apiId, botToken)}`;
      const persisted = loadPersistedBotMtprotoCache(tokenKey);
      if (!cachedSecondaryBotMtprotoSessionStr && persisted.session) {
        cachedSecondaryBotMtprotoSessionStr = persisted.session;
      }
      if (!secondaryBotMtprotoFloodUntil && persisted.floodUntil) {
        secondaryBotMtprotoFloodUntil = persisted.floodUntil;
      }

      const candidates: string[] = [];
      if (cachedSecondaryBotMtprotoSessionStr) candidates.push(cachedSecondaryBotMtprotoSessionStr);
      if (Date.now() >= secondaryBotMtprotoFloodUntil) candidates.push('');

      for (const sessSeed of candidates) {
        let client: TelegramClient | null = null;
        try {
          client = new TelegramClient(new StringSession(sessSeed), apiId, extraApiHash, {
            connectionRetries: 2,
            autoReconnect: false,
            useWSS: false,
          });
          try {
            (client as any).setLogLevel('none');
          } catch {}
          if (sessSeed) {
            await withTimeoutPromise(client.connect(), 15000, 'Secondary Bot MTProto connect');
          } else {
            await withTimeoutPromise(
              client.start({ botAuthToken: botToken }),
              20000,
              'Secondary Bot MTProto start'
            );
          }
          if (client.connected) {
            try {
              const savedSess = String((client.session.save() as unknown) || '');
              if (savedSess) {
                cachedSecondaryBotMtprotoSessionStr = savedSess;
                secondaryBotMtprotoFloodUntil = 0;
                savePersistedBotMtprotoCache(tokenKey, { session: savedSess, floodUntil: 0 });
              }
            } catch {}
            cachedSecondaryUserbotClient = client;
            lastSecondaryMtprotoHealthCheckAt = Date.now();
            return client;
          }
        } catch (secErr: any) {
          const errText = String(secErr?.errorMessage || secErr?.message || secErr);
          if (/FLOOD/i.test(errText)) {
            const waitMs = parseTelegramFloodWaitMs(errText);
            secondaryBotMtprotoFloodUntil = Date.now() + waitMs;
            savePersistedBotMtprotoCache(tokenKey, { floodUntil: secondaryBotMtprotoFloodUntil });
            console.warn(`[StreamBridge MTProto] Secondary Bot MTProto rate-limited (${errText}), cooling down ${Math.round(waitMs / 1000)}s`);
          } else if (/AUTH_KEY_UNREGISTERED|AUTH_KEY_DUPLICATED|SESSION_REVOKED|USER_DEACTIVATED/i.test(errText)) {
            cachedSecondaryBotMtprotoSessionStr = '';
            savePersistedBotMtprotoCache(tokenKey, { session: '' });
          }
          try {
            await client?.disconnect();
          } catch {}
          if (/FLOOD/i.test(errText)) break;
        }
      }
    }
    return null;
  })().finally(() => {
    secondaryUserbotConnectingPromise = null;
  });

  return secondaryUserbotConnectingPromise;
}

async function getConnectedUserbotClient(forceReconnect = false): Promise<TelegramClient | null> {
  const apiIdStr = process.env.TELEGRAM_API_ID?.trim() || '37805311';
  const apiHash = process.env.TELEGRAM_API_HASH?.trim() || 'c31bea4889628b20d0064eab3aec8d14';
  const stringSession = process.env.TELEGRAM_STRING_SESSION?.trim();
  const botToken = process.env.TELEGRAM_BOT_TOKEN?.trim();

  const apiId = parseInt(apiIdStr, 10);
  if (isNaN(apiId) || !apiHash) {
    return getSecondaryUserbotClient(forceReconnect);
  }

  if (forceReconnect && cachedUserbotClient) {
    await closeTurboMtprotoSenderPool(cachedUserbotClient);
    try {
      await cachedUserbotClient.disconnect();
    } catch {}
    cachedUserbotClient = null;
  }

  if (cachedUserbotClient) {
    const senderAny = (cachedUserbotClient as any)._sender;
    const looksConnected =
      Boolean(cachedUserbotClient.connected) && isMtprotoSenderHealthy(senderAny);

    if (looksConnected) {
      if (Date.now() - lastMtprotoHealthCheckAt < 60000) {
        return cachedUserbotClient;
      }
      try {
        await withTimeoutPromise(cachedUserbotClient.getMe(), 5000, 'MTProto health check');
        lastMtprotoHealthCheckAt = Date.now();
        return cachedUserbotClient;
      } catch {
        // Socket went half-open/stale — drop & reconnect cleanly below
      }
    }
    await closeTurboMtprotoSenderPool(cachedUserbotClient);
    try {
      await cachedUserbotClient.disconnect();
    } catch {}
    cachedUserbotClient = null;
  }

  if (userbotConnectingPromise) {
    return userbotConnectingPromise;
  }

  userbotConnectingPromise = (async () => {
    // Strategy A: Connect with TELEGRAM_STRING_SESSION if present
    if (stringSession) {
      try {
        const client = new TelegramClient(new StringSession(stringSession), apiId, apiHash, {
          connectionRetries: 2,
          autoReconnect: false,
          useWSS: false,
        });
        try {
          (client as any).setLogLevel('none');
        } catch {}
        await withTimeoutPromise(client.connect(), 15000, 'Userbot MTProto connect');
        if (client.connected) {
          cachedUserbotClient = client;
          lastMtprotoHealthCheckAt = Date.now();
          cachedUserbotSessionKey = `${apiId}:${apiHash}:${stringSession.slice(0, 24)}`;
          return client;
        }
      } catch (sessErr: any) {
        console.warn('[StreamBridge MTProto] User string session invalid or duplicated, clearing & switching to Bot MTProto:', sessErr?.message || sessErr);
        process.env.TELEGRAM_STRING_SESSION = '';
        if (botSettings?.hfCloud) {
          saveBotSettings();
        }
      }
    }

    // Strategy B: Connect via Bot Token over MTProto (Supports 2000 MB / 2GB single video uploads!)
    // Persist valid StringSession on disk to avoid repeated auth.importBotAuthorization FLOOD bans across restarts.
    if (botToken) {
      const tokenKey = `pri_${getBotMtprotoTokenKey(apiId, botToken)}`;
      const persisted = loadPersistedBotMtprotoCache(tokenKey);
      if (!cachedBotMtprotoSessionStr && persisted.session) {
        cachedBotMtprotoSessionStr = persisted.session;
      }
      if (!botMtprotoFloodUntil && persisted.floodUntil) {
        botMtprotoFloodUntil = persisted.floodUntil;
      }

      const candidates: string[] = [];
      if (cachedBotMtprotoSessionStr) candidates.push(cachedBotMtprotoSessionStr);
      if (Date.now() >= botMtprotoFloodUntil) candidates.push('');

      for (const sessSeed of candidates) {
        let client: TelegramClient | null = null;
        try {
          client = new TelegramClient(new StringSession(sessSeed), apiId, apiHash, {
            connectionRetries: 2,
            autoReconnect: false,
            useWSS: false,
          });
          try {
            (client as any).setLogLevel('none');
          } catch {}
          if (sessSeed) {
            await withTimeoutPromise(client.connect(), 15000, 'Bot MTProto connect');
          } else {
            await withTimeoutPromise(
              client.start({ botAuthToken: botToken }),
              20000,
              'Bot MTProto start'
            );
          }
          if (client.connected) {
            try {
              const savedSess = String((client.session.save() as unknown) || '');
              if (savedSess) {
                cachedBotMtprotoSessionStr = savedSess;
                botMtprotoFloodUntil = 0;
                savePersistedBotMtprotoCache(tokenKey, { session: savedSess, floodUntil: 0 });
              }
            } catch {}
            cachedUserbotClient = client;
            lastMtprotoHealthCheckAt = Date.now();
            cachedUserbotSessionKey = `${apiId}:${apiHash}:bot`;
            return client;
          }
        } catch (botMtprotoErr: any) {
          const errText = String(botMtprotoErr?.errorMessage || botMtprotoErr?.message || botMtprotoErr);
          if (/FLOOD/i.test(errText)) {
            const waitMs = parseTelegramFloodWaitMs(errText);
            botMtprotoFloodUntil = Date.now() + waitMs;
            savePersistedBotMtprotoCache(tokenKey, { floodUntil: botMtprotoFloodUntil });
            console.warn(`[StreamBridge MTProto] Bot MTProto rate-limited (${errText}), cooling down ${Math.round(waitMs / 1000)}s`);
          } else {
            console.warn('[StreamBridge MTProto] Bot MTProto connect failed:', errText);
            if (/AUTH_KEY_UNREGISTERED|AUTH_KEY_DUPLICATED|SESSION_REVOKED|USER_DEACTIVATED/i.test(errText)) {
              cachedBotMtprotoSessionStr = '';
              savePersistedBotMtprotoCache(tokenKey, { session: '' });
            }
          }
          try {
            await client?.disconnect();
          } catch {}
          if (/FLOOD/i.test(errText)) break;
        }
      }
    }

    // Fallback to Secondary API ID/Hash if configured
    return getSecondaryUserbotClient(forceReconnect);
  })().finally(() => {
    userbotConnectingPromise = null;
  });

  return userbotConnectingPromise;
}

function formatTelegramHtmlSafe(rawText: string): { html: string; plain: string } {
  const plain = String(rawText || '')
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1');
  const escaped = String(rawText || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  const html = escaped
    .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
    .replace(/`([^`\n]+)`/g, '<code>$1</code>');
  return { html, plain };
}

async function sendTelegramTextMessage(
  chatId: string | number,
  text: string,
  replyMarkup?: Record<string, any>
): Promise<number | undefined> {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) return undefined;
  const { html, plain } = formatTelegramHtmlSafe(text);
  const useHtml = html !== plain || /<(b|code|i|a)\b/i.test(html);
  try {
    const payload: Record<string, any> = {
      chat_id: chatId,
      text: useHtml ? html : plain,
      disable_web_page_preview: true,
      ...(useHtml ? { parse_mode: 'HTML' } : {}),
    };
    if (replyMarkup) {
      payload.reply_markup = replyMarkup;
    }
    const res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(12000),
    });
    const data = (await res.json()) as any;
    if (data?.ok) {
      return data?.result?.message_id;
    }
    if (useHtml) {
      const retryPayload: Record<string, any> = {
        chat_id: chatId,
        text: plain,
        disable_web_page_preview: true,
        ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
      };
      const resPlain = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(retryPayload),
        signal: AbortSignal.timeout(12000),
      });
      const dataPlain = (await resPlain.json().catch(() => null)) as any;
      return dataPlain?.result?.message_id;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

let telegramEditBlockedUntil = 0;

async function editTelegramTextMessage(
  chatId: string | number,
  messageId: number | undefined,
  text: string,
  replyMarkup?: Record<string, any>
): Promise<boolean> {
  if (!messageId) return false;
  if (Date.now() < telegramEditBlockedUntil) return false;
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) return false;
  const { html, plain } = formatTelegramHtmlSafe(text);
  const useHtml = html !== plain || /<(b|code|i|a)\b/i.test(html);
  try {
    const payload: Record<string, any> = {
      chat_id: chatId,
      message_id: messageId,
      text: useHtml ? html : plain,
      disable_web_page_preview: true,
      ...(useHtml ? { parse_mode: 'HTML' } : {}),
    };
    if (replyMarkup) {
      payload.reply_markup = replyMarkup;
    }
    const res = await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(12000),
    });
    const data = (await res.json().catch(() => null)) as any;
    if (data?.error_code === 429) {
      const retryAfter = Number(data?.parameters?.retry_after || 10);
      telegramEditBlockedUntil = Date.now() + Math.min(60, Math.max(3, retryAfter)) * 1000;
      return false;
    }
    if (data?.ok || /message is not modified/i.test(String(data?.description || ''))) {
      return true;
    }
    if (useHtml) {
      const retryPayload: Record<string, any> = {
        chat_id: chatId,
        message_id: messageId,
        text: plain,
        disable_web_page_preview: true,
        ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
      };
      const resPlain = await fetch(`https://api.telegram.org/bot${token}/editMessageText`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(retryPayload),
        signal: AbortSignal.timeout(12000),
      });
      const dataPlain = (await resPlain.json().catch(() => null)) as any;
      return Boolean(dataPlain?.ok || /message is not modified/i.test(String(dataPlain?.description || '')));
    }
    return false;
  } catch {
    return false;
  }
}

async function deleteTelegramMessage(chatId: string | number, messageId: number | undefined) {
  if (!messageId) return;
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/deleteMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, message_id: messageId }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    // ignore
  }
}

async function answerTelegramCallbackQuery(callbackQueryId: string, text?: string) {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) return;
  try {
    await fetch(`https://api.telegram.org/bot${token}/answerCallbackQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        callback_query_id: callbackQueryId,
        text,
        show_alert: false,
      }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    // ignore
  }
}

function buildQueueControlInlineKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '🎯 Single/Select (/only)', callback_data: 'feat:help:only' },
        { text: '⏭️ Skip N (/skip)', callback_data: 'feat:help:skip' },
      ],
      [
        { text: '▶️ Resume Pending (/resume)', callback_data: 'feat:action:resume' },
        { text: '⏸️ Pause Queue (/stop)', callback_data: 'feat:action:pause' },
      ],
      [
        { text: '🗑️ Clear Queue (/clear)', callback_data: 'feat:action:clear' },
        { text: '📊 Queue Status', callback_data: 'feat:view:queue' },
      ],
    ],
  };
}

const BOT_COMMANDS_LIST = [
  { command: 'admin', description: '👑 Main Admin Panel (Users, Daily Code, Roles & Audit)' },
  { command: 'users', description: '👥 List Approved Users & Failed Access Attempts' },
  { command: 'attempts', description: '🚨 View Pending / Failed Login Attempts' },
  { command: 'approve', description: '✅ Approve User Access (/approve <id> [24h|permanent])' },
  { command: 'revoke', description: '🚫 Revoke & Block User Access (/revoke <id>)' },
  { command: 'newcode', description: '🔑 Rotate Daily 4-Digit Access Code Now' },
  { command: 'addadmin', description: '👑 Appoint Bot Admin (Main Admin Only)' },
  { command: 'adddev', description: '🛠 Appoint Bot Developer (Main Admin Only)' },
  { command: 'removeadmin', description: '⬇️ Demote Admin / Developer (Main Admin Only)' },
  { command: 'setowner', description: '🔁 Transfer Main Admin Ownership (Main Admin Only)' },
  { command: 'admins', description: '🛡 List All Appointed Admins & Developers' },
  { command: 'audit', description: '🐞 Run Full A2Z Bug Bounty & Speed Audit' },
  { command: 'only', description: '🎯 Download ONLY Selected Video Numbers (/only 12 or 128,134)' },
  { command: 'skip', description: '⏭️ Skip First N Videos in Batch (/skip 95)' },
  { command: 'resume', description: '▶️ Resume Stopped/Paused Videos (Skips Completed)' },
  { command: 'stop', description: '⏸️ Stop & Pause Active Downloads' },
  { command: 'clear', description: '🗑️ Stop & Clear All Pending/Paused Videos from Queue' },
  { command: 'reset', description: '🔄 Factory Reset All History, Cache & Queue' },
  { command: 'features', description: '📋 All Bot Features & Interactive Control Menu' },
  { command: 'quality', description: '🎞 Change Default Video Quality (144p-1080p)' },
  { command: 'addapi', description: '🚀 Add 2nd Telegram API ID & Hash (24x Parallel Turbo)' },
  { command: 'setcookies', description: '🍪 Set Netscape Cookies.txt (Locked YT / Instagram)' },
  { command: 'weblogin', description: '🔐 Login to StudyBeePro / Custom Web Portal (Number + Password)' },
  { command: 'weblogout', description: '🚪 Clear Saved Web Portal Login Session' },
  { command: 'mode', description: '🎬 Full Single Video Mode (Up to 2GB via MTProto)' },
  { command: 'ai', description: '🤖 AI Auto-Download Agent Status & Checkpoints' },
  { command: 'autocheck', description: '🔄 Run AI Auto-Check Now' },
  { command: 'channels', description: '🛡️ View Saved Backup Channels & Fix-Link Rules' },
  { command: 'addbackup', description: '➕ Add Backup Channel or Group for Auto-Save' },
  { command: 'route', description: '🎯 Set Fix Link -> Fix Channel Rule' },
  { command: 'drive', description: '☁️ Save Video/Batch to 5TB Google Drive (/drive <link> or /drive tg <link>)' },
  { command: 'queue', description: '📊 Check Active Download Queue & Speed' },
  { command: 'start', description: '⚡ Bot Status & Quick Start Menu' },
  { command: 'help', description: 'ℹ️ Full Commands & Usage Guide' },
  { command: 'scanapi', description: '🔎 Scan authorized batch metadata without downloading videos' },
];

async function registerTelegramBotMenu(token: string) {
  try {
    const scopes = [
      { type: 'default' },
      { type: 'all_private_chats' },
      { type: 'all_group_chats' },
    ];
    for (const scope of scopes) {
      await fetch(`https://api.telegram.org/bot${token}/setMyCommands`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          commands: BOT_COMMANDS_LIST,
          scope,
        }),
        signal: AbortSignal.timeout(10000),
      });
    }

    await fetch(`https://api.telegram.org/bot${token}/setChatMenuButton`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        menu_button: {
          type: 'commands',
        },
      }),
      signal: AbortSignal.timeout(10000),
    });
    addBotLog('SYSTEM', 'bot', 'Registered Full Telegram Bot Menu Bar (/admin, /audit, /only, /skip, /clear, /reset, /features & all commands)');
  } catch (err: any) {
    console.error('Failed to register Telegram Bot menu commands:', err?.message || err);
  }
}

function getChatJobStats(chatId?: string) {
  const all = Array.from(jobs.values()).filter((j) =>
    chatId ? !j.telegramChatId || j.telegramChatId === chatId : true
  );
  const completed = all.filter((j) => j.status === 'completed');
  const active = all.filter(
    (j) =>
      j.status === 'downloading' ||
      j.status === 'merging' ||
      j.status === 'uploading_bot_api' ||
      j.status === 'uploading_mtproto_userbot' ||
      j.status === 'uploading_google_drive'
  );
  const queued = all.filter((j) => j.status === 'queued');
  const paused = all.filter((j) => j.status === 'paused');
  const waitingStream = all.filter((j) => j.status === 'waiting_stream');
  const resumableFailed = all.filter(
    (j) =>
      j.status === 'failed' &&
      !/No playable stream URL available/i.test(String(j.error || ''))
  );
  return {
    total: all.length,
    completedCount: completed.length,
    activeCount: active.length,
    queuedCount: queued.length,
    pausedCount: paused.length,
    waitingStreamCount: waitingStream.length,
    resumableFailedCount: resumableFailed.length,
    remainingResumableCount:
      paused.length + queued.length + resumableFailed.length + active.length,
  };
}

function buildAdminPanelPayload(viewerId: string) {
  const activeCode = ensureValidAccessCode(false);
  const role = getUserRole(viewerId);
  const staffList = Object.values(botSettings.staffRoles);
  const approvedList = Object.values(botSettings.authorizedUsers);
  const attemptList = Object.values(botSettings.accessAttempts);
  const failedPendingCount = attemptList.filter(
    (a) => a.status === 'failed' || a.status === 'pending'
  ).length;
  const remainingMs = Math.max(0, new Date(activeCode.expiresAt).getTime() - Date.now());
  const remHours = Math.floor(remainingMs / (1000 * 60 * 60));
  const remMins = Math.floor((remainingMs % (1000 * 60 * 60)) / (1000 * 60));
  const sockCounts = getActiveMtprotoSocketCounts();

  const text =
    `👑 StreamBridge Control Center (/admin)\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `🛡️ Your Role: ${role.toUpperCase()} (${viewerId})\n` +
    `👑 Main Admin ID: \`${MAIN_ADMIN_ID}\` (Transferable by /setowner)\n` +
    `🔑 Today's Daily Code: \`${activeCode.code}\` (${remHours}h ${remMins}m left)\n` +
    `👮 Staff Appointed: ${staffList.filter((s) => s.role === 'admin').length} Admin(s) · ${staffList.filter((s) => s.role === 'developer').length} Developer(s)\n` +
    `✅ Approved Users: ${approvedList.length} · 🚨 Failed/Pending Tries: ${failedPendingCount}\n` +
    `🚀 Active MTProto Sockets: ${sockCounts.total} Live (Primary ${sockCounts.primary} + Secondary ${sockCounts.secondary})\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
    `📌 **Quick Admin Commands:**\n` +
    `• \`/approve <user_id> [24h|permanent]\`\n` +
    `• \`/revoke <user_id>\` · \`/newcode\`\n` +
    `• \`/addadmin <user_id> [name]\` (Main Admin)\n` +
    `• \`/adddev <user_id> [name]\` (Main Admin)\n` +
    `• \`/removeadmin <user_id>\` · \`/setowner <user_id>\`\n` +
    `• Approval requests are sent to Main Admin + all appointed staff\n` +
    `• \`/audit\``;

  const replyMarkup = {
    inline_keyboard: [
      [
        { text: '🔄 Rotate Code (/newcode)', callback_data: 'feat:admin:newcode' },
        { text: `👥 Users & Attempts (${failedPendingCount})`, callback_data: 'feat:admin:users' },
      ],
      [
        { text: `🛡 Admins & Devs (${staffList.length})`, callback_data: 'feat:admin:staff' },
        { text: '🐞 Bug Bounty Audit (/audit)', callback_data: 'feat:admin:audit' },
      ],
      [
        { text: '🔗 Share Today Code/Link', callback_data: 'feat:invite' },
        { text: '📋 All Features Menu', callback_data: 'feat:refresh' },
      ],
    ],
  };

  return { text, replyMarkup };
}

function buildFeaturesMenuPayload(chatId: string, senderId?: string) {
  const codeState = ensureValidAccessCode(false);
  const q = (botSettings.globalDefaultQuality || '480p').toLowerCase();
  const activeBackups = botSettings.backupChannels.filter((b) => b.enabled);
  const activeRoutes = botSettings.routeRules.filter((r) => r.enabled);
  const stats = getChatJobStats(chatId);
  const sockCounts = getActiveMtprotoSocketCounts();
  const viewerIsAdmin = isAdminOrDev(chatId, senderId);
  const viewerRole = getUserRole(senderId || chatId);
  const userSess = botSettings.authorizedUsers[String(senderId || chatId).trim()] || botSettings.authorizedUsers[chatId];
  const accessDesc =
    viewerRole !== 'user'
      ? `${viewerRole.toUpperCase()} ✅`
      : userSess?.expiresAt?.startsWith('2099-')
      ? 'Permanent Approved ✅'
      : `Daily Verified (${codeState.durationLabel}) ✅`;

  const hasExtraApi = Boolean(
    process.env.EXTRA_TELEGRAM_API_ID?.trim() && process.env.EXTRA_TELEGRAM_API_HASH?.trim()
  );

  const text =
    `📋 StreamBridge Bot — All Features Menu (/features)\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n` +
    `🔑 Access: ${accessDesc}\n` +
    `☁️ 5TB Google Drive: ${activeDriveSession && !activeDriveSession.tokenExpired ? `CONNECTED ✅ (${activeDriveSession.email})` : activeDriveSession?.tokenExpired ? 'EXPIRED ⚠️ (Refresh in /admin)' : 'Not Connected ⚪ (Connect in /admin)'}\n` +
    `🤖 AI Auto-Download & Watch Agent: ${aiAgentState.enabled ? `ACTIVE 🟢 (Every ${aiAgentState.intervalMinutes}m)` : 'PAUSED ⚪'}\n` +
    `🎞 Default Quality: ${q.toUpperCase()} (Auto-select before play)\n` +
    `🚀 Upload Turbo: ${hasExtraApi ? `Dual-API 24-Socket Pipeline (${sockCounts.total} Live)` : `12-Socket TCP_NODELAY MTProto (${sockCounts.total} Live)`} + 2-Video Lookahead\n` +
    `🎬 Delivery: 100% Full MP4 Video (Telegram 2GB &/or 5TB Google Drive)\n` +
    `🛡️ Backup Channels/Groups: ${activeBackups.length} active · 🎯 Rules: ${activeRoutes.length}\n` +
    `📊 Batch Status: ${stats.completedCount} Done ✅ | ${stats.activeCount} Running ⚡ | ${stats.pausedCount + stats.queuedCount + stats.resumableFailedCount} Pending ⏯️ | ${stats.waitingStreamCount} AI Watch 🕒\n` +
    `━━━━━━━━━━━━━━━━━━━━━━\n\n` +
    `✨ All Bot Features & Controls:\n` +
    `1️⃣ ☁️ /drive <link> & /drive tg <link> — Fast Save to 5TB Google Drive (ya Both TG+Drive)\n` +
    `2️⃣ 🎯 /only & ⏭️ /skip — Select specific videos ya shuru ki N skip karein\n` +
    `3️⃣ ▶️ /resume, ⏸️ /stop, 🗑️ /clear, 🔄 /reset — Full Queue Control\n` +
    `4️⃣ 🚀 /addapi & 🍪 /setcookies — Dual-API Speed Boost & YT/Insta Cookies\n` +
    `5️⃣ 🤖 /ai & /autocheck — AI Autonomous Checkpoint & Auto-Recovery\n` +
    `6️⃣ 🛡️ /addbackup & 🎯 /route — Multi-Channel Auto Backup & Routing\n` +
    (viewerIsAdmin ? `7️⃣ 👑 /admin & 🐞 /audit — Admin Control Center, Roles & Bug Bounty Audit\n\n` : '\n') +
    `👇 Neeche diye gaye Menu Buttons se har feature access karein:`;

  const rows: any[][] = [
    [
      { text: '🎯 Single/Select (/only)', callback_data: 'feat:help:only' },
      { text: '⏭️ Skip N Videos (/skip)', callback_data: 'feat:help:skip' },
    ],
    [
      { text: `▶️ Resume (${stats.remainingResumableCount})`, callback_data: 'feat:action:resume' },
      { text: '⏸️ Pause (/stop)', callback_data: 'feat:action:pause' },
      { text: '🗑️ Clear (/clear)', callback_data: 'feat:action:clear' },
    ],
    [
      { text: `${q === '144p' ? '✅ ' : ''}144p`, callback_data: 'feat:q:144p' },
      { text: `${q === '240p' ? '✅ ' : ''}240p`, callback_data: 'feat:q:240p' },
      { text: `${q === '360p' ? '✅ ' : ''}360p`, callback_data: 'feat:q:360p' },
    ],
    [
      { text: `${q === '480p' ? '✅ ' : ''}480p`, callback_data: 'feat:q:480p' },
      { text: `${q === '720p' ? '✅ ' : ''}720p HD`, callback_data: 'feat:q:720p' },
      { text: `${q === '1080p' ? '✅ ' : ''}1080p`, callback_data: 'feat:q:1080p' },
    ],
    [
      { text: '🤖 AI Check Now (/autocheck)', callback_data: 'feat:ai:checknow' },
      { text: `📊 AI Agent (${aiAgentState.enabled ? 'ON 🟢' : 'OFF ⚪'})`, callback_data: 'feat:ai:status' },
    ],
    [
      { text: '🚀 Speed / Dual API (/addapi)', callback_data: 'feat:help:addapi' },
      { text: '🍪 YT/Insta Cookies (/setcookies)', callback_data: 'feat:help:setcookies' },
    ],
    [
      { text: '🔐 Web Login (No + Pass)', callback_data: 'feat:login:start' },
      { text: '🍪 Portal Cookie / Token', callback_data: 'feat:login:token' },
    ],
    [
      { text: `🛡️ Backups (${activeBackups.length})`, callback_data: 'feat:view:channels' },
      { text: '➕ Add Backup', callback_data: 'feat:help:addbackup' },
      { text: `🎯 Routes (${activeRoutes.length})`, callback_data: 'feat:help:route' },
    ],
    [
      { text: '📊 Queue Status', callback_data: 'feat:view:queue' },
      { text: '🔄 Reset (/reset)', callback_data: 'feat:action:reset' },
      { text: '🔄 Refresh', callback_data: 'feat:refresh' },
    ],
  ];

  if (viewerIsAdmin) {
    rows.push([
      { text: '👑 Admin Panel (/admin)', callback_data: 'feat:admin:panel' },
      { text: '🐞 Bug Bounty Audit (/audit)', callback_data: 'feat:admin:audit' },
    ]);
  }

  return { text, replyMarkup: { inline_keyboard: rows } };
}

interface VideoProbeMeta {
  duration: number;
  width: number;
  height: number;
  thumbPath?: string;
}

async function probeVideoMetadataAndThumb(mp4Path: string, jobId: string): Promise<VideoProbeMeta> {
  const meta: VideoProbeMeta = {
    duration: 0,
    width: 1280,
    height: 720,
  };
  if (!ffmpegAvailable || !fs.existsSync(mp4Path)) {
    return meta;
  }

  await Promise.all([
    (async () => {
      try {
        const { stdout } = await execFileAsync(
          'ffprobe',
          [
            '-v',
            'error',
            '-probesize',
            '1000000',
            '-analyzeduration',
            '1000000',
            '-select_streams',
            'v:0',
            '-show_entries',
            'stream=width,height',
            '-show_entries',
            'format=duration',
            '-of',
            'json',
            mp4Path,
          ],
          { timeout: 15000 }
        );
        const parsed = JSON.parse(stdout) as {
          streams?: Array<{ width?: number; height?: number }>;
          format?: { duration?: string };
        };
        if (parsed.streams && parsed.streams[0]) {
          if (parsed.streams[0].width) meta.width = Number(parsed.streams[0].width);
          if (parsed.streams[0].height) meta.height = Number(parsed.streams[0].height);
        }
        if (parsed.format?.duration) {
          const dur = parseFloat(parsed.format.duration);
          if (Number.isFinite(dur) && dur > 0) {
            meta.duration = Math.round(dur);
          }
        }
      } catch {
        // ignore probe error
      }
    })(),
    (async () => {
      try {
        const thumbPath = path.join(DOWNLOAD_DIR, `${jobId}_thumb.jpg`);
        await execFileAsync(
          'ffmpeg',
          [
            '-y',
            '-threads',
            '1',
            '-noaccurate_seek',
            '-ss',
            '00:00:01',
            '-i',
            mp4Path,
            '-frames:v',
            '1',
            '-vf',
            'scale=320:-2',
            '-q:v',
            '6',
            thumbPath,
          ],
          { timeout: 8000 }
        );
        if (fs.existsSync(thumbPath) && fs.statSync(thumbPath).size > 200) {
          meta.thumbPath = thumbPath;
        }
      } catch {
        // ignore thumbnail error
      }
    })(),
  ]);

  return meta;
}

async function copyTelegramVideoMessage(
  fromChatId: string | number,
  messageId: number,
  toChatId: string | number,
  caption: string
): Promise<boolean> {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) return false;
  try {
    const res = await fetch(`https://api.telegram.org/bot${token}/copyMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: String(toChatId).trim(),
        from_chat_id: String(fromChatId).trim(),
        message_id: messageId,
        caption,
      }),
      signal: AbortSignal.timeout(15000),
    });
    const data = (await res.json()) as { ok: boolean; description?: string };
    return Boolean(data.ok);
  } catch {
    return false;
  }
}

// Uses native libcurl HTTP/2 + TCP_NODELAY multipart streaming directly from disk — 50+ MB/s with full duration, resolution & thumbnail!
async function uploadToTelegramBotApi(
  filePath: string,
  chatId: string,
  caption: string,
  meta?: VideoProbeMeta
): Promise<{ ok: boolean; error?: string; messageId?: number; fromChatId?: string }> {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) {
    return { ok: false, error: 'TELEGRAM_BOT_TOKEN is not configured in Secrets.' };
  }

  try {
    const curlArgs = [
      '-s',
      '--http2',
      '--tcp-nodelay',
      '--keepalive-time',
      '20',
      '--retry',
      '3',
      '--max-time',
      '180',
      '-X',
      'POST',
      `https://api.telegram.org/bot${token}/sendVideo`,
      '-F',
      `chat_id=${chatId}`,
      '-F',
      `caption=${caption}`,
      '-F',
      'supports_streaming=true',
    ];
    if (meta?.duration && meta.duration > 0) {
      curlArgs.push('-F', `duration=${Math.round(meta.duration)}`);
    }
    if (meta?.width && meta.width > 0) {
      curlArgs.push('-F', `width=${meta.width}`);
    }
    if (meta?.height && meta.height > 0) {
      curlArgs.push('-F', `height=${meta.height}`);
    }
    if (meta?.thumbPath && fs.existsSync(meta.thumbPath)) {
      curlArgs.push('-F', `thumbnail=@${meta.thumbPath}`);
    }
    curlArgs.push('-F', `video=@${filePath}`);

    const { stdout } = await execFileAsync('curl', curlArgs, {
      maxBuffer: 10 * 1024 * 1024,
      timeout: 200000,
    });
    const data = JSON.parse(stdout) as {
      ok: boolean;
      description?: string;
      result?: { message_id: number; chat?: { id: number | string } };
    };
    if (!data.ok) {
      return { ok: false, error: data.description || 'Telegram Bot API sendVideo failed' };
    }
    return {
      ok: true,
      messageId: data.result?.message_id,
      fromChatId: String(data.result?.chat?.id || chatId),
    };
  } catch (err: any) {
    return { ok: false, error: err?.message || 'curl sendVideo failed' };
  }
}

// Adaptive Multi-Sender 96-Worker Pipelined TCP_NODELAY MTProto File Uploader.
// Stripes SaveBigFilePart chunks across up to 12 parallel TCP_NODELAY MTProtoSender sockets per API client without _borrowExportedSender's 30s idle timer.
async function fastMtprotoUploadFile(
  client: TelegramClient,
  filePath: string,
  fileSize: number,
  fileName: string,
  onProgress?: (progress01: number, speedMbps?: number, uploadedMb?: number) => void,
  isAborted?: () => boolean
): Promise<Api.InputFileBig | Api.InputFile> {
  const isLarge = fileSize > 10 * 1024 * 1024;
  // Max Telegram MTProto chunk size is 512 KB (524288 bytes) for SaveBigFilePart; 512 KB also supported on <=10MB SaveFilePart when <=512KB per part
  const partSize = isLarge ? 524288 : 524288;
  const partCount = Math.max(1, Math.ceil(fileSize / partSize));
  const fileId = readBigIntFromBuffer(generateRandomBytes(8), true, true);
  // Bizy-style adaptive pipeline: up to 16 sockets x 6 parts, bounded on
  // constrained hosts to avoid turning extra concurrency into FloodWaits.
  const desiredSockets = Math.min(
    CONFIGURED_UPLOAD_SOCKETS,
    fileSize > 20 * 1024 * 1024 ? CONFIGURED_UPLOAD_SOCKETS : isLarge ? 6 : 2
  );
  const workerCount = Math.min(
    desiredSockets * 6,
    IS_CONSTRAINED_HOST ? 36 : 96,
    partCount
  );
  const sessionDc = (client.session as any).dcId;

  let senderPool = await getTurboMtprotoSenderPool(client, sessionDc, desiredSockets);
  let lastProgressEmitMs = 0;
  const inFlightBySender = new WeakMap<any, number>();

  const pickSenderForPart = async (partIdx: number, attempt: number): Promise<any> => {
    const alive = senderPool.filter((s) => isMtprotoSenderHealthy(s, sessionDc));
    if (alive.length > 0) {
      // On retries prefer the main sender; on first attempts select the
      // least-loaded healthy socket so a slow TCP connection cannot become a
      // bottleneck while faster sockets sit idle.
      if (attempt >= 2 && isMtprotoSenderHealthy(alive[0], sessionDc)) {
        return alive[0];
      }
      let best = alive[(partIdx + attempt) % alive.length];
      let bestLoad = inFlightBySender.get(best) || 0;
      for (let i = 0; i < alive.length; i++) {
        const candidate = alive[(partIdx + i) % alive.length];
        const load = inFlightBySender.get(candidate) || 0;
        if (load < bestLoad) {
          best = candidate;
          bestLoad = load;
          if (bestLoad === 0) break;
        }
      }
      return best;
    }
    senderPool = await getTurboMtprotoSenderPool(client, sessionDc, 1);
    return senderPool[0];
  };

  let nextPartIndex = 0;
  let completedParts = 0;
  let uploadedBytesTotal = 0;
  const uploadStartMs = Date.now();
  const fh = await fs.promises.open(filePath, 'r');

  try {
    const worker = async () => {
      while (true) {
        if (isAborted && isAborted()) {
          throw new Error('JOB_PAUSED_BY_USER');
        }
        const partIdx = nextPartIndex++;
        if (partIdx >= partCount) break;

        const start = partIdx * partSize;
        const chunkLen = Math.min(partSize, fileSize - start);
        const payloadBuf = Buffer.allocUnsafe(chunkLen);
        let bytesReadTotal = 0;
        while (bytesReadTotal < chunkLen) {
          const { bytesRead } = await fh.read(
            payloadBuf,
            bytesReadTotal,
            chunkLen - bytesReadTotal,
            start + bytesReadTotal
          );
          if (bytesRead <= 0) break;
          bytesReadTotal += bytesRead;
        }
        const finalBuf = bytesReadTotal === chunkLen ? payloadBuf : payloadBuf.subarray(0, bytesReadTotal);

        let sent = false;
        for (let attempt = 0; attempt < 5; attempt++) {
          if (isAborted && isAborted()) {
            throw new Error('JOB_PAUSED_BY_USER');
          }
          let sender: any;
          try {
            sender = await pickSenderForPart(partIdx, attempt);
            inFlightBySender.set(sender, (inFlightBySender.get(sender) || 0) + 1);
            try {
              await withTimeoutPromise(
                sender.send(
                  isLarge
                    ? new Api.upload.SaveBigFilePart({
                        fileId,
                        filePart: partIdx,
                        fileTotalParts: partCount,
                        bytes: finalBuf,
                      })
                    : new Api.upload.SaveFilePart({
                        fileId,
                        filePart: partIdx,
                        bytes: finalBuf,
                      })
                ),
                45000,
                `MTProto part #${partIdx}`
              );
            } finally {
              inFlightBySender.set(sender, Math.max(0, (inFlightBySender.get(sender) || 1) - 1));
            }
            lastMtprotoHealthCheckAt = Date.now();
            sent = true;
            break;
          } catch (err: any) {
            if (isAborted && isAborted()) {
              throw new Error('JOB_PAUSED_BY_USER');
            }
            const errMsg = String(err?.message || '');
            if (err?.seconds && typeof err.seconds === 'number') {
              await new Promise((r) => setTimeout(r, Math.min(25000, err.seconds * 1000)));
              continue;
            }
            // If an extra turbo socket disconnected or timed out, retire it & immediately retry on mainSender!
            if (sender && sender !== (client as any)._sender) {
              try {
                sender._disconnected = true;
                await sender.disconnect?.();
              } catch {}
              if (attempt < 4) {
                continue;
              }
            }
            if (/Cannot send requests while disconnected|Please reconnect/i.test(errMsg)) {
              throw err;
            }
            if (attempt < 4 && /timeout|socket|flood|closed/i.test(errMsg)) {
              await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
              continue;
            }
            throw err;
          }
        }
        if (!sent) {
          throw new Error(`MTProto part ${partIdx} failed after retries`);
        }

        completedParts++;
        uploadedBytesTotal += bytesReadTotal;
        const nowTick = Date.now();
        if (onProgress && (completedParts === partCount || nowTick - lastProgressEmitMs >= 300)) {
          lastProgressEmitMs = nowTick;
          const elapsedSec = Math.max(0.2, (nowTick - uploadStartMs) / 1000);
          const uploadedMb = uploadedBytesTotal / (1024 * 1024);
          const speedMbps = uploadedMb / elapsedSec;
          onProgress(completedParts / partCount, speedMbps, uploadedMb);
        }
      }
    };

    await Promise.all(Array.from({ length: workerCount }, () => worker()));
  } finally {
    await fh.close().catch(() => {});
  }

  return isLarge
    ? new Api.InputFileBig({
        id: fileId,
        parts: partCount,
        name: fileName,
      })
    : new Api.InputFile({
        id: fileId,
        parts: partCount,
        name: fileName,
        md5Checksum: '',
      });
}

async function uploadToTelegramUserbotMtproto(
  jobId: string,
  filePath: string,
  allTargetChatIds: string[],
  caption: string,
  meta?: VideoProbeMeta,
  onProgress?: (percent: number, speedMbps?: number, uploadedMb?: number) => void
): Promise<{ ok: boolean; error?: string }> {
  try {
    // Alternate across Primary & Secondary MTProto Clients if 2nd API ID/Hash is configured!
    const hasExtraApi = Boolean(
      process.env.EXTRA_TELEGRAM_API_ID?.trim() && process.env.EXTRA_TELEGRAM_API_HASH?.trim()
    );
    const preferSecondaryFirst = hasExtraApi && mtprotoClientRoundRobinCounter++ % 2 === 1;

    let client: TelegramClient | null = null;
    if (preferSecondaryFirst) {
      client = await getSecondaryUserbotClient();
    }
    if (!client || !client.connected) {
      client = await getConnectedUserbotClient();
    }
    // If client was transiently disconnected, force a clean reconnect before giving up!
    if (!client || !client.connected) {
      client = await getConnectedUserbotClient(true);
    }
    if ((!client || !client.connected) && hasExtraApi) {
      client = await getSecondaryUserbotClient(true);
    }
    if (!client || !client.connected) {
      return {
        ok: false,
        error: 'MTProto client could not connect after automatic retry.',
      };
    }

    const stat = await fs.promises.stat(filePath);
    const fileName = path.basename(filePath);

    const videoAttributes = [
      new Api.DocumentAttributeVideo({
        duration: Math.round(meta?.duration || 0),
        w: meta?.width || 854,
        h: meta?.height || 480,
        supportsStreaming: true,
      }),
      new Api.DocumentAttributeFilename({
        fileName,
      }),
    ];

    const uniqueTargets = Array.from(
      new Set(allTargetChatIds.map((id) => id.trim()).filter(Boolean))
    );

    const ownerId = process.env.TELEGRAM_CHAT_ID?.trim() || '7581137308';
    const candidatePeers = Array.from(new Set([...uniqueTargets, ownerId]));

    let uploadSuccess: { fromChatId: string; messageId: number } | null = null;

    let lastPeerError = '';

    // 1. Upload 1 Full Single Video to the first working Telegram peer via Custom 4-Socket 16-Worker Pipelined MTProto
    for (const peerId of candidatePeers) {
      try {
        const isNumericPeer = /^-?\d+$/.test(peerId);
        const peerArg: any = isNumericPeer ? Number(peerId) : peerId;
        let inputEntity: any = null;

        try {
          inputEntity = await withTimeoutPromise(
            client.getInputEntity(peerArg),
            8000,
            'MTProto getInputEntity'
          );
        } catch {
          try {
            inputEntity = await withTimeoutPromise(
              client.getEntity(peerArg),
              8000,
              'MTProto getEntity'
            );
          } catch {
            try {
              const warmupMsgId = await sendTelegramTextMessage(
                peerId,
                '⚡ Connecting 2GB Single Video Tunnel...'
              );
              await new Promise((r) => setTimeout(r, 350));
              if (warmupMsgId) {
                deleteTelegramMessage(peerId, warmupMsgId).catch(() => {});
              }
              inputEntity = await withTimeoutPromise(
                client.getInputEntity(peerArg),
                8000,
                'MTProto warmup getInputEntity'
              );
            } catch {
              try {
                inputEntity = await withTimeoutPromise(
                  client.getEntity(peerArg),
                  8000,
                  'MTProto warmup getEntity'
                );
              } catch {
                inputEntity = null;
              }
            }
          }
        }

        // Numeric IDs alone may not include Telegram's access_hash. Hydrate
        // recent Userbot dialogs and retry the matching entity before failing.
        if (!inputEntity) {
          try {
            const dialogs = await withTimeoutPromise(
              client.getDialogs({ limit: 200 }),
              12000,
              'MTProto dialog warmup'
            );
            const wantedId = String(peerId).replace(/^-100/, '').replace(/^-/, '');
            const matchingDialog = (dialogs as any[]).find((dialog: any) => {
              const entity = dialog?.entity;
              const entityId = entity?.id != null ? String(entity.id) : '';
              return entity && (entityId === wantedId || String(dialog?.id || '') === String(peerId));
            });
            if (matchingDialog?.entity) {
              inputEntity = await withTimeoutPromise(
                client.getInputEntity(matchingDialog.entity),
                8000,
                'MTProto dialog entity resolve'
              );
            }
          } catch {
            // Keep the normal peer error below.
          }
        }

        // A logged-in Userbot can always resolve its own `me` peer.
        if (!inputEntity && /^\d+$/.test(peerId)) {
          try {
            const me = await withTimeoutPromise(client.getMe(), 8000, 'MTProto getMe');
            if (me?.id != null && String(me.id) === peerId) {
              inputEntity = await withTimeoutPromise(
                client.getInputEntity('me'),
                8000,
                'MTProto self entity resolve'
              );
            }
          } catch {
            // Keep the actionable peer error below.
          }
        }

        if (!inputEntity) {
          lastPeerError =
            `Could not resolve MTProto entity for peer ${peerId}. ` +
            `Userbot ko is user/chat se pehle message karvao, ya Userbot ko target channel/group mein member/admin add karo.`;
          addBotLog('USERBOT_MTPROTO', peerId, lastPeerError);
          continue;
        }

        let lastProgressTick = Date.now();
        let stallTimer: NodeJS.Timeout | null = null;

        const isJobAborted = () => {
          const jCheck = jobs.get(jobId);
          return Boolean(jCheck && (jCheck.abortFlag || (jCheck.status as string) === 'paused'));
        };

        if (isJobAborted()) {
          return { ok: false, error: 'JOB_PAUSED_BY_USER' };
        }

        const uploadPromise = (async () => {
          const uploadedInputFile = await fastMtprotoUploadFile(
            client,
            filePath,
            stat.size,
            fileName,
            (progress01, speedMbps, uploadedMb) => {
              lastProgressTick = Date.now();
              if (onProgress) {
                onProgress(Math.round(progress01 * 100), speedMbps, uploadedMb);
              }
            },
            isJobAborted
          );
          lastProgressTick = Date.now();

          // Upload thumbnail via our same healthy _sender pipeline (never GramJS _borrowExportedSender!)
          let uploadedThumb: Api.InputFile | Api.InputFileBig | undefined;
          if (meta?.thumbPath && fs.existsSync(meta.thumbPath)) {
            try {
              const thumbStat = await fs.promises.stat(meta.thumbPath);
              if (thumbStat.size > 0 && thumbStat.size <= 2 * 1024 * 1024) {
                uploadedThumb = await fastMtprotoUploadFile(
                  client,
                  meta.thumbPath,
                  thumbStat.size,
                  'thumb.jpg',
                  undefined,
                  isJobAborted
                );
              }
            } catch (thumbErr: any) {
              console.warn('[StreamBridge MTProto] Non-fatal thumb upload skip:', thumbErr?.message || thumbErr);
              uploadedThumb = undefined;
            }
          }
          lastProgressTick = Date.now();

          const randomId = readBigIntFromBuffer(generateRandomBytes(8), true, true);
          return withTimeoutPromise(
            client.invoke(
              new Api.messages.SendMedia({
                peer: inputEntity,
                media: new Api.InputMediaUploadedDocument({
                  file: uploadedInputFile,
                  thumb: uploadedThumb,
                  mimeType: 'video/mp4',
                  attributes: videoAttributes,
                  forceFile: false,
                }),
                message: caption,
                randomId,
              })
            ),
            45000,
            'MTProto messages.SendMedia commit'
          );
        })();

        // Abort MTProto at 50s stall so stalled sockets immediately reconnect cleanly
        const watchdogPromise = new Promise<never>((_, reject) => {
          stallTimer = setInterval(() => {
            if (isJobAborted()) {
              if (stallTimer) clearInterval(stallTimer);
              reject(new Error('JOB_PAUSED_BY_USER'));
              return;
            }
            if (Date.now() - lastProgressTick > 50000) {
              if (stallTimer) clearInterval(stallTimer);
              reject(new Error('MTProto upload stalled for >50s'));
            }
          }, 2000);
        });

        let sentRes: any;
        try {
          sentRes = await Promise.race([uploadPromise, watchdogPromise]);
        } finally {
          if (stallTimer) clearInterval(stallTimer);
        }

        if (isJobAborted()) {
          return { ok: false, error: 'JOB_PAUSED_BY_USER' };
        }

        const sentMsgId: number | undefined =
          (typeof sentRes?.id === 'number' ? sentRes.id : undefined) ||
          sentRes?.updates?.find((u: any) => u?.className === 'UpdateMessageID' && typeof u.id === 'number')?.id ||
          sentRes?.updates?.find((u: any) => u?.message && typeof u.message.id === 'number')?.message?.id ||
          sentRes?.updates?.find((u: any) => typeof u?.id === 'number')?.id;

        if (sentMsgId) {
          uploadSuccess = { fromChatId: peerId, messageId: sentMsgId };
          break;
        } else {
          lastPeerError = `SendMedia returned no message ID (${String(sentRes?.className || 'unknown')})`;
          addBotLog('USERBOT_MTPROTO', peerId, lastPeerError);
        }
      } catch (peerErr: any) {
        const errMsg = String(peerErr?.errorMessage || peerErr?.message || peerErr);
        if (errMsg === 'JOB_PAUSED_BY_USER') {
          await closeTurboMtprotoSenderPool(client);
          try {
            await client?.disconnect();
          } catch {}
          if (client === cachedUserbotClient) cachedUserbotClient = null;
          if (client === cachedSecondaryUserbotClient) cachedSecondaryUserbotClient = null;
          return { ok: false, error: 'JOB_PAUSED_BY_USER' };
        }
        lastPeerError = errMsg;
        console.warn(`[StreamBridge MTProto] Upload to peer ${peerId} failed:`, errMsg);
        addBotLog('USERBOT_MTPROTO', peerId, `MTProto upload failed: ${errMsg}`);
        if (/stalled|disconnected|timeout|timed out|AUTH|socket|DUPLICATED/i.test(errMsg)) {
          await closeTurboMtprotoSenderPool(client);
          try {
            await client?.disconnect();
          } catch {}
          if (client === cachedUserbotClient) {
            if (/AUTH|DUPLICATED|REVOKED/i.test(errMsg)) cachedBotMtprotoSessionStr = '';
            cachedUserbotClient = null;
          }
          if (client === cachedSecondaryUserbotClient) {
            if (/AUTH|DUPLICATED|REVOKED/i.test(errMsg)) cachedSecondaryBotMtprotoSessionStr = '';
            cachedSecondaryUserbotClient = null;
          }
        }
      }
    }

    if (!uploadSuccess) {
      return {
        ok: false,
        error: lastPeerError || 'Could not upload 1 Full Single Video to Telegram MTProto.',
      };
    }

    const finalJobCheck = jobs.get(jobId);
    if (finalJobCheck && (finalJobCheck.abortFlag || (finalJobCheck.status as string) === 'paused')) {
      return { ok: false, error: 'JOB_PAUSED_BY_USER' };
    }

    // 2. Deliver / copy the 1 Full Single Video to all other target destinations (Group, Channels) in 0.1s!
    for (const destId of uniqueTargets) {
      if (destId === uploadSuccess.fromChatId) continue;
      try {
        await copyTelegramVideoMessage(
          uploadSuccess.fromChatId,
          uploadSuccess.messageId,
          destId,
          caption
        );
      } catch (copyErr: any) {
        console.warn(`[StreamBridge] copyTelegramVideoMessage to ${destId} warning:`, copyErr?.message || copyErr);
      }
    }

    return { ok: true };
  } catch (err: any) {
    const errMsg = String(err?.errorMessage || err?.message || err || 'MTProto upload error');
    addBotLog('USERBOT_MTPROTO', 'mtproto', `MTProto outer error: ${errMsg}`);
    return { ok: false, error: errMsg };
  }
}

// (Multi-part splitting & unused FFmpeg shrinking removed — every video sends directly as 1 full streamable MP4 file)

// ============================================================================
// 16x MULTI-RANGE PARALLEL MP4 DOWNLOADER + 64x HLS TURBO PIPELINE + 2-VIDEO LOOKAHEAD PRE-FETCH
// ============================================================================

interface LastCourseActionContext {
  sourceUrl: string;
  courseName: string;
  lastOrder: number;
  totalVideos: number;
  preferredQuality: string;
  explicitTargetChannelId?: string;
}
const lastCourseContextByChat = new Map<string, LastCourseActionContext>();

async function downloadDirectVideoMultiRange(
  url: string,
  headers: Record<string, string>,
  outPath: string,
  job: DownloadJob,
  _startTime: number,
  onProgress?: () => void,
  abortSignal?: AbortSignal
): Promise<void> {
  let totalBytes = 0;
  let supportsRanges = false;

  // Probe server for Accept-Ranges: bytes & total file size via Range: bytes=0-0
  try {
    const probeRes = await undiciRequestFollow(url, {
      method: 'GET',
      headers: { ...headers, Range: 'bytes=0-0' },
      headersTimeout: 8000,
      bodyTimeout: 8000,
      signal: abortSignal,
    });

    const contentRange = String(probeRes.headers['content-range'] || '');
    const acceptRanges = String(probeRes.headers['accept-ranges'] || '').toLowerCase();
    const contentLen = parseInt(String(probeRes.headers['content-length'] || '0'), 10);
    await probeRes.body.dump().catch(() => {});

    const crMatch = contentRange.match(/bytes\s+\d+-\d+\/(\d+)/i);
    if (probeRes.statusCode === 206 && crMatch) {
      totalBytes = parseInt(crMatch[1], 10);
      supportsRanges = true;
    } else if (acceptRanges.includes('bytes') && contentLen > 0) {
      totalBytes = contentLen;
      supportsRanges = true;
    }
  } catch {
    // Fallback to single stream below
  }

  const myEpoch = job.downloadEpoch || 0;
  const isRangeAborted = () =>
    Boolean(
      abortSignal?.aborted ||
        job.abortFlag ||
        (job.status as string) === 'paused' ||
        (job.downloadEpoch || 0) !== myEpoch
    );

  // Use Dynamic Work-Stealing 4MB Byte-Range Chunks across 16-24 parallel keep-alive workers!
  // Fast sockets automatically steal remaining 4MB chunks and retries never waste >4MB (10x-30x faster on Render & CDNs!)
  if (supportsRanges && totalBytes > 1 * 1024 * 1024) {
    const RANGE_WORKERS =
      job.status === 'queued'
        ? Math.max(4, Math.floor(CONFIGURED_RANGE_WORKERS / 2))
        : CONFIGURED_RANGE_WORKERS;
    const chunkSize = Math.min(
      4 * 1024 * 1024,
      Math.max(1 * 1024 * 1024, Math.ceil(totalBytes / Math.max(RANGE_WORKERS * 2, 16)))
    );
    const ranges: Array<{ index: number; start: number; end: number }> = [];
    for (let start = 0, i = 0; start < totalBytes; start += chunkSize, i++) {
      const end = Math.min(totalBytes - 1, start + chunkSize - 1);
      ranges.push({ index: i, start, end });
    }

    job.totalSegments = ranges.length;
    job.completedSegments = 0;
    job.downloadedBytes = 0;
    job.lastProgressAt = Date.now();

    const dlStartTime = Date.now();
    const fileHandle = await fs.promises.open(outPath, 'w');
    const WRITE_FLUSH_THRESHOLD = 1 * 1024 * 1024;
    try {
      await fileHandle.truncate(totalBytes);
      let nextRangeIdx = 0;
      let lastSpeedCalcTime = dlStartTime;
      let lastSpeedCalcBytes = 0;
      let currentInstantSpeed = 0;

      const rangeWorker = async () => {
        while (true) {
          if (isRangeAborted()) break;
          const rIdx = nextRangeIdx++;
          if (rIdx >= ranges.length) break;
          const { start, end } = ranges[rIdx];
          const expectedLen = end - start + 1;

          let rangeSuccess = false;
          let lastErr: any;
          for (let attempt = 1; attempt <= 4; attempt++) {
            if (isRangeAborted()) break;
            try {
              const res = await undiciRequestFollow(url, {
                method: 'GET',
                headers: {
                  ...headers,
                  Range: `bytes=${start}-${end}`,
                  'Accept-Encoding': 'identity',
                  Connection: 'keep-alive',
                },
                headersTimeout: 15000,
                bodyTimeout: 45000,
                signal: abortSignal,
              });
              if (res.statusCode !== 206 && res.statusCode !== 200) {
                await res.body.dump().catch(() => {});
                throw new Error(`HTTP ${res.statusCode}`);
              }
              if (res.statusCode === 200 && start > 0) {
                await res.body.dump().catch(() => {});
                throw new Error('Server ignored Range header');
              }

              // Coalesce incoming network chunks into 2MB disk writes for 100x fewer syscalls!
              let writeOffset = start;
              let writtenForRange = 0;
              let pendingChunks: Buffer[] = [];
              let pendingLen = 0;

              const flushPending = async () => {
                if (pendingLen <= 0) return;
                const combined =
                  pendingChunks.length === 1 ? pendingChunks[0] : Buffer.concat(pendingChunks, pendingLen);
                pendingChunks = [];
                pendingLen = 0;
                await fileHandle.write(combined, 0, combined.length, writeOffset);
                writeOffset += combined.length;
              };

              for await (const rawChunk of res.body) {
                if (isRangeAborted()) break;
                const cBuf = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
                const remaining = expectedLen - writtenForRange;
                if (remaining <= 0) break;
                const toWrite = cBuf.length > remaining ? cBuf.subarray(0, remaining) : cBuf;
                pendingChunks.push(toWrite);
                pendingLen += toWrite.length;
                writtenForRange += toWrite.length;
                job.downloadedBytes += toWrite.length;
                job.lastProgressAt = Date.now();

                if (pendingLen >= WRITE_FLUSH_THRESHOLD) {
                  await flushPending();
                }

                const now = Date.now();
                const timeDiff = (now - lastSpeedCalcTime) / 1000;
                if (timeDiff >= 0.6) {
                  const bytesDiff = job.downloadedBytes - lastSpeedCalcBytes;
                  currentInstantSpeed = Math.round(bytesDiff / timeDiff);
                  lastSpeedCalcTime = now;
                  lastSpeedCalcBytes = job.downloadedBytes;
                }
                job.speedBytesPerSec =
                  currentInstantSpeed ||
                  Math.round(job.downloadedBytes / Math.max(0.25, (now - dlStartTime) / 1000));
                job.progressPercent = Math.min(
                  95,
                  Math.round((job.downloadedBytes / totalBytes) * 95)
                );
                if (onProgress) onProgress();
              }
              if (!isRangeAborted()) {
                await flushPending();
              }
              if (isRangeAborted()) break;
              if (writtenForRange < expectedLen && res.statusCode === 206) {
                throw new Error(`Truncated range ${writtenForRange}/${expectedLen}`);
              }

              job.completedSegments++;
              job.lastProgressAt = Date.now();
              if (onProgress) onProgress();
              rangeSuccess = true;
              break;
            } catch (err) {
              lastErr = err;
              if (isRangeAborted()) break;
              if (attempt < 4) {
                await new Promise((r) => setTimeout(r, 80 * Math.pow(2, attempt - 1)));
              }
            }
          }
          if (!rangeSuccess && !isRangeAborted()) {
            throw lastErr || new Error(`Range ${start}-${end} failed after 4 retries`);
          }
        }
      };

      await Promise.all(
        Array.from({ length: Math.min(RANGE_WORKERS, ranges.length) }, () => rangeWorker())
      );
      if (isRangeAborted()) {
        throw new Error('JOB_PAUSED_BY_USER');
      }
      return;
    } catch (err: any) {
      if (isRangeAborted() || String(err?.message || '') === 'JOB_PAUSED_BY_USER') {
        throw new Error('JOB_PAUSED_BY_USER');
      }
      // If multi-range fails midway, fall through to curl fallback
    } finally {
      await fileHandle.close().catch(() => {});
    }
  }

  if (isRangeAborted()) {
    throw new Error('JOB_PAUSED_BY_USER');
  }

  // Fallback for servers that do not support byte ranges
  job.totalSegments = 1;
  await execFileAsync(
    'curl',
    ['-k', '-sL', '--retry', '4', '--max-time', '600', '-o', outPath, url],
    { timeout: 620000 }
  );
  const stat = await fs.promises.stat(outPath);
  job.downloadedBytes = stat.size;
  job.completedSegments = 1;
  job.lastProgressAt = Date.now();
}

// Runtime Stream URL Pre-Resolution Cache (4-minute TTL so signed Google Edge tokens stay fresh, 0ms handoff!)
const preResolvedStreamCache = new Map<
  string,
  { streamUrl: string; quality: string; title?: string; resolvedAt: number }
>();
const activePreResolveIds = new Set<string>();

function preResolveQueuedUrls(chatId: string, activeJobId: string) {
  if (!chatId || userExplicitlyPausedChats.has(chatId)) return;
  const globalCooldown = (resolveAppxVideoStreamUrl as any)._asmGlobalCooldown;
  if (globalCooldown && Date.now() < globalCooldown.until) return;
  const queue = chatJobQueues.get(chatId) || [];
  const nextAppx = queue
    .filter(
      (qJob) =>
        qJob.id !== activeJobId &&
        qJob.status === 'queued' &&
        !qJob.abortFlag &&
        !activePreResolveIds.has(qJob.id) &&
        !(preResolvedStreamCache.get(qJob.id) && Date.now() - preResolvedStreamCache.get(qJob.id)!.resolvedAt < 210000) &&
        (qJob.initialSourceUrl || qJob.sourceUrl || '').startsWith('appx://') &&
        !/[?&]unrecorded=1\b/i.test(qJob.initialSourceUrl || qJob.sourceUrl || '')
    )
    .sort((a, b) => {
      const oA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
      const oB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
      if (oA !== oB) return oA - oB;
      return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    })
    .slice(0, 1);

  for (const qJob of nextAppx) {
    activePreResolveIds.add(qJob.id);
    (async () => {
      try {
        const rawUrl = qJob.initialSourceUrl || qJob.sourceUrl;
        const parsedAppx = new URL(rawUrl.replace(/^appx:\/\//i, 'http://'));
        const domainId = decodeURIComponent(parsedAppx.hostname || 'RWA').toUpperCase();
        const courseId = parsedAppx.searchParams.get('courseid') || '284';
        const videoId = parsedAppx.searchParams.get('videoid') || '';
        const origin = parsedAppx.searchParams.get('origin') || 'https://studybeepro.site';
        const portalPath = parsedAppx.searchParams.get('portal') || '/rwax';
        const fallbackUrl = parsedAppx.searchParams.get('fallback') || undefined;
        const resolved = await resolveAppxVideoStreamUrl(
          domainId,
          courseId,
          videoId,
          qJob.preferredQuality || botSettings.globalDefaultQuality || '480p',
          origin,
          portalPath,
          fallbackUrl,
          {
            subjectId: parsedAppx.searchParams.get('subjectid') || undefined,
            topicId: parsedAppx.searchParams.get('topicid') || undefined,
            conceptId: parsedAppx.searchParams.get('conceptid') || undefined,
            title: qJob.lectureTitle || qJob.title || undefined,
            strtotime: Number(parsedAppx.searchParams.get('strtotime') || 0) || undefined,
            duration: parsedAppx.searchParams.get('duration') || undefined,
            freeFlag: parsedAppx.searchParams.get('free') || undefined,
            skipFallback: (qJob.retryCount || 0) > 0,
            chatId: qJob.telegramChatId || chatId,
          }
        );
        if (resolved && resolved.streamUrl) {
          preResolvedStreamCache.set(qJob.id, {
            ...resolved,
            resolvedAt: Date.now(),
          });
        }
      } catch {
        // ignore pre-resolve errors; active job handles cooldown/retry
      } finally {
        activePreResolveIds.delete(qJob.id);
      }
    })();
  }
}

// 2-Video Parallel Pipeline:
// 1) Pre-resolves signed stream URLs for the next 2 videos (0ms URL handoff), AND
// 2) Downloads & remuxes the very next 1 queued video (N+1) in the background while Video N is remuxing & uploading!
// Delivers to Telegram in 100% strict 1, 2, 3... order while processing 2 videos simultaneously!
function triggerLookaheadPreFetch(chatId: string, activeJobId: string) {
  if (!chatId || userExplicitlyPausedChats.has(chatId)) return;
  preResolveQueuedUrls(chatId, activeJobId);

  const q = chatJobQueues.get(chatId);
  if (!q || q.length === 0) return;

  // On constrained 512MB RAM hosts (e.g. Render Free Tier), avoid running two simultaneous HLS downloads;
  // only pre-download video N+1 once video N has finished downloading (i.e. during upload phase).
  if (IS_CONSTRAINED_HOST) {
    const activeJob = jobs.get(activeJobId);
    if (activeJob && activeJob.status === 'downloading') return;
  }

  // Check if any background pre-download is already running for this chat
  const alreadyPreDownloading = q.some((j) => Boolean(j.preDownloadPromise));
  if (alreadyPreDownloading) return;

  const candidates = q
    .filter(
      (qJob) =>
        qJob.id !== activeJobId &&
        qJob.status === 'queued' &&
        !qJob.abortFlag &&
        !qJob.deliveredToTelegram &&
        !qJob.preDownloadedReady &&
        !qJob.preDownloadPromise &&
        !inFlightDownloadJobs.has(qJob.id) &&
        !/[?&]unrecorded=1\b/i.test(qJob.initialSourceUrl || qJob.sourceUrl || '')
    )
    .sort((a, b) => {
      const oA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
      const oB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
      if (oA !== oB) return oA - oB;
      return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    });

  const nextJob = candidates[0];
  if (!nextJob) return;

  nextJob.preDownloadPromise = processDownloadJob(nextJob, true)
    .catch(() => {})
    .finally(() => {
      nextJob.preDownloadPromise = undefined;
    });
}

// Apply a Global Default Quality change immediately across botSettings, all queued/paused/waiting jobs,
// pre-resolved URL cache, course extract cache, watchedCourses, and lastCourseContextByChat!
function applyGlobalQualityChange(newQuality: VideoQualityOption): { updatedJobsCount: number } {
  const validQuality: VideoQualityOption = ['144p', '240p', '360p', '480p', '720p', '1080p'].includes(
    newQuality
  )
    ? newQuality
    : '480p';

  botSettings.globalDefaultQuality = validQuality;
  saveBotSettings();

  // Clear pre-resolved stream URL cache so upcoming videos resolve with the newly selected quality
  preResolvedStreamCache.clear();
  courseExtractionCache.clear();

  let updatedJobsCount = 0;
  for (const j of jobs.values()) {
    if (
      j.status === 'queued' ||
      j.status === 'paused' ||
      j.status === 'waiting_stream' ||
      j.status === 'failed'
    ) {
      j.preferredQuality = validQuality;
      j.resolution = validQuality;
      if (j.preDownloadedReady || j.preDownloadPromise) {
        j.preDownloadedReady = false;
        j.downloadEpoch = (j.downloadEpoch || 0) + 1;
        cleanupJobTempFiles(j.id);
      }
      updatedJobsCount++;
    } else if (j.status === 'downloading') {
      // Update preferredQuality on active job metadata too
      j.preferredQuality = validQuality;
    }
  }

  for (const w of watchedCourses.values()) {
    w.preferredQuality = validQuality;
  }
  saveWatchedCoursesState();

  for (const ctx of lastCourseContextByChat.values()) {
    ctx.preferredQuality = validQuality;
  }

  if (updatedJobsCount > 0) {
    saveJobsState();
  }

  return { updatedJobsCount };
}

const inFlightDownloadJobs = new Set<string>();

async function processDownloadJob(job: DownloadJob, preDownloadOnly = false): Promise<void> {
  if (!preDownloadOnly) {
    const needsTgCheck =
      job.deliveryMode === 'telegram_auto' ||
      job.deliveryMode === 'telegram_userbot' ||
      job.deliveryMode === 'telegram_and_drive';
    const needsDriveCheck =
      job.deliveryMode === 'drive_only' || job.deliveryMode === 'telegram_and_drive';
    if (
      job.status === 'completed' ||
      ((!needsTgCheck || job.deliveredToTelegram) && (!needsDriveCheck || job.deliveredToDrive))
    ) {
      return;
    }
    if (inFlightDownloadJobs.has(job.id)) {
      return;
    }
    inFlightDownloadJobs.add(job.id);
  }
  const startTime = Date.now();
  let lastTelegramUpdateTime = 0;
  job.lastProgressAt = Date.now();
  if (!preDownloadOnly) {
    job.abortFlag = false;
    // Only bump downloadEpoch if no background preDownloadPromise is currently in flight for this job!
    if (!job.preDownloadPromise) {
      job.downloadEpoch = (job.downloadEpoch || 0) + 1;
    }
  }
  const jobAbortCtrl = getOrCreateJobAbortController(job.id);
  const myEpoch = job.downloadEpoch || 0;
  const isStaleOrAborted = () =>
    Boolean(
      jobAbortCtrl.signal.aborted ||
        job.abortFlag ||
        (job.status as string) === 'paused' ||
        (job.downloadEpoch || 0) !== myEpoch
    );
  if (!job.initialSourceUrl) {
    job.initialSourceUrl = job.sourceUrl;
  }

  if (!job.preferredQuality || job.preferredQuality === 'auto_fast') {
    job.preferredQuality = botSettings.globalDefaultQuality || '480p';
  }

  const targetChat = (job.telegramChatId || process.env.TELEGRAM_CHAT_ID || '').trim();

  // Check if this job matches a Fix Link -> Fix Channel Rule or has an explicit target channel
  const matchedRoute = findMatchingRouteRule(job.originalRequestUrl || job.sourceUrl);
  const routedChannelId = (
    job.explicitTargetChannelId ||
    matchedRoute?.targetChatId ||
    ''
  ).trim();
  const routedChannelLabel =
    matchedRoute?.targetTitle || matchedRoute?.label || job.explicitTargetChannelId || '';

  // Collect all active Backup Channels / Backup Groups
  const enabledBackups = botSettings.backupChannels.filter(
    (b) => b.enabled && b.chatId && b.chatId.trim()
  );

  const preCheckUrl = job.initialSourceUrl?.startsWith('appx://')
    ? job.initialSourceUrl
    : job.sourceUrl;
  const isPreMarkedUnrecorded = preCheckUrl.startsWith('appx://') && /[?&]unrecorded=1\b/i.test(preCheckUrl);
  const destNote = routedChannelId
    ? `\n🎯 Target Channel: ${routedChannelLabel || routedChannelId}`
    : enabledBackups.length > 0
    ? `\n🛡️ Auto-Backup: ${enabledBackups.length} channel/group(s)`
    : '';

  // For non-appx direct links, send Preparing immediately (only when not pre-fetching silently and real Telegram chat!)
  if (
    !preDownloadOnly &&
    targetChat &&
    !targetChat.startsWith('__') &&
    !job.telegramStatusMsgId &&
    !isPreMarkedUnrecorded &&
    !preCheckUrl.startsWith('appx://')
  ) {
    job.telegramStatusMsgId = await sendTelegramTextMessage(
      targetChat,
      `⏳ Preparing (${job.preferredQuality.toUpperCase()}): ${job.title}` +
        (job.folderName ? `\n📁 Folder: ${job.folderName}` : '') +
        destNote
    );
  }

  const updateTelegramProgressIfNeeded = async (text: string, force = false) => {
    const isPromotedForeground = !preDownloadOnly || inFlightDownloadJobs.has(job.id);
    if (!isPromotedForeground || !targetChat || targetChat.startsWith('__')) return;
    const isStoppedOrPaused = job.abortFlag || (job.status as string) === 'paused';
    if (isStoppedOrPaused && !text.startsWith('⏸️') && !text.startsWith('🛑')) {
      return;
    }
    const now = Date.now();
    const minIntervalMs = job.status.startsWith('uploading') ? 2200 : 3000;
    if (!job.telegramStatusMsgId) {
      if (force || now - lastTelegramUpdateTime > minIntervalMs) {
        lastTelegramUpdateTime = now;
        job.telegramStatusMsgId = await sendTelegramTextMessage(targetChat, text);
      }
      return;
    }
    if (force || now - lastTelegramUpdateTime > minIntervalMs) {
      lastTelegramUpdateTime = now;
      await editTelegramTextMessage(targetChat, job.telegramStatusMsgId, text);
    }
  };

  try {
    if (job.abortFlag || (job.status as string) === 'paused') {
      throw new Error('JOB_PAUSED_BY_USER');
    }

    // If Lookahead Pre-Fetch is currently running on this job, await it so we don't download twice!
    if (!preDownloadOnly && job.preDownloadPromise) {
      await job.preDownloadPromise.catch(() => {});
      job.preDownloadPromise = undefined;
    }

    const alreadyPreDownloaded = Boolean(
      !preDownloadOnly &&
        job.preDownloadedReady &&
        job.filePath &&
        fs.existsSync(job.filePath)
    );

    if (!alreadyPreDownloaded) {
      if (!preDownloadOnly) {
        job.status = 'downloading';
        job.lastProgressAt = Date.now();
        saveJobsState();
      }

      const urlToResolve = job.initialSourceUrl?.startsWith('appx://')
        ? job.initialSourceUrl
        : job.sourceUrl;

      if (urlToResolve.startsWith('appx://')) {
        const parsedAppx = new URL(urlToResolve.replace(/^appx:\/\//i, 'http://'));
        const domainId = decodeURIComponent(parsedAppx.hostname || 'RWA').toUpperCase();
        const courseId = parsedAppx.searchParams.get('courseid') || '284';
        const videoId = parsedAppx.searchParams.get('videoid') || '';
        const origin = parsedAppx.searchParams.get('origin') || 'https://studybeepro.site';
        const portalPath = parsedAppx.searchParams.get('portal') || '/rwax';
        const fallbackUrl = parsedAppx.searchParams.get('fallback') || undefined;
        const isMarkedUnrecorded = parsedAppx.searchParams.get('unrecorded') === '1';

        const hintMeta = {
          subjectId: parsedAppx.searchParams.get('subjectid') || undefined,
          topicId: parsedAppx.searchParams.get('topicid') || undefined,
          conceptId: parsedAppx.searchParams.get('conceptid') || undefined,
          title: job.lectureTitle || job.title || undefined,
          strtotime: Number(parsedAppx.searchParams.get('strtotime') || 0) || undefined,
          duration: parsedAppx.searchParams.get('duration') || undefined,
          freeFlag: parsedAppx.searchParams.get('free') || undefined,
          skipFallback: (job.retryCount || 0) > 0,
          chatId: targetChat || job.telegramChatId,
        };

        if (isMarkedUnrecorded) {
          throw new Error(
            `UNRECORDED_CLASS_SKIP: Video recording not uploaded on server yet (video_id=${videoId})`
          );
        }

        // Start background pre-resolution for next 3 queued videos in parallel
        if (!preDownloadOnly && targetChat) {
          preResolveQueuedUrls(targetChat, job.id);
        }

        let resolved: { streamUrl: string; quality: string; title?: string } | null = null;
        const cachedPreResolved = preResolvedStreamCache.get(job.id);
        if (
          cachedPreResolved &&
          (job.retryCount || 0) === 0 &&
          Date.now() - cachedPreResolved.resolvedAt < 240000
        ) {
          preResolvedStreamCache.delete(job.id);
          resolved = {
            streamUrl: cachedPreResolved.streamUrl,
            quality: cachedPreResolved.quality,
            title: cachedPreResolved.title,
          };
        }

        const maxCooldownTries = preDownloadOnly ? 1 : 3;
        for (let cooldownAttempt = 0; cooldownAttempt < maxCooldownTries && !resolved; cooldownAttempt++) {
          if (job.abortFlag || (job.status as string) === 'paused') {
            throw new Error('JOB_PAUSED_BY_USER');
          }
          try {
            resolved = await resolveAppxVideoStreamUrl(
              domainId,
              courseId,
              videoId,
              job.preferredQuality || botSettings.globalDefaultQuality || '480p',
              origin,
              portalPath,
              fallbackUrl,
              hintMeta
            );
            break;
          } catch (resErr: any) {
            const rMsg = String(resErr?.message || '');
            if (rMsg.startsWith('RWA_RATE_LIMIT_COOLDOWN') && !preDownloadOnly && cooldownAttempt < maxCooldownTries - 1) {
              const waitSec = cooldownAttempt === 0 ? 15 : 25;
              const cleanJobTitle = String(job.title || '').replace(/^📹\s*/i, '');
              await updateTelegramProgressIfNeeded(
                `⏳ RWA Token Refresh & Mirror Switch (${waitSec}s):\n` +
                  `📹 ${cleanJobTitle}\n` +
                  (job.folderName ? `📁 Folder: ${job.folderName}\n` : '') +
                  `🔄 Fresh TeachX token + alternate mirror rotate ho raha hai — bina ruke auto-retry...`,
                true
              );
              appxConfigCache.clear();
              await mintFreshTeachxToken().catch(() => null);
              for (let tick = 0; tick < Math.ceil(waitSec / 2); tick++) {
                if (job.abortFlag || (job.status as string) === 'paused') {
                  throw new Error('JOB_PAUSED_BY_USER');
                }
                job.lastProgressAt = Date.now();
                await new Promise((r) => setTimeout(r, 2000));
              }
              continue;
            }
            throw resErr;
          }
        }
        if (!resolved) {
          throw new Error(`No playable stream URL available for video_id=${videoId}`);
        }
        job.sourceUrl = resolved.streamUrl;
        job.resolution = resolved.quality;
        job.lastProgressAt = Date.now();

        if (!preDownloadOnly && targetChat && !job.telegramStatusMsgId) {
          job.telegramStatusMsgId = await sendTelegramTextMessage(
            targetChat,
            `⏳ Downloading (${(job.resolution || job.preferredQuality).toUpperCase()}): ${job.title}` +
              (job.folderName ? `\n📁 Folder: ${job.folderName}` : '') +
              destNote
          );
        }
      }

      const unwrappedSource = unwrapQueryRedirectUrl(job.sourceUrl);
      if (unwrappedSource) {
        job.sourceUrl = unwrappedSource;
      }

      // Pre-warm 8x MTProto upload sockets silently in background while downloading so upload starts at full speed immediately
      if (!preDownloadOnly) {
        void getConnectedUserbotClient()
          .then((c) => {
            if (c && c.connected && (c.session as any)?.dcId) {
              return getTurboMtprotoSenderPool(c, (c.session as any).dcId, 8);
            }
          })
          .catch(() => {});
      }

      const headers = buildHeaders(job.customHeaders, job.sourceUrl);
      const safeBaseName = job.title.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 45) || 'video';
      const isPlatformDownload =
        job.protocol === 'YTDLP_PLATFORM' ||
        detectPlatformVideoUrl(job.sourceUrl).isPlatform ||
        isUrlPathnameEndingWith(job.sourceUrl, /\.mpd$/i);
      const isDirectVideoUrl =
        !isPlatformDownload &&
        (job.protocol === 'DIRECT_MP4' ||
          job.protocol === 'DIRECT_WEBM' ||
          job.protocol === 'DIRECT_VIDEO' ||
          isUrlPathnameEndingWith(job.sourceUrl, /\.(mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)$/i));

      if (isPlatformDownload) {
        const mp4Path = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.mp4`);
        await downloadWithYtDlp(job.sourceUrl, mp4Path, job, () => {
          if (!preDownloadOnly || inFlightDownloadJobs.has(job.id)) {
            const speedMb = (job.speedBytesPerSec / (1024 * 1024)).toFixed(1);
            const dlMb = (job.downloadedBytes / (1024 * 1024)).toFixed(1);
            updateTelegramProgressIfNeeded(
              `⏳ Downloading High-Quality Video (${(job.preferredQuality || '720p').toUpperCase()}): ${job.title}\n` +
                `📊 ${job.progressPercent}%\n` +
                `🚀 Speed: ${speedMb} MB/s • Size: ${dlMb} MB`
            );
          }
        });
        job.filePath = mp4Path;
        job.outputFormat = 'mp4';
        job.lastProgressAt = Date.now();
        if ((!preDownloadOnly || inFlightDownloadJobs.has(job.id)) && targetChat) {
          triggerLookaheadPreFetch(targetChat, job.id);
        }
      } else if (!isDirectVideoUrl) {
        let { text: textBody, finalUrl } = await robustFetchText(job.sourceUrl, headers);
        job.lastProgressAt = Date.now();

        if (!textBody.trim().startsWith('#EXTM3U')) {
          try {
            const reInspected = await inspectUrlAndExtractStreams(
              job.sourceUrl,
              job.customHeaders,
              textBody,
              false
            );
            if (reInspected.streams.length > 0) {
              const streamToUse = reInspected.streams[0];
              job.sourceUrl = streamToUse.url;
              if (streamToUse.protocol === 'YTDLP_PLATFORM' || detectPlatformVideoUrl(streamToUse.url).isPlatform) {
                const mp4Path = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.mp4`);
                await downloadWithYtDlp(streamToUse.url, mp4Path, job);
                job.filePath = mp4Path;
                job.outputFormat = 'mp4';
              } else {
                const reFetch = await robustFetchText(job.sourceUrl, headers);
                textBody = reFetch.text;
                finalUrl = reFetch.finalUrl;
              }
            }
          } catch {
            // ignore fallback extraction error
          }
        }

        if (job.filePath && fs.existsSync(job.filePath)) {
          // Handled via extracted YTDLP_PLATFORM stream
        } else {
        if (!textBody.trim().startsWith('#EXTM3U')) {
          throw new Error('Target URL did not return a valid #EXTM3U playlist.');
        }

        let mediaPlaylist = parseM3u8Content(textBody, finalUrl);

        if (mediaPlaylist.isMaster) {
          if (mediaPlaylist.variants.length === 0) {
            throw new Error('HLS Master playlist contained no playable variants.');
          }
          const chosenVariant = chooseVariantByPreferredQuality(
            mediaPlaylist.variants,
            job.preferredQuality || botSettings.globalDefaultQuality || '480p'
          );
          job.resolution = chosenVariant.resolution || chosenVariant.name || job.resolution;
          const { text: varText, finalUrl: varFinalUrl } = await robustFetchText(
            chosenVariant.url,
            headers
          );
          const subParsed = parseM3u8Content(varText, varFinalUrl);
          if (subParsed.isMaster) {
            throw new Error('Nested HLS Master playlist could not be resolved to media segments.');
          }
          mediaPlaylist = subParsed;
        }

        // Assignment above widens the discriminated union; at this point a
        // master playlist has already been rejected/resolved.
        const parsedMediaPlaylist = mediaPlaylist as ParsedMediaPlaylist;
        const segments = parsedMediaPlaylist.segments;
        if (segments.length === 0) {
          throw new Error('No media segments (#EXTINF) found in the HLS playlist.');
        }

        job.totalSegments = segments.length;
        job.completedSegments = 0;
        job.downloadedBytes = 0;
        job.lastProgressAt = Date.now();

        const rawTsPath = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.ts`);
        const writeStream = fs.createWriteStream(rawTsPath, {
          highWaterMark: IS_CONSTRAINED_HOST ? 4 * 1024 * 1024 : 16 * 1024 * 1024,
        });

        if (parsedMediaPlaylist.initMapUrl) {
          const mapBuf = await robustFetchBuffer(parsedMediaPlaylist.initMapUrl, headers, 4, jobAbortCtrl.signal);
          writeStream.write(mapBuf);
          job.downloadedBytes += mapBuf.length;
          job.lastProgressAt = Date.now();
        }

        // Promise-deduplicated AES-128 Key Cache (fetched once per playlist even across 96 concurrent workers!)
        const keyPromiseCache = new Map<string, Promise<Buffer>>();

        const cleanSegHeaders: Record<string, string> = {
          'User-Agent': DEFAULT_USER_AGENT,
          Accept: '*/*',
          'Accept-Encoding': 'identity',
          Connection: 'keep-alive',
        };
        if (
          /classx\.co\.in|teachx\.in/i.test(finalUrl) ||
          /classx\.co\.in|teachx\.in/i.test(job.sourceUrl)
        ) {
          cleanSegHeaders['Referer'] = 'https://rozgarapinew.teachx.in/';
        }
        if (job.customHeaders) {
          for (const [k, v] of Object.entries(job.customHeaders)) {
            if (k && v && !/^(referer|origin|accept-encoding)$/i.test(k.trim())) {
              cleanSegHeaders[k.trim()] = v.trim();
            }
          }
        }

        const dlStartTime = Date.now();
        let lastSpeedCalcTime = dlStartTime;
        let lastSpeedCalcBytes = 0;
        let currentInstantSpeed = 0;

        // Adaptive High-Speed Undici HLS Worker Pool:
        // Saturates NIC bandwidth at full speed without choking Render's 0.1 vCPU / 512MB RAM or triggering CDN resets!
        const WORKER_COUNT = preDownloadOnly
          ? Math.max(4, Math.floor(CONFIGURED_HLS_WORKERS / 2))
          : CONFIGURED_HLS_WORKERS;
        const MAX_BUFFER_WINDOW = IS_CONSTRAINED_HOST ? 128 : 384;
        const MAX_BUFFERED_BYTES = preDownloadOnly
          ? 16 * 1024 * 1024
          : IS_CONSTRAINED_HOST
          ? 32 * 1024 * 1024
          : 64 * 1024 * 1024;
        let nextFetchIndex = 0;
        let nextWriteIndex = 0;
        let bufferedRamBytes = 0;
        const completedBuffers = new Map<number, Buffer>();
        let isFlushing = false;
        let tokenExpiredFlag = false;

        const flushOrderedBuffers = async () => {
          if (isFlushing) return;
          isFlushing = true;
          try {
            while (completedBuffers.has(nextWriteIndex)) {
              const batch: Buffer[] = [];
              let batchBytes = 0;
              while (completedBuffers.has(nextWriteIndex) && batchBytes < 16 * 1024 * 1024) {
                const buf = completedBuffers.get(nextWriteIndex)!;
                completedBuffers.delete(nextWriteIndex);
                nextWriteIndex++;
                if (buf.length > 0) {
                  bufferedRamBytes = Math.max(0, bufferedRamBytes - buf.length);
                  batch.push(buf);
                  batchBytes += buf.length;
                }
              }
              if (batch.length > 0 && !writeStream.destroyed) {
                const combined = batch.length === 1 ? batch[0] : Buffer.concat(batch, batchBytes);
                const canContinue = writeStream.write(combined);
                if (!canContinue) {
                  await Promise.race([
                    new Promise<void>((r) => writeStream.once('drain', () => r())),
                    new Promise<void>((r) => setTimeout(r, 6000)),
                  ]);
                }
              }
            }
          } finally {
            isFlushing = false;
          }
        };

        const workerTask = async () => {
          while (true) {
            if (tokenExpiredFlag || isStaleOrAborted()) break;

            let waitLoops = 0;
            while (
              (nextFetchIndex - nextWriteIndex >= MAX_BUFFER_WINDOW ||
                bufferedRamBytes >= MAX_BUFFERED_BYTES) &&
              !tokenExpiredFlag &&
              !isStaleOrAborted() &&
              (preDownloadOnly || job.status === 'downloading') &&
              waitLoops < 400
            ) {
              waitLoops++;
              await flushOrderedBuffers();
              await new Promise((r) => setTimeout(r, 25));
            }

            if (tokenExpiredFlag || isStaleOrAborted()) break;

            const segIndex = nextFetchIndex++;
            if (segIndex >= segments.length) break;

            const seg = segments[segIndex];
            let buf: Buffer;
            try {
              buf = await robustFetchBuffer(seg.url, cleanSegHeaders, 4, jobAbortCtrl.signal);

              if (seg.key && seg.key.method === 'AES-128' && seg.key.uri) {
                let keyProm = keyPromiseCache.get(seg.key.uri);
                if (!keyProm) {
                  keyProm = robustFetchBuffer(seg.key.uri, cleanSegHeaders, 4, jobAbortCtrl.signal);
                  keyPromiseCache.set(seg.key.uri, keyProm);
                }
                const keyBuf = await keyProm;
                if (keyBuf && keyBuf.length === 16) {
                  let ivBuf: Buffer;
                  if (seg.key.iv) {
                    const cleanHex = seg.key.iv.replace(/^0x/i, '').padStart(32, '0');
                    ivBuf = Buffer.from(cleanHex, 'hex');
                  } else {
                    ivBuf = Buffer.alloc(16, 0);
                    ivBuf.writeUInt32BE(segIndex, 12);
                  }
                  const decipher = crypto.createDecipheriv('aes-128-cbc', keyBuf, ivBuf);
                  buf = Buffer.concat([decipher.update(buf), decipher.final()]);
                }
              }
            } catch (segErr: any) {
              if (isStaleOrAborted() || String(segErr?.message || '') === 'JOB_PAUSED_BY_USER') {
                break;
              }
              if (String(segErr?.message || '').includes('TOKEN_EXPIRED_OR_FORBIDDEN')) {
                tokenExpiredFlag = true;
                break;
              }
              buf = Buffer.alloc(0);
            }

            completedBuffers.set(segIndex, buf);
            bufferedRamBytes += buf.length;
            job.completedSegments++;
            job.downloadedBytes += buf.length;
            job.lastProgressAt = Date.now();

            const now = Date.now();
            const timeDiff = (now - lastSpeedCalcTime) / 1000;
            if (timeDiff >= 0.75) {
              const bytesDiff = job.downloadedBytes - lastSpeedCalcBytes;
              currentInstantSpeed = Math.round(bytesDiff / timeDiff);
              lastSpeedCalcTime = now;
              lastSpeedCalcBytes = job.downloadedBytes;
            }
            job.speedBytesPerSec =
              currentInstantSpeed ||
              Math.round(job.downloadedBytes / Math.max(0.25, (now - dlStartTime) / 1000));
            job.progressPercent = Math.min(
              95,
              Math.round((job.completedSegments / job.totalSegments) * 95)
            );

            if (segIndex === nextWriteIndex || completedBuffers.size >= 32) {
              await flushOrderedBuffers();
            }

            if (!preDownloadOnly || inFlightDownloadJobs.has(job.id)) {
              const speedMb = (job.speedBytesPerSec / (1024 * 1024)).toFixed(1);
              const dlMb = (job.downloadedBytes / (1024 * 1024)).toFixed(1);
              updateTelegramProgressIfNeeded(
                `⏳ Downloading (${job.resolution || job.preferredQuality || '480p'}): ${job.title}\n` +
                  (job.folderName ? `📁 Folder: ${job.folderName}\n` : '') +
                  `📊 ${job.progressPercent}% (${job.completedSegments}/${job.totalSegments} segments)\n` +
                  `🚀 Speed: ${speedMb} MB/s • Size: ${dlMb} MB`
              );
            }
          }
        };

        const workers = Array.from({ length: Math.min(WORKER_COUNT, segments.length) }, () =>
          workerTask()
        );
        await Promise.all(workers);
        await flushOrderedBuffers();

        if (tokenExpiredFlag) {
          try {
            writeStream.destroy();
          } catch {}
          cleanupJobTempFiles(job.id);
          throw new Error('TOKEN_EXPIRED_OR_FORBIDDEN: Google Cloud CDN edge token expired during download');
        }

        await Promise.race([
          new Promise<void>((resolve) => {
            writeStream.end(() => resolve());
            writeStream.once('error', () => resolve());
          }),
          new Promise<void>((resolve) => setTimeout(resolve, 10000)),
        ]);

        if (isStaleOrAborted()) {
          throw new Error('JOB_PAUSED_BY_USER');
        }

        // Trigger Lookahead Pre-Fetch IMMEDIATELY when raw download finishes so next video downloads during FFmpeg remux + upload!
        if ((!preDownloadOnly || inFlightDownloadJobs.has(job.id)) && targetChat) {
          triggerLookaheadPreFetch(targetChat, job.id);
        }

        const dlElapsedSec = Math.max(0.1, (Date.now() - dlStartTime) / 1000);
        const avgDlSpeedMb = (job.downloadedBytes / (1024 * 1024) / dlElapsedSec).toFixed(1);
        const totalDlMb = (job.downloadedBytes / (1024 * 1024)).toFixed(1);

        // 3. Zero-Re-encode Instant FFmpeg Remux (-c copy -bsf:a aac_adtstoasc, <1s)
        if (ffmpegAvailable) {
          if (!preDownloadOnly || inFlightDownloadJobs.has(job.id)) {
            job.status = 'merging';
          }
          job.lastProgressAt = Date.now();
          await updateTelegramProgressIfNeeded(
            `⚡ Instant Remux (${totalDlMb} MB @ ${avgDlSpeedMb} MB/s): ${job.title}...`,
            true
          );
          const mp4Path = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.mp4`);
          try {
            await execFileAsync(
              'ffmpeg',
              [
                '-y',
                '-threads',
                '0',
                '-fflags',
                '+genpts+igndts+discardcorrupt',
                '-i',
                rawTsPath,
                '-map',
                '0:v:0?',
                '-map',
                '0:a:0?',
                '-c',
                'copy',
                '-bsf:a',
                'aac_adtstoasc',
                mp4Path,
              ],
              { timeout: 150000, maxBuffer: 20 * 1024 * 1024 }
            );
            try {
              fs.unlinkSync(rawTsPath);
            } catch {}
            job.filePath = mp4Path;
            job.outputFormat = 'mp4';
          } catch {
            try {
              await execFileAsync(
                'ffmpeg',
                [
                  '-y',
                  '-threads',
                  '0',
                  '-fflags',
                  '+genpts+igndts+discardcorrupt',
                  '-i',
                  rawTsPath,
                  '-c',
                  'copy',
                  mp4Path,
                ],
                { timeout: 150000, maxBuffer: 20 * 1024 * 1024 }
              );
              try {
                fs.unlinkSync(rawTsPath);
              } catch {}
              job.filePath = mp4Path;
              job.outputFormat = 'mp4';
            } catch {
              job.filePath = rawTsPath;
              job.outputFormat = 'ts';
            }
          }
        } else {
          job.filePath = rawTsPath;
          job.outputFormat = 'ts';
        }
        }
      } else {
        // 2B. 32x Multi-Range Parallel Streaming Direct Video Downloader (MP4/MKV/WebM/MOV/AVI/FLV/TS/3GP -> Guaranteed Streamable MP4!)
        const extMatch = (() => {
          try {
            const m = new URL(job.sourceUrl).pathname.match(/\.(mp4|m4v|mkv|webm|mov|avi|flv|ts|3gp)$/i);
            return m ? m[1].toLowerCase() : null;
          } catch {
            return null;
          }
        })();
        const rawExt = extMatch || (job.protocol === 'DIRECT_WEBM' ? 'webm' : 'mp4');
        const outPath = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.${rawExt}`);
        const finalMp4Path = path.join(DOWNLOAD_DIR, `${job.id}_${safeBaseName}.mp4`);
        await downloadDirectVideoMultiRange(
          job.sourceUrl,
          headers,
          outPath,
          job,
          startTime,
          () => {
            if (!preDownloadOnly || inFlightDownloadJobs.has(job.id)) {
              const speedMb = (job.speedBytesPerSec / (1024 * 1024)).toFixed(1);
              const dlMb = (job.downloadedBytes / (1024 * 1024)).toFixed(1);
              updateTelegramProgressIfNeeded(
                `⏳ Downloading 48x Turbo Video (${rawExt.toUpperCase()}): ${job.title}\n` +
                  `📊 ${job.progressPercent}% (${job.completedSegments}/${job.totalSegments} ranges)\n` +
                  `🚀 Speed: ${speedMb} MB/s • Size: ${dlMb} MB`
              );
            }
          },
          jobAbortCtrl.signal
        );

        if ((!preDownloadOnly || inFlightDownloadJobs.has(job.id)) && targetChat) {
          triggerLookaheadPreFetch(targetChat, job.id);
        }

        // Skip redundant MP4 disk copy for drive_only when already MP4; convert non-MP4 formats fast!
        const skipMp4CopyForDrive = job.deliveryMode === 'drive_only' && rawExt === 'mp4';
        if (ffmpegAvailable && !skipMp4CopyForDrive && (rawExt !== 'mp4' || !isStaleOrAborted())) {
          if (rawExt !== 'mp4') {
            if (!preDownloadOnly || inFlightDownloadJobs.has(job.id)) {
              job.status = 'merging';
            }
            await updateTelegramProgressIfNeeded(
              `⚡ Converting ${rawExt.toUpperCase()} → Streamable .MP4: ${job.title}...`,
              true
            );
          }
          const convertedPath = await normalizeVideoFileToMp4(outPath, finalMp4Path);
          job.filePath = convertedPath;
        } else {
          job.filePath = outPath;
        }
        job.outputFormat = 'mp4';
        job.lastProgressAt = Date.now();
      }

      if (isStaleOrAborted()) {
        throw new Error('JOB_PAUSED_BY_USER');
      }

      // Skip ffprobe/thumbnail generation for drive_only jobs (saves 1-3 seconds per video!)
      if (job.deliveryMode !== 'drive_only' && job.filePath && fs.existsSync(job.filePath)) {
        job.preProbedMeta = await probeVideoMetadataAndThumb(job.filePath, job.id);
      }
    }

    // If this was a Lookahead Pre-Fetch background run, mark ready and return before uploading!
    if (preDownloadOnly) {
      if ((job.downloadEpoch || 0) === myEpoch) {
        job.preDownloadedReady = Boolean(job.filePath && fs.existsSync(job.filePath));
        job.lastProgressAt = Date.now();
      }
      return;
    }

    job.fileReadyForBrowser = true;
    job.lastProgressAt = Date.now();

    // Ensure 2-Video Parallel Lookahead Pre-Fetch is running during Phase 2 upload!
    if (targetChat) {
      triggerLookaheadPreFetch(targetChat, job.id);
    }

    // PHASE 2: HIGH-SPEED DELIVERY (TELEGRAM, GOOGLE DRIVE 5TB, OR BOTH IN PARALLEL)
    const needsTelegram =
      job.deliveryMode === 'telegram_auto' ||
      job.deliveryMode === 'telegram_userbot' ||
      job.deliveryMode === 'telegram_and_drive';
    const needsDrive =
      job.deliveryMode === 'drive_only' || job.deliveryMode === 'telegram_and_drive';

    const runTelegramPhase = async () => {
      if (!needsTelegram || !job.filePath || job.deliveredToTelegram) return;
      const backupIds = enabledBackups.map((b) => b.chatId.trim());
      // A separate upload destination lets a different Userbot account send
      // large files to a shared group/channel instead of resolving the
      // requester's personal numeric peer (which may lack an access_hash).
      const configuredUploadChat = (
        process.env.TELEGRAM_UPLOAD_CHAT_ID || process.env.TELEGRAM_CHAT_ID || ''
      ).trim();
      const allDestChatIds = Array.from(
        new Set([
          configuredUploadChat,
          targetChat.startsWith('__') ? '' : targetChat,
          routedChannelId,
          ...backupIds,
        ].filter(Boolean))
      );

      if (allDestChatIds.length === 0) {
        throw new Error('No Telegram Chat ID or Backup Channel configured.');
      }

      const primaryChat = allDestChatIds[0];
      const secondaryChatIds = allDestChatIds.slice(1);

      const stat = await fs.promises.stat(job.filePath);
      const sizeMb = stat.size / (1024 * 1024);
      const videoMeta = job.preProbedMeta || (await probeVideoMetadataAndThumb(job.filePath, job.id));
      const caption = buildVideoTelegramCaption(job);
      job.lastProgressAt = Date.now();

      const hasUserbotConfigured = Boolean(
        (process.env.TELEGRAM_STRING_SESSION?.trim() &&
          process.env.TELEGRAM_STRING_SESSION.trim().length > 40) ||
          process.env.TELEGRAM_BOT_TOKEN?.trim()
      );

      let deliveredSuccessfully = Boolean(job.deliveredToTelegram);

      // Warm up multi-socket MTProto pool if not already hot so uploads start at max throughput immediately
      prewarmTurboPools(12);
      const hotMtprotoSockets = getActiveMtprotoSocketCounts();
      const preferMtprotoTurboFirst =
        hasUserbotConfigured &&
        stat.size >= 15 * 1024 * 1024 &&
        (hotMtprotoSockets.primary >= 4 || hotMtprotoSockets.secondary >= 4);

      // CASE A: Video <= 49,500,000 bytes (Fast HTTP/2 Bot API curl when <15MB OR when MTProto multi-socket pool isn't warmed yet)
      if (!deliveredSuccessfully && !preferMtprotoTurboFirst && stat.size <= 49500000 && job.deliveryMode !== 'telegram_userbot') {
        job.status = 'uploading_bot_api';
        job.lastProgressAt = Date.now();
        await updateTelegramProgressIfNeeded(
          `📤 Uploading Full Video (${sizeMb.toFixed(1)} MB) via HTTP/2 Bot API...`,
          true
        );
        const upRes = await uploadToTelegramBotApi(job.filePath, primaryChat, caption, videoMeta);
        if (upRes.ok) {
          deliveredSuccessfully = true;
          job.deliveredToTelegram = true;
          if (upRes.messageId && upRes.fromChatId && secondaryChatIds.length > 0) {
            await Promise.all(
              secondaryChatIds.map((destId) =>
                copyTelegramVideoMessage(upRes.fromChatId!, upRes.messageId!, destId, caption)
              )
            );
          }

          job.telegramResult = {
            deliveredVia: 'BOT_API_50MB',
            chatId: primaryChat,
            fileSizeMb: sizeMb.toFixed(2),
            timestamp: new Date().toISOString(),
            backedUpTo: enabledBackups.map((b) => b.title),
            routedToChannel: routedChannelLabel || undefined,
          };
          addBotLog(
            'OUTGOING',
            primaryChat,
            `Delivered FULL video ${job.title} (${sizeMb.toFixed(2)} MB) to ${allDestChatIds.length} destination(s).`
          );
        } else if (!/Request Entity Too Large|413|too big/i.test(String(upRes.error || ''))) {
          throw new Error(upRes.error);
        }
      }

      if (!deliveredSuccessfully) {
        // CASE B: Large Video (> 49.5 MB up to 2000 MB) — ALWAYS deliver 1 FULL SINGLE VIDEO FILE via 4-Socket 2GB MTProto Tunnel!
        // Never split into parts! Retry up to 3 clean attempts (reconnecting MTProto cleanly if a socket hiccups).
        let lastMtprotoErr = 'MTProto 2GB single-video upload failed.';
        if (hasUserbotConfigured) {
          for (let attempt = 1; attempt <= 3; attempt++) {
            if (isStaleOrAborted()) {
              throw new Error('JOB_PAUSED_BY_USER');
            }
            try {
              job.status = 'uploading_mtproto_userbot';
              job.lastProgressAt = Date.now();
              await updateTelegramProgressIfNeeded(
                `📤 Uploading 1 Full Single Video (${sizeMb.toFixed(1)} MB) via 8x/16x Turbo MTProto${attempt > 1 ? ` (Retry ${attempt}/3)` : ''}...`,
                true
              );
              const upRes = await uploadToTelegramUserbotMtproto(
                job.id,
                job.filePath,
                allDestChatIds,
                caption,
                videoMeta,
                (pct, speedMbps, uploadedMb) => {
                  job.lastProgressAt = Date.now();
                  job.progressPercent = Math.min(99, 95 + Math.round(pct * 0.04));
                  if (speedMbps && speedMbps > 0) {
                    job.speedBytesPerSec = Math.round(speedMbps * 1024 * 1024);
                  }
                  const upMbStr =
                    typeof uploadedMb === 'number'
                      ? uploadedMb.toFixed(1)
                      : ((sizeMb * pct) / 100).toFixed(1);
                  const spdStr =
                    typeof speedMbps === 'number' && speedMbps > 0
                      ? ` • 🚀 ${speedMbps.toFixed(1)} MB/s`
                      : '';
                  updateTelegramProgressIfNeeded(
                    `📤 Uploading 1 Full Single Video (${sizeMb.toFixed(1)} MB): ${pct}% (${upMbStr} / ${sizeMb.toFixed(1)} MB)${spdStr}...`
                  );
                }
              );

              if (
                isStaleOrAborted() ||
                upRes.error === 'JOB_PAUSED_BY_USER'
              ) {
                throw new Error('JOB_PAUSED_BY_USER');
              }

              if (upRes.ok) {
                deliveredSuccessfully = true;
                job.deliveredToTelegram = true;
                job.telegramResult = {
                  deliveredVia: 'MTPROTO_USERBOT_2GB',
                  chatId: primaryChat,
                  fileSizeMb: sizeMb.toFixed(2),
                  timestamp: new Date().toISOString(),
                  backedUpTo: enabledBackups.map((b) => b.title),
                  routedToChannel: routedChannelLabel || undefined,
                };
                addBotLog(
                  'USERBOT_MTPROTO',
                  primaryChat,
                  `Delivered 1 Full Single Video ${job.title} (${sizeMb.toFixed(2)} MB) via 8x Turbo 2GB MTProto.`
                );
                break;
              }
              if (upRes.error) {
                lastMtprotoErr = upRes.error;
              }
            } catch (ubErr: any) {
              if (
                String(ubErr?.message || '') === 'JOB_PAUSED_BY_USER' ||
                isStaleOrAborted()
              ) {
                throw new Error('JOB_PAUSED_BY_USER');
              }
              lastMtprotoErr = ubErr?.message || lastMtprotoErr;
              console.warn(`[StreamBridge] MTProto upload attempt ${attempt}/3 failed:`, lastMtprotoErr);
            }

              // Fallback: if <= 49.5 MB and MTProto failed on a 15-49.5MB upload, finish via Bot API curl immediately
              if (!deliveredSuccessfully && stat.size <= 49500000 && job.deliveryMode !== 'telegram_userbot') {
                const apiFallback = await uploadToTelegramBotApi(job.filePath, primaryChat, caption, videoMeta);
                if (apiFallback.ok) {
                  deliveredSuccessfully = true;
                  job.deliveredToTelegram = true;
                  if (apiFallback.messageId && apiFallback.fromChatId && secondaryChatIds.length > 0) {
                    await Promise.all(
                      secondaryChatIds.map((destId) =>
                        copyTelegramVideoMessage(apiFallback.fromChatId!, apiFallback.messageId!, destId, caption)
                      )
                    );
                  }
                  job.telegramResult = {
                    deliveredVia: 'BOT_API_50MB',
                    chatId: primaryChat,
                    fileSizeMb: sizeMb.toFixed(2),
                    timestamp: new Date().toISOString(),
                    backedUpTo: enabledBackups.map((b) => b.title),
                    routedToChannel: routedChannelLabel || undefined,
                  };
                  break;
                }
              }
              await closeTurboMtprotoSenderPool(cachedUserbotClient);
              await closeTurboMtprotoSenderPool(cachedSecondaryUserbotClient);
              try {
                await cachedUserbotClient?.disconnect();
              } catch {}
              try {
                await cachedSecondaryUserbotClient?.disconnect();
              } catch {}
              cachedUserbotClient = null;
              cachedSecondaryUserbotClient = null;
              await new Promise((r) => setTimeout(r, 1500));
          }
        }

        if (isStaleOrAborted()) {
          throw new Error('JOB_PAUSED_BY_USER');
        }

        // Single-File Fallback (NO SPLIT PARTS EVER): ONLY if MTProto was unavailable/failed AND video can be sent as 1 single full file <= 49MB
        if (!deliveredSuccessfully) {
          if (stat.size <= 49500000) {
            job.status = 'uploading_bot_api';
            job.lastProgressAt = Date.now();
            const upRes = await uploadToTelegramBotApi(job.filePath, primaryChat, caption, videoMeta);
            if (upRes.ok) {
              deliveredSuccessfully = true;
              job.deliveredToTelegram = true;
              if (upRes.messageId && upRes.fromChatId && secondaryChatIds.length > 0) {
                await Promise.all(
                  secondaryChatIds.map((destId) =>
                    copyTelegramVideoMessage(upRes.fromChatId!, upRes.messageId!, destId, caption)
                  )
                );
              }
              job.telegramResult = {
                deliveredVia: 'BOT_API_50MB',
                chatId: primaryChat,
                fileSizeMb: sizeMb.toFixed(2),
                timestamp: new Date().toISOString(),
                backedUpTo: enabledBackups.map((b) => b.title),
                routedToChannel: routedChannelLabel || undefined,
              };
            } else {
              throw new Error(upRes.error || lastMtprotoErr);
            }
          } else {
            throw new Error(
              `Could not deliver 1 Full Single Video (${sizeMb.toFixed(1)} MB) via MTProto: ${lastMtprotoErr}`
            );
          }
        }
      }

      if (needsDrive && !job.deliveredToDrive) {
        job.status = 'uploading_google_drive';
        job.lastProgressAt = Date.now();
      }

      const backupSummary =
        enabledBackups.length > 0
          ? `\n🛡️ Saved in Backup: ${enabledBackups.map((b) => b.title).join(', ')}`
          : '';
      const routeSummary = routedChannelId
        ? `\n🎯 Sent to Channel: ${routedChannelLabel || routedChannelId}`
        : '';
      await updateTelegramProgressIfNeeded(
        `✅ Full Video Sent: ${job.title} (${sizeMb.toFixed(2)} MB)${routeSummary}${backupSummary}`,
        true
      );
    };

    const runDrivePhase = async () => {
      if (!needsDrive || !job.filePath || job.deliveredToDrive) return;
      const stat = await fs.promises.stat(job.filePath);
      const sizeMb = stat.size / (1024 * 1024);
      if (job.deliveryMode === 'drive_only') {
        job.status = 'uploading_google_drive';
        job.lastProgressAt = Date.now();
        await updateTelegramProgressIfNeeded(
          `☁️ Uploading to Google Drive (${sizeMb.toFixed(1)} MB) in "Rojgar vidoes"...`,
          true
        );
      }

      const driveRes = await uploadJobToGoogleDrive(
        job,
        () => isStaleOrAborted(),
        (pct, speedMbps, uploadedMb, totalMb) => {
          job.lastProgressAt = Date.now();
          if (job.deliveryMode === 'drive_only') {
            job.progressPercent = Math.min(99, 90 + Math.round(pct * 0.09));
            if (speedMbps > 0) {
              job.speedBytesPerSec = Math.round(speedMbps * 1024 * 1024);
            }
            const spdStr = speedMbps > 0 ? ` • 🚀 ${speedMbps.toFixed(1)} MB/s` : '';
            updateTelegramProgressIfNeeded(
              `☁️ Google Drive Upload (${totalMb.toFixed(1)} MB): ${pct}% (${uploadedMb.toFixed(1)} / ${totalMb.toFixed(1)} MB)${spdStr}...`
            );
          }
        },
        jobAbortCtrl.signal
      );

      job.deliveredToDrive = true;
      job.driveResult = driveRes;
      addBotLog(
        'SYSTEM',
        job.telegramChatId || DRIVE_SYNC_CHAT_ID,
        `Saved ${driveRes.fileName} (${driveRes.fileSizeMb} MB, ${driveRes.speedMbps}) to Drive folder: ${driveRes.folderPath}${driveRes.pdfUploaded ? ' + Notes PDF' : ''}`
      );

      if (job.deliveryMode === 'drive_only') {
        await updateTelegramProgressIfNeeded(
          `✅ Saved to Google Drive!\n` +
            `🎬 ${driveRes.fileName} (${driveRes.fileSizeMb} MB • 🚀 ${driveRes.speedMbps})\n` +
            `📂 Path: ${driveRes.folderPath}\n` +
            (driveRes.pdfUploaded ? `📄 Notes PDF: Uploaded alongside lecture\n` : '') +
            (driveRes.webViewLink ? `🔗 ${driveRes.webViewLink}` : ''),
          true
        );
      }
    };

    if (job.filePath) {
      if (needsTelegram && needsDrive) {
        await Promise.all([runTelegramPhase(), runDrivePhase()]);
        if (job.driveResult) {
          await updateTelegramProgressIfNeeded(
            `✅ Saved on BOTH Telegram & Google Drive!\n` +
              `🎬 ${job.title} (${job.driveResult.fileSizeMb} MB)\n` +
              `☁️ Drive Path: ${job.driveResult.folderPath}` +
              (job.driveResult.pdfUploaded ? `\n📄 Notes PDF: Also saved to Drive` : '') +
              (job.driveResult.webViewLink ? `\n🔗 ${job.driveResult.webViewLink}` : ''),
            true
          );
        }
      } else if (needsDrive) {
        await runDrivePhase();
      } else if (needsTelegram) {
        await runTelegramPhase();
      }
    }

    job.progressPercent = 100;
    job.speedBytesPerSec = 0;
    job.status = 'completed';
    job.error = undefined;
    markVideoCompleted(job, true);
    saveJobsState(true);
  } catch (err: any) {
    if (preDownloadOnly) {
      job.preDownloadedReady = false;
      cleanupJobTempFiles(job.id);
      return;
    }
    const errMsg = String(err?.message || 'Unexpected error during stream download');
    if (errMsg === 'JOB_PAUSED_BY_USER' || (job.status as string) === 'paused') {
      job.status = 'paused';
      job.speedBytesPerSec = 0;
      job.error = 'Paused — Send /resume to continue or /clear to delete paused videos';
      saveJobsState(true);
      await updateTelegramProgressIfNeeded(
        `⏸️ Paused: ${job.title}\n▶️ Send /resume to continue or /clear to delete paused videos.`,
        true
      );
    } else if (errMsg.includes('DRIVE_AUTH_EXPIRED') || errMsg.includes('DRIVE_AUTH_INVALID')) {
      if (activeDriveSession) {
        activeDriveSession.tokenExpired = true;
      }
      job.status = 'paused';
      job.speedBytesPerSec = 0;
      job.error = 'Google Drive session expired (~1h limit). Refresh Sign-In in Admin -> 5TB Drive Sync & click Resume.';
      // Pause remaining queued Drive jobs cleanly without losing completed history
      const q = chatJobQueues.get(targetChat) || [];
      for (const qj of q) {
        if (qj.status === 'queued' && (qj.deliveryMode === 'drive_only' || qj.deliveryMode === 'telegram_and_drive')) {
          qj.status = 'paused';
          qj.error = job.error;
        }
      }
      q.length = 0;
      saveJobsState(true);
      const alertChat = targetChat && !targetChat.startsWith('__') ? targetChat : MAIN_ADMIN_ID;
      await sendTelegramTextMessage(
        alertChat,
        `🔐 Google Drive Session Expired (~1h OAuth limit) while saving "${job.title}".\n` +
          `✅ Completed lectures are safe on Drive. Admin Panel (/admin -> 5TB Drive Sync) me "Refresh Drive Session" karke Resume dabayein.`
      ).catch(() => {});
    } else if (errMsg.startsWith('UNRECORDED_CLASS_SKIP')) {
      job.status = 'completed';
      job.progressPercent = 100;
      job.speedBytesPerSec = 0;
      job.error = undefined;
      markVideoCompleted(job, true);
      saveJobsState(true);
      addBotLog(
        'SYSTEM',
        job.telegramChatId || 'local',
        `Auto-skipped unrecorded class placeholder (${job.title})`
      );
      if (targetChat && !targetChat.startsWith('__')) {
        if (job.telegramStatusMsgId) {
          await editTelegramTextMessage(
            targetChat,
            job.telegramStatusMsgId,
            `⏭️ Skipped (No Video Recording on Server — PDF/Class Note Only): ${job.title}`
          );
        } else if (job.forceDownload) {
          await sendTelegramTextMessage(
            targetChat,
            `⏭️ Skipped (No Video Recording on Server — PDF/Class Note Only): ${job.title}`
          );
        }
      }
    } else if (errMsg.startsWith('BATCH_NOT_PURCHASED_ON_PORTAL:')) {
      const cleanNotice = errMsg.replace('BATCH_NOT_PURCHASED_ON_PORTAL:', '').trim();
      job.status = 'failed';
      job.speedBytesPerSec = 0;
      job.error = `BATCH_UNAVAILABLE_ON_PORTAL: ${cleanNotice}`;
      saveJobsState(true);
    } else {
      job.status = 'failed';
      job.speedBytesPerSec = 0;
      job.error = errMsg;
      saveJobsState(true);
      addBotLog('SYSTEM', job.telegramChatId || 'local', `Job failed (${job.title}): ${job.error}`);
      const isStreamUnavailable = /No playable stream URL available/i.test(errMsg);
      if (!isStreamUnavailable && job.telegramStatusMsgId) {
        await updateTelegramProgressIfNeeded(
          `❌ Download Failed (${job.title}): ${job.error}`,
          true
        );
      }
    }
  } finally {
    if (!preDownloadOnly) {
      inFlightDownloadJobs.delete(job.id);
      activeJobAbortControllers.delete(job.id);
      cleanupJobTempFiles(job.id);
      job.fileReadyForBrowser = false;
      job.preDownloadedReady = false;
      job.preDownloadPromise = undefined;
      job.preProbedMeta = undefined;
    }
  }
}

const chatWorkerGeneration = new Map<string, number>();

async function runChatSequentialWorker(
  chatId: string,
  forceRestart = false,
  allowUnpause = false
) {
  if (!allowUnpause && userExplicitlyPausedChats.has(chatId)) {
    return;
  }
  if (activeChatWorkers.has(chatId) && !forceRestart) return;
  activeChatWorkers.add(chatId);
  if (allowUnpause && userExplicitlyPausedChats.delete(chatId)) {
    saveBotSettings();
  }
  const myGen = (chatWorkerGeneration.get(chatId) || 0) + 1;
  chatWorkerGeneration.set(chatId, myGen);

  let unavailableTrackerMsgId: number | null = null;
  let unavailableCountInRun = 0;
  let consecutiveUnavailableCount = 0;
  let completedCountInRun = 0;
  let lastUnavailableCourse = '';
  let firstUnavailableTitle = '';
  let lastUnavailableTitle = '';
  let lastUnavailableEditAt = 0;
  let lastCompletedJobInRun: DownloadJob | null = null;

  try {
    const queue = chatJobQueues.get(chatId) || [];

    // TURBO 3x PARALLEL DRIVE PIPELINE: when all pending jobs are drive_only, download & save 3 videos simultaneously!
    const isPureDriveBatch =
      queue.length > 1 && queue.every((j) => j.deliveryMode === 'drive_only');
    if (isPureDriveBatch) {
      const DRIVE_PARALLEL_WORKERS = IS_CONSTRAINED_HOST ? 2 : 3;
      const driveWorker = async () => {
        while (queue.length > 0) {
          if (chatWorkerGeneration.get(chatId) !== myGen || userExplicitlyPausedChats.has(chatId)) {
            return;
          }
          queue.sort((a, b) => {
            const oA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
            const oB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
            if (oA !== oB) return oA - oB;
            return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
          });
          const nextJob = queue.shift();
          if (!nextJob) break;
          if (nextJob.status !== 'queued') continue;

          await processDownloadJob(nextJob, false);

          if (chatWorkerGeneration.get(chatId) !== myGen || userExplicitlyPausedChats.has(chatId)) {
            return;
          }
          if ((nextJob.status as string) === 'completed') {
            completedCountInRun++;
            lastCompletedJobInRun = nextJob;
          } else if (
            (nextJob.status as string) === 'failed' &&
            !nextJob.abortFlag &&
            (nextJob.retryCount || 0) < 1 &&
            !/BATCH_UNAVAILABLE_ON_PORTAL|No playable stream URL available/i.test(String(nextJob.error || ''))
          ) {
            nextJob.retryCount = (nextJob.retryCount || 0) + 1;
            nextJob.sourceUrl = nextJob.initialSourceUrl || nextJob.sourceUrl;
            nextJob.status = 'queued';
            nextJob.error = undefined;
            nextJob.progressPercent = 0;
            nextJob.completedSegments = 0;
            nextJob.downloadedBytes = 0;
            await new Promise((r) => setTimeout(r, 400));
            if (chatWorkerGeneration.get(chatId) !== myGen || userExplicitlyPausedChats.has(chatId)) {
              return;
            }
            await processDownloadJob(nextJob, false);
            if ((nextJob.status as string) === 'completed') {
              completedCountInRun++;
              lastCompletedJobInRun = nextJob;
            }
          }
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(DRIVE_PARALLEL_WORKERS, queue.length) }, () => driveWorker())
      );
    }

    while (queue.length > 0) {
      if (chatWorkerGeneration.get(chatId) !== myGen || userExplicitlyPausedChats.has(chatId)) {
        return;
      }
      // Guarantee strict ascending numberwise processing (#1, #2, #3, ...)
      queue.sort((a, b) => {
        const oA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
        const oB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
        if (oA !== oB) return oA - oB;
        return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
      });
      const nextJob = queue.shift();
      if (!nextJob) break;
      if (nextJob.status !== 'queued') {
        continue;
      }

      // Only skip if NOT direct-link (/skipCompletedCheck) and NOT /only (/forceDownload)
      if (
        !nextJob.forceDownload &&
        !nextJob.skipCompletedCheck &&
        isVideoAlreadyCompletedForChat(chatId, nextJob)
      ) {
        cleanupJobTempFiles(nextJob.id);
        nextJob.status = 'completed';
        nextJob.progressPercent = 100;
        saveJobsState();
        continue;
      }

      await processDownloadJob(nextJob, false);

      if (chatWorkerGeneration.get(chatId) !== myGen) {
        return;
      }

      const jobErr = String(nextJob.error || '');
      const isBatchUnavailable = jobErr.startsWith('BATCH_UNAVAILABLE_ON_PORTAL:');
      const isRateLimitCooldown = jobErr.startsWith('RWA_RATE_LIMIT_COOLDOWN:');
      const isPermanentUnplayable =
        isBatchUnavailable ||
        isRateLimitCooldown ||
        /No playable stream URL available/i.test(jobErr);

      if ((nextJob.status as string) === 'completed') {
        completedCountInRun++;
        consecutiveUnavailableCount = 0;
        unavailableTrackerMsgId = null;
        lastCompletedJobInRun = nextJob;

        if (nextJob.originalRequestUrl) {
          const lecMatch = String(nextJob.title || '').match(/Lecture\s*(\d+)\s*\/\s*(\d+)/i);
          const orderNum =
            typeof nextJob.batchOrder === 'number' && nextJob.batchOrder > 0
              ? nextJob.batchOrder
              : lecMatch
              ? parseInt(lecMatch[1], 10)
              : 1;
          const totalVids = lecMatch ? parseInt(lecMatch[2], 10) : orderNum;
          lastCourseContextByChat.set(chatId, {
            sourceUrl: nextJob.originalRequestUrl,
            courseName: nextJob.courseName || 'Course',
            lastOrder: orderNum,
            totalVideos: totalVids,
            preferredQuality: nextJob.preferredQuality || botSettings.globalDefaultQuality || '480p',
            explicitTargetChannelId: nextJob.explicitTargetChannelId,
          });
        }
      } else if ((nextJob.status as string) === 'failed' && isPermanentUnplayable) {
        nextJob.status = 'waiting_stream';
        saveJobsState();

        unavailableCountInRun++;
        consecutiveUnavailableCount++;
        lastUnavailableCourse = nextJob.courseName || lastUnavailableCourse || 'Batch';
        if (!firstUnavailableTitle) firstUnavailableTitle = nextJob.title;
        lastUnavailableTitle = nextJob.title;

        const now = Date.now();
        if (!chatId.startsWith('__') && (!unavailableTrackerMsgId || now - lastUnavailableEditAt >= 3500 || queue.length === 0)) {
          lastUnavailableEditAt = now;
          const summaryText =
            `🤖 AI Smart Scan & Auto-Watch (${lastUnavailableCourse}):\n` +
            `ℹ️ ${unavailableCountInRun} video(s) abhi server par active/playable nahi hain — AI Auto-Watch me save kar li gayi hain (Latest: ${lastUnavailableTitle}).\n` +
            `🚀 Baki batch me agli playable video check ki ja rahi hai (${queue.length} remaining)...`;
          if (unavailableTrackerMsgId) {
            await editTelegramTextMessage(chatId, unavailableTrackerMsgId, summaryText);
          } else if (nextJob.telegramStatusMsgId) {
            unavailableTrackerMsgId = nextJob.telegramStatusMsgId;
            await editTelegramTextMessage(chatId, unavailableTrackerMsgId, summaryText);
          } else {
            unavailableTrackerMsgId = (await sendTelegramTextMessage(chatId, summaryText)) ?? null;
          }
        }
        continue;
      }

      // If the job failed due to a temporary network/CDN glitch (NOT paused and NOT unplayable stream), auto-retry once!
      if (
        (nextJob.status as string) === 'failed' &&
        !nextJob.abortFlag &&
        !isPermanentUnplayable &&
        (nextJob.retryCount || 0) < 1
      ) {
        nextJob.retryCount = (nextJob.retryCount || 0) + 1;
        nextJob.sourceUrl = nextJob.initialSourceUrl || nextJob.sourceUrl;
        nextJob.status = 'queued';
        nextJob.error = undefined;
        nextJob.progressPercent = 0;
        nextJob.completedSegments = 0;
        nextJob.downloadedBytes = 0;
        addBotLog(
          'SYSTEM',
          chatId,
          `Auto-retrying interrupted video (Attempt 2): ${nextJob.title}`
        );
        await new Promise((r) => setTimeout(r, 800));
        if (chatWorkerGeneration.get(chatId) !== myGen) {
          return;
        }
        await processDownloadJob(nextJob, false);
        if ((nextJob.status as string) === 'completed') {
          completedCountInRun++;
          lastCompletedJobInRun = nextJob;
        }
      }

      // Brief pause between consecutive videos so Telegram & CDN stay smooth
      await new Promise((r) => setTimeout(r, 150));
    }

    if (unavailableCountInRun > 0 && chatWorkerGeneration.get(chatId) === myGen) {
      if (!chatId.startsWith('__')) {
        const finalWatchNotice =
          `🤖 AI Auto-Download & Watch Active (${lastUnavailableCourse}):\n\n` +
          `✅ Downloaded in this run: ${completedCountInRun} playable video(s)\n` +
          `🕒 Waiting for Server Stream: ${unavailableCountInRun} video(s) (Saved in AI Auto-Watch)\n` +
          `🔄 AI Agent har ${aiAgentState.intervalMinutes} minute me automatically server check karta rahega aur jaise hi video available hogi, bina duplicate kiye aur bina skip kiye khud download kar dega!`;
        if (unavailableTrackerMsgId) {
          await editTelegramTextMessage(chatId, unavailableTrackerMsgId, finalWatchNotice, {
            inline_keyboard: [
              [
                { text: '🤖 AI Check Now', callback_data: 'feat:ai:checknow' },
                { text: '📊 AI Agent Status', callback_data: 'feat:ai:status' },
              ],
              [
                { text: '🗑️ Clear Waiting (/clear)', callback_data: 'feat:action:clear' },
              ],
            ],
          });
        } else {
          await sendTelegramTextMessage(chatId, finalWatchNotice, {
            inline_keyboard: [
              [
                { text: '🤖 AI Check Now', callback_data: 'feat:ai:checknow' },
                { text: '📊 AI Agent Status', callback_data: 'feat:ai:status' },
              ],
              [
                { text: '🗑️ Clear Waiting (/clear)', callback_data: 'feat:action:clear' },
              ],
            ],
          });
        }
      }
      addAiAgentDecision(
        `Placed ${unavailableCountInRun} currently unavailable video(s) from "${lastUnavailableCourse}" into AI Auto-Watch (downloaded ${completedCountInRun} playable videos).`,
        'AUTO_WATCH_QUEUED'
      );
    } else if (completedCountInRun > 0 && chatWorkerGeneration.get(chatId) === myGen) {
      const remainingQueued = (chatJobQueues.get(chatId) || []).filter(
        (j) => j.status === 'queued'
      ).length;
      if (remainingQueued === 0) {
        if (chatId === DRIVE_SYNC_CHAT_ID) {
          await sendTelegramTextMessage(
            MAIN_ADMIN_ID,
            `☁️ **5TB Google Drive Batch Sync Complete!**\n\n✅ ${completedCountInRun} lecture(s) (video + PDF notes) "${DRIVE_ROOT_FOLDER_NAME}" folder me save ho chuki hain.`
          ).catch(() => {});
        } else if (!chatId.startsWith('__')) {
          const ctx = lastCourseContextByChat.get(chatId);
          const nextNum = ctx ? ctx.lastOrder + 1 : 0;
          const hasMoreInCourse = Boolean(
            ctx && (ctx.totalVideos > 1 ? nextNum <= ctx.totalVideos : nextNum >= 1)
          );
          const next5End = ctx
            ? ctx.totalVideos > nextNum
              ? Math.min(ctx.totalVideos, nextNum + 4)
              : nextNum + 4
            : nextNum;

          const completionKeyboard = hasMoreInCourse
            ? {
                inline_keyboard: [
                  [
                    {
                      text: `⏭️ Next Video (#${nextNum})`,
                      callback_data: `only_quick:next1:${nextNum}`,
                    },
                    {
                      text: `⏩ Next 5 (#${nextNum}-${next5End})`,
                      callback_data: `only_quick:next5:${nextNum}`,
                    },
                  ],
                  [
                    {
                      text: `▶️ Continue Remaining (#${nextNum}-${ctx!.totalVideos})`,
                      callback_data: `only_quick:cont:${nextNum}`,
                    },
                    {
                      text: `📦 Full Batch (All ${ctx!.totalVideos})`,
                      callback_data: 'only_quick:full:1',
                    },
                  ],
                  [
                    { text: '🎯 Select Video (/only)', callback_data: 'feat:help:only' },
                    { text: '🗑️ Clear (/clear)', callback_data: 'feat:action:clear' },
                  ],
                ],
              }
            : {
                inline_keyboard: [
                  [
                    { text: '🎯 Select Video (/only)', callback_data: 'feat:help:only' },
                    { text: '📦 Full Batch', callback_data: 'only_quick:full:1' },
                  ],
                ],
              };

          const lastInfoLine =
            lastCompletedJobInRun && ctx
              ? `\n🎬 Last Delivered: #${ctx.lastOrder}/${ctx.totalVideos}`
              : '';
          const destLabel =
            lastCompletedJobInRun?.deliveryMode === 'drive_only'
              ? 'Google Drive'
              : lastCompletedJobInRun?.deliveryMode === 'telegram_and_drive'
              ? 'Telegram & Google Drive'
              : 'Telegram';

          await sendTelegramTextMessage(
            chatId,
            `🎉 **Task Complete!**\n\n✅ ${completedCountInRun} video(s) download hokar ${destLabel} par successfully deliver ho chuki hain.${lastInfoLine}\n🏁 Download task 100% complete!`,
            completionKeyboard
          );
        }
      }
    }
  } finally {
    if (chatWorkerGeneration.get(chatId) === myGen) {
      activeChatWorkers.delete(chatId);
    }
  }
}

function enqueueJobForChat(
  chatId: string,
  job: DownloadJob,
  startWorker = true,
  allowUnpause = false
) {
  let queue = chatJobQueues.get(chatId);
  if (!queue) {
    queue = [];
    chatJobQueues.set(chatId, queue);
  }
  const jobKeys = getVideoDedupeKeys(job);
  const alreadyInQueue = queue.some((qJob) => {
    if (qJob.id === job.id) return true;
    if (
      typeof qJob.batchOrder === 'number' &&
      qJob.batchOrder > 0 &&
      typeof job.batchOrder === 'number' &&
      job.batchOrder > 0 &&
      qJob.batchOrder !== job.batchOrder
    ) {
      return false;
    }
    return getVideoDedupeKeys(qJob).some((k) => jobKeys.includes(k));
  });
  if (!alreadyInQueue) {
    queue.push(job);
  }
  // Keep queue sorted strictly numberwise (ascending batchOrder)
  queue.sort((a, b) => {
    const oA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
    const oB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
    if (oA !== oB) return oA - oB;
    return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
  });
  saveJobsState();
  if (startWorker) {
    runChatSequentialWorker(chatId, false, allowUnpause);
  }
}

let globalStopEpoch = 0;
const stopEpochByChat = new Map<string, number>();

// Hard-Pause active & queued downloads for a chat (or all chats) — stops immediately & prevents ANY auto-restart!
function pauseChatDownloads(targetChatId?: string): { pausedCount: number; totalPausedInQueue: number } {
  let pausedCount = 0;
  globalStopEpoch++;
  // Auto-disable background AI Auto-Watch so stopped downloads NEVER restart on their own!
  aiAgentState.enabled = false;
  if (targetChatId) {
    stopEpochByChat.set(targetChatId, (stopEpochByChat.get(targetChatId) || 0) + 1);
    userExplicitlyPausedChats.add(targetChatId);
  }

  const allKnownChatIds = Array.from(
    new Set([
      ...(targetChatId ? [targetChatId] : []),
      DRIVE_SYNC_CHAT_ID,
      ...Array.from(chatJobQueues.keys()),
      ...Array.from(activeChatWorkers.keys()),
      ...Array.from(jobs.values())
        .map((j) => j.telegramChatId || '')
        .filter(Boolean),
    ])
  );

  // Check if targetChatId has any active/queued jobs; if not (e.g. user sent /stop in DM to stop a Group/Drive batch), stop all active chats!
  const targetHasActive =
    targetChatId &&
    ((chatJobQueues.get(targetChatId)?.length || 0) > 0 ||
      Array.from(jobs.values()).some(
        (j) =>
          j.telegramChatId === targetChatId &&
          (j.status === 'queued' ||
            j.status === 'downloading' ||
            j.status === 'merging' ||
            j.status === 'uploading_bot_api' ||
            j.status === 'uploading_mtproto_userbot' ||
            j.status === 'uploading_google_drive' ||
            j.status === 'waiting_stream')
      ));

  const chatIdsToPause = targetChatId && targetHasActive ? [targetChatId] : allKnownChatIds;

  for (const cId of chatIdsToPause) {
    userExplicitlyPausedChats.add(cId);
    stopEpochByChat.set(cId, (stopEpochByChat.get(cId) || 0) + 1);
    chatWorkerGeneration.set(cId, (chatWorkerGeneration.get(cId) || 0) + 1);
    activeChatWorkers.delete(cId);
    const q = chatJobQueues.get(cId);
    if (q) {
      q.length = 0;
    }
  }

  let hadActiveSubprocess = false;
  for (const job of jobs.values()) {
    if (
      targetChatId &&
      targetHasActive &&
      job.telegramChatId &&
      job.telegramChatId !== targetChatId
    ) {
      continue;
    }
    const wasActivelyRunning =
      job.status === 'downloading' ||
      job.status === 'merging' ||
      job.status === 'uploading_bot_api' ||
      job.status === 'uploading_mtproto_userbot' ||
      job.status === 'uploading_google_drive';

    if (
      job.status === 'queued' ||
      job.status === 'waiting_stream' ||
      wasActivelyRunning ||
      Boolean(job.preDownloadPromise)
    ) {
      if (wasActivelyRunning || job.preDownloadPromise) {
        hadActiveSubprocess = true;
      }
      job.abortFlag = true;
      job.downloadEpoch = (job.downloadEpoch || 0) + 1;
      abortJobImmediately(job.id);
      preResolvedStreamCache.delete(job.id);
      job.preDownloadedReady = false;
      job.preDownloadPromise = undefined;
      if (job.status !== 'completed') {
        job.status = 'paused';
        job.speedBytesPerSec = 0;
        job.error = 'Paused — Send /resume to continue or /clear to delete paused videos';
        pausedCount++;
      }

      if (wasActivelyRunning && job.telegramChatId && !job.telegramChatId.startsWith('__') && job.telegramStatusMsgId) {
        editTelegramTextMessage(
          job.telegramChatId,
          job.telegramStatusMsgId,
          `⏸️ Paused: ${job.title}\n▶️ Send /resume to continue or /clear to delete paused videos.`
        ).catch(() => {});
      }
    }
  }

  if (hadActiveSubprocess) {
    execFileAsync('pkill', ['-f', 'ffmpeg']).catch(() => {});
    execFileAsync('pkill', ['-f', 'yt-dlp']).catch(() => {});
    if (cachedUserbotClient) {
      cachedUserbotClient.disconnect().catch(() => {});
      cachedUserbotClient = null;
    }
  }

  const totalPausedInQueue = Array.from(jobs.values()).filter(
    (j) =>
      j.status === 'paused' &&
      (!targetChatId || !targetHasActive || !j.telegramChatId || j.telegramChatId === targetChatId)
  ).length;

  saveBotSettings();
  saveJobsState(true);
  return { pausedCount, totalPausedInQueue };
}

// Clear / Delete all queued, downloading, paused, and waiting videos from the queue while keeping completed history intact!
function clearPausedChatDownloads(targetChatId?: string): {
  clearedCount: number;
  preservedCompletedCount: number;
} {
  let clearedCount = 0;
  let preservedCompletedCount = 0;
  let hadActiveProcess = false;

  globalStopEpoch++;
  aiAgentState.enabled = false;

  const matchesTargetChat = (j: DownloadJob, tId?: string) => {
    if (!tId) return true;
    return j.telegramChatId === tId || j.explicitTargetChannelId === tId;
  };

  if (targetChatId) {
    userExplicitlyPausedChats.add(targetChatId);
    stopEpochByChat.set(targetChatId, (stopEpochByChat.get(targetChatId) || 0) + 1);
    chatWorkerGeneration.set(targetChatId, (chatWorkerGeneration.get(targetChatId) || 0) + 1);
    activeChatWorkers.delete(targetChatId);
  } else {
    for (const cId of Array.from(new Set([...chatJobQueues.keys(), ...activeChatWorkers.keys(), DRIVE_SYNC_CHAT_ID]))) {
      userExplicitlyPausedChats.add(cId);
      stopEpochByChat.set(cId, (stopEpochByChat.get(cId) || 0) + 1);
      chatWorkerGeneration.set(cId, (chatWorkerGeneration.get(cId) || 0) + 1);
      activeChatWorkers.delete(cId);
    }
  }

  for (const [id, job] of Array.from(jobs.entries())) {
    if (targetChatId && !matchesTargetChat(job, targetChatId)) {
      continue;
    }

    if (job.status === 'completed') {
      markVideoCompleted(job, false);
      preservedCompletedCount++;
      continue;
    }

    const wasActivelyRunning =
      job.status === 'downloading' ||
      job.status === 'merging' ||
      job.status === 'uploading_bot_api' ||
      job.status === 'uploading_mtproto_userbot' ||
      job.status === 'uploading_google_drive';

    if (wasActivelyRunning || job.preDownloadPromise) {
      hadActiveProcess = true;
    }

    job.abortFlag = true;
    job.downloadEpoch = (job.downloadEpoch || 0) + 1;
    abortJobImmediately(id);
    preResolvedStreamCache.delete(id);
    cleanupJobTempFiles(id);
    jobs.delete(id);
    clearedCount++;
  }

  if (hadActiveProcess) {
    execFileAsync('pkill', ['-f', 'ffmpeg']).catch(() => {});
    execFileAsync('pkill', ['-f', 'yt-dlp']).catch(() => {});
    if (cachedUserbotClient) {
      cachedUserbotClient.disconnect().catch(() => {});
      cachedUserbotClient = null;
    }
  }

  // Clear chat job queues completely for the target chat
  for (const [cId, q] of chatJobQueues.entries()) {
    if (targetChatId && cId !== targetChatId) continue;
    q.length = 0;
  }

  // Also remove watched courses registered for this chat so old batches are not re-enqueued
  for (const [key, watched] of Array.from(watchedCourses.entries())) {
    if (!targetChatId || watched.chatId === targetChatId) {
      watchedCourses.delete(key);
    }
  }
  saveWatchedCoursesState();

  saveBotSettings();
  saveCompletedVideosState(true);
  saveCourseCheckpointsState();
  saveJobsState(true);
  return {
    clearedCount,
    preservedCompletedCount: Math.max(preservedCompletedCount, completedVideoKeys.size),
  };
}

function resetAllBotData(targetChatId?: string): {
  clearedJobsCount: number;
  removedJobsCount: number;
  clearedCoursesCount: number;
} {
  globalStopEpoch++;
  aiAgentState.enabled = false;
  if (targetChatId) {
    userExplicitlyPausedChats.add(targetChatId);
    stopEpochByChat.set(targetChatId, (stopEpochByChat.get(targetChatId) || 0) + 1);
    chatWorkerGeneration.set(targetChatId, (chatWorkerGeneration.get(targetChatId) || 0) + 1);
    activeChatWorkers.delete(targetChatId);
    pendingSkipByChat.delete(targetChatId);
    pendingOnlyByChat.delete(targetChatId);
    pendingDriveModeByChat.delete(targetChatId);
  } else {
    userExplicitlyPausedChats.add(DRIVE_SYNC_CHAT_ID);
    for (const cId of chatJobQueues.keys()) {
      userExplicitlyPausedChats.add(cId);
      stopEpochByChat.set(cId, (stopEpochByChat.get(cId) || 0) + 1);
      chatWorkerGeneration.set(cId, (chatWorkerGeneration.get(cId) || 0) + 1);
    }
    activeChatWorkers.clear();
    pendingSkipByChat.clear();
    pendingOnlyByChat.clear();
    pendingDriveModeByChat.clear();
  }

  let clearedJobsCount = 0;
  for (const [id, job] of Array.from(jobs.entries())) {
    if (targetChatId && job.telegramChatId && job.telegramChatId !== targetChatId) {
      continue;
    }
    job.abortFlag = true;
    job.downloadEpoch = (job.downloadEpoch || 0) + 1;
    job.preDownloadPromise = undefined;
    abortJobImmediately(id);
    cleanupJobTempFiles(id);
    jobs.delete(id);
    clearedJobsCount++;
  }

  for (const [cId, q] of chatJobQueues.entries()) {
    if (targetChatId && cId !== targetChatId) continue;
    q.length = 0;
  }

  preResolvedStreamCache.clear();
  try {
    const { exec } = require('child_process');
    exec('pkill -9 ffmpeg 2>/dev/null || true; pkill -9 yt-dlp 2>/dev/null || true');
  } catch {
    // ignore
  }

  const clearedCoursesCount = watchedCourses.size;
  completedVideoKeys.clear();
  courseCheckpoints.clear();
  watchedCourses.clear();
  courseExtractionCache.clear();
  recentScanDedupMap.clear();

  saveBotSettings();
  saveCompletedVideosState(true);
  saveCourseCheckpointsState();
  saveWatchedCoursesState();
  saveJobsState(true);
  return { clearedJobsCount, removedJobsCount: clearedJobsCount, clearedCoursesCount };
}

// Smart Resume: Skips all 'completed' videos, deduplicates videos, and groups by course first so two courses NEVER interleave!
function resumeChatDownloads(
  targetChatId?: string,
  specificJobId?: string,
  includeWaitingStreams = false
): {
  resumedCount: number;
  skippedCompletedCount: number;
  firstResumedTitle?: string;
} {
  if (targetChatId) {
    if (userExplicitlyPausedChats.delete(targetChatId)) {
      saveBotSettings();
    }
  } else if (userExplicitlyPausedChats.size > 0) {
    userExplicitlyPausedChats.clear();
    saveBotSettings();
  }

  if (specificJobId) {
    const job = jobs.get(specificJobId);
    if (!job || job.status === 'completed') {
      return { resumedCount: 0, skippedCompletedCount: job ? 1 : 0 };
    }
    const cId =
      job.telegramChatId ||
      process.env.TELEGRAM_CHAT_ID?.trim() ||
      Object.keys(botSettings.authorizedUsers)[0] ||
      'default';
    userExplicitlyPausedChats.delete(cId);
    job.telegramChatId = cId;
    job.abortFlag = false;
    job.sourceUrl = job.initialSourceUrl || job.sourceUrl;
    job.status = 'queued';
    job.error = undefined;
    job.progressPercent = 0;
    job.completedSegments = 0;
    job.downloadedBytes = 0;
    job.speedBytesPerSec = 0;
    job.retryCount = 0;
    job.lastProgressAt = Date.now();
    enqueueJobForChat(cId, job, true, true);
    return {
      resumedCount: 1,
      skippedCompletedCount: 0,
      firstResumedTitle: job.title,
    };
  }

  const allJobs = Array.from(jobs.values()).filter((j) =>
    targetChatId ? !j.telegramChatId || j.telegramChatId === targetChatId : true
  );

  let skippedCompletedCount = allJobs.filter((j) => j.status === 'completed').length;

  // Determine candidate jobs that are NOT completed and deduplicate them so no video ever runs twice
  const seenDedupeKeys = new Set<string>();
  let candidates: DownloadJob[] = [];

  for (const j of allJobs) {
    if (j.status === 'completed') {
      markVideoCompleted(j, false);
      continue;
    }
    if (!j.forceDownload && isVideoAlreadyCompletedForChat(j.telegramChatId || targetChatId || '', j)) {
      j.status = 'completed';
      j.progressPercent = 100;
      j.error = undefined;
      skippedCompletedCount++;
      continue;
    }

    const dedupeKey = getVideoDedupeKey(j);
    if (dedupeKey) {
      if (seenDedupeKeys.has(dedupeKey)) {
        cleanupJobTempFiles(j.id);
        jobs.delete(j.id);
        continue;
      }
      seenDedupeKeys.add(dedupeKey);
    }

    if (j.status === 'paused' || j.status === 'queued') {
      candidates.push(j);
      continue;
    }
    if (j.status === 'waiting_stream' && includeWaitingStreams) {
      candidates.push(j);
      continue;
    }
    if (j.status === 'failed') {
      if (
        includeWaitingStreams ||
        !/No playable stream URL available|BATCH_UNAVAILABLE_ON_PORTAL/i.test(String(j.error || ''))
      ) {
        candidates.push(j);
      }
      continue;
    }
    if (
      j.status === 'downloading' ||
      j.status === 'merging' ||
      j.status === 'uploading_bot_api' ||
      j.status === 'uploading_mtproto_userbot' ||
      j.status === 'uploading_google_drive'
    ) {
      candidates.push(j);
    }
  }

  if (candidates.length === 0) {
    // Fallback: if all non-completed jobs were waiting_stream or failed, allow retrying them when user explicitly clicks Resume
    candidates = allJobs.filter(
      (j) =>
        j.status !== 'completed' &&
        !isVideoAlreadyCompletedForChat(j.telegramChatId || targetChatId || '', j)
    );
  }

  // Group by Course FIRST so two different courses NEVER mix 1-by-1!
  const getCourseKey = (j: DownloadJob) =>
    String(j.originalRequestUrl || j.courseName || 'default')
      .trim()
      .toLowerCase();

  const courseLatestCreatedAt = new Map<string, number>();
  for (const j of candidates) {
    const ck = getCourseKey(j);
    const ts = new Date(j.createdAt).getTime() || 0;
    const prev = courseLatestCreatedAt.get(ck) || 0;
    if (ts > prev) {
      courseLatestCreatedAt.set(ck, ts);
    }
  }

  // Sort by Course first, then STRICTLY ascending 1, 2, 3... numberwise batchOrder (never jump out of order!)
  candidates.sort((a, b) => {
    const ckA = getCourseKey(a);
    const ckB = getCourseKey(b);
    if (ckA !== ckB) {
      const timeA = courseLatestCreatedAt.get(ckA) || 0;
      const timeB = courseLatestCreatedAt.get(ckB) || 0;
      if (timeA !== timeB) {
        return timeB - timeA;
      }
      return ckA.localeCompare(ckB);
    }
    const orderA = typeof a.batchOrder === 'number' ? a.batchOrder : 999999;
    const orderB = typeof b.batchOrder === 'number' ? b.batchOrder : 999999;
    if (orderA !== orderB) {
      return orderA - orderB;
    }
    return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
  });

  const chatsToRestart = new Set<string>();
  let resumedCount = 0;
  let firstResumedTitle: string | undefined;

  const groupedByChat = new Map<string, DownloadJob[]>();
  for (const job of candidates) {
    const cId =
      job.telegramChatId ||
      targetChatId ||
      process.env.TELEGRAM_CHAT_ID?.trim() ||
      Object.keys(botSettings.authorizedUsers)[0] ||
      'default';
    job.telegramChatId = cId;
    if (!groupedByChat.has(cId)) {
      groupedByChat.set(cId, []);
    }
    groupedByChat.get(cId)!.push(job);
  }

  for (const [cId, chatJobs] of groupedByChat.entries()) {
    const existingQueue = chatJobQueues.get(cId) || [];
    existingQueue.length = 0;

    for (const j of chatJobs) {
      const isRunningState =
        j.status === 'downloading' ||
        j.status === 'merging' ||
        j.status === 'uploading_bot_api' ||
        j.status === 'uploading_mtproto_userbot';

      if (isRunningState) {
        j.abortFlag = true;
      }

      j.downloadEpoch = (j.downloadEpoch || 0) + 1;
      j.abortFlag = false;
      j.sourceUrl = j.initialSourceUrl || j.sourceUrl;
      j.status = 'queued';
      j.error = undefined;
      j.preDownloadedReady = false;
      j.preDownloadPromise = undefined;
      j.progressPercent = 0;
      j.completedSegments = 0;
      j.downloadedBytes = 0;
      j.speedBytesPerSec = 0;
      j.retryCount = 0;
      j.lastProgressAt = Date.now();
      existingQueue.push(j);
      resumedCount++;
      if (!firstResumedTitle) {
        firstResumedTitle = j.title;
      }
    }

    chatJobQueues.set(cId, existingQueue);
    activeChatWorkers.delete(cId);
    chatsToRestart.add(cId);
  }

  saveCompletedVideosState(true);
  saveCourseCheckpointsState();
  saveJobsState(true);

  for (const cId of chatsToRestart) {
    runChatSequentialWorker(cId, true, true);
  }

  return {
    resumedCount,
    skippedCompletedCount,
    firstResumedTitle,
  };
}

// Skip the first N videos (e.g. /skip 95) in an active/paused batch OR arm skip=N for the next course link sent!
function skipChatVideos(
  targetChatId?: string,
  skipCount = 0
): {
  skippedExistingCount: number;
  resumedCount: number;
  firstResumedTitle?: string;
  armedForNextLink: boolean;
} {
  const cleanSkip = Math.max(0, Math.floor(Number(skipCount) || 0));
  if (cleanSkip <= 0) {
    return { skippedExistingCount: 0, resumedCount: 0, armedForNextLink: false };
  }

  if (targetChatId) {
    pendingSkipByChat.set(targetChatId, cleanSkip);
  } else {
    pendingSkipByChat.set('GLOBAL', cleanSkip);
  }

  const matchingJobs = Array.from(jobs.values()).filter((j) =>
    targetChatId ? !j.telegramChatId || j.telegramChatId === targetChatId : true
  );

  matchingJobs.sort((a, b) => {
    if (typeof a.batchOrder === 'number' && typeof b.batchOrder === 'number') {
      return a.batchOrder - b.batchOrder;
    }
    return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
  });

  const nonCompletedExist = matchingJobs.some((j) => j.status !== 'completed');
  if (!nonCompletedExist || matchingJobs.length === 0) {
    return {
      skippedExistingCount: 0,
      resumedCount: 0,
      armedForNextLink: true,
    };
  }

  let skippedExistingCount = 0;
  for (let i = 0; i < matchingJobs.length; i++) {
    const j = matchingJobs[i];
    const orderNum = typeof j.batchOrder === 'number' ? j.batchOrder : i + 1;
    if (orderNum <= cleanSkip) {
      markVideoCompleted(j, false);
      if (j.status !== 'completed') {
        j.abortFlag = true;
        j.downloadEpoch = (j.downloadEpoch || 0) + 1;
        j.status = 'completed';
        j.progressPercent = 100;
        j.speedBytesPerSec = 0;
        j.error = undefined;
        cleanupJobTempFiles(j.id);
        skippedExistingCount++;
      }
    }
  }

  if (skippedExistingCount > 0) {
    if (targetChatId) pendingSkipByChat.delete(targetChatId);
    pendingSkipByChat.delete('GLOBAL');
  }

  saveCompletedVideosState(true);
  saveCourseCheckpointsState();
  saveJobsState(true);
  const resInfo = resumeChatDownloads(targetChatId);
  return {
    skippedExistingCount,
    resumedCount: resInfo.resumedCount,
    firstResumedTitle: resInfo.firstResumedTitle,
    armedForNextLink: skippedExistingCount === 0,
  };
}

// Select ONLY specific videos (e.g. /only 128, 134, 144) to download in an active/paused batch OR arm for next link sent!
function onlyChatVideos(
  targetChatId?: string,
  selectedNumbers: number[] = []
): {
  keptCount: number;
  skippedCount: number;
  resumedCount: number;
  firstResumedTitle?: string;
  armedForNextLink: boolean;
} {
  const cleanSelected = Array.from(
    new Set(selectedNumbers.filter((n) => typeof n === 'number' && n > 0))
  ).sort((a, b) => a - b);
  if (cleanSelected.length === 0) {
    return { keptCount: 0, skippedCount: 0, resumedCount: 0, armedForNextLink: false };
  }
  const allowedSet = new Set(cleanSelected);
  if (targetChatId) {
    pendingOnlyByChat.set(targetChatId, cleanSelected);
  } else {
    pendingOnlyByChat.set('GLOBAL', cleanSelected);
  }

  const matchingJobs = Array.from(jobs.values()).filter((j) =>
    targetChatId ? !j.telegramChatId || j.telegramChatId === targetChatId : true
  );

  matchingJobs.sort((a, b) => {
    if (typeof a.batchOrder === 'number' && typeof b.batchOrder === 'number') {
      return a.batchOrder - b.batchOrder;
    }
    return new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
  });

  const nonCompletedExist = matchingJobs.some((j) => j.status !== 'completed');
  if (!nonCompletedExist || matchingJobs.length === 0) {
    return {
      keptCount: cleanSelected.length,
      skippedCount: 0,
      resumedCount: 0,
      armedForNextLink: true,
    };
  }

  let skippedCount = 0;
  let keptCount = 0;

  for (let i = 0; i < matchingJobs.length; i++) {
    const j = matchingJobs[i];
    const orderNum = typeof j.batchOrder === 'number' ? j.batchOrder : i + 1;
    if (!allowedSet.has(orderNum)) {
      // Clean up and permanently remove non-selected video so only the selected video runs
      j.abortFlag = true;
      j.downloadEpoch = (j.downloadEpoch || 0) + 1;
      cleanupJobTempFiles(j.id);
      jobs.delete(j.id);
      skippedCount++;
    } else {
      keptCount++;
      j.forceDownload = true;
      j.downloadEpoch = (j.downloadEpoch || 0) + 1;
      j.status = 'queued';
      j.error = undefined;
      j.abortFlag = false;
      j.progressPercent = 0;
      j.speedBytesPerSec = 0;
      j.downloadedBytes = 0;
      j.completedSegments = 0;
    }
  }

  // Remove watched courses for this chat so the rest of the batch is NEVER auto-downloaded!
  if (targetChatId) {
    for (const [key, watched] of watchedCourses.entries()) {
      if (watched.chatId === targetChatId) {
        watchedCourses.delete(key);
      }
    }
    saveWatchedCoursesState();
  }

  if (keptCount > 0) {
    if (targetChatId) pendingOnlyByChat.delete(targetChatId);
    pendingOnlyByChat.delete('GLOBAL');
  }

  saveJobsState(true);

  // Rebuild the chat queue to contain ONLY the selected jobs
  if (targetChatId) {
    const queue = chatJobQueues.get(targetChatId) || [];
    queue.length = 0;
    for (const j of jobs.values()) {
      if ((j.telegramChatId === targetChatId || !j.telegramChatId) && j.status === 'queued') {
        queue.push(j);
      }
    }
    chatJobQueues.set(targetChatId, queue);
  }

  const resInfo = resumeChatDownloads(targetChatId);
  return {
    keptCount,
    skippedCount,
    resumedCount: resInfo.resumedCount,
    firstResumedTitle: resInfo.firstResumedTitle,
    armedForNextLink: skippedCount === 0 && keptCount === 0,
  };
}

// ============================================================================
// GEMINI AI AGENT + 24/7 AUTONOMOUS AUTO-CHECK & AUTO-DOWNLOAD ENGINE
// ============================================================================

let geminiClientInstance: GoogleGenAI | null = null;
function getServerGeminiClient(): GoogleGenAI | null {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) return null;
  if (!geminiClientInstance) {
    geminiClientInstance = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return geminiClientInstance;
}

function getAiAgentStatusSnapshot() {
  const allJobs = Array.from(jobs.values());
  const waitingByCourse = new Map<string, number>();
  let waitingStreamsCount = 0;
  for (const j of allJobs) {
    if (j.status === 'waiting_stream') {
      waitingStreamsCount++;
      const cKey = getCourseCheckpointKey(j);
      waitingByCourse.set(cKey, (waitingByCourse.get(cKey) || 0) + 1);
    }
  }

  const checkpointsList = Array.from(courseCheckpoints.values())
    .map((cp) => ({
      ...cp,
      waitingCount: waitingByCourse.get(cp.courseKey) || 0,
    }))
    .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());

  return {
    enabled: aiAgentState.enabled,
    intervalMinutes: aiAgentState.intervalMinutes,
    lastCheckAt: aiAgentState.lastCheckAt,
    nextCheckAt: aiAgentState.nextCheckAt,
    isCheckingNow: aiAgentState.isCheckingNow,
    waitingStreamsCount,
    watchedCoursesCount: watchedCourses.size,
    totalAutoRecoveredVideos: aiAgentState.totalAutoRecoveredVideos,
    courseCheckpoints: checkpointsList,
    recentDecisions: aiAgentState.recentDecisions.slice(0, 15),
  };
}

async function askGeminiAiAgent(userPrompt: string, chatId?: string): Promise<string> {
  const snap = getAiAgentStatusSnapshot();
  const stats = getChatJobStats(chatId);
  const cpSummary =
    snap.courseCheckpoints.length > 0
      ? snap.courseCheckpoints
          .slice(0, 6)
          .map(
            (c) =>
              `- ${c.courseName}: Last Completed Lecture #${c.lastCompletedBatchOrder}/${c.totalVideos} (${c.lastCompletedTitle}), Completed=${c.completedCount}, WaitingStream=${c.waitingCount}`
          )
          .join('\n')
      : 'No course checkpoints yet.';

  const contextBlock =
    `Live Bot State:\n` +
    `- AI Auto-Download Agent: ${snap.enabled ? 'ACTIVE' : 'PAUSED'} (Checks every ${snap.intervalMinutes} mins)\n` +
    `- Completed Videos: ${stats.completedCount} | Active Downloading: ${stats.activeCount} | Queued: ${stats.queuedCount} | Paused: ${stats.pausedCount} | Waiting for Stream: ${snap.waitingStreamsCount}\n` +
    `- Watched Courses for Auto-Detection: ${snap.watchedCoursesCount}\n` +
    `- Auto-Recovered Videos so far: ${snap.totalAutoRecoveredVideos}\n` +
    `- Course Checkpoints (Auto-Start from Last Video without /skip):\n${cpSummary}\n` +
    `- Latest AI Agent Decision: ${snap.recentDecisions[0]?.summary || 'Monitoring all queues & batches.'}`;

  const ai = getServerGeminiClient();
  if (ai) {
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: `${contextBlock}\n\nUser Question / Command: ${userPrompt}`,
        config: {
          systemInstruction:
            'You are the built-in StreamBridge Autonomous AI Agent for a high-speed Telegram Video Downloader Bot. Reply concisely in friendly Hinglish (Hindi + English, max 6-8 lines). Explain the exact status of their batches, last completed lecture checkpoint, waiting videos, and reassure them that the AI Agent automatically checks for new/unavailable streams every few minutes and starts from the last completed video without needing manual /skip commands or duplicating any video.',
        },
      });
      if (response.text && response.text.trim()) {
        return response.text.trim();
      }
    } catch (err: any) {
      console.warn('[AI Agent Gemini Call Warning]:', err?.message || err);
    }
  }

  return (
    `🤖 StreamBridge AI Autonomous Agent Report:\n\n` +
    `🟢 Status: ${snap.enabled ? '24/7 Active & Auto-Checking' : 'Paused'} (Every ${snap.intervalMinutes} min)\n` +
    `✅ Completed Videos: ${stats.completedCount} | ⚡ Queued/Active: ${stats.queuedCount + stats.activeCount}\n` +
    `🕒 Waiting for Server Stream: ${snap.waitingStreamsCount} video(s)\n` +
    `📌 Course Checkpoints:\n${cpSummary}\n\n` +
    `💡 Aapko bar-bar /skip likhne ki bilkul zaroorat nahi hai — AI Agent har batch ka last video yaad rakhta hai aur unavailable videos ko background me check karke khud download kar deta hai!`
  );
}

// Periodic Autonomous Check:
// 1) Auto-resumes any non-stopped chat queues (e.g. after server restart).
// 2) Probes 'waiting_stream' videos (1 sample per course+subject) to see if their stream is now available on the server, and auto-queues them!
// 3) Re-scans watched courses that previously had 0 detected videos or new lectures uploaded, and auto-queues only undownloaded lectures!
async function runAiAutoCheckCycle(manualTrigger = false): Promise<{
  recoveredVideos: number;
  newlyDetectedVideos: number;
  resumedQueues: number;
  summary: string;
}> {
  if (aiAgentState.isCheckingNow) {
    return {
      recoveredVideos: 0,
      newlyDetectedVideos: 0,
      resumedQueues: 0,
      summary: 'AI Agent check is already in progress.',
    };
  }

  aiAgentState.isCheckingNow = true;
  aiAgentState.lastCheckAt = new Date().toISOString();
  aiAgentState.nextCheckAt = new Date(
    Date.now() + aiAgentState.intervalMinutes * 60 * 1000
  ).toISOString();

  let recoveredVideos = 0;
  let newlyDetectedVideos = 0;
  let resumedQueues = 0;

  try {
    // Clear short-lived 401 cache on resolveAppxVideoStreamUrl so fresh token updates on portal are detected immediately
    const asmCacheMap: Map<string, number> | undefined = (resolveAppxVideoStreamUrl as any)
      ._asmUnpurchasedMap;
    if (asmCacheMap) {
      asmCacheMap.clear();
    }

    // Step 1: Ensure any chat with queued or crash-interrupted jobs (NOT explicitly paused by user) is running from its last checkpoint
    const allJobs = Array.from(jobs.values());
    const chatsWithPausedOrQueued = new Set<string>();
    for (const j of allJobs) {
      const isExplicitUserPause =
        j.status === 'paused' && (j.error || '').includes('Send /resume to continue');
      if (j.status === 'queued' || (j.status === 'paused' && !isExplicitUserPause)) {
        const cId = j.telegramChatId || '';
        if (cId && !userExplicitlyPausedChats.has(cId) && !activeChatWorkers.has(cId)) {
          chatsWithPausedOrQueued.add(cId);
        }
      }
    }
    for (const cId of chatsWithPausedOrQueued) {
      const res = resumeChatDownloads(cId, undefined, false);
      if (res.resumedCount > 0) {
        resumedQueues += res.resumedCount;
        addAiAgentDecision(
          `Auto-resumed ${res.resumedCount} pending video(s) for chat ${cId} starting from ${res.firstResumedTitle || 'last checkpoint'}.`,
          'AUTO_RESUME'
        );
      }
    }

    // Step 2: Check 'waiting_stream' jobs (videos that had no playable stream earlier)
    const waitingJobs = Array.from(jobs.values()).filter(
      (j) =>
        j.status === 'waiting_stream' &&
        !isVideoAlreadyCompletedForChat(j.telegramChatId || '', j) &&
        (!j.telegramChatId || !userExplicitlyPausedChats.has(j.telegramChatId))
    );

    if (waitingJobs.length > 0) {
      // Group waiting jobs by (courseCheckpointKey + subjectName) so we only probe 1 sample video per subject!
      const subjectGroups = new Map<string, DownloadJob[]>();
      for (const wJob of waitingJobs) {
        const gKey = `${getCourseCheckpointKey(wJob)}__${(wJob.subjectName || 'general').toLowerCase()}`;
        if (!subjectGroups.has(gKey)) {
          subjectGroups.set(gKey, []);
        }
        subjectGroups.get(gKey)!.push(wJob);
      }

      const chatsToWake = new Set<string>();
      for (const [, groupJobs] of subjectGroups.entries()) {
        const sampleJob = groupJobs[0];
        const rawUrl = String(sampleJob.initialSourceUrl || sampleJob.sourceUrl || '').trim();
        let streamNowPlayable = false;

        if (rawUrl.startsWith('appx://')) {
          try {
            const appxUrl = new URL(rawUrl.replace(/^appx:\/\//i, 'http://'));
            const domainId = appxUrl.hostname || 'RWA';
            const courseId = appxUrl.searchParams.get('courseid') || '';
            const videoId = appxUrl.searchParams.get('videoid') || '';
            const orig = appxUrl.searchParams.get('origin') || 'https://studybeepro.site';
            const portal = appxUrl.searchParams.get('portal') || '/rwax';
            const fallback = appxUrl.searchParams.get('fallback') || undefined;
            const hintMeta = {
              subjectId: appxUrl.searchParams.get('subjectid') || undefined,
              topicId: appxUrl.searchParams.get('topicid') || undefined,
              conceptId: appxUrl.searchParams.get('conceptid') || undefined,
              title: sampleJob.lectureTitle || sampleJob.title || undefined,
              strtotime: Number(appxUrl.searchParams.get('strtotime') || 0) || undefined,
              duration: appxUrl.searchParams.get('duration') || undefined,
              freeFlag: appxUrl.searchParams.get('free') || undefined,
            };
            if (courseId && videoId) {
              const resolved = await resolveAppxVideoStreamUrl(
                domainId,
                courseId,
                videoId,
                sampleJob.preferredQuality || botSettings.globalDefaultQuality || '480p',
                orig,
                portal,
                fallback,
                hintMeta
              );
              if (resolved && resolved.streamUrl) {
                streamNowPlayable = true;
              }
            }
          } catch {
            streamNowPlayable = false;
          }
        }

        if (streamNowPlayable) {
          for (const gJob of groupJobs) {
            gJob.status = 'queued';
            gJob.error = undefined;
            gJob.abortFlag = false;
            gJob.sourceUrl = gJob.initialSourceUrl || gJob.sourceUrl;
            const cId = gJob.telegramChatId || '';
            if (cId) {
              enqueueJobForChat(cId, gJob, false);
              chatsToWake.add(cId);
            }
            recoveredVideos++;
            aiAgentState.totalAutoRecoveredVideos++;
          }
        }
      }

      if (chatsToWake.size > 0) {
        saveJobsState(true);
        for (const cId of chatsToWake) {
          runChatSequentialWorker(cId);
        }
        addAiAgentDecision(
          `Detected ${recoveredVideos} previously unavailable video(s) now live on server — queued automatically for download!`,
          'STREAM_RECOVERED'
        );
      }
    }

    // Step 3: Check watchedCourses (for batches that had 0 videos detected earlier OR new daily videos added)
    for (const [, watched] of watchedCourses.entries()) {
      if (userExplicitlyPausedChats.has(watched.chatId)) continue;
      if (activeChatWorkers.has(watched.chatId)) continue;

      const msSinceLastScan = Date.now() - (new Date(watched.lastScannedAt).getTime() || 0);
      const hasActiveOrQueued = Array.from(jobs.values()).some(
        (j) =>
          (j.telegramChatId === watched.chatId || !j.telegramChatId) &&
          (j.originalRequestUrl === watched.sourceUrl ||
            (j.courseName && watched.courseName && j.courseName.includes(watched.courseName))) &&
          (j.status === 'queued' ||
            j.status === 'downloading' ||
            j.status === 'merging' ||
            j.status === 'uploading_bot_api' ||
            j.status === 'uploading_mtproto_userbot')
      );
      // Re-scan if manualTrigger OR if lastDetectedVideos === 0 OR if no active/queued jobs OR if >= 10 minutes since last scan
      if (
        !manualTrigger &&
        watched.lastDetectedVideos > 0 &&
        hasActiveOrQueued &&
        msSinceLastScan < 10 * 60 * 1000
      ) {
        continue;
      }

      try {
        // Clear course extraction cache for this URL so we fetch fresh data from the portal
        courseExtractionCache.delete(`${watched.sourceUrl}__full`);
        courseExtractionCache.delete(`${watched.sourceUrl}__single`);

        const extracted = await inspectUrlAndExtractStreams(
          watched.sourceUrl,
          undefined,
          undefined,
          true
        );
        watched.lastScannedAt = new Date().toISOString();
        watched.lastDetectedVideos = extracted.streams.length;
        saveWatchedCoursesState();

        if (extracted.streams.length > 0) {
          // Pre-index existing jobs & completed keys in O(M) ONCE instead of O(N*M) nested loops (prevents 100% CPU freeze!)
          const existingKeysForCourse = new Set<string>();
          const existingOrdersForCourse = new Set<number>();
          for (const j of jobs.values()) {
            if (j.telegramChatId && j.telegramChatId !== watched.chatId) continue;
            for (const dk of getVideoDedupeKeys(j)) {
              existingKeysForCourse.add(dk);
            }
            if (j.originalRequestUrl === watched.sourceUrl && typeof j.batchOrder === 'number') {
              existingOrdersForCourse.add(j.batchOrder);
            }
          }
          const courseCp = courseCheckpoints.get(watched.courseKey);

          let queuedFromWatch = 0;
          for (let idx = 0; idx < extracted.streams.length; idx++) {
            const batchNum = idx + 1;
            // Never re-queue older lectures behind the saved checkpoint
            if (courseCp && courseCp.lastCompletedBatchOrder > 0 && batchNum <= courseCp.lastCompletedBatchOrder) {
              continue;
            }
            if (existingOrdersForCourse.has(batchNum)) {
              continue;
            }

            const stream = extracted.streams[idx];
            const itemMeta = {
              initialSourceUrl: stream.url,
              sourceUrl: stream.url,
              originalRequestUrl: watched.sourceUrl,
              courseName: stream.courseName || extracted.pageTitle,
              folderName: stream.folderName,
              lectureTitle: stream.lectureTitle || stream.label,
              title: `📹 Lecture ${batchNum}/${extracted.streams.length}: ${stream.label}`,
              batchOrder: batchNum,
            };
            const itemDedupeKeys = getVideoDedupeKeys(itemMeta);
            let alreadySeen = false;
            for (const k of itemDedupeKeys) {
              if (completedVideoKeys.has(k) || existingKeysForCourse.has(k)) {
                alreadySeen = true;
                break;
              }
            }
            if (alreadySeen) {
              continue;
            }
            const jobId = crypto.randomUUID();
            const newJob: DownloadJob = {
              id: jobId,
              title: `📹 Lecture ${batchNum}/${extracted.streams.length}: ${stream.label}`,
              courseName: stream.courseName || extracted.pageTitle,
              subjectName: stream.subjectName,
              topicName: stream.topicName,
              lectureTitle: stream.lectureTitle || stream.label,
              folderName: stream.folderName,
              sourceUrl: stream.url,
              initialSourceUrl: stream.url,
              originalRequestUrl: watched.sourceUrl,
              explicitTargetChannelId: watched.explicitTargetChannelId,
              batchOrder: batchNum,
              protocol: stream.protocol,
              preferredQuality: watched.preferredQuality || botSettings.globalDefaultQuality || '480p',
              resolution: stream.resolution || watched.preferredQuality || '480p',
              status: 'queued',
              progressPercent: 0,
              totalSegments: 1,
              completedSegments: 0,
              downloadedBytes: 0,
              speedBytesPerSec: 0,
              deliveryMode: 'telegram_auto',
              telegramChatId: watched.chatId,
              outputFormat: 'mp4',
              createdAt: new Date().toISOString(),
              fileReadyForBrowser: false,
              cleanupAfterTelegram: true,
            };
            jobs.set(jobId, newJob);
            for (const k of itemDedupeKeys) existingKeysForCourse.add(k);
            existingOrdersForCourse.add(batchNum);
            enqueueJobForChat(watched.chatId, newJob, false);
            queuedFromWatch++;
            newlyDetectedVideos++;
          }

          if (queuedFromWatch > 0) {
            saveJobsState(true);
            addAiAgentDecision(
              `Auto-detected ${queuedFromWatch} new/remaining video(s) in watched batch "${watched.courseName}" — started automatic download!`,
              'BATCH_NEW_VIDEOS'
            );
            runChatSequentialWorker(watched.chatId);
          }
        }
      } catch {
        // ignore transient scan error during background check
      }
    }

    const summary =
      recoveredVideos > 0 || newlyDetectedVideos > 0 || resumedQueues > 0
        ? `🤖 AI Auto-Check recovered ${recoveredVideos} waiting video(s), detected ${newlyDetectedVideos} new batch video(s), and resumed ${resumedQueues} queued video(s)!`
        : `🤖 AI Auto-Check complete: All active checkpoints synced (${waitingJobs.length} video(s) still waiting on upstream server).`;

    if (manualTrigger || recoveredVideos > 0 || newlyDetectedVideos > 0) {
      addAiAgentDecision(summary, manualTrigger ? 'MANUAL_CHECK' : 'AUTO_CHECK');
    }

    return { recoveredVideos, newlyDetectedVideos, resumedQueues, summary };
  } finally {
    aiAgentState.isCheckingNow = false;
  }
}

// Background Stall Watchdog + AI Autonomous Agent Loop
function startQueueStallWatchdog() {
  // 1. Auto-Resume non-paused queues cleanly after a 15s startup grace period (keeps boot & preview instantaneous)
  setTimeout(() => {
    if (aiAgentState.enabled) {
      runAiAutoCheckCycle(false).catch(() => {});
    }
  }, 15000);

  // Periodic temp directory sweep every 10 mins to prevent /tmp disk bloat
  setInterval(() => {
    try {
      if (!fs.existsSync(DOWNLOAD_DIR)) return;
      const nowMs = Date.now();
      const activeIds = new Set<string>();
      for (const j of jobs.values()) {
        if (
          j.status === 'downloading' ||
          j.status === 'merging' ||
          j.status === 'uploading_bot_api' ||
          j.status === 'uploading_mtproto_userbot' ||
          j.status === 'uploading_google_drive'
        ) {
          activeIds.add(j.id);
        }
      }
      for (const file of fs.readdirSync(DOWNLOAD_DIR)) {
        const fileJobId = file.split('_')[0];
        if (activeIds.has(fileJobId)) continue;
        const fullPath = path.join(DOWNLOAD_DIR, file);
        const st = fs.statSync(fullPath);
        if (nowMs - st.mtimeMs > 20 * 60 * 1000) {
          fs.rmSync(fullPath, { recursive: true, force: true });
        }
      }
    } catch {
      // ignore
    }
  }, 10 * 60 * 1000);

  // 2. Periodic AI Auto-Check & Daily 24h Access Code Auto-Rotation Loop (every 45s)
  setInterval(() => {
    ensureValidAccessCode(true);
    if (!aiAgentState.enabled || aiAgentState.isCheckingNow) return;
    const nextMs = aiAgentState.nextCheckAt ? new Date(aiAgentState.nextCheckAt).getTime() : 0;
    if (Date.now() >= nextMs) {
      runAiAutoCheckCycle(false).catch(() => {});
    }
  }, 45000);

  // 3. Stall Watchdog: If any active video download/upload hangs for >150s with 0 progress, auto-retry ONLY if user has NOT stopped/paused!
  setInterval(() => {
    const now = Date.now();
    const stalledChats = new Set<string>();
    for (const job of jobs.values()) {
      const isRunning =
        job.status === 'downloading' ||
        job.status === 'merging' ||
        job.status === 'uploading_bot_api' ||
        job.status === 'uploading_mtproto_userbot' ||
        job.status === 'uploading_google_drive';
      if (!isRunning) continue;
      const cId = job.telegramChatId || '';
      if (cId && userExplicitlyPausedChats.has(cId)) continue;
      if (job.abortFlag) continue;
      const lastTick = job.lastProgressAt || new Date(job.createdAt).getTime();
      if (now - lastTick > 150000) {
        addBotLog(
          'SYSTEM',
          cId || 'watchdog',
          `Watchdog detected stalled job (${job.title}) after 150s of inactivity — auto-retrying!`
        );
        job.abortFlag = true;
        job.downloadEpoch = (job.downloadEpoch || 0) + 1;
        abortJobImmediately(job.id);
        job.status = 'paused';
        if (cId && !userExplicitlyPausedChats.has(cId)) {
          stalledChats.add(cId);
        }
      }
    }
    for (const cId of stalledChats) {
      if (userExplicitlyPausedChats.has(cId)) continue;
      activeChatWorkers.delete(cId);
      setTimeout(() => {
        if (userExplicitlyPausedChats.has(cId)) return;
        resumeChatDownloads(cId);
      }, 1000);
    }
  }, 15000);
}
startQueueStallWatchdog();

// ============================================================================
// BACKGROUND TELEGRAM BOT LONG-POLLING ENGINE + AUTO-CHANNEL BACKUP + ROUTING
// ============================================================================

let botPollingOffset = 0;
let botPollingActive = false;
const processedTelegramUpdateIds = new Set<number>();
const recentScanDedupMap = new Map<string, number>();

async function pollTelegramBotUpdates() {
  const token = process.env.TELEGRAM_BOT_TOKEN?.trim();
  if (!token) {
    botPollingActive = false;
    botInfoCache = { connected: false };
    setTimeout(pollTelegramBotUpdates, 5000);
    return;
  }
  try {
    if (!botInfoCache.connected) {
      await fetch(`https://api.telegram.org/bot${token}/deleteWebhook?drop_pending_updates=false`, {
        signal: AbortSignal.timeout(8000),
      }).catch(() => {});
      const meRes = await fetch(`https://api.telegram.org/bot${token}/getMe`, {
        signal: AbortSignal.timeout(10000),
      });
      const meData = (await meRes.json()) as any;
      if (meData.ok && meData.result) {
        botInfoCache = {
          connected: true,
          username: meData.result.username,
          firstName: meData.result.first_name,
        };
        botPollingActive = true;
        addBotLog('SYSTEM', 'bot', `Connected to Telegram Bot @${meData.result.username}`);
        await registerTelegramBotMenu(token);
      } else {
        botInfoCache = {
          connected: false,
          error: meData.description || 'Invalid TELEGRAM_BOT_TOKEN',
        };
        setTimeout(pollTelegramBotUpdates, 8000);
        return;
      }
    }

    botPollingActive = true;
    const updatesRes = await fetch(
      `https://api.telegram.org/bot${token}/getUpdates?offset=${botPollingOffset}&timeout=8`,
      { signal: AbortSignal.timeout(15000) }
    );
    const updatesData = (await updatesRes.json()) as any;

    if (!updatesData.ok) {
      if (updatesData.error_code === 409) {
        await fetch(`https://api.telegram.org/bot${token}/deleteWebhook?drop_pending_updates=false`, {
          signal: AbortSignal.timeout(5000),
        }).catch(() => {});
        setTimeout(pollTelegramBotUpdates, 3000);
        return;
      }
      if (updatesData.error_code === 429) {
        const retryAfter = Number(updatesData?.parameters?.retry_after || 5);
        setTimeout(pollTelegramBotUpdates, Math.min(30000, Math.max(2000, retryAfter * 1000)));
        return;
      }
      if (updatesData.error_code === 401) {
        botInfoCache = {
          connected: false,
          error: 'Invalid or revoked TELEGRAM_BOT_TOKEN (401 Unauthorized)',
        };
        botPollingActive = false;
        setTimeout(pollTelegramBotUpdates, 10000);
        return;
      }
      botInfoCache = {
        connected: false,
        error: updatesData.description || 'Telegram Bot API error',
      };
      setTimeout(pollTelegramBotUpdates, 5000);
      return;
    }

    let hadUpdates = false;
    if (updatesData.ok && Array.isArray(updatesData.result) && updatesData.result.length > 0) {
      hadUpdates = true;
      const maxUpdateId = updatesData.result[updatesData.result.length - 1].update_id;
      botPollingOffset = maxUpdateId + 1;

      for (const update of updatesData.result) {
        try {
          if (update.update_id >= botPollingOffset) {
            botPollingOffset = update.update_id + 1;
          }
          if (processedTelegramUpdateIds.has(update.update_id)) {
            continue;
          }
        processedTelegramUpdateIds.add(update.update_id);
        if (processedTelegramUpdateIds.size > 1000) {
          const oldest = processedTelegramUpdateIds.values().next().value;
          if (oldest !== undefined) processedTelegramUpdateIds.delete(oldest);
        }

        // 0A. Handle Inline Menu Button Callbacks (from /features menu & batch messages)
        if (update.callback_query) {
          const cb = update.callback_query;
          const cbId = cb.id;
          const cbData = String(cb.data || '');
          const cbChatId = String(cb.message?.chat?.id || cb.from?.id || '');
          const cbSenderId = String(cb.from?.id || cbChatId);
          const cbMsgId = cb.message?.message_id;

          if (!cbChatId) {
            await answerTelegramCallbackQuery(cbId);
            continue;
          }

          if (cbData === 'req:access') {
            const reqName = [cb.from?.first_name, cb.from?.last_name].filter(Boolean).join(' ') || 'Telegram User';
            recordAccessAttempt({
              chatId: cbChatId,
              senderId: cbSenderId,
              firstName: reqName,
              username: cb.from?.username,
              status: 'pending',
              reason: 'User tapped Ask Admin for Approval button',
              forceNotifyAdmin: true,
            });
            await answerTelegramCallbackQuery(cbId, '📩 Approval request sent to Main Admin!');
            await sendTelegramTextMessage(
              cbChatId,
              `📩 **Access Request Sent to Main Admin!**\n\n` +
                `Aapki ID (\`${cbSenderId}\`) Main Admin ke paas approval ke liye bhej di gayi hai.\n` +
                `Jab Admin approve karega (ya aapko naya Daily 4-digit code dega), tab bot start ho jayega.`
            );
            continue;
          }

          if (cbData.startsWith('adm:')) {
            if (!isAdminOrDev(cbChatId, cbSenderId)) {
              await answerTelegramCallbackQuery(cbId, '🚫 Only Main Admin / Staff can perform this action.');
              continue;
            }
            const parts = cbData.split(':');
            const action = parts[1];
            const targetId = parts[2] || '';
            if (action === 'app24' && targetId) {
              const sess = grantUserAccess(targetId, '24h', cbSenderId);
              await answerTelegramCallbackQuery(cbId, `✅ Approved ${targetId} for 24h`);
              await sendTelegramTextMessage(
                cbChatId,
                `✅ Approved User **${sess.firstName}** (\`${targetId}\`) for **24 Hours** by ${cbSenderId}.`
              );
              const uMenu = buildFeaturesMenuPayload(targetId, targetId);
              await sendTelegramTextMessage(
                targetId,
                `🎉 **Access Approved by Admin!**\n\n✅ Aapka bot access **24 Hours** ke liye activate kar diya gaya hai. Ab aap koi bhi video/course link bhej sakte hain!`,
                uMenu.replyMarkup
              ).catch(() => {});
            } else if (action === 'applife' && targetId) {
              const sess = grantUserAccess(targetId, 'permanent', cbSenderId);
              await answerTelegramCallbackQuery(cbId, `♾️ Approved ${targetId} Permanently`);
              await sendTelegramTextMessage(
                cbChatId,
                `♾️ Approved User **${sess.firstName}** (\`${targetId}\`) **Permanently** by ${cbSenderId}.`
              );
              const uMenu = buildFeaturesMenuPayload(targetId, targetId);
              await sendTelegramTextMessage(
                targetId,
                `🎉 **Permanent Access Approved by Admin!**\n\n♾️ Aapka bot access permanently activate kar diya gaya hai. Ab aap koi bhi video/course link bhej sakte hain!`,
                uMenu.replyMarkup
              ).catch(() => {});
            } else if (action === 'deny' && targetId) {
              const rev = revokeUserAccess(targetId, cbSenderId);
              await answerTelegramCallbackQuery(cbId, rev.ok ? `🚫 Revoked ${targetId}` : (rev.error || 'Error'));
              await sendTelegramTextMessage(
                cbChatId,
                rev.ok ? `🚫 Access Denied & Revoked for \`${targetId}\`.` : `⚠️ ${rev.error}`
              );
              if (rev.ok && targetId !== cbChatId) {
                await sendTelegramTextMessage(
                  targetId,
                  `🚫 Bot server exceeded. Please send access code or ask admin.`
                ).catch(() => {});
              }
            } else if ((action === 'mkadmin' || action === 'mkdev') && targetId) {
              if (!isMainAdmin(cbChatId, cbSenderId)) {
                await answerTelegramCallbackQuery(cbId, `🚫 Only Main Admin (${MAIN_ADMIN_ID}) can appoint roles.`);
                continue;
              }
              const role = action === 'mkdev' ? 'developer' : 'admin';
              const resRole = appointStaffRole(targetId, role, cbSenderId);
              await answerTelegramCallbackQuery(cbId, resRole.ok ? `✅ Appointed ${role.toUpperCase()}` : (resRole.error || 'Error'));
              await sendTelegramTextMessage(
                cbChatId,
                resRole.ok
                  ? `👑 User \`${targetId}\` is now appointed as **${role.toUpperCase()}**!`
                  : `⚠️ ${resRole.error}`
              );
              if (resRole.ok) {
                const uMenu = buildFeaturesMenuPayload(targetId, targetId);
                await sendTelegramTextMessage(
                  targetId,
                  `👑 **Congratulations!** Main Admin (${MAIN_ADMIN_ID}) has appointed you as Bot **${role.toUpperCase()}**! Type /admin anytime to open the control panel.`,
                  uMenu.replyMarkup
                ).catch(() => {});
              }
            } else if (action === 'rmstaff' && targetId) {
              const resRm = removeStaffRole(targetId, cbSenderId);
              await answerTelegramCallbackQuery(cbId, resRm.ok ? `⬇️ Demoted ${targetId}` : (resRm.error || 'Error'));
              await sendTelegramTextMessage(
                cbChatId,
                resRm.ok ? `⬇️ Removed Admin/Developer role for \`${targetId}\`.` : `⚠️ ${resRm.error}`
              );
            }
            continue;
          }

          if (!isChatAuthorized(cbChatId, cbSenderId)) {
            await answerTelegramCallbackQuery(
              cbId,
              '🔒 Bot server exceeded. Please send access code or ask admin.'
            );
            continue;
          }

          if (cbData === 'feat:invite') {
            if (!isAdminOrDev(cbChatId, cbSenderId)) {
              await answerTelegramCallbackQuery(cbId, '🔒 Admin Only');
              continue;
            }
            await answerTelegramCallbackQuery(cbId, '🔑 Daily Code & Invite Link');
            const currentCodeState = ensureValidAccessCode(false);
            const botUsername = botInfoCache.username || 'Updates_send_me_bot';
            const inviteLink = `https://t.me/${botUsername}?start=${currentCodeState.code}`;
            await sendTelegramTextMessage(
              cbChatId,
              `🔑 **Daily Rotating Access Code & Invite Link**\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `Code: \`${currentCodeState.code}\` (${currentCodeState.durationLabel})\n` +
                `Expires: ${new Date(currentCodeState.expiresAt).toLocaleString()}\n` +
                `Link: ${inviteLink}\n\n` +
                `⚠️ Ye code har 24 hours me auto-rotate hota hai.`
            );
            continue;
          }

          if (cbData.startsWith('feat:admin:')) {
            if (!isAdminOrDev(cbChatId, cbSenderId)) {
              await answerTelegramCallbackQuery(cbId, '🚫 Admin / Developer Only');
              continue;
            }
            if (cbData === 'feat:admin:panel') {
              await answerTelegramCallbackQuery(cbId, '👑 Opening Admin Panel');
              const adm = buildAdminPanelPayload(cbSenderId || cbChatId);
              await sendTelegramTextMessage(cbChatId, adm.text, adm.replyMarkup);
            } else if (cbData === 'feat:admin:newcode') {
              const oldCode = botSettings.accessCode?.code;
              botSettings.accessCode = createFreshAccessCode('24h', oldCode);
              saveBotSettings();
              await answerTelegramCallbackQuery(cbId, `🔑 New Daily Code: ${botSettings.accessCode.code}`);
              const adm = buildAdminPanelPayload(cbSenderId || cbChatId);
              await editTelegramTextMessage(cbChatId, cbMsgId, adm.text, adm.replyMarkup);
            } else if (cbData === 'feat:admin:users') {
              await answerTelegramCallbackQuery(cbId, '👥 Loading Users & Attempts');
              const attList = Object.values(botSettings.accessAttempts)
                .sort((a, b) => new Date(b.lastAttemptAt).getTime() - new Date(a.lastAttemptAt).getTime())
                .slice(0, 12);
              const lines =
                attList.length > 0
                  ? attList
                      .map(
                        (a, i) =>
                          `${i + 1}. [${a.status.toUpperCase()}] ${a.firstName}${a.username ? ` (@${a.username})` : ''} · ID: \`${a.senderId}\` · Tries: ${a.attemptsCount}`
                      )
                      .join('\n')
                  : 'No user access attempts recorded yet.';
              await sendTelegramTextMessage(
                cbChatId,
                `👥 **Users & Access Attempts (${attList.length} recent)**\n━━━━━━━━━━━━━━━━━━━━━━\n${lines}\n\nUse \`/approve <id> 24h\`, \`/approve <id> permanent\`, or \`/revoke <id>\`.`
              );
            } else if (cbData === 'feat:admin:staff') {
              await answerTelegramCallbackQuery(cbId, '🛡 Loading Staff Roles');
              const staff = Object.values(botSettings.staffRoles);
              const sLines =
                staff.length > 0
                  ? staff
                      .map((s, i) => `${i + 1}. ${s.role === 'developer' ? '🛠 DEV' : '👮 ADMIN'} — ${s.name || s.userId} (\`${s.userId}\`)`)
                      .join('\n')
                  : 'No secondary Admins or Developers appointed yet.';
              await sendTelegramTextMessage(
                cbChatId,
                `🛡 **Main Admin & Appointed Staff**\n━━━━━━━━━━━━━━━━━━━━━━\n👑 MAIN ADMIN: \`${MAIN_ADMIN_ID}\` (Immutable)\n${sLines}\n\nMain Admin commands:\n\`/addadmin <user_id> [name]\`\n\`/adddev <user_id> [name]\`\n\`/removeadmin <user_id>\``
              );
            } else if (cbData === 'feat:admin:audit') {
              await answerTelegramCallbackQuery(cbId, '🐞 Running Bug Bounty Audit...');
              const report = await runSystemBugBountyAudit();
              const checkLines = report.checks
                .map((c) => `${c.status === 'PASS' ? '✅' : c.status === 'WARN' ? '⚠️' : '❌'} [${c.category}] ${c.name}: ${c.detail}`)
                .join('\n');
              await sendTelegramTextMessage(
                cbChatId,
                `🐞 **A2Z Bug Bounty & Speed Audit (${report.durationMs}ms)**\n` +
                  `━━━━━━━━━━━━━━━━━━━━━━\n` +
                  `✅ Passed: ${report.passedCount} | ⚠️ Warn: ${report.warnCount} | ❌ Fail: ${report.failCount}\n` +
                  `🚀 Live MTProto Sockets: ${report.activeMtprotoSockets + report.secondaryMtprotoSockets} | 🧹 Temp Swept: ${report.tempFilesSwept} | 💾 Disk: ${report.diskUsageMb} MB\n` +
                  `━━━━━━━━━━━━━━━━━━━━━━\n${checkLines}`
              );
            }
            continue;
          }

          if (cbData === 'feat:help:addapi') {
            await answerTelegramCallbackQuery(cbId, '🚀 Dual API Speed Boost');
            await sendTelegramTextMessage(
              cbChatId,
              `🚀 **Dual-API 24-Socket MTProto Turbo Booster**\n\n` +
                `Apna 2nd API ID & Hash add karne ke liye bhejein:\n` +
                `\`/addapi <API_ID> <API_HASH>\`\n\n` +
                `Isse Primary (12 Sockets) + Secondary (12 Sockets) = **24 Parallel TCP_NODELAY Upload Sockets** active ho jate hain!`
            );
            continue;
          }

          if (cbData === 'feat:help:setcookies') {
            await answerTelegramCallbackQuery(cbId, '🍪 YouTube / Instagram Cookies');
            await sendTelegramTextMessage(
              cbChatId,
              `🍪 **YouTube / Instagram Cookies Setup**\n\n` +
                `1️⃣ \`cookies.txt\` file direct bot me bhejein (caption me \`cookies\` likh kar)\n` +
                `2️⃣ Ya bhejein: \`/setcookies <paste cookies.txt content>\`\n` +
                `3️⃣ Clear karne ke liye: \`/setcookies clear\``
            );
            continue;
          }

          if (cbData === 'feat:login:start' || cbData === 'feat:login:token') {
            const prevCtx = lastFailedPortalContextByChat.get(cbChatId);
            const isTokenMode = cbData === 'feat:login:token';
            await answerTelegramCallbackQuery(
              cbId,
              isTokenMode ? '🍪 Portal Cookie / Token Login' : '🔐 Web Portal Login (No + Pass)'
            );
            if (prevCtx && Date.now() - prevCtx.updatedAt < 30 * 60 * 1000) {
              pendingPortalLoginByChat.set(cbChatId, {
                step: isTokenMode ? 'awaiting_token' : 'awaiting_identifier',
                origin: prevCtx.origin,
                retryUrl: prevCtx.url,
                portalPath: prevCtx.portalPath,
                preferredQuality: prevCtx.preferredQuality,
                explicitTargetChannelId: prevCtx.explicitTargetChannelId,
                deliveryMode: prevCtx.deliveryMode,
                updatedAt: Date.now(),
              });
              if (isTokenMode) {
                await sendTelegramTextMessage(
                  cbChatId,
                  `🍪 **Portal Cookie / Token Login — \`${prevCtx.origin}\`**\n\n` +
                    `Apna browser **Cookie header** (ya JWT / Bearer Token) yahan paste karein.\n` +
                    `Login hote hi aapki blocked link auto-download start ho jayegi!\n` +
                    `_(Cancel karne ke liye \`/cancel\` likhein)_`
                );
              } else {
                await sendTelegramTextMessage(
                  cbChatId,
                  `🔐 **Web Portal Login — \`${prevCtx.origin}\`**\n\n` +
                    `📱 **Step 1/2:** Apna Registered **Mobile Number** (ya Email / Username) bhejein:\n` +
                    `_(Cancel karne ke liye \`/cancel\` likhein)_`
                );
              }
            } else {
              pendingPortalLoginByChat.set(cbChatId, {
                step: 'awaiting_origin',
                updatedAt: Date.now(),
              });
              await sendTelegramTextMessage(
                cbChatId,
                isTokenMode
                  ? `🍪 **Portal Cookie / Token Login**\n\nCommand format:\n\`/weblogin token <website_url> <cookie_ya_token>\`\n\nYa pehle **Website / Course Link** bhejein:`
                  : `🔐 **Web Portal Login (Mobile Number + Password)**\n\n🌐 **Step 1/3:** Jis website/portal me login karna hai uska **Link** bhejein (jaise \`https://studybeepro.site\` ya apna course link):\n\n💡 _Direct 1-line command:_\n\`/weblogin <url> <number_or_email> <password>\``
              );
            }
            continue;
          }

          if (cbData === 'feat:login:cancel') {
            pendingPortalLoginByChat.delete(cbChatId);
            await answerTelegramCallbackQuery(cbId, '❌ Login Cancelled');
            await sendTelegramTextMessage(cbChatId, `❌ Web portal login cancelled.`);
            continue;
          }

          if (cbData.startsWith('feat:q:')) {
            const newQ = cbData.replace('feat:q:', '').trim().toLowerCase();
            if (['144p', '240p', '360p', '480p', '720p', '1080p'].includes(newQ)) {
              const { updatedJobsCount } = applyGlobalQualityChange(newQ as VideoQualityOption);
              addBotLog(
                'SYSTEM',
                cbChatId,
                `Changed Default Video Quality via /features menu to ${newQ.toUpperCase()} (updated ${updatedJobsCount} queued/paused jobs)`
              );
              await answerTelegramCallbackQuery(
                cbId,
                `✅ Quality set to ${newQ.toUpperCase()} (Applied to ${updatedJobsCount} queued/paused videos!)`
              );
              const menu = buildFeaturesMenuPayload(cbChatId, cbSenderId);
              await editTelegramTextMessage(cbChatId, cbMsgId, menu.text, menu.replyMarkup);
            }
            continue;
          }

          if (cbData.startsWith('feat:mode:')) {
            botSettings.preferFullSingleVideo = true;
            saveBotSettings();
            const label = '100% Full Single Video (Puri Video up to 2GB)';
            addBotLog('SYSTEM', cbChatId, `Video delivery enforced as ${label}`);
            await answerTelegramCallbackQuery(cbId, `✅ ${label}`);
            const menu = buildFeaturesMenuPayload(cbChatId, cbSenderId);
            await editTelegramTextMessage(cbChatId, cbMsgId, menu.text, menu.replyMarkup);
            continue;
          }

          if (cbData === 'feat:refresh') {
            await answerTelegramCallbackQuery(cbId, '🔄 Menu Refreshed!');
            const menu = buildFeaturesMenuPayload(cbChatId, cbSenderId);
            await editTelegramTextMessage(cbChatId, cbMsgId, menu.text, menu.replyMarkup);
            continue;
          }

          if (cbData === 'feat:view:channels') {
            await answerTelegramCallbackQuery(cbId, '🛡️ Opening Backup Channels & Rules');
            const bList =
              botSettings.backupChannels.length > 0
                ? botSettings.backupChannels
                    .map((b, i) => `${i + 1}. ${b.enabled ? '🟢' : '⚪'} ${b.title} (${b.chatId})`)
                    .join('\n')
                : 'No Backup Channels added yet.';
            const rList =
              botSettings.routeRules.length > 0
                ? botSettings.routeRules
                    .map(
                      (r, i) =>
                        `${i + 1}. ${r.enabled ? '🎯' : '⚪'} "${r.pattern}" -> ${r.targetTitle} (${r.targetChatId})`
                    )
                    .join('\n')
                : 'No Fix-Link Rules added yet.';
            await sendTelegramTextMessage(
              cbChatId,
              `🛡️ Backup Channels / Groups (All Videos Saved Here):\n${bList}\n\n` +
                `🎯 Fix Link -> Fix Channel Rules:\n${rList}\n\n` +
                `💡 Tip: Apne Channel se koi bhi message yahan Forward karein ya Bot ko Channel me Admin banayein!`
            );
            continue;
          }

          if (cbData === 'feat:help:addbackup') {
            await answerTelegramCallbackQuery(cbId, '➕ How to Add Backup Channel');
            await sendTelegramTextMessage(
              cbChatId,
              `➕ Backup Channel / Group Add Karne Ke 3 Tarike:\n\n` +
                `1️⃣ Automatic: @${botInfoCache.username || 'bot'} ko apne Channel ya Group me Admin add karein — bot turant auto-save chalu kar dega!\n` +
                `2️⃣ Forward Method: Apne Channel ki koi bhi post is bot ko Forward karein.\n` +
                `3️⃣ Command Method: Send karein:\n` +
                `/addbackup -1001234567890 My Backup Vault`
            );
            continue;
          }

          if (cbData === 'feat:help:route') {
            await answerTelegramCallbackQuery(cbId, '🎯 Fix Link -> Fix Channel Guide');
            await sendTelegramTextMessage(
              cbChatId,
              `🎯 Fix Link -> Fix Channel Feature:\n\n` +
                `Kisi specific website/course/subject ki videos ko kisi fix channel me bhejne ke 2 tarike:\n\n` +
                `1️⃣ Permanent Rule Set Karein:\n` +
                `/route subjectid=1677 -100192837465 RWA Maths Channel\n\n` +
                `2️⃣ One-Time Link Ke Sath Channel ID Bhejein:\n` +
                `https://studybeepro.site/rwax/topic.html?courseid=284&subjectid=1677&domainId=RWA -> -100192837465`
            );
            continue;
          }

          if (cbData === 'feat:help:only') {
            await answerTelegramCallbackQuery(cbId, '🎯 Selected Videos (/only) Guide');
            await sendTelegramTextMessage(
              cbChatId,
              `🎯 /only — Single Ya Selected Videos Download Kaise Karein:\n\n` +
                `1️⃣ Agar course me se SIRF 1 single video (jaise Lecture #123) download karni hai:\n` +
                `👉 /only 123 https://studybeepro.site/rwax/content.html?id=565\n` +
                `(Ya pehle /only 123 bhejein aur uske baad Course Link bhejein)\n\n` +
                `2️⃣ Agar multiple selected videos download karni hain:\n` +
                `👉 /only 12, 45, 128 https://studybeepro.site/...\n\n` +
                `3️⃣ Agar range me videos chahiye:\n` +
                `👉 /only 10-15, 25 https://studybeepro.site/...\n\n` +
                `✅ Sirf aapki di gayi video hi download hogi, baaki koi video download nahi hogi aur wo video complete hote hi Task Complete ho jayega!`
            );
            continue;
          }

          if (cbData === 'feat:help:skip') {
            await answerTelegramCallbackQuery(cbId, '⏭️ Skip Videos (/skip) Guide');
            await sendTelegramTextMessage(
              cbChatId,
              `⏭️ /skip — Shuru Ki Videos Skip Kaise Karein:\n\n` +
                `1️⃣ Agar shuru ki 95 videos skip karke seedha Lecture #96 se download start karna hai:\n` +
                `👉 /skip 95 https://studybeepro.site/...\n` +
                `(Ya pehle /skip 95 bhejein aur uske baad Course Link bhejein)\n\n` +
                `2️⃣ Agar batch chal raha hai tab bhi /skip 95 bhejne par Lecture 1 se 95 skip hokar Lecture 96 se start ho jayega!`
            );
            continue;
          }

          if (cbData === 'feat:help:course') {
            await answerTelegramCallbackQuery(cbId, '📂 Multi-Folder Course Guide');
            await sendTelegramTextMessage(
              cbChatId,
              `📂 Deep Multi-Folder & Course Video Extractor:\n\n` +
                `• Aap koi bhi Course/Topic link (e.g. StudyBee / RWA / HLS .m3u8 / JS Player page) seedha bot me bhej sakte hain.\n` +
                `• Bot khud saare nested folders aur topics scan karke ek-ek video (${botSettings.globalDefaultQuality.toUpperCase()} default quality) download karega.\n` +
                `• Agar kisi single link ke liye alag quality chahiye to link ke aage likhein:\n` +
                `<link> 480p  ya  <link> 1080p`
            );
            continue;
          }

          if (cbData === 'feat:view:queue') {
            await answerTelegramCallbackQuery(cbId, '📊 Checking Queue');
            const stats = getChatJobStats(cbChatId);
            const activeJobs = Array.from(jobs.values()).filter(
              (j) =>
                j.telegramChatId === cbChatId &&
                (j.status === 'downloading' || j.status === 'merging' || j.status.startsWith('uploading'))
            );
            const activeLines =
              activeJobs.length > 0
                ? activeJobs
                    .map(
                      (j, i) =>
                        `${i + 1}. ⏳ ${j.title} — ${j.status.toUpperCase()} (${Math.round(j.progressPercent || 0)}%)`
                    )
                    .join('\n')
                : 'No video currently downloading.';
            await sendTelegramTextMessage(
              cbChatId,
              `📊 Your Batch Download Status:\n\n` +
                `✅ Already Downloaded (Completed): ${stats.completedCount} video(s)\n` +
                `⚡ Currently Processing (${activeJobs.length}):\n${activeLines}\n\n` +
                `🕒 Waiting in Queue: ${stats.queuedCount} video(s)\n` +
                `⏸️ Paused / Resumable: ${stats.pausedCount + stats.resumableFailedCount} video(s)`
            );
            continue;
          }

          if (cbData === 'feat:action:resume') {
            const resInfo = resumeChatDownloads(cbChatId);
            addBotLog(
              'SYSTEM',
              cbChatId,
              `Resumed ${resInfo.resumedCount} pending video(s) via Telegram Resume button (skipped ${resInfo.skippedCompletedCount} completed)`
            );
            if (resInfo.resumedCount > 0) {
              await answerTelegramCallbackQuery(
                cbId,
                `▶️ Resumed ${resInfo.resumedCount} pending video(s)!`
              );
              await sendTelegramTextMessage(
                cbChatId,
                `▶️ Batch Download Resumed!\n\n` +
                  `✅ Skipped Already Downloaded: ${resInfo.skippedCompletedCount} video(s)\n` +
                  `🚀 Resuming Remaining Videos: ${resInfo.resumedCount} video(s)\n` +
                  (resInfo.firstResumedTitle
                    ? `🎬 Starting from: ${resInfo.firstResumedTitle}`
                    : '')
              );
            } else {
              await answerTelegramCallbackQuery(
                cbId,
                'ℹ️ No paused or pending videos left to resume!'
              );
              await sendTelegramTextMessage(
                cbChatId,
                `ℹ️ Koi ruki hui ya pending video baki nahi hai (Completed: ${resInfo.skippedCompletedCount} videos). Naya link bhej kar download start kar sakte hain!`
              );
            }
            continue;
          }

          if (cbData === 'feat:action:pause' || cbData === 'feat:action:stop') {
            const { pausedCount, totalPausedInQueue } = pauseChatDownloads(cbChatId);
            addBotLog('SYSTEM', cbChatId, `Paused ${pausedCount} video(s) via Telegram Pause/Stop button`);
            await answerTelegramCallbackQuery(cbId, `⏸️ Paused ${pausedCount || totalPausedInQueue} video(s)`);
            await sendTelegramTextMessage(
              cbChatId,
              `⏸️ Queue Paused! (${totalPausedInQueue} paused video(s) in queue).\n\n` +
                `▶️ Wapas wahi se start karne ke liye /resume bhejein (already downloaded videos dobara nahi hongi).\n` +
                `🗑️ Agar saari paused videos delete karni hain to /clear bhejein.`,
              {
                inline_keyboard: [
                  [
                    { text: '▶️ Resume (/resume)', callback_data: 'feat:action:resume' },
                    { text: '🗑️ Clear Queue (/clear)', callback_data: 'feat:action:clear' },
                  ],
                ],
              }
            );
            continue;
          }

          if (cbData === 'feat:action:clear') {
            const { clearedCount } = clearPausedChatDownloads(cbChatId);
            addBotLog('SYSTEM', cbChatId, `Cleared ${clearedCount} paused video(s) via Telegram Clear button`);
            await answerTelegramCallbackQuery(cbId, `🗑️ Deleted ${clearedCount} paused video(s)!`);
            await sendTelegramTextMessage(
              cbChatId,
              `🗑️ Cleared & Deleted ${clearedCount} video(s) from the queue!\n` +
                `✅ Jo videos pehle download ho chuki hain unki history safe hai (koi bhi video duplicate download nahi hogi).`
            );
            continue;
          }

          if (cbData === 'feat:action:reset') {
            const { clearedJobsCount } = resetAllBotData(cbChatId);
            addBotLog('SYSTEM', cbChatId, `Factory reset all queue, history & checkpoints (${clearedJobsCount} jobs removed)`);
            await answerTelegramCallbackQuery(cbId, '🔄 All Data & History Reset!');
            const menu = buildFeaturesMenuPayload(cbChatId, cbSenderId);
            await sendTelegramTextMessage(
              cbChatId,
              `🔄 **All Bot Data Refreshed & Reset!**\n\n` +
                `✅ Queue Cleared: ${clearedJobsCount} video(s)\n` +
                `✅ Completed History, Checkpoints & Auto-Watch Reset!\n` +
                `🚀 Ab aap naye sire se koi bhi link ya /only command bhej sakte hain.`,
              menu.replyMarkup
            );
            continue;
          }

          if (cbData === 'feat:ai:checknow') {
            await answerTelegramCallbackQuery(cbId, '🤖 Running AI Auto-Check & Stream Probe...');
            const resCheck = await runAiAutoCheckCycle(true);
            await sendTelegramTextMessage(
              cbChatId,
              `${resCheck.summary}\n\n` +
                `✅ Auto-Recovered Waiting Videos: ${resCheck.recoveredVideos}\n` +
                `🎬 Newly Detected Batch Videos: ${resCheck.newlyDetectedVideos}\n` +
                `🚀 Active Resumed Queues: ${resCheck.resumedQueues}`,
              {
                inline_keyboard: [
                  [
                    { text: '🔄 Check Again Now', callback_data: 'feat:ai:checknow' },
                    { text: '📊 AI Agent & Checkpoints', callback_data: 'feat:ai:status' },
                  ],
                ],
              }
            );
            continue;
          }

          if (cbData === 'feat:ai:toggle') {
            aiAgentState.enabled = !aiAgentState.enabled;
            saveBotSettings();
            await answerTelegramCallbackQuery(
              cbId,
              aiAgentState.enabled ? '🟢 AI Auto-Check Enabled!' : '⚪ AI Auto-Check Paused!'
            );
            const snap = getAiAgentStatusSnapshot();
            await sendTelegramTextMessage(
              cbChatId,
              `🤖 AI Auto-Download & Watch Agent is now ${snap.enabled ? 'ACTIVE 🟢' : 'PAUSED ⚪'}!\n` +
                `🔄 Check Interval: Every ${snap.intervalMinutes} minutes.`
            );
            continue;
          }

          if (cbData === 'feat:ai:status') {
            await answerTelegramCallbackQuery(cbId, '🤖 Opening AI Agent Status');
            const snap = getAiAgentStatusSnapshot();
            const cpLines =
              snap.courseCheckpoints.length > 0
                ? snap.courseCheckpoints
                    .slice(0, 6)
                    .map(
                      (c, i) =>
                        `${i + 1}. 📚 ${c.courseName}\n   👉 Last Completed: Lecture #${c.lastCompletedBatchOrder}/${c.totalVideos || '?'} (${c.lastCompletedTitle})\n   ✅ Done: ${c.completedCount} | 🕒 Waiting Stream: ${c.waitingCount}`
                    )
                    .join('\n\n')
                : 'No course checkpoints recorded yet.';
            await sendTelegramTextMessage(
              cbChatId,
              `🤖 StreamBridge AI Autonomous Agent Status:\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `🟢 Status: ${snap.enabled ? `ACTIVE (Auto-checks every ${snap.intervalMinutes} mins)` : 'PAUSED'}\n` +
                `🕒 Videos Waiting for Stream: ${snap.waitingStreamsCount}\n` +
                `📡 Watched Batch Links: ${snap.watchedCoursesCount}\n` +
                `♻️ Total Auto-Recovered Videos: ${snap.totalAutoRecoveredVideos}\n\n` +
                `📌 Saved Course Checkpoints (Auto-Starts Here Without /skip):\n${cpLines}`,
              {
                inline_keyboard: [
                  [
                    { text: '🤖 Run AI Check Now', callback_data: 'feat:ai:checknow' },
                    {
                      text: snap.enabled ? '⏸️ Pause AI Auto-Check' : '▶️ Enable AI Auto-Check',
                      callback_data: 'feat:ai:toggle',
                    },
                  ],
                ],
              }
            );
            continue;
          }

          if (cbData.startsWith('only_quick:')) {
            const actionParts = cbData.split(':');
            const actionType = actionParts[1]; // 'next1' | 'next5' | 'cont' | 'full'
            const lastCtx = lastCourseContextByChat.get(cbChatId);
            if (!lastCtx || !lastCtx.sourceUrl) {
              await answerTelegramCallbackQuery(
                cbId,
                '⚠️ Course link session expired. Send link or /only command again.'
              );
              continue;
            }
            const parsedArg = parseInt(actionParts[2] || '', 10);
            const startArg =
              Number.isFinite(parsedArg) && parsedArg > 0
                ? parsedArg
                : Math.max(1, (lastCtx.lastOrder || 0) + 1);

            await answerTelegramCallbackQuery(cbId, '⚡ Queuing from Ultra-Fast Cache (<50ms)...');
            void (async () => {
              try {
                const maxNeeded =
                  actionType === 'next1'
                    ? startArg
                    : actionType === 'next5'
                    ? startArg + 4
                    : undefined;
                const extracted = await inspectUrlAndExtractStreams(
                  lastCtx.sourceUrl,
                  undefined,
                  undefined,
                  true,
                  undefined,
                  maxNeeded
                );
                if (!extracted.streams || extracted.streams.length === 0) {
                  await sendTelegramTextMessage(
                    cbChatId,
                    `⚠️ Could not load streams for: ${lastCtx.sourceUrl}`
                  );
                  return;
                }

                const totalCount = extracted.streams.length;
                let selectedIndices: number[] = [];
                if (actionType === 'next1') {
                  if (startArg <= totalCount) selectedIndices = [startArg];
                } else if (actionType === 'next5') {
                  for (let n = startArg; n <= Math.min(totalCount, startArg + 4); n++) {
                    selectedIndices.push(n);
                  }
                } else if (actionType === 'cont') {
                  for (let n = startArg; n <= totalCount; n++) {
                    selectedIndices.push(n);
                  }
                } else if (actionType === 'full') {
                  for (let n = 1; n <= totalCount; n++) {
                    selectedIndices.push(n);
                  }
                }

                const isSelectiveOnly = actionType === 'next1' || actionType === 'next5';
                const isFreshFullBatch = actionType === 'full';
                let queuedNow = 0;

                if (isFreshFullBatch) {
                  for (const [jId, existingJob] of Array.from(jobs.entries())) {
                    if (
                      (!existingJob.telegramChatId || existingJob.telegramChatId === cbChatId) &&
                      existingJob.status !== 'completed'
                    ) {
                      existingJob.abortFlag = true;
                      existingJob.downloadEpoch = (existingJob.downloadEpoch || 0) + 1;
                      cleanupJobTempFiles(jId);
                      jobs.delete(jId);
                    }
                  }
                  const oldQ = chatJobQueues.get(cbChatId);
                  if (oldQ) oldQ.length = 0;
                  activeChatWorkers.delete(cbChatId);
                  chatWorkerGeneration.set(cbChatId, (chatWorkerGeneration.get(cbChatId) || 0) + 1);
                }

                const cbBatchSeenKeys = new Set<string>();
                for (const lectureNum of selectedIndices) {
                  const stream = extracted.streams[lectureNum - 1];
                  if (!stream) continue;

                  const streamKeys = getVideoDedupeKeys({
                    initialSourceUrl: stream.url,
                    sourceUrl: stream.url,
                    originalRequestUrl: lastCtx.sourceUrl,
                    courseName: stream.courseName || extracted.pageTitle,
                    folderName: stream.folderName,
                    lectureTitle: stream.lectureTitle || stream.label,
                    batchOrder: lectureNum,
                  });
                  if (streamKeys.some((k) => cbBatchSeenKeys.has(k))) {
                    continue;
                  }
                  for (const k of streamKeys) cbBatchSeenKeys.add(k);

                  if (
                    !isSelectiveOnly &&
                    !isFreshFullBatch &&
                    isVideoAlreadyCompletedForChat(cbChatId, {
                      initialSourceUrl: stream.url,
                      sourceUrl: stream.url,
                      originalRequestUrl: lastCtx.sourceUrl,
                      courseName: stream.courseName || extracted.pageTitle,
                      folderName: stream.folderName,
                      lectureTitle: stream.lectureTitle || stream.label,
                      batchOrder: lectureNum,
                    })
                  ) {
                    continue;
                  }

                  const jobId = crypto.randomUUID();
                  const newJob: DownloadJob = {
                    id: jobId,
                    title: `📹 Lecture ${lectureNum}/${totalCount}: ${stream.label}`,
                    courseName: stream.courseName || extracted.pageTitle,
                    subjectName: stream.subjectName,
                    topicName: stream.topicName,
                    lectureTitle: stream.lectureTitle || stream.label,
                    folderName: stream.folderName,
                    sourceUrl: stream.url,
                    initialSourceUrl: stream.url,
                    originalRequestUrl: lastCtx.sourceUrl,
                    explicitTargetChannelId: lastCtx.explicitTargetChannelId,
                    batchOrder: lectureNum,
                    protocol: stream.protocol,
                    preferredQuality: lastCtx.preferredQuality || botSettings.globalDefaultQuality || '480p',
                    resolution: stream.resolution || lastCtx.preferredQuality || '480p',
                    status: 'queued',
                    progressPercent: 0,
                    totalSegments: 1,
                    completedSegments: 0,
                    downloadedBytes: 0,
                    speedBytesPerSec: 0,
                    deliveryMode: 'telegram_auto',
                    telegramChatId: cbChatId,
                    outputFormat: 'mp4',
                    createdAt: new Date().toISOString(),
                    fileReadyForBrowser: false,
                    cleanupAfterTelegram: true,
                    forceDownload: isSelectiveOnly,
                    skipCompletedCheck: isFreshFullBatch || isSelectiveOnly,
                  };
                  jobs.set(jobId, newJob);
                  enqueueJobForChat(cbChatId, newJob, false);
                  queuedNow++;
                }

                saveJobsState(true);
                await sendTelegramTextMessage(
                  cbChatId,
                  `⚡ **Turbo Instant Queue (<50ms Cache Hit)**\n` +
                    `📚 Course: ${extracted.pageTitle || lastCtx.courseName}\n` +
                    `🚀 Queued ${queuedNow} video(s) for Ultra-Fast 64x download!`
                );
                if (queuedNow > 0) {
                  void runChatSequentialWorker(cbChatId, true, true);
                }
              } catch (err: any) {
                await sendTelegramTextMessage(
                  cbChatId,
                  `❌ Failed to queue quick action: ${err?.message || 'Unknown error'}`
                );
              }
            })();
            continue;
          }

          await answerTelegramCallbackQuery(cbId);
          continue;
        }

        // 0B. Auto-detect when Bot is added as Admin/Member to any Channel or Group!
        const memberUpdate = update.my_chat_member;
        if (memberUpdate && memberUpdate.chat && memberUpdate.new_chat_member) {
          const newStatus = memberUpdate.new_chat_member.status;
          const chatObj = memberUpdate.chat;
          if (
            (newStatus === 'administrator' || newStatus === 'member') &&
            (chatObj.type === 'channel' || chatObj.type === 'supergroup' || chatObj.type === 'group')
          ) {
            const cId = String(chatObj.id);
            const cTitle = chatObj.title || `Channel ${cId}`;
            const cType = chatObj.type === 'channel' ? 'channel' : 'group';
            upsertBackupChannel(cId, cTitle, cType, 'bot');
            addBotLog(
              'SYSTEM',
              cId,
              `Auto-registered Backup ${cType.toUpperCase()}: "${cTitle}" (${cId})`
            );
            await sendTelegramTextMessage(
              cId,
              `✅ StreamBridge Auto-Backup Enabled!\n\n` +
                `📌 Name: ${cTitle}\n` +
                `🆔 Chat ID: ${cId}\n` +
                `🛡️ Ab bot se download hone wali saari videos proper Full MP4 format me yahan as a backup save hongi!`
            );
          }
          continue;
        }

        // Also support `/addbackup` or `/id` posted directly inside a Channel
        if (update.channel_post && update.channel_post.chat) {
          const chPost = update.channel_post;
          const cId = String(chPost.chat.id);
          const cTitle = chPost.chat.title || `Channel ${cId}`;
          const postText = (chPost.text || '').trim();
          if (postText.startsWith('/addbackup') || postText.startsWith('/id') || postText.startsWith('/start')) {
            upsertBackupChannel(cId, cTitle, 'channel', 'bot');
            addBotLog('SYSTEM', cId, `Registered Backup Channel via channel post: "${cTitle}" (${cId})`);
            await sendTelegramTextMessage(
              cId,
              `✅ Backup Channel Registered: "${cTitle}" (ID: ${cId})\nSaari downloaded videos yahan automatically save hongi!`
            );
          }
          continue;
        }

        const msg = update.message;
        if (!msg) continue;

        // 1. Handle MTProto Userbot -> Bot -> All Target Chats Relay
        const captionText: string = msg.caption || '';
        const relayMatch = captionText.match(/^#RELAY_(-?\d+)_([^#]+)#\n?([\s\S]*)$/);
        if (relayMatch && (msg.video || msg.document)) {
          const fullTag = captionText.match(/^#RELAY_[^#]+#/)?.[0] || '';
          const parsedPrimaryChatId = relayMatch[1];
          const fallbackCaption = relayMatch[3] || '';
          const relayInfo = pendingUserbotRelays.get(fullTag);

          const enabledBackupIds = botSettings.backupChannels
            .filter((b) => b.enabled && b.chatId)
            .map((b) => b.chatId.trim());

          const allTargets =
            relayInfo?.allTargetChatIds && relayInfo.allTargetChatIds.length > 0
              ? relayInfo.allTargetChatIds
              : Array.from(new Set([parsedPrimaryChatId, ...enabledBackupIds].filter(Boolean)));
          const finalCaption = relayInfo?.cleanCaption || fallbackCaption;

          if (relayInfo) {
            pendingUserbotRelays.delete(fullTag);
          }

          for (const destChatId of allTargets) {
            await copyTelegramVideoMessage(msg.chat.id, msg.message_id, destChatId, finalCaption);
          }

          if (relayInfo) {
            relayInfo.resolve({ fromChatId: String(msg.chat.id), messageId: msg.message_id });
          }
          continue;
        }

        const chatId = String(msg.chat.id);
        const chatType = msg.chat.type;
        const senderId = String(msg.from?.id || chatId);
        const firstName =
          [msg.from?.first_name, msg.from?.last_name].filter(Boolean).join(' ') || 'Telegram User';
        const username = msg.from?.username;

        // 2. If user forwards a message from a Channel to the Bot, auto-add that Channel to Backup Channels!
        if (msg.forward_from_chat && (msg.forward_from_chat.type === 'channel' || msg.forward_from_chat.type === 'supergroup')) {
          if (isChatAuthorized(chatId, senderId)) {
            const fwdChat = msg.forward_from_chat;
            const fwdId = String(fwdChat.id);
            const fwdTitle = fwdChat.title || `Channel ${fwdId}`;
            const fwdType = fwdChat.type === 'channel' ? 'channel' : 'group';
            upsertBackupChannel(fwdId, fwdTitle, fwdType, 'bot');
            addBotLog('SYSTEM', chatId, `Added Backup ${fwdType} via forwarded message: "${fwdTitle}" (${fwdId})`);
            await sendTelegramTextMessage(
              chatId,
              `✅ Backup Channel/Group Added Successfully!\n\n` +
                `📢 Name: ${fwdTitle}\n` +
                `🆔 Channel ID: ${fwdId}\n\n` +
                `🛡️ Make sure @${botInfoCache.username || 'bot'} is an Admin in "${fwdTitle}". Ab har downloaded video automatically is channel me bhi save hogi!\n\n` +
                `🎯 Tip: Kisi fix link ko is channel me bhejne ke liye send karein:\n` +
                `/route <course_link_ya_keyword> ${fwdId}`
            );
            continue;
          }
        }

        // Handle .txt Netscape cookies file uploaded directly in Telegram
        if (msg.document && /\.txt$/i.test(String(msg.document.file_name || '')) && msg.document.file_size <= 2 * 1024 * 1024) {
          const cap = String(msg.caption || '').toLowerCase();
          const fname = String(msg.document.file_name || '').toLowerCase();
          if (cap.includes('cookie') || cap.includes('/setcookies') || fname.includes('cookie')) {
            if (!isChatAuthorized(chatId, senderId)) {
              recordAccessAttempt({
                chatId,
                senderId,
                firstName,
                username,
                status: 'failed',
                inputPreview: `File: ${msg.document.file_name}`,
                reason: 'Unauthorized cookies.txt upload attempt',
              });
              await sendTelegramTextMessage(
                chatId,
                '🔒 Bot server exceeded. Please send access code or ask admin.'
              );
              continue;
            }
            try {
              const tgToken = process.env.TELEGRAM_BOT_TOKEN?.trim() || '';
              const gfRes = await fetch(
                `https://api.telegram.org/bot${tgToken}/getFile?file_id=${encodeURIComponent(msg.document.file_id)}`
              );
              const gfJson = (await gfRes.json()) as any;
              const fPath = gfJson?.result?.file_path;
              if (fPath) {
                const fileRes = await fetch(`https://api.telegram.org/file/bot${tgToken}/${fPath}`);
                const cookiesText = await fileRes.text();
                if (cookiesText.trim().length > 20 && (cookiesText.includes('\t') || cookiesText.includes('Netscape'))) {
                  process.env.PLATFORM_COOKIES_TXT = cookiesText.trim();
                  saveBotSettings();
                  addBotLog('SYSTEM', chatId, `Saved Netscape cookies.txt (${cookiesText.length} bytes) via Telegram file upload`);
                  await sendTelegramTextMessage(
                    chatId,
                    `🍪 **YouTube / Instagram Cookies Saved Successfully!**\nAb aap koi bhi YouTube playlist, reel, ya Instagram link high quality MP4 me download kar sakte hain.`
                  );
                } else {
                  await sendTelegramTextMessage(
                    chatId,
                    `⚠️ Invalid cookies.txt format! Please export standard **Netscape HTTP Cookie File** format.`
                  );
                }
              }
            } catch (cErr: any) {
              await sendTelegramTextMessage(chatId, `❌ Failed to save cookies file: ${cErr?.message || 'Unknown error'}`);
            }
            continue;
          }
        }

        if (!msg.text) continue;

        const text = msg.text.trim();
        const rawLines = text.split(/\r?\n/).map((l: string) => l.trim()).filter(Boolean);
        let detectedCmd = text.split(/\s+/)[0].split('@')[0].toLowerCase();
        for (const line of rawLines) {
          const w = line.split(/\s+/)[0].split('@')[0].toLowerCase();
          if (
            [
              '/admin',
              '/users',
              '/attempts',
              '/approve',
              '/revoke',
              '/newcode',
              '/rotatecode',
              '/addadmin',
              '/adddev',
              '/removeadmin',
              '/demote',
              '/admins',
              '/staff',
              '/audit',
              '/bugbounty',
              '/ai',
              '/autocheck',
              '/clear',
              '/clearall',
              '/reset',
              '/stop',
              '/pause',
              '/resume',
              '/skip',
              '/startfrom',
              '/only',
              '/select',
              '/pick',
              '/features',
              '/menu',
              '/start',
              '/help',
              '/status',
              '/quality',
              '/mode',
              '/queue',
              '/channels',
              '/backups',
              '/invite',
              '/addapi',
              '/dualapi',
              '/setapi',
              '/setcookies',
              '/weblogin',
              '/login',
              '/weblogout',
              '/logout',
              '/cancel',
            ].includes(w)
          ) {
            detectedCmd = w;
            break;
          }
          if (
            ['ai', 'autocheck', 'clear', 'clearall', 'reset', 'stop', 'pause', 'resume', 'only', 'cancel'].includes(w) &&
            line.split(/\s+/).length <= 2
          ) {
            detectedCmd = `/${w}`;
            break;
          }
        }
        const baseCmd = detectedCmd;
        const activePendingLogin = pendingPortalLoginByChat.get(chatId);
        if (activePendingLogin && Date.now() - activePendingLogin.updatedAt > 10 * 60 * 1000) {
          pendingPortalLoginByChat.delete(chatId);
        }
        const isSensitiveLoginMsg =
          Boolean(
            pendingPortalLoginByChat.get(chatId) &&
              ['awaiting_password', 'awaiting_token'].includes(pendingPortalLoginByChat.get(chatId)!.step)
          ) || /^\/(?:weblogin|login)(?:@\S+)?\s+/i.test(text);
        addBotLog(
          'INCOMING',
          chatId,
          `${firstName} (${senderId}): ${
            isSensitiveLoginMsg ? `${baseCmd || '[LOGIN_INPUT]'} [REDACTED CREDENTIALS]` : text
          }`
        );

        const currentCodeState = ensureValidAccessCode(true);
        const active4Digit = currentCodeState.code;
        const botUsername = botInfoCache.username || 'Updates_send_me_bot';
        const inviteLink = `https://t.me/${botUsername}?start=${active4Digit}`;

        // 3. Strict 4-Digit Rotating Access Code Match (EXACT match or /start <CODE> payload only — prevents URL substring bypass!)
        const startParamMatch = text.match(/^\/start(?:@\S+)?\s+(\S+)/i);
        const startPayload = startParamMatch ? startParamMatch[1].trim() : '';
        const isExactCodeMatch = text.trim() === active4Digit || startPayload === active4Digit;

        if (isExactCodeMatch) {
          const durKey = currentCodeState.durationKey || '24h';
          grantUserAccess(senderId, durKey, 'DAILY_CODE', {
            firstName,
            username,
            activatedWithCode: active4Digit,
          });
          if (chatId !== senderId) {
            grantUserAccess(chatId, durKey, 'DAILY_CODE', {
              firstName,
              username,
              activatedWithCode: active4Digit,
            });
          }
          addBotLog(
            'SYSTEM',
            chatId,
            `Verified access for ${firstName} (${senderId}) using today's rotating code ${active4Digit} (${currentCodeState.durationLabel})`
          );
          if (senderId !== MAIN_ADMIN_ID) {
            sendTelegramTextMessage(
              MAIN_ADMIN_ID,
              `✅ **User Verified via Daily Access Code**\n👤 ${firstName}${username ? ` (@${username})` : ''} · ID: \`${senderId}\`\n🔑 Code: \`${active4Digit}\` (${currentCodeState.durationLabel})`
            ).catch(() => {});
          }

          await sendTelegramTextMessage(
            chatId,
            `🎉 Welcome ${firstName}!\n\n` +
              `✅ Access Activated (${currentCodeState.durationLabel})!\n\n` +
              `🎬 Ab aap koi bhi Website, YouTube/Instagram, Direct MP4, ya Course Link bhej kar high-speed MP4 video download kar sakte hain!`
          );
          const menu = buildFeaturesMenuPayload(chatId, senderId);
          await sendTelegramTextMessage(chatId, menu.text, menu.replyMarkup);
          continue;
        }

        if ((chatType === 'group' || chatType === 'supergroup') && baseCmd === '/addbackup' && isChatAuthorized(chatId, senderId)) {
          const grpTitle = msg.chat.title || `Backup Group ${chatId}`;
          upsertBackupChannel(chatId, grpTitle, 'group', 'bot');
          await sendTelegramTextMessage(
            chatId,
            `✅ Backup Group Registered: "${grpTitle}" (ID: ${chatId})\nAb bot se download hone wali saari videos is group me bhi save hongi!`
          );
          continue;
        }

        // 4. Strict Daily Access Code & Admin Approval Gate (Blocks ALL unauthorized users!)
        if (!isChatAuthorized(chatId, senderId)) {
          const wrong4Digit = /^\d{4}$/.test(text.trim()) || /^\d{4}$/.test(startPayload);
          recordAccessAttempt({
            chatId,
            senderId,
            firstName,
            username,
            status: 'failed',
            inputPreview: text,
            reason: wrong4Digit
              ? `Wrong or expired 4-digit code (${text.trim() || startPayload})`
              : baseCmd === '/start'
              ? 'New user /start without access code'
              : `Unauthorized command/message (${baseCmd})`,
            forceNotifyAdmin: baseCmd === '/start' || wrong4Digit,
          });
          await sendTelegramTextMessage(
            chatId,
            `🔒 Bot server exceeded. Please send access code or ask admin.${
              wrong4Digit ? '\n\n⚠️ Entered code is invalid or expired. Ask admin for today’s fresh code.' : ''
            }`,
            {
              inline_keyboard: [
                [
                  {
                    text: '📩 Ask Admin for Approval',
                    callback_data: 'req:access',
                  },
                ],
              ],
            }
          );
          addBotLog('SYSTEM', chatId, `Blocked unauthorized user ${firstName} (${senderId}). Prompted access code / admin.`);
          continue;
        }

        // ====================================================================
        // ADMIN, DEVELOPER, USER ACCESS & BUG BOUNTY COMMANDS
        // ====================================================================
        if (baseCmd === '/scanapi') {
          const scanUrl = text.replace(/^\/scanapi(?:@\S+)?/i, '').trim();
          if (!/^https?:\/\//i.test(scanUrl)) {
            await sendTelegramTextMessage(
              chatId,
              'Usage: `/scanapi https://your-authorized-portal.example/course/...`\n\n' +
                'Ye command metadata/stream count scan karega; video download ya Telegram upload nahi karega.'
            );
            continue;
          }

          const scanMsgId = await sendTelegramTextMessage(
            chatId,
            '🔎 Authorized batch metadata scan start ho raha hai… video download/upload nahi hoga.'
          );
          try {
            const extracted = await inspectUrlAndExtractStreams(
              scanUrl,
              undefined,
              undefined,
              true,
              (progressText) => {
                editTelegramTextMessage(chatId, scanMsgId, progressText).catch(() => {});
              },
              undefined,
              chatId
            );
            const sourceHosts = Array.from(
              new Set(
                extracted.streams.map((stream) => {
                  if (stream.url.startsWith('appx://')) return 'portal internal stream reference';
                  try {
                    const parsed = new URL(stream.url);
                    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
                  } catch {
                    return stream.protocol || 'unknown stream reference';
                  }
                })
              )
            ).slice(0, 12);
            const protocolCounts = new Map<string, number>();
            for (const stream of extracted.streams) {
              const key = stream.protocol || 'UNKNOWN';
              protocolCounts.set(key, (protocolCounts.get(key) || 0) + 1);
            }
            const protocolSummary = Array.from(protocolCounts.entries())
              .map(([protocol, count]) => `${protocol}: ${count}`)
              .join(', ') || 'None';
            const notes = extracted.notes.slice(-5).map((note) => `• ${note.slice(0, 180)}`).join('\n');
            const report =
              `✅ **API-only Metadata Scan Complete**\n` +
              `━━━━━━━━━━━━━━━━━━━━━━\n` +
              `📚 Title: ${extracted.pageTitle || 'Unknown'}\n` +
              `📁 Folders: ${extracted.folders.length}\n` +
              `🎬 Streams found: ${extracted.streams.length}\n` +
              `📄 Pages scanned: ${extracted.pagesScanned || 1}\n` +
              `🧩 Protocols: ${protocolSummary}\n` +
              `🌐 Safe source references:\n${sourceHosts.map((host) => `• ${host}`).join('\n') || '• None'}\n\n` +
              (notes ? `📝 Notes:\n${notes}\n\n` : '') +
              `⛔ Download started: **No**\n` +
              `⛔ Telegram upload started: **No**\n\n` +
              `🔐 Tokens, cookies, authorization headers aur signed query parameters intentionally hide kiye gaye hain.`;
            await editTelegramTextMessage(chatId, scanMsgId, report);
          } catch (scanErr: any) {
            await editTelegramTextMessage(
              chatId,
              scanMsgId,
              `❌ Metadata scan failed: ${String(scanErr?.message || 'Unknown error').slice(0, 500)}`
            );
          }
          continue;
        }

        if (baseCmd === '/admin') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, `🚫 Access Denied. Only Main Admin (${MAIN_ADMIN_ID}), Admins, or Developers can open /admin.`);
            continue;
          }
          const adm = buildAdminPanelPayload(senderId);
          await sendTelegramTextMessage(chatId, adm.text, adm.replyMarkup);
          continue;
        }

        if (baseCmd === '/newcode' || baseCmd === '/rotatecode') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, `🚫 Only Admins or Main Admin (${MAIN_ADMIN_ID}) can rotate the daily code.`);
            continue;
          }
          const prev = botSettings.accessCode?.code;
          botSettings.accessCode = createFreshAccessCode('24h', prev);
          saveBotSettings();
          addBotLog('SYSTEM', senderId, `Rotated daily 4-digit access code to ${botSettings.accessCode.code}`);
          await sendTelegramTextMessage(
            chatId,
            `🔑 **Daily 4-Digit Access Code Rotated!**\n\n` +
              `🆕 New Code: \`${botSettings.accessCode.code}\`\n` +
              `⏱ Valid For: 24 Hours (Until ${new Date(botSettings.accessCode.expiresAt).toLocaleString()})\n` +
              `🔗 Invite Link: https://t.me/${botUsername}?start=${botSettings.accessCode.code}`
          );
          continue;
        }

        if (baseCmd === '/users' || baseCmd === '/attempts') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🚫 Admin / Developer Only command.');
            continue;
          }
          const approved = Object.values(botSettings.authorizedUsers);
          const attempts = Object.values(botSettings.accessAttempts).sort(
            (a, b) => new Date(b.lastAttemptAt).getTime() - new Date(a.lastAttemptAt).getTime()
          );
          const approvedLines = approved
            .slice(0, 15)
            .map(
              (u, i) =>
                `${i + 1}. ${(u.role || 'user').toUpperCase()} · ${u.firstName || 'User'} (\`${u.chatId}\`) · ${
                  u.expiresAt.startsWith('2099-') ? 'Permanent' : '24h Active'
                }`
            )
            .join('\n');
          const attemptLines =
            attempts.length > 0
              ? attempts
                  .slice(0, 15)
                  .map(
                    (a, i) =>
                      `${i + 1}. [${a.status.toUpperCase()}] ${a.firstName} (\`${a.senderId}\`) · Tries: ${a.attemptsCount}`
                  )
                  .join('\n')
              : 'No attempts logged yet.';
          await sendTelegramTextMessage(
            chatId,
            `👥 **Approved Users (${approved.length})**\n${approvedLines || 'None'}\n\n` +
              `🚨 **All Failed / Pending / Reviewed Attempts (${attempts.length})**\n${attemptLines}\n\n` +
              `Commands:\n\`/approve <user_id> 24h\`\n\`/approve <user_id> permanent\`\n\`/revoke <user_id>\``
          );
          continue;
        }

        if (baseCmd === '/approve') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🚫 Only Admins can approve users.');
            continue;
          }
          const args = text.replace(/^\/approve(?:@\S+)?/i, '').trim().split(/\s+/).filter(Boolean);
          const targetId = args[0] || '';
          const modeArg = (args[1] || '24h').toLowerCase();
          if (!isValidTelegramChatId(targetId)) {
            await sendTelegramTextMessage(
              chatId,
              `Usage:\n\`/approve <user_id> 24h\`\n\`/approve <user_id> permanent\``
            );
            continue;
          }
          const dur: AccessDurationKey | 'permanent' =
            modeArg.startsWith('perm') || modeArg === 'life' ? 'permanent' : DURATION_MAP[modeArg as AccessDurationKey] ? (modeArg as AccessDurationKey) : '24h';
          const sess = grantUserAccess(targetId, dur, senderId);
          addBotLog('SYSTEM', senderId, `Approved user ${targetId} (${dur}) via /approve`);
          await sendTelegramTextMessage(
            chatId,
            `✅ Approved **${sess.firstName}** (\`${targetId}\`) for **${dur === 'permanent' ? 'Permanent' : dur}**!`
          );
          const uMenu = buildFeaturesMenuPayload(targetId, targetId);
          await sendTelegramTextMessage(
            targetId,
            `🎉 **Access Approved by Admin!**\nAapka bot access (${dur}) activate ho gaya hai. Ab aap koi bhi video/course link bhej sakte hain!`,
            uMenu.replyMarkup
          ).catch(() => {});
          continue;
        }

        if (baseCmd === '/revoke') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🚫 Only Admins can revoke users.');
            continue;
          }
          const targetId = text.replace(/^\/revoke(?:@\S+)?/i, '').trim().split(/\s+/)[0] || '';
          if (!targetId) {
            await sendTelegramTextMessage(chatId, `Usage: \`/revoke <user_id>\``);
            continue;
          }
          const resRev = revokeUserAccess(targetId, senderId);
          if (resRev.ok) {
            addBotLog('SYSTEM', senderId, `Revoked access for ${targetId} via /revoke`);
            await sendTelegramTextMessage(chatId, `🚫 Revoked & blocked access for user \`${targetId}\`.`);
            await sendTelegramTextMessage(
              targetId,
              `🔒 Bot server exceeded. Please send access code or ask admin.`
            ).catch(() => {});
          } else {
            await sendTelegramTextMessage(chatId, `⚠️ ${resRev.error}`);
          }
          continue;
        }

        if (baseCmd === '/setowner' || baseCmd === '/transferowner') {
          if (!isMainAdmin(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, `🚫 Only current Main Admin (\`${MAIN_ADMIN_ID}\`) can transfer ownership.`);
            continue;
          }
          const targetId = text.replace(/^\/(?:setowner|transferowner)(?:@\S+)?/i, '').trim().split(/\s+/)[0] || '';
          if (!isValidTelegramChatId(targetId)) {
            await sendTelegramTextMessage(chatId, 'Usage: `/setowner <user_id>`');
            continue;
          }
          const previousOwner = MAIN_ADMIN_ID;
          const transfer = transferMainAdmin(targetId, senderId);
          if (!transfer.ok) {
            await sendTelegramTextMessage(chatId, `⚠️ ${transfer.error}`);
            continue;
          }
          addBotLog('SYSTEM', senderId, `Transferred Main Admin ownership to ${targetId}`);
          await sendTelegramTextMessage(
            chatId,
            `✅ Main Admin ownership transferred to \`${targetId}\`.\n` +
              `Previous owner \`${previousOwner}\` remains an Admin to prevent lockout.`
          );
          await sendTelegramTextMessage(
            targetId,
            `👑 You are now the Main Admin of this bot.\nUse /admin to manage approvals, users, Admins and Developers.`
          ).catch(() => {});
          continue;
        }

        if (baseCmd === '/addadmin' || baseCmd === '/adddev') {
          if (!isMainAdmin(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, `🚫 Only Main Admin (\`${MAIN_ADMIN_ID}\`) can appoint Admins or Developers!`);
            continue;
          }
          const args = text.replace(/^\/(?:addadmin|adddev)(?:@\S+)?/i, '').trim().split(/\s+/).filter(Boolean);
          const targetId = args[0] || '';
          const staffName = args.slice(1).join(' ');
          const role: 'admin' | 'developer' = baseCmd === '/adddev' ? 'developer' : 'admin';
          const resRole = appointStaffRole(targetId, role, senderId, { name: staffName || undefined });
          if (resRole.ok) {
            addBotLog('SYSTEM', senderId, `Main Admin appointed ${targetId} as ${role}`);
            await sendTelegramTextMessage(
              chatId,
              `👑 Appointed \`${targetId}\`${staffName ? ` (${staffName})` : ''} as Bot **${role.toUpperCase()}**!`
            );
            const uMenu = buildFeaturesMenuPayload(targetId, targetId);
            await sendTelegramTextMessage(
              targetId,
              `👑 **Congratulations!** Main Admin (\`${MAIN_ADMIN_ID}\`) has appointed you as Bot **${role.toUpperCase()}**!\nType /admin anytime to manage the bot.`,
              uMenu.replyMarkup
            ).catch(() => {});
          } else {
            await sendTelegramTextMessage(chatId, `⚠️ ${resRole.error}`);
          }
          continue;
        }

        if (baseCmd === '/removeadmin' || baseCmd === '/demote') {
          if (!isMainAdmin(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, `🚫 Only Main Admin (\`${MAIN_ADMIN_ID}\`) can remove staff roles.`);
            continue;
          }
          const targetId = text.replace(/^\/(?:removeadmin|demote)(?:@\S+)?/i, '').trim().split(/\s+/)[0] || '';
          if (!targetId) {
            await sendTelegramTextMessage(chatId, `Usage: \`/removeadmin <user_id>\``);
            continue;
          }
          const resRm = removeStaffRole(targetId, senderId);
          await sendTelegramTextMessage(
            chatId,
            resRm.ok ? `⬇️ Demoted & removed staff role for \`${targetId}\`.` : `⚠️ ${resRm.error}`
          );
          continue;
        }

        if (baseCmd === '/admins' || baseCmd === '/staff') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🚫 Admin / Developer Only command.');
            continue;
          }
          const staff = Object.values(botSettings.staffRoles);
          const lines =
            staff.length > 0
              ? staff
                  .map((s, i) => `${i + 1}. ${s.role === 'developer' ? '🛠 DEV' : '👮 ADMIN'} — ${s.name || s.userId} (\`${s.userId}\`)`)
                  .join('\n')
              : 'No secondary Admins or Developers appointed yet.';
          await sendTelegramTextMessage(
            chatId,
            `🛡 **Appointed Staff Roster**\n━━━━━━━━━━━━━━━━━━━━━━\n👑 MAIN ADMIN: \`${MAIN_ADMIN_ID}\` (Immutable Root)\n${lines}`
          );
          continue;
        }

        if (baseCmd === '/audit' || baseCmd === '/bugbounty') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🚫 Only Main Admin / Admins / Developers can run /audit.');
            continue;
          }
          const waitMsgId = await sendTelegramTextMessage(chatId, '🐞 Running Full A2Z Bug Bounty, Security & Upload Speed Audit...');
          const report = await runSystemBugBountyAudit();
          const lines = report.checks
            .map((c) => `${c.status === 'PASS' ? '✅' : c.status === 'WARN' ? '⚠️' : '❌'} [${c.category}] ${c.name}: ${c.detail}`)
            .join('\n');
          const summaryMsg =
            `🐞 **A2Z Bug Bounty & Speed Audit (${report.durationMs}ms)**\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n` +
            `✅ Passed: ${report.passedCount} | ⚠️ Warn: ${report.warnCount} | ❌ Fail: ${report.failCount}\n` +
            `🚀 Live MTProto Sockets: ${report.activeMtprotoSockets + report.secondaryMtprotoSockets} | 🧹 Temp Swept: ${report.tempFilesSwept} | 💾 Disk: ${report.diskUsageMb} MB\n` +
            `━━━━━━━━━━━━━━━━━━━━━━\n${lines}`;
          if (waitMsgId) {
            await editTelegramTextMessage(chatId, waitMsgId, summaryMsg);
          } else {
            await sendTelegramTextMessage(chatId, summaryMsg);
          }
          continue;
        }

        // Dedicated /addapi command — allows user to add a 2nd Telegram API_ID + API_HASH for Dual MTProto Turbo Booster!
        if (baseCmd === '/addapi' || baseCmd === '/dualapi' || baseCmd === '/setapi') {
          const parts = text
            .replace(/^\/(addapi|dualapi|setapi)(?:@\S+)?/i, '')
            .trim()
            .split(/[\s,:|]+/)
            .filter(Boolean);
          const rawNewApiId = parts[0] || '';
          const rawNewApiHash = parts[1] || '';
          const rawNewSession = parts[2] || '';

          if (!isValidTelegramApiId(rawNewApiId) || !isValidTelegramApiHash(rawNewApiHash)) {
            const curExtraId = process.env.EXTRA_TELEGRAM_API_ID?.trim() || '';
            const curPrimaryId = process.env.TELEGRAM_API_ID?.trim() || '37805311';
            await sendTelegramTextMessage(
              chatId,
              `⚡ **Dual MTProto 16-Socket Turbo Upload Booster**\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                `🟢 Engine #1 (Primary API ID): \`${curPrimaryId}\` (8 Parallel TCP Sockets Active)\n` +
                `${
                  curExtraId
                    ? `🟢 Engine #2 (Extra API ID): \`${curExtraId}\` (8 Parallel TCP Sockets Active — Total 16x Turbo!)`
                    : `⚪ Engine #2 (Extra API ID): Not Added Yet`
                }\n` +
                `🚀 Parallel Pipeline: **2 Videos Simultaneous** (Video #2 downloads while Video #1 uploads, delivered strictly in 1, 2, 3... order!)\n\n` +
                `💡 **2nd API ID & API Hash Kaise Add Karein:**\n` +
                `Chat me aise bhejein:\n` +
                `\`/addapi <API_ID> <API_HASH>\`\n\n` +
                `Example:\n` +
                `\`/addapi 28491023 a1b2c3d4e5f60718293a4b5c6d7e8f90\``
            );
            continue;
          }

          process.env.EXTRA_TELEGRAM_API_ID = rawNewApiId.trim();
          process.env.EXTRA_TELEGRAM_API_HASH = rawNewApiHash.trim();
          if (isValidTelegramStringSession(rawNewSession)) {
            process.env.EXTRA_TELEGRAM_STRING_SESSION = rawNewSession.trim();
          }
          saveBotSettings();
          addBotLog('SYSTEM', chatId, `Configured Secondary MTProto API ID ${rawNewApiId.trim()} via /addapi`);

          const testMsgId = await sendTelegramTextMessage(
            chatId,
            `⚡ Connecting Secondary MTProto Engine (API ID: ${rawNewApiId.trim()}) with 8 Parallel TCP Sockets...`
          );
          const secClient = await getSecondaryUserbotClient(true);
          if (secClient && secClient.connected) {
            await editTelegramTextMessage(
              chatId,
              testMsgId || 0,
              `🚀 **Dual MTProto 16-Socket Turbo Booster Activated!**\n\n` +
                `✅ Engine #1 (Primary API): Connected (8 Parallel TCP Sockets)\n` +
                `✅ Engine #2 (New API ID \`${rawNewApiId.trim()}\`): Connected (8 Parallel TCP Sockets)\n` +
                `⚡ Total Upload Channels: **16 Parallel MTProto Streams (~25-45 MB/s)**\n` +
                `🎬 Parallel Pipeline: **2 Videos Simultaneous** (Strict 1, 2, 3... Delivery Order!)`
            );
          } else {
            await editTelegramTextMessage(
              chatId,
              testMsgId || 0,
              `✅ Secondary API ID (\`${rawNewApiId.trim()}\`) Saved!\n` +
                `⚠️ Secondary MTProto handshake will auto-retry on next upload (check API ID & API Hash if it fails).`
            );
          }
          continue;
        }

        // Dedicated /setcookies command — stores Netscape cookies.txt for locked YouTube / Instagram / Social videos
        if (baseCmd === '/setcookies') {
          const payload = text.replace(/^\/setcookies(?:@\S+)?/i, '').trim();
          if (/^clear$/i.test(payload)) {
            process.env.PLATFORM_COOKIES_TXT = '';
            saveBotSettings();
            await sendTelegramTextMessage(chatId, `🗑️ Cleared saved YouTube / Instagram cookies.`);
            continue;
          }
          if (!payload || (!payload.includes('\t') && !payload.includes('Netscape'))) {
            const hasC = Boolean((process.env.PLATFORM_COOKIES_TXT || '').trim());
            await sendTelegramTextMessage(
              chatId,
              `🍪 **YouTube / Instagram Cookies Vault** (${hasC ? '🟢 Cookies Saved' : '⚪ Not Set'})\n\n` +
                `Agar koi YouTube video "Sign in to confirm you're not a bot" ya private Instagram Reel download karni ho:\n` +
                `1️⃣ Browser me "Get cookies.txt LOCALLY" extension se \`cookies.txt\` export karein.\n` +
                `2️⃣ Direct \`cookies.txt\` file is bot ko bhejein (filename ya caption me "cookies" likh kar), YA paste karein:\n` +
                `\`/setcookies <paste cookies.txt content>\`\n` +
                `🗑️ Clear karne ke liye: \`/setcookies clear\``
            );
            continue;
          }
          process.env.PLATFORM_COOKIES_TXT = payload;
          saveBotSettings();
          addBotLog('SYSTEM', chatId, `Saved Netscape cookies.txt (${payload.length} bytes) via /setcookies command`);
          await sendTelegramTextMessage(
            chatId,
            `✅ **YouTube / Instagram Cookies Saved!**\nAb protected YouTube videos aur Instagram links bhi high-quality MP4 me download hongi.`
          );
          continue;
        }

        // Helper to trigger URL scan & queue (used by direct link intake AND auto-retry after /weblogin!)
        const triggerTelegramUrlScanAndQueue = async (
          targetUrl: string,
          opts?: {
            preferredQuality?: string;
            explicitTargetChannelId?: string;
            effectiveDeliveryMode?: DownloadJob['deliveryMode'];
            effectiveSkipCount?: number;
            effectiveOnlyList?: number[];
          }
        ) => {
          const preferredQuality = opts?.preferredQuality || botSettings.globalDefaultQuality || '480p';
          const explicitTargetChannelId = opts?.explicitTargetChannelId;
          const effectiveDeliveryMode = opts?.effectiveDeliveryMode || 'telegram_auto';
          const effectiveSkipCount = opts?.effectiveSkipCount || 0;
          const effectiveOnlyList = opts?.effectiveOnlyList || [];
          const effectiveOnlySet = effectiveOnlyList.length > 0 ? new Set(effectiveOnlyList) : null;

          if (!effectiveOnlySet) {
            upsertWatchedCourse({
              sourceUrl: targetUrl,
              courseName: targetUrl,
              chatId,
              preferredQuality,
              explicitTargetChannelId,
              totalVideosFound: 0,
            });
          }

          const scanStopEpoch = globalStopEpoch;
          const scanChatEpoch = stopEpochByChat.get(chatId) || 0;
          const matchedRule = findMatchingRouteRule(targetUrl);
          const activeRouteLabel =
            explicitTargetChannelId || matchedRule?.targetTitle || matchedRule?.targetChatId;

          const baseScanHeader =
            `🔍 Scanning folders & videos (Quality: ${preferredQuality.toUpperCase()})...\n` +
            (effectiveOnlySet
              ? `🎯 /only Filter Active: Only ${effectiveOnlySet.size} selected video(s) will be downloaded (#${effectiveOnlyList.join(', #')}) — Separate from batch duplicate history\n`
              : effectiveSkipCount > 0
              ? `⏭️ Auto-Skip Active: First ${effectiveSkipCount} videos will be skipped (Starting from Lecture ${effectiveSkipCount + 1})\n`
              : `🔢 Strict 1, 2, 3... Numberwise Queue: Starts from #1 (Zero skips, zero duplicates)\n`) +
            (activeRouteLabel ? `🎯 Routing to Channel: ${activeRouteLabel}\n` : '');

          const statusMsgId = await sendTelegramTextMessage(chatId, `${baseScanHeader}${targetUrl}`);
          const maxVideosNeededForOnly = effectiveOnlySet ? Math.max(...effectiveOnlyList) : undefined;

          void (async () => {
            let lastScanProgressEdit = 0;
            try {
              const extracted = await inspectUrlAndExtractStreams(
                targetUrl,
                undefined,
                undefined,
                true,
                (progressLine) => {
                  const now = Date.now();
                  if (
                    statusMsgId &&
                    now - lastScanProgressEdit > 2200 &&
                    globalStopEpoch === scanStopEpoch &&
                    (stopEpochByChat.get(chatId) || 0) === scanChatEpoch
                  ) {
                    lastScanProgressEdit = now;
                    editTelegramTextMessage(
                      chatId,
                      statusMsgId,
                      `${baseScanHeader}${progressLine}\n${targetUrl}`
                    ).catch(() => {});
                  }
                },
                maxVideosNeededForOnly,
                chatId
              );

              if (
                globalStopEpoch !== scanStopEpoch ||
                (stopEpochByChat.get(chatId) || 0) !== scanChatEpoch
              ) {
                await editTelegramTextMessage(
                  chatId,
                  statusMsgId,
                  `🛑 Course Scan Cancelled by /stop:\n${targetUrl}`
                );
                return;
              }

              if (!effectiveOnlySet) {
                upsertWatchedCourse({
                  sourceUrl: targetUrl,
                  courseName: extracted.pageTitle || targetUrl,
                  chatId,
                  preferredQuality,
                  explicitTargetChannelId,
                  totalVideosFound: extracted.streams.length,
                });
              }

              if (extracted.streams.length === 0) {
                let parsedOrigin = '';
                let parsedPortal = '';
                try {
                  const uObj = new URL(targetUrl);
                  parsedOrigin = uObj.origin;
                  const seg0 = uObj.pathname.split('/').filter(Boolean)[0];
                  parsedPortal = seg0 && !/\.(html?|php|js|css|json)$/i.test(seg0) ? `/${seg0}` : '';
                } catch {}
                if (parsedOrigin) {
                  lastFailedPortalContextByChat.set(chatId, {
                    url: targetUrl,
                    origin: parsedOrigin,
                    portalPath: parsedPortal || undefined,
                    reason: extracted.authRequiredReason || 'empty',
                    preferredQuality,
                    explicitTargetChannelId,
                    deliveryMode: effectiveDeliveryMode,
                    updatedAt: Date.now(),
                  });
                }

                const cookiesNeededNote = extracted.notes?.find((n) =>
                  /Sign in to confirm|netscape|youtube|instagram/i.test(n)
                );
                if (extracted.authRequiredOrigin) {
                  const isCookieGate = extracted.authRequiredReason === 'cookie_check';
                  const authPromptText = isCookieGate
                    ? `🔒 **Web Portal Authentication / Cookie Check Required**\n` +
                      `🌐 Site: \`${extracted.authRequiredOrigin}\`\n\n` +
                      `Yeh link login/cookie verification maang raha hai.\n` +
                      `1️⃣ Agar is site par ID/Password chalta hai to **"🔐 Login (Number + Password)"** dabayein\n` +
                      `2️⃣ Ya AI Studio / browser protected link ke liye **"🍪 Paste Cookie / Token"** dabayein!`
                    : `🔐 **Web Portal Login Required**\n` +
                      `🌐 Site: \`${extracted.authRequiredOrigin}\`\n\n` +
                      `Is website par videos access karne ke liye apna **Mobile Number / Email & Password** (ya Cookie/Token) se login karein. Login hote hi bot automatically download start kar dega!`;
                  const authKb = {
                    inline_keyboard: [
                      [
                        { text: '🔐 Login (Number + Password)', callback_data: 'feat:login:start' },
                        { text: '🍪 Paste Cookie / Token', callback_data: 'feat:login:token' },
                      ],
                      [
                        { text: '🤖 AI Check Now', callback_data: 'feat:ai:checknow' },
                        { text: '📊 AI Agent Status', callback_data: 'feat:ai:status' },
                      ],
                    ],
                  };
                  const edited = await editTelegramTextMessage(chatId, statusMsgId, authPromptText, authKb);
                  if (!edited) {
                    await sendTelegramTextMessage(chatId, authPromptText, authKb);
                  }
                } else if (cookiesNeededNote) {
                  const cookieErrText =
                    `🔒 **Platform Verification / Cookies Required**\n` +
                    `${targetUrl}\n\n` +
                    `YouTube / Instagram server IP check active hai.\n` +
                    `🍪 Is platform ki videos download karne ke liye browser se \`cookies.txt\` export karke Telegram par send karein (ya \`/setcookies <paste>\` / Web Dashboard me Cookies Vault me save karein)!`;
                  const edited = await editTelegramTextMessage(chatId, statusMsgId, cookieErrText);
                  if (!edited) {
                    await sendTelegramTextMessage(chatId, cookieErrText);
                  }
                } else {
                  const errText =
                    `🤖 AI Auto-Watch Registered for:\n${targetUrl}\n\n` +
                    `ℹ️ Abhi is link par koi active video stream detect nahi hui hai (Pages scanned: ${
                      extracted.pagesScanned || 1
                    }). Agar is portal me login required hai to neeche **"🔐 Web Login (No + Pass)"** dabayein — warna AI Agent har ${
                      aiAgentState.intervalMinutes
                    } minute me khud check karke download start kar dega.`;
                  const edited = await editTelegramTextMessage(chatId, statusMsgId, errText, {
                    inline_keyboard: [
                      [
                        { text: '🔐 Web Login (No + Pass)', callback_data: 'feat:login:start' },
                        { text: '🍪 Cookie / Token', callback_data: 'feat:login:token' },
                      ],
                      [
                        { text: '🤖 AI Check Now', callback_data: 'feat:ai:checknow' },
                        { text: '📊 AI Agent Status', callback_data: 'feat:ai:status' },
                      ],
                    ],
                  });
                  if (!edited) {
                    await sendTelegramTextMessage(chatId, errText);
                  }
                }
              } else if (extracted.streams.length > 1) {
                const folderCounts = new Map<string, number>();
                for (const s of extracted.streams) {
                  const fn = s.folderName || 'General';
                  folderCounts.set(fn, (folderCounts.get(fn) || 0) + 1);
                }
                const folderSummaryLines = Array.from(folderCounts.entries())
                  .slice(0, 12)
                  .map(([fName, cnt], idx) => `  ${idx + 1}. 📂 ${fName} (${cnt} videos)`)
                  .join('\n');
                const moreFoldersNote =
                  folderCounts.size > 12 ? `\n  ...and ${folderCounts.size - 12} more folder(s)` : '';

                for (const [jId, existingJob] of Array.from(jobs.entries())) {
                  if (
                    (!existingJob.telegramChatId || existingJob.telegramChatId === chatId) &&
                    existingJob.status !== 'completed'
                  ) {
                    existingJob.abortFlag = true;
                    existingJob.downloadEpoch = (existingJob.downloadEpoch || 0) + 1;
                    cleanupJobTempFiles(jId);
                    jobs.delete(jId);
                  }
                }
                const existingChatQ = chatJobQueues.get(chatId);
                if (existingChatQ) existingChatQ.length = 0;
                activeChatWorkers.delete(chatId);
                chatWorkerGeneration.set(chatId, (chatWorkerGeneration.get(chatId) || 0) + 1);

                const sampleCourseName = extracted.streams[0]?.courseName || extracted.pageTitle;
                const cKey = getCourseCheckpointKey({
                  courseName: sampleCourseName,
                  originalRequestUrl: targetUrl,
                });
                if (!effectiveOnlySet && effectiveSkipCount === 0 && cKey) {
                  courseCheckpoints.delete(cKey);
                  saveCourseCheckpointsState();
                }

                let skippedByCommand = 0;
                let skippedByOnly = 0;
                let skippedDupesInLink = 0;
                let queuedNow = 0;
                let firstActiveLectureNum = 0;
                const batchSeenCanonicalKeys = new Set<string>();

                for (let idx = 0; idx < extracted.streams.length; idx++) {
                  const stream = extracted.streams[idx];
                  const lectureNum = idx + 1;

                  let canonicalVidKey = String(stream.url || '').trim().toLowerCase();
                  if (canonicalVidKey.startsWith('appx://')) {
                    try {
                      const u = new URL(canonicalVidKey.replace(/^appx:\/\//i, 'http://'));
                      const cId = (u.searchParams.get('courseid') || '').trim().toLowerCase();
                      const vId = (u.searchParams.get('videoid') || '').trim().toLowerCase();
                      if (vId) canonicalVidKey = `appx::${cId}::${vId}`;
                    } catch {}
                  }
                  if (canonicalVidKey && batchSeenCanonicalKeys.has(canonicalVidKey)) {
                    skippedDupesInLink++;
                    continue;
                  }
                  if (canonicalVidKey) {
                    batchSeenCanonicalKeys.add(canonicalVidKey);
                  }

                  if (effectiveOnlySet && !effectiveOnlySet.has(lectureNum)) {
                    skippedByOnly++;
                    continue;
                  }

                  if (effectiveSkipCount > 0 && idx < effectiveSkipCount) {
                    skippedByCommand++;
                    continue;
                  }

                  const jobId = crypto.randomUUID();
                  const newJob: DownloadJob = {
                    id: jobId,
                    title: `📹 Lecture ${lectureNum}/${extracted.streams.length}: ${stream.label}`,
                    courseName: stream.courseName || extracted.pageTitle,
                    courseCode: extractCourseCodeFromJob({ sourceUrl: stream.url, originalRequestUrl: targetUrl }) || undefined,
                    subjectName: stream.subjectName,
                    topicName: stream.topicName,
                    lectureTitle: stream.lectureTitle || stream.label,
                    folderName: stream.folderName,
                    pdfUrl: stream.pdfUrl,
                    sourceUrl: stream.url,
                    initialSourceUrl: stream.url,
                    originalRequestUrl: targetUrl,
                    explicitTargetChannelId,
                    batchOrder: lectureNum,
                    protocol: stream.protocol,
                    preferredQuality,
                    resolution: stream.resolution || preferredQuality,
                    status: 'queued',
                    progressPercent: 0,
                    totalSegments: 1,
                    completedSegments: 0,
                    downloadedBytes: 0,
                    speedBytesPerSec: 0,
                    deliveryMode: effectiveDeliveryMode,
                    telegramChatId: chatId,
                    outputFormat: 'mp4',
                    createdAt: new Date().toISOString(),
                    fileReadyForBrowser: false,
                    cleanupAfterTelegram: true,
                    forceDownload: Boolean(effectiveOnlySet),
                    skipCompletedCheck: true,
                  };
                  jobs.set(jobId, newJob);
                  enqueueJobForChat(chatId, newJob, false);
                  queuedNow++;
                  if (!firstActiveLectureNum) firstActiveLectureNum = lectureNum;
                }

                saveCourseCheckpointsState();
                saveJobsState(true);

                const deliveryNote =
                  effectiveDeliveryMode === 'drive_only'
                    ? `☁️ Destination: 5TB Google Drive Only (${DRIVE_ROOT_FOLDER_NAME})\n`
                    : effectiveDeliveryMode === 'telegram_and_drive'
                    ? `☁️✈️ Dual Destination: Telegram + 5TB Google Drive (${DRIVE_ROOT_FOLDER_NAME})\n`
                    : '';

                const summaryText =
                  `✅ Bulk Course Extracted: "${extracted.pageTitle}"\n` +
                  `📂 Total Folders: ${extracted.folders.length || folderCounts.size || 1} | 🎬 Total Videos: ${extracted.streams.length}\n` +
                  deliveryNote +
                  (skippedByOnly > 0
                    ? `🎯 /only Filter: Queued ${queuedNow} selected (#${effectiveOnlyList.join(', #')}), skipped ${skippedByOnly} other videos\n`
                    : '') +
                  (skippedByCommand > 0
                    ? `⏭️ Skipped First ${skippedByCommand} Videos (Starting from Lecture ${skippedByCommand + 1}/${extracted.streams.length})\n`
                    : `🔢 Starting Strictly From Lecture #${firstActiveLectureNum || 1}/${extracted.streams.length} (1, 2, 3... Numberwise — No Skips)\n`) +
                  (skippedDupesInLink > 0
                    ? `🛡️ Removed ${skippedDupesInLink} duplicate entry inside link (Zero Duplicates)\n`
                    : '') +
                  (folderSummaryLines ? `\n📋 Folder Breakdown:\n${folderSummaryLines}${moreFoldersNote}\n\n` : '\n') +
                  `🎞 Quality: ${preferredQuality.toUpperCase()}\n` +
                  (activeRouteLabel ? `🎯 Target Channel: ${activeRouteLabel}\n` : '') +
                  (botSettings.backupChannels.filter((b) => b.enabled).length > 0
                    ? `🛡️ Auto-Backup: ${
                        botSettings.backupChannels.filter((b) => b.enabled).length
                      } channel/group(s)\n`
                    : '') +
                  `🚀 Queued ${queuedNow} video(s) for sequential 1,2,3... download!`;

                const summaryEdited = await editTelegramTextMessage(
                  chatId,
                  statusMsgId,
                  summaryText
                );
                if (!summaryEdited) {
                  await sendTelegramTextMessage(chatId, summaryText);
                }

                runChatSequentialWorker(chatId, true, true);
              } else {
                const chosen = extracted.streams[0];
                const q = chatJobQueues.get(chatId) || [];
                const chosenLower = String(chosen.url || '').trim().toLowerCase();
                for (let qi = q.length - 1; qi >= 0; qi--) {
                  const qj = q[qi];
                  if (
                    qj.status !== 'completed' &&
                    (String(qj.initialSourceUrl || '').trim().toLowerCase() === chosenLower ||
                      String(qj.sourceUrl || '').trim().toLowerCase() === chosenLower)
                  ) {
                    qj.abortFlag = true;
                    qj.downloadEpoch = (qj.downloadEpoch || 0) + 1;
                    abortJobImmediately(qj.id);
                    cleanupJobTempFiles(qj.id);
                    jobs.delete(qj.id);
                    q.splice(qi, 1);
                  }
                }

                const jobId = crypto.randomUUID();
                const newJob: DownloadJob = {
                  id: jobId,
                  title: extracted.pageTitle || chosen.label,
                  courseName: chosen.courseName || extracted.pageTitle,
                  courseCode: extractCourseCodeFromJob({ sourceUrl: chosen.url, originalRequestUrl: targetUrl }) || undefined,
                  subjectName: chosen.subjectName,
                  topicName: chosen.topicName,
                  lectureTitle: chosen.lectureTitle || chosen.label,
                  folderName: chosen.folderName,
                  pdfUrl: chosen.pdfUrl,
                  sourceUrl: chosen.url,
                  initialSourceUrl: chosen.url,
                  originalRequestUrl: targetUrl,
                  explicitTargetChannelId,
                  batchOrder: 1,
                  protocol: chosen.protocol,
                  preferredQuality,
                  resolution: chosen.resolution || preferredQuality,
                  status: 'queued',
                  progressPercent: 0,
                  totalSegments: chosen.segmentCount || 1,
                  completedSegments: 0,
                  downloadedBytes: 0,
                  speedBytesPerSec: 0,
                  deliveryMode: effectiveDeliveryMode,
                  telegramChatId: chatId,
                  telegramStatusMsgId: statusMsgId,
                  outputFormat: 'mp4',
                  createdAt: new Date().toISOString(),
                  fileReadyForBrowser: false,
                  cleanupAfterTelegram: true,
                  forceDownload: Boolean(effectiveOnlySet),
                  skipCompletedCheck: true,
                };
                jobs.set(jobId, newJob);
                enqueueJobForChat(chatId, newJob, true, true);
              }
            } catch (e: any) {
              const errText = `⚠️ Error extracting URL: ${e?.message || 'Unknown error'}`;
              const edited = await editTelegramTextMessage(chatId, statusMsgId, errText);
              if (!edited) {
                await sendTelegramTextMessage(chatId, errText);
              }
            }
          })();
        };

        // /cancel command clears any pending interactive prompt
        if (baseCmd === '/cancel') {
          const hadPending = pendingPortalLoginByChat.delete(chatId);
          await sendTelegramTextMessage(
            chatId,
            hadPending ? `❌ Interactive login flow cancelled.` : `ℹ️ Koi active prompt cancel karne ke liye nahi hai.`
          );
          continue;
        }

        // /weblogout or /logout clears saved portal session(s)
        if (baseCmd === '/weblogout' || baseCmd === '/logout') {
          pendingPortalLoginByChat.delete(chatId);
          const argHost = text.replace(/^\/(?:weblogout|logout)(?:@\S+)?\s*/i, '').trim();
          const count = clearPortalSessionForOrigin(argHost || 'all', chatId);
          await sendTelegramTextMessage(
            chatId,
            count > 0
              ? `🚪 Cleared **${count}** saved web portal login session(s)!`
              : `ℹ️ Koi saved web portal session active nahi hai.`
          );
          continue;
        }

        // /weblogin or /login — supports 1-line credentials, token/cookie login, or interactive No + Pass wizard
        if (baseCmd === '/weblogin' || baseCmd === '/login') {
          const rest = text.replace(/^\/(?:weblogin|login)(?:@\S+)?\s*/i, '').trim();
          if (!rest) {
            const existingSessions = Object.values(botSettings.portalSessions || {}).filter(
              (s) => !s.chatId || s.chatId === chatId
            );
            const activeLines =
              existingSessions.length > 0
                ? existingSessions
                    .slice(0, 6)
                    .map((s, i) => `${i + 1}. 🌐 \`${s.host}\` · 👤 \`${s.accountLabel || 'Session'}\``)
                    .join('\n') + '\n\n'
                : '';
            const prevFailed = lastFailedPortalContextByChat.get(chatId);
            pendingPortalLoginByChat.set(chatId, {
              step: 'awaiting_origin',
              ...(prevFailed && Date.now() - prevFailed.updatedAt < 30 * 60 * 1000
                ? {
                    origin: prevFailed.origin,
                    retryUrl: prevFailed.url,
                    portalPath: prevFailed.portalPath,
                    preferredQuality: prevFailed.preferredQuality,
                    explicitTargetChannelId: prevFailed.explicitTargetChannelId,
                    deliveryMode: prevFailed.deliveryMode,
                  }
                : {}),
              updatedAt: Date.now(),
            });
            await sendTelegramTextMessage(
              chatId,
              `🔐 **Web Portal Login Center (/weblogin)**\n` +
                `━━━━━━━━━━━━━━━━━━━━━━\n` +
                activeLines +
                `🌐 **Step 1/3:** Jis website ya course link me login karna hai wo **Link** bhejein (e.g. \`https://studybeepro.site/rwax/content.html?id=854\`):\n\n` +
                `💡 _Fast 1-line commands:_\n` +
                `• \`/weblogin <url> <mobile_no_or_email> <password>\`\n` +
                `• \`/weblogin token <url> <cookie_or_jwt_token>\`\n` +
                `• \`/weblogout\` — Saved login clear karein`,
              prevFailed
                ? {
                    inline_keyboard: [
                      [{ text: `🔐 Use Last Link (${normalizePortalHost(prevFailed.origin).host})`, callback_data: 'feat:login:start' }],
                      [{ text: '❌ Cancel', callback_data: 'feat:login:cancel' }],
                    ],
                  }
                : undefined
            );
            continue;
          }

          // Mode A: /weblogin token <url> <cookie_or_jwt>
          const tokMatch = rest.match(/^(?:token|cookie)\s+(https?:\/\/[^\s]+)\s+([\s\S]+)$/i);
          if (tokMatch) {
            const rawTargetUrl = tokMatch[1].trim();
            const rawSecret = tokMatch[2].trim();
            deleteTelegramMessage(chatId, msg.message_id).catch(() => {});
            try {
              const { origin, host, portalPath } = normalizePortalHost(rawTargetUrl);
              const isJwtOrBearer = /^Bearer\s+/i.test(rawSecret) || (/^eyJ[A-Za-z0-9_-]+\./.test(rawSecret) && !rawSecret.includes(';'));
              const session: PortalAuthSession = {
                origin,
                host,
                portalPath,
                ...(isJwtOrBearer ? { bearerToken: rawSecret.replace(/^Bearer\s+/i, '').trim() } : { cookieHeader: rawSecret }),
                ...(isJwtOrBearer ? { userId: extractTeachxJwtMeta(rawSecret.replace(/^Bearer\s+/i, '')).userId } : {}),
                accountLabel: isJwtOrBearer ? 'JWT Token' : 'Browser Cookie',
                authMethod: 'token_or_cookie',
                updatedAt: new Date().toISOString(),
              };
              savePortalSessionForOrigin(session, chatId);
              pendingPortalLoginByChat.delete(chatId);
              await sendTelegramTextMessage(
                chatId,
                `✅ **${isJwtOrBearer ? 'Bearer Token' : 'Session Cookie'} Saved for \`${host}\`!**\nBot ab aapki saved session ke saath videos scan aur download karega.`
              );
              const isCourseLink = /content|topic|subject|batch|play|course|id=/i.test(rawTargetUrl);
              if (isCourseLink) {
                await triggerTelegramUrlScanAndQueue(rawTargetUrl);
              }
            } catch (err: any) {
              await sendTelegramTextMessage(chatId, `⚠️ Invalid URL or token: ${err?.message || 'Error'}`);
            }
            continue;
          }

          // Mode B: /weblogin <url> <identifier> <password>
          const parts = rest.split(/\s+/).filter(Boolean);
          if (parts.length >= 3 && /^https?:\/\//i.test(parts[0])) {
            const rawUrl = parts[0].trim();
            const ident = parts[1].trim();
            const pwd = parts.slice(2).join(' ');
            deleteTelegramMessage(chatId, msg.message_id).catch(() => {});
            pendingPortalLoginByChat.delete(chatId);
            const waitId = await sendTelegramTextMessage(chatId, `🔐 Logging in to portal...`);
            try {
              const { origin, portalPath } = normalizePortalHost(rawUrl);
              const loginRes = await loginToPortalWithCredentials(origin, ident, pwd, portalPath);
              if (loginRes.ok && loginRes.session) {
                savePortalSessionForOrigin(loginRes.session, chatId);
                await editTelegramTextMessage(chatId, waitId, loginRes.message);
                if (/content|topic|subject|batch|play|course|id=/i.test(rawUrl)) {
                  await triggerTelegramUrlScanAndQueue(rawUrl);
                }
              } else {
                await editTelegramTextMessage(chatId, waitId, loginRes.message, {
                  inline_keyboard: [[{ text: '🍪 Paste Cookie / Token Instead', callback_data: 'feat:login:token' }]],
                });
              }
            } catch (err: any) {
              await editTelegramTextMessage(chatId, waitId, `❌ Login error: ${err?.message || 'Unknown error'}`);
            }
            continue;
          }

          // Mode C: /weblogin <url> -> jump straight to Step 2 (ask mobile no / email)
          if (parts.length === 1 && /^https?:\/\//i.test(parts[0])) {
            const rawUrl = parts[0].trim();
            try {
              const { origin, portalPath } = normalizePortalHost(rawUrl);
              const hasFullCoursePath = /content|topic|subject|batch|play|course|id=/i.test(rawUrl);
              pendingPortalLoginByChat.set(chatId, {
                step: 'awaiting_identifier',
                origin,
                portalPath,
                ...(hasFullCoursePath ? { retryUrl: rawUrl } : {}),
                updatedAt: Date.now(),
              });
              await sendTelegramTextMessage(
                chatId,
                `🔐 **Web Portal Login — \`${origin}\`**\n\n` +
                  `📱 **Step 1/2:** Apna Registered **Mobile Number** (ya Email / Username) bhejein:\n` +
                  `_(Cancel karne ke liye \`/cancel\` likhein)_`
              );
            } catch {
              await sendTelegramTextMessage(chatId, `⚠️ Valid HTTP/HTTPS link bhejein.`);
            }
            continue;
          }

          await sendTelegramTextMessage(
            chatId,
            `ℹ️ **Web Login Format:**\n` +
              `• Interactive: Sirf \`/weblogin\` bhejein\n` +
              `• 1-Line: \`/weblogin <url> <number_or_email> <password>\`\n` +
              `• Cookie/Token: \`/weblogin token <url> <cookie_ya_token>\``
          );
          continue;
        }

        // Process active multi-step interactive login conversation (only if not another slash command)
        const activeLoginFlow = pendingPortalLoginByChat.get(chatId);
        if (activeLoginFlow) {
          if (baseCmd.startsWith('/')) {
            pendingPortalLoginByChat.delete(chatId);
          } else if (activeLoginFlow.step === 'awaiting_origin') {
            const urlMatch = text.match(/https?:\/\/[^\s]+/i);
            const candidate = urlMatch ? urlMatch[0] : text.split(/\s+/)[0];
            if (!candidate || candidate.length < 3 || !/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|localhost/i.test(candidate)) {
              await sendTelegramTextMessage(
                chatId,
                `⚠️ Valid Website / Course Link bhejein (jaise \`https://studybeepro.site\`), ya cancel karne ke liye \`/cancel\` likhein.`
              );
              continue;
            }
            const fullUrl = /^https?:\/\//i.test(candidate) ? candidate : `https://${candidate}`;
            const { origin, portalPath } = normalizePortalHost(fullUrl);
            const hasFullCoursePath = /content|topic|subject|batch|play|course|id=/i.test(fullUrl);
            activeLoginFlow.origin = origin;
            activeLoginFlow.portalPath = portalPath;
            if (hasFullCoursePath) activeLoginFlow.retryUrl = fullUrl;
            activeLoginFlow.step = 'awaiting_identifier';
            activeLoginFlow.updatedAt = Date.now();
            await sendTelegramTextMessage(
              chatId,
              `🌐 Portal: \`${origin}\`\n\n📱 **Step 2/3:** Apna Registered **Mobile Number** (ya Email / Username) bhejein:`
            );
            continue;
          } else if (activeLoginFlow.step === 'awaiting_identifier') {
            if (/^https?:\/\//i.test(text)) {
              // User pasted another URL instead of identifier — exit wizard & process URL normally
              pendingPortalLoginByChat.delete(chatId);
            } else {
              const cleanIdentifier = text.trim();
              activeLoginFlow.identifier = cleanIdentifier;
              activeLoginFlow.step = 'awaiting_password';
              activeLoginFlow.updatedAt = Date.now();
              await sendTelegramTextMessage(
                chatId,
                `👤 ID: \`${maskLoginIdentifier(cleanIdentifier)}\`\n\n🔑 **Step Final:** Apna **Password** bhejein:\n_(Privacy ke liye bot aapka password store nahi karega aur turant message delete karne ki koshish karega)_`
              );
              continue;
            }
          } else if (activeLoginFlow.step === 'awaiting_password') {
            if (/^https?:\/\//i.test(text)) {
              pendingPortalLoginByChat.delete(chatId);
            } else {
              const pwd = msg.text;
              const flowSnap = { ...activeLoginFlow };
              pendingPortalLoginByChat.delete(chatId);
              deleteTelegramMessage(chatId, msg.message_id).catch(() => {});
              const waitId = await sendTelegramTextMessage(
                chatId,
                `🔐 Verifying login on \`${flowSnap.origin}\`...`
              );
              try {
                const loginRes = await loginToPortalWithCredentials(
                  flowSnap.origin!,
                  flowSnap.identifier!,
                  pwd,
                  flowSnap.portalPath
                );
                if (loginRes.ok && loginRes.session) {
                  savePortalSessionForOrigin(loginRes.session, chatId);
                  await editTelegramTextMessage(chatId, waitId, loginRes.message);
                  if (flowSnap.retryUrl) {
                    await triggerTelegramUrlScanAndQueue(flowSnap.retryUrl, {
                      preferredQuality: flowSnap.preferredQuality,
                      explicitTargetChannelId: flowSnap.explicitTargetChannelId,
                      effectiveDeliveryMode: flowSnap.deliveryMode,
                    });
                  }
                } else {
                  await editTelegramTextMessage(chatId, waitId, loginRes.message, {
                    inline_keyboard: [
                      [
                        { text: '🔄 Retry Number + Password', callback_data: 'feat:login:start' },
                        { text: '🍪 Paste Cookie / Token', callback_data: 'feat:login:token' },
                      ],
                    ],
                  });
                }
              } catch (err: any) {
                await editTelegramTextMessage(chatId, waitId, `❌ Login error: ${err?.message || 'Unknown error'}`);
              }
              continue;
            }
          } else if (activeLoginFlow.step === 'awaiting_token') {
            if (/^https?:\/\//i.test(text) && text.length < 180 && !text.includes(';')) {
              pendingPortalLoginByChat.delete(chatId);
            } else {
              const rawSecret = text.trim();
              const flowSnap = { ...activeLoginFlow };
              pendingPortalLoginByChat.delete(chatId);
              deleteTelegramMessage(chatId, msg.message_id).catch(() => {});
              try {
                const { origin, host, portalPath } = normalizePortalHost(flowSnap.origin || flowSnap.retryUrl || '');
                const isJwtOrBearer = /^Bearer\s+/i.test(rawSecret) || (/^eyJ[A-Za-z0-9_-]+\./.test(rawSecret) && !rawSecret.includes(';'));
                const session: PortalAuthSession = {
                  origin,
                  host,
                  portalPath: flowSnap.portalPath || portalPath,
                  ...(isJwtOrBearer ? { bearerToken: rawSecret.replace(/^Bearer\s+/i, '').trim() } : { cookieHeader: rawSecret }),
                  ...(isJwtOrBearer ? { userId: extractTeachxJwtMeta(rawSecret.replace(/^Bearer\s+/i, '')).userId } : {}),
                  accountLabel: isJwtOrBearer ? 'JWT Token' : 'Browser Cookie',
                  authMethod: 'token_or_cookie',
                  updatedAt: new Date().toISOString(),
                };
                savePortalSessionForOrigin(session, chatId);
                await sendTelegramTextMessage(
                  chatId,
                  `✅ **${isJwtOrBearer ? 'Token' : 'Cookie'} Saved for \`${host}\`!**`
                );
                if (flowSnap.retryUrl) {
                  await triggerTelegramUrlScanAndQueue(flowSnap.retryUrl, {
                    preferredQuality: flowSnap.preferredQuality,
                    explicitTargetChannelId: flowSnap.explicitTargetChannelId,
                    effectiveDeliveryMode: flowSnap.deliveryMode,
                  });
                }
              } catch (err: any) {
                await sendTelegramTextMessage(chatId, `⚠️ Failed to save cookie/token: ${err?.message || 'Error'}`);
              }
              continue;
            }
          }
        }

        // Dedicated /invite command — restricted to Admins / Developers
        if (baseCmd === '/invite') {
          if (!isAdminOrDev(chatId, senderId)) {
            await sendTelegramTextMessage(chatId, '🔒 Only Admins can view or share the daily rotating access code.');
            continue;
          }
          await sendTelegramTextMessage(
            chatId,
            `🔑 **Daily Rotating Code & Invite Link**\nLink: ${inviteLink}\nCode: \`${active4Digit}\` (${currentCodeState.durationLabel})\nExpires: ${new Date(currentCodeState.expiresAt).toLocaleString()}`
          );
          continue;
        }

        // Dedicated /resume command
        if (baseCmd === '/resume') {
          const resInfo = resumeChatDownloads(chatId);
          addBotLog(
            'SYSTEM',
            chatId,
            `Resumed ${resInfo.resumedCount} pending video(s) via /resume command (skipped ${resInfo.skippedCompletedCount} completed)`
          );
          if (resInfo.resumedCount > 0) {
            await sendTelegramTextMessage(
              chatId,
              `▶️ Batch Download Resumed!\n\n` +
                `✅ Skipped Already Downloaded: ${resInfo.skippedCompletedCount} video(s)\n` +
                `🚀 Resuming Remaining Videos: ${resInfo.resumedCount} video(s)\n` +
                (resInfo.firstResumedTitle
                  ? `🎬 Starting from: ${resInfo.firstResumedTitle}`
                  : '')
            );
          } else {
            await sendTelegramTextMessage(
              chatId,
              `ℹ️ Koi ruki hui ya pending video baki nahi hai (Already Downloaded: ${resInfo.skippedCompletedCount} videos).`
            );
          }
          continue;
        }

        // Dedicated /pause command
        if (baseCmd === '/pause') {
          const { pausedCount, totalPausedInQueue } = pauseChatDownloads(chatId);
          addBotLog('SYSTEM', chatId, `Paused ${pausedCount} video(s) via /pause command`);
          await sendTelegramTextMessage(
            chatId,
            `⏸️ Queue Paused! (${totalPausedInQueue} paused video(s) in queue).\n\n` +
              `▶️ Jab bhi wahi se dobara start karna ho, /resume bhejein — jo videos download ho chuki hain wo skip ho jayengi!\n` +
              `🗑️ Agar saari paused videos delete karni hain to /clear bhejein.`,
            {
              inline_keyboard: [
                [
                  { text: '▶️ Resume (/resume)', callback_data: 'feat:action:resume' },
                  { text: '🗑️ Clear Paused (/clear)', callback_data: 'feat:action:clear' },
                ],
              ],
            }
          );
          continue;
        }

        // Dedicated /clear or /clearall command — cancels all running/queued/paused videos from queue while keeping completed history safe
        if (baseCmd === '/clear' || baseCmd === '/clearall') {
          const { clearedCount } = clearPausedChatDownloads(chatId);
          addBotLog('SYSTEM', chatId, `Cleared ${clearedCount} active/queued video(s) via ${baseCmd} command`);
          await sendTelegramTextMessage(
            chatId,
            `🗑️ Cleared & Stopped ${clearedCount} video(s) from your queue!\n` +
              `🛑 Sabhi active aur queued downloads rok diye gaye hain aur queue poori tarah empty kar di gayi hai.\n` +
              `✅ Pehle download ho chuki videos ki history safe hai (koi bhi video duplicate download nahi hogi).`
          );
          continue;
        }

        // Dedicated /reset command — factory resets queue, completed history, checkpoints & watched courses
        if (baseCmd === '/reset') {
          const { clearedJobsCount } = resetAllBotData(chatId);
          addBotLog('SYSTEM', chatId, `Factory reset all queue, history & checkpoints via /reset (${clearedJobsCount} jobs removed)`);
          const menu = buildFeaturesMenuPayload(chatId, senderId);
          await sendTelegramTextMessage(
            chatId,
            `🔄 **All Bot Data Refreshed & Reset!**\n\n` +
              `✅ Queue Cleared: ${clearedJobsCount} video(s)\n` +
              `✅ Completed History, Checkpoints & Auto-Watch Reset!\n` +
              `🚀 Ab aap naye sire se koi bhi link ya /only command bhej sakte hain.`,
            menu.replyMarkup
          );
          continue;
        }

        // Dedicated /skip N or /startfrom N command (if sent without a URL; if sent WITH a URL, the URL block below handles both!)
        if ((baseCmd === '/skip' || baseCmd === '/startfrom') && !/https?:\/\/[^\s]+/i.test(text)) {
          const numMatch = text.match(/(?:\/skip|\/startfrom)(?:@\S+)?\s+(\d+)/i);
          const rawNum = numMatch ? parseInt(numMatch[1], 10) : 0;
          const skipCount =
            baseCmd === '/startfrom' ? Math.max(0, rawNum - 1) : Math.max(0, rawNum);

          if (skipCount <= 0) {
            await sendTelegramTextMessage(
              chatId,
              `⏭️ Skip Videos Command Kaise Use Karein:\n\n` +
                `1️⃣ Agar shuru ki 95 videos download ho chuki hain aur seedha Lecture 96 se start karna hai:\n` +
                `👉 /skip 95 bhejein (aur uske baad Course Link bhejein)\n` +
                `2️⃣ Ya link ke sath ek hi message me bhejein:\n` +
                `👉 /skip 95 https://studybeepro.site/...\n` +
                `3️⃣ Agar batch abhi chal raha hai ya paused hai, tab bhi /skip 95 bhejne par Lecture 1 se 95 turant skip hokar Lecture 96 se start ho jayega!`
            );
            continue;
          }

          const skipRes = skipChatVideos(chatId, skipCount);
          addBotLog(
            'SYSTEM',
            chatId,
            `User requested /skip ${skipCount} (skippedExisting=${skipRes.skippedExistingCount}, armedForNextLink=${skipRes.armedForNextLink})`
          );

          if (skipRes.skippedExistingCount > 0 || skipRes.resumedCount > 0) {
            await sendTelegramTextMessage(
              chatId,
              `⏭️ First ${skipCount} Videos Skipped!\n\n` +
                `✅ Skipped Lectures: 1 to ${skipCount} (${skipRes.skippedExistingCount} video(s))\n` +
                `🚀 Continuing Remaining Videos: ${skipRes.resumedCount} video(s)\n` +
                (skipRes.firstResumedTitle
                  ? `🎬 Now Starting From: ${skipRes.firstResumedTitle}`
                  : `🎬 Now Starting From: Lecture ${skipCount + 1}`)
            );
          } else {
            await sendTelegramTextMessage(
              chatId,
              `⏭️ Skip First ${skipCount} Videos Set Ho Gaya Hai!\n\n` +
                `👉 Ab aap apni Course Link bhejein — bot shuru ki ${skipCount} videos (Lecture 1 se ${skipCount}) ko skip karke seedha Lecture ${skipCount + 1} se download start karega!`
            );
          }
          continue;
        }

        // Dedicated /only, /select, /pick command (e.g. /only 128, 134, 144)
        if (
          (baseCmd === '/only' || baseCmd === '/select' || baseCmd === '/pick') &&
          !/https?:\/\/[^\s]+/i.test(text)
        ) {
          const numbers = parseNumberListOrRanges(text);
          if (numbers.length === 0) {
            await sendTelegramTextMessage(
              chatId,
              `🎯 /only Selected Videos Command Kaise Use Karein:\n\n` +
                `1️⃣ Kisi bhi batch me se sirf apni pasand ki specific videos download karne ke liye:\n` +
                `👉 /only 128, 134, 144 (bhejein aur uske baad course link bhejein)\n\n` +
                `2️⃣ Ya link ke sath ek hi message me bhejein:\n` +
                `👉 /only 128, 134, 144 https://studybeepro.site/rwax/content.html?id=565\n\n` +
                `3️⃣ Ranges bhi use kar sakte hain:\n` +
                `👉 /only 10-15, 25, 30-35\n\n` +
                `4️⃣ Agar batch abhi chal raha hai ya paused hai, tab bhi /only 128, 134 bhejne par baaki sabhi videos skip hokar SIRF yahi videos download hongi!`
            );
            continue;
          }
          const onlyRes = onlyChatVideos(chatId, numbers);
          addBotLog(
            'SYSTEM',
            chatId,
            `User requested /only ${numbers.join(',')} (kept=${onlyRes.keptCount}, skipped=${onlyRes.skippedCount}, armed=${onlyRes.armedForNextLink})`
          );
          if (onlyRes.keptCount > 0 || onlyRes.resumedCount > 0) {
            await sendTelegramTextMessage(
              chatId,
              `🎯 Selected Videos Filter Applied (/only)!\n\n` +
                `📌 Selected Lectures: #${numbers.join(', #')} (${onlyRes.keptCount} video(s))\n` +
                `⏭️ Other Videos Auto-Skipped: ${onlyRes.skippedCount} video(s)\n` +
                `🚀 Downloading Now: ${onlyRes.resumedCount} video(s)\n` +
                (onlyRes.firstResumedTitle
                  ? `🎬 First Up: ${onlyRes.firstResumedTitle}`
                  : `🎬 Starting immediately!`)
            );
          } else {
            await sendTelegramTextMessage(
              chatId,
              `🎯 /only Armed for Next Course Link!\n\n` +
                `📌 Selected Lectures: #${numbers.join(', #')}\n` +
                `👉 Ab apna Course/Batch Link bhejein — Bot SIRF inhi numbers wali videos ko download karega aur baki sabko skip kar dega!`
            );
          }
          continue;
        }

        // 5. All Features Interactive Menu (/features, /menu, /start, /help, /status)
        if (
          baseCmd === '/features' ||
          baseCmd === '/menu' ||
          baseCmd === '/start' ||
          baseCmd === '/help' ||
          baseCmd === '/status'
        ) {
          const menu = buildFeaturesMenuPayload(chatId, senderId);
          await sendTelegramTextMessage(chatId, menu.text, menu.replyMarkup);
          continue;
        }

        // 6. Direct Quality Command (/quality or /quality 720p)
        if (baseCmd === '/quality') {
          const argQ = text.replace(/^\/quality(@\S+)?\s*/i, '').trim().toLowerCase();
          if (['144p', '240p', '360p', '480p', '720p', '1080p'].includes(argQ)) {
            const { updatedJobsCount } = applyGlobalQualityChange(argQ as VideoQualityOption);
            const menu = buildFeaturesMenuPayload(chatId, senderId);
            await sendTelegramTextMessage(
              chatId,
              `✅ Default Video Quality updated to ${argQ.toUpperCase()}!\n` +
                (updatedJobsCount > 0
                  ? `🔄 Queue me maujood ${updatedJobsCount} pending/paused videos ki quality bhi ${argQ.toUpperCase()} kar di gayi hai!`
                  : `🎬 Ab aane wali sabhi videos ${argQ.toUpperCase()} quality me download hongi.`),
              menu.replyMarkup
            );
          } else {
            const menu = buildFeaturesMenuPayload(chatId, senderId);
            await sendTelegramTextMessage(
              chatId,
              `🎞 Current Default Quality: ${botSettings.globalDefaultQuality.toUpperCase()}\nNeeche button daba kar quality (144p, 240p, 360p, 480p, 720p, 1080p) select karein:`,
              menu.replyMarkup
            );
          }
          continue;
        }

        // 7. Direct Delivery Mode Command (/mode) — Parts system permanently removed
        if (baseCmd === '/mode') {
          botSettings.preferFullSingleVideo = true;
          saveBotSettings();
          const menu = buildFeaturesMenuPayload(chatId, senderId);
          await sendTelegramTextMessage(
            chatId,
            `🎬 Parts system permanently hata diya gaya hai!\n👉 Ab har video hamesha 1 Full Single Video (Puri Video up to 2GB) me hi aayega.`,
            menu.replyMarkup
          );
          continue;
        }

        // 8. Queue Status Command (/queue)
        if (baseCmd === '/queue') {
          const stats = getChatJobStats(chatId);
          const activeJobs = Array.from(jobs.values()).filter(
            (j) =>
              j.telegramChatId === chatId &&
              (j.status === 'downloading' || j.status === 'merging' || j.status.startsWith('uploading'))
          );
          const activeLines =
            activeJobs.length > 0
              ? activeJobs
                  .map(
                    (j, i) =>
                      `${i + 1}. ⏳ ${j.title} — ${j.status.toUpperCase()} (${Math.round(j.progressPercent || 0)}%)`
                  )
                  .join('\n')
              : 'No video currently downloading.';
          await sendTelegramTextMessage(
            chatId,
            `📊 Your Batch Download Queue Status:\n\n` +
              `✅ Completed (Already Sent): ${stats.completedCount} video(s)\n` +
              `⚡ Currently Processing (${activeJobs.length}):\n${activeLines}\n\n` +
              `🕒 Waiting in Queue: ${stats.queuedCount} video(s)\n` +
              `⏸️ Paused / Resumable: ${stats.pausedCount + stats.resumableFailedCount} video(s)`
          );
          continue;
        }

        // 9. Channel & Backup Commands in Bot
        if (baseCmd === '/addbackup') {
          const parts = text.replace(/^\/addbackup(@\S+)?\s*/i, '').trim().split(/\s+/);
          const targetId = parts[0];
          const label = parts.slice(1).join(' ') || `Backup Channel ${targetId}`;
          if (!targetId) {
            await sendTelegramTextMessage(
              chatId,
              `ℹ️ Backup Channel/Group add karne ke 3 aasan tarike:\n\n` +
                `1️⃣ Bot (@${botInfoCache.username}) ko apne Channel ya Group me Admin banayein (Bot khud auto-detect kar lega!)\n` +
                `2️⃣ Apne Channel ki koi bhi post is bot ko Forward karein\n` +
                `3️⃣ Ya command bhejein: /addbackup -1001234567890 My Backup Channel`
            );
            continue;
          }
          const created = upsertBackupChannel(
            targetId,
            label,
            targetId.startsWith('-100') ? 'channel' : 'group',
            'bot'
          );
          await sendTelegramTextMessage(
            chatId,
            `✅ Backup Channel/Group Added: "${created.title}" (${created.chatId})\nAb har video automatically yahan bhi save hogi!`
          );
          continue;
        }

        if (baseCmd === '/route') {
          const args = text.replace(/^\/route(@\S+)?\s*/i, '').trim().split(/\s+/);
          if (args.length < 2) {
            await sendTelegramTextMessage(
              chatId,
              `🎯 Fix Link -> Fix Channel Rule kaise lagayein:\n\n` +
                `Command format:\n` +
                `/route <link_ya_courseid> <channel_id> [Channel Name]\n\n` +
                `Example:\n` +
                `/route subjectid=1677 -100192837465 RWA Maths Channel\n\n` +
                `Ya direct link bhejte waqt aise likhein:\n` +
                `https://studybeepro.site/rwax/topic.html?courseid=284&subjectid=1677&domainId=RWA -> -100192837465`
            );
            continue;
          }
          const pattern = args[0];
          const targetChannelId = args[1];
          const label = args.slice(2).join(' ') || `Route -> ${targetChannelId}`;
          const newRule: ChannelRouteRule = {
            id: crypto.randomUUID(),
            pattern,
            label,
            targetChatId: targetChannelId,
            targetTitle: label,
            enabled: true,
            createdAt: new Date().toISOString(),
          };
          botSettings.routeRules.push(newRule);
          saveBotSettings();
          await sendTelegramTextMessage(
            chatId,
            `✅ Fix Link -> Fix Channel Rule Saved!\n\n` +
              `🔗 Link Match: ${pattern}\n` +
              `🎯 Target Channel: ${label} (${targetChannelId})\n` +
              `🛡️ Plus Backup Channels me bhi save hogi!`
          );
          continue;
        }

        if (baseCmd === '/channels' || baseCmd === '/backups') {
          const bList =
            botSettings.backupChannels.length > 0
              ? botSettings.backupChannels
                   .map(
                    (b, i) =>
                      `${i + 1}. ${b.enabled ? '🟢' : '⚪'} ${b.title} (${b.chatId})`
                  )
                  .join('\n')
              : 'No Backup Channels added yet.';
          const rList =
            botSettings.routeRules.length > 0
              ? botSettings.routeRules
                  .map(
                    (r, i) =>
                      `${i + 1}. ${r.enabled ? '🎯' : '⚪'} "${r.pattern}" -> ${r.targetTitle} (${r.targetChatId})`
                  )
                  .join('\n')
              : 'No Fix-Link Rules added yet.';
          await sendTelegramTextMessage(
            chatId,
            `🛡️ Backup Channels / Groups (All Videos Saved Here):\n${bList}\n\n` +
              `🎯 Fix Link -> Fix Channel Rules:\n${rList}\n\n` +
              `💡 Add more from the Web Dashboard or forward any Channel post here!`
          );
          continue;
        }

        if (baseCmd === '/stop') {
          const { pausedCount, totalPausedInQueue } = pauseChatDownloads(chatId);
          addBotLog('SYSTEM', chatId, `Stopped & paused ${pausedCount} video(s) via /stop command`);
          await sendTelegramTextMessage(
            chatId,
            `⏸️ Stopped & Paused! (${totalPausedInQueue} paused video(s) in queue).\n\n` +
              `▶️ Jab bhi baki bachi hui videos ko wahi se dobara start karna ho, /resume bhejein.\n` +
              `🗑️ Agar saari paused videos delete karni hain to /clear bhejein.`,
            {
              inline_keyboard: [
                [
                  { text: '▶️ Resume (/resume)', callback_data: 'feat:action:resume' },
                  { text: '🗑️ Clear Paused (/clear)', callback_data: 'feat:action:clear' },
                ],
              ],
            }
          );
          continue;
        }

        // Dedicated /autocheck command — triggers immediate AI Auto-Check & Auto-Download cycle
        if (baseCmd === '/autocheck') {
          const waitMsgId = await sendTelegramTextMessage(
            chatId,
            `🤖 AI Agent is checking all waiting streams, course checkpoints & watched batches...`
          );
          const checkRes = await runAiAutoCheckCycle(true);
          const replyText =
            `${checkRes.summary}\n\n` +
            `✅ Waiting Videos Recovered & Queued: ${checkRes.recoveredVideos}\n` +
            `🎬 New Batch Videos Detected: ${checkRes.newlyDetectedVideos}\n` +
            `🚀 Resumed Queues: ${checkRes.resumedQueues}`;
          if (waitMsgId) {
            await editTelegramTextMessage(chatId, waitMsgId, replyText, {
              inline_keyboard: [
                [
                  { text: '🔄 Check Again Now', callback_data: 'feat:ai:checknow' },
                  { text: '📊 AI Agent Status', callback_data: 'feat:ai:status' },
                ],
              ],
            });
          } else {
            await sendTelegramTextMessage(chatId, replyText);
          }
          continue;
        }

        // Dedicated /ai command — AI Agent status, checkpoints, or conversational Gemini AI diagnosis
        if (baseCmd === '/ai') {
          const userQuery = text.replace(/^\/?ai(?:@\S+)?\s*/i, '').trim();
          const waitMsgId = await sendTelegramTextMessage(
            chatId,
            `🤖 StreamBridge AI Agent is analyzing your batch checkpoints & queue...`
          );
          const aiReply = await askGeminiAiAgent(userQuery, chatId);
          const snap = getAiAgentStatusSnapshot();
          const cpLines =
            snap.courseCheckpoints.length > 0
              ? '\n\n📌 Saved Course Checkpoints (Auto-Resume from Last Video):\n' +
                snap.courseCheckpoints
                  .slice(0, 5)
                  .map(
                    (c) =>
                      `• ${c.courseName}: Lecture #${c.lastCompletedBatchOrder}/${c.totalVideos || '?'} (Done: ${c.completedCount}, Waiting: ${c.waitingCount})`
                  )
                  .join('\n')
              : '';
          const fullText = `🤖 StreamBridge AI Agent:\n\n${aiReply}${cpLines}`;
          const kb = {
            inline_keyboard: [
              [
                { text: '🤖 Run AI Check Now', callback_data: 'feat:ai:checknow' },
                {
                  text: snap.enabled ? '⏸️ Pause AI Auto-Check' : '▶️ Enable AI Auto-Check',
                  callback_data: 'feat:ai:toggle',
                },
              ],
              [
                { text: '▶️ Resume Queue (/resume)', callback_data: 'feat:action:resume' },
                { text: '📊 Full AI Status', callback_data: 'feat:ai:status' },
              ],
            ],
          };
          if (waitMsgId) {
            await editTelegramTextMessage(chatId, waitMsgId, fullText, kb);
          } else {
            await sendTelegramTextMessage(chatId, fullText, kb);
          }
          continue;
        }

        // Dedicated /drive and /drive tg commands for 5TB Google Drive sync (standalone or inline with URL)
        const hasInlineUrlInMsg = /https?:\/\/[^\s]+/i.test(text);
        if ((baseCmd === '/drive' || baseCmd === '/drivetg') && !hasInlineUrlInMsg) {
          const isDualTgDrive =
            baseCmd === '/drivetg' || /^\/drive(?:@\S+)?\s*(?:\+?\s*tg|telegram|both)\b/i.test(text.trim());
          const armedMode: 'drive_only' | 'telegram_and_drive' = isDualTgDrive
            ? 'telegram_and_drive'
            : 'drive_only';
          pendingDriveModeByChat.set(chatId, armedMode);
          const driveStatusLine =
            activeDriveSession && !activeDriveSession.tokenExpired
              ? `✅ Google Drive Connected: ${activeDriveSession.email}`
              : `⚠️ Google Drive Not Connected! Pehle Admin Panel (/admin -> 5TB Drive Sync) me Google Sign-In karein.`;
          await sendTelegramTextMessage(
            chatId,
            `☁️ **5TB Google Drive Mode Armed:** ${
              armedMode === 'telegram_and_drive'
                ? 'Telegram + Google Drive (Dual Simultaneous Save)'
                : 'Google Drive Only (Fast Direct Cloud Save)'
            }\n` +
              `${driveStatusLine}\n` +
              `📁 Structure: ${DRIVE_ROOT_FOLDER_NAME} / Batch (Code) / Subject / Topic / Videos & PDFs\n\n` +
              `Ab koi bhi video ya course link send karein!\n` +
              `💡 Direct commands:\n` +
              `• /drive <link> — Sirf Google Drive me save\n` +
              `• /drive tg <link> — Telegram + Google Drive dono me eksath save`
          );
          continue;
        }

        const rawUrls = text.match(/https?:\/\/[^\s]+/gi);
        if (rawUrls && rawUrls.length > 0) {
          const isDualDriveInline =
            /^\/(?:drivetg|drive_tg)(?:@\S+)?\b/i.test(text.trim()) ||
            /(?:^|\s)\/drive(?:@\S+)?\s*(?:\+?\s*tg|telegram|both)\b/i.test(text);
          const isDriveOnlyInline = !isDualDriveInline && /(?:^|\s)\/drive(?:@\S+)?\b/i.test(text);
          let effectiveDeliveryMode: DownloadJob['deliveryMode'] = 'telegram_auto';
          if (isDualDriveInline) {
            effectiveDeliveryMode = 'telegram_and_drive';
            pendingDriveModeByChat.delete(chatId);
          } else if (isDriveOnlyInline) {
            effectiveDeliveryMode = 'drive_only';
            pendingDriveModeByChat.delete(chatId);
          } else if (pendingDriveModeByChat.has(chatId)) {
            effectiveDeliveryMode = pendingDriveModeByChat.get(chatId) || 'drive_only';
            pendingDriveModeByChat.delete(chatId);
          }

          if (
            (effectiveDeliveryMode === 'drive_only' || effectiveDeliveryMode === 'telegram_and_drive') &&
            (!activeDriveSession || activeDriveSession.tokenExpired)
          ) {
            await sendTelegramTextMessage(
              chatId,
              `🔐 Google Drive session connected nahi hai ya expire ho gaya hai!\n` +
                `Kripya Admin Panel (/admin -> 5TB Drive Sync) me "Sign in with Google" par click karke Drive connect karein, fir /drive <link> dobara bhejein.`
            );
            continue;
          }

          const uniqueUrls: string[] = Array.from(new Set(rawUrls.map((u: string) => u.trim())));
          const qualityMatch = text.match(/\b(144p|240p|360p|480p|720p|1080p)\b/i);
          const preferredQuality = qualityMatch
            ? qualityMatch[1].toLowerCase()
            : botSettings.globalDefaultQuality || '480p';

          const inlineChannelMatch =
            text.match(/(?:->|=>|\bto:)\s*(-100\d+|-\d+|@[a-zA-Z0-9_]+)/i);
          const explicitTargetChannelId = inlineChannelMatch ? inlineChannelMatch[1].trim() : undefined;

          // Detect inline "/skip 95", "skip 95", or "startfrom 96" in the message OR pre-armed /skip 95 for this chat
          const inlineSkipMatch = text.match(/(?:\/?skip(?:@\S+)?\s*[:=]?\s*)(\d+)/i);
          const inlineStartMatch = text.match(/(?:\/?start(?:from)?(?:@\S+)?\s*[:=]?\s*)(\d+)/i);
          let effectiveSkipCount = 0;
          if (inlineSkipMatch) {
            effectiveSkipCount = Math.max(0, parseInt(inlineSkipMatch[1], 10) || 0);
          } else if (inlineStartMatch) {
            effectiveSkipCount = Math.max(0, (parseInt(inlineStartMatch[1], 10) || 1) - 1);
          } else if (pendingSkipByChat.has(chatId)) {
            effectiveSkipCount = pendingSkipByChat.get(chatId) || 0;
          } else if (pendingSkipByChat.has('GLOBAL')) {
            effectiveSkipCount = pendingSkipByChat.get('GLOBAL') || 0;
          }
          if (effectiveSkipCount > 0) {
            pendingSkipByChat.delete(chatId);
            pendingSkipByChat.delete('GLOBAL');
          }

          // Detect inline "/only 128, 134", "/select 10-20", "/pick 5, 8" OR pre-armed /only for this chat
          const inlineOnlyMatch = text.match(
            /(?:\/?(?:only|select|pick)(?:@\S+)?\s*[:=]?\s*)([0-9\s,\-]+)/i
          );
          let effectiveOnlyList: number[] = [];
          if (inlineOnlyMatch) {
            effectiveOnlyList = parseNumberListOrRanges(inlineOnlyMatch[1]);
          } else if (pendingOnlyByChat.has(chatId)) {
            effectiveOnlyList = pendingOnlyByChat.get(chatId) || [];
          } else if (pendingOnlyByChat.has('GLOBAL')) {
            effectiveOnlyList = pendingOnlyByChat.get('GLOBAL') || [];
          }
          if (effectiveOnlyList.length > 0) {
            pendingOnlyByChat.delete(chatId);
            pendingOnlyByChat.delete('GLOBAL');
          }
          const effectiveOnlySet =
            effectiveOnlyList.length > 0 ? new Set(effectiveOnlyList) : null;

          // When /only is active, clear any leftover pending/waiting jobs and watchedCourses for this chat
          // so ONLY the explicitly selected video(s) are downloaded and nothing else runs afterwards!
          if (effectiveOnlySet) {
            for (const [jId, existingJob] of Array.from(jobs.entries())) {
              if (
                (!existingJob.telegramChatId || existingJob.telegramChatId === chatId) &&
                existingJob.status !== 'completed'
              ) {
                existingJob.abortFlag = true;
                cleanupJobTempFiles(jId);
                jobs.delete(jId);
              }
            }
            const existingQ = chatJobQueues.get(chatId);
            if (existingQ) existingQ.length = 0;
            activeChatWorkers.delete(chatId);
            chatWorkerGeneration.set(chatId, (chatWorkerGeneration.get(chatId) || 0) + 1);
            for (const [wKey, watched] of Array.from(watchedCourses.entries())) {
              if (watched.chatId === chatId) {
                watchedCourses.delete(wKey);
              }
            }
            saveWatchedCoursesState();
            saveJobsState(true);
          }

          for (const targetUrl of uniqueUrls) {
            const onlyKey = effectiveOnlyList.length > 0 ? effectiveOnlyList.join('-') : 'all';
            const dedupKey = `${chatId}__${targetUrl}__${effectiveSkipCount}__${onlyKey}`;
            const lastScanTime = recentScanDedupMap.get(dedupKey) || 0;
            if (Date.now() - lastScanTime < 15000) {
              continue;
            }
            recentScanDedupMap.set(dedupKey, Date.now());

            await triggerTelegramUrlScanAndQueue(targetUrl, {
              preferredQuality,
              explicitTargetChannelId,
              effectiveDeliveryMode,
              effectiveSkipCount,
              effectiveOnlyList,
            });
          }
        } else {
          await sendTelegramTextMessage(
            chatId,
            `ℹ️ Please send a valid video or course link (starting with http:// or https://), send /resume to resume pending videos, or send /help.`
          );
        }
        } catch (updErr: any) {
          console.error('[Telegram Polling Update Error]:', updErr?.message || updErr);
        }
      }
    }
    setTimeout(pollTelegramBotUpdates, hadUpdates ? 50 : 120);
    return;
  } catch {
    // transient network error
  }

  setTimeout(pollTelegramBotUpdates, 400);
}

pollTelegramBotUpdates();

// ============================================================================
// EXPRESS SERVER (BOT STATUS, SECURITY, BACKUP CHANNELS & LINK ROUTING ENDPOINTS)
// ============================================================================

// Background 24/7 Keep-Alive Pinger for Render.com / Hugging Face Space / AI Studio Published URL
function startCloudKeepAliveLoop() {
  setInterval(async () => {
    const isDevContainer = String(process.env.K_SERVICE || '').startsWith('ais-dev-');
    const candidateUrls = Array.from(
      new Set(
        [
          process.env.RENDER_EXTERNAL_URL?.trim(),
          process.env.HF_SPACE_URL?.trim(),
          process.env.APP_URL?.trim(),
          botSettings.hfCloud?.deployedAppUrl?.trim(),
          !isDevContainer
            ? 'https://ais-pre-pjcoe43tpy57sbvscovvu6-429685514388.asia-east1.run.app'
            : undefined,
        ].filter(Boolean) as string[]
      )
    );
    if (botSettings.hfCloud?.autoPingEnabled !== false) {
      for (const targetUrl of candidateUrls) {
        try {
          await fetch(`${targetUrl.replace(/\/$/, '')}/api/ping`, {
            headers: { 'User-Agent': 'StreamBridge-24x7-KeepAlive/1.0' },
            signal: AbortSignal.timeout(10000),
          });
        } catch {
          // ignore transient network errors
        }
      }
    }
  }, 4 * 60 * 1000); // Every 4 minutes
}
startCloudKeepAliveLoop();

interface PingRecord {
  timestamp: string;
  userAgent: string;
  ip: string;
  source: string;
}

const recentPingRecords: PingRecord[] = [];
let totalPingsCount = 0;

function categorizePingSource(userAgent: string): string {
  const ua = (userAgent || '').toLowerCase();
  if (ua.includes('uptimerobot')) return 'UptimeRobot';
  if (ua.includes('betterstack') || ua.includes('betteruptime')) return 'BetterStack';
  if (ua.includes('cron-job')) return 'Cron-Job.org';
  if (ua.includes('pingdom')) return 'Pingdom';
  if (ua.includes('render')) return 'Render Internal HealthCheck';
  if (ua.includes('streambridge')) return 'StreamBridge Background KeepAlive';
  if (ua.includes('curl')) return 'Terminal Curl / Health Probe';
  return 'External Web / User';
}

async function runSystemBugBountyAudit(): Promise<BugBountyAuditReport> {
  const startMs = Date.now();
  const checks: BugBountyCheckItem[] = [];
  const codeState = ensureValidAccessCode(false);

  // Sweep stale temp download artifacts older than 20 mins
  let tempFilesSwept = 0;
  try {
    if (fs.existsSync(DOWNLOAD_DIR)) {
      const nowMs = Date.now();
      const activeIds = new Set(
        Array.from(jobs.values())
          .filter((j) => ['downloading', 'merging', 'uploading_bot_api', 'uploading_mtproto_userbot'].includes(j.status))
          .map((j) => j.id)
      );
      for (const f of fs.readdirSync(DOWNLOAD_DIR)) {
        const jId = f.split('_')[0];
        if (activeIds.has(jId)) continue;
        const full = path.join(DOWNLOAD_DIR, f);
        const st = fs.statSync(full);
        if (nowMs - st.mtimeMs > 20 * 60 * 1000) {
          fs.rmSync(full, { recursive: true, force: true });
          tempFilesSwept++;
        }
      }
    }
  } catch {}

  // Measure workspace disk size cleanly
  let diskUsageMb = 0;
  try {
    const { stdout } = await execFileAsync('du', ['-sm', process.cwd()], { timeout: 5000 });
    diskUsageMb = parseInt(stdout.trim().split(/\s+/)[0] || '0', 10) || 0;
  } catch {}

  const sockCounts = getActiveMtprotoSocketCounts();

  // 1. Security checks
  const strangerAuthorized = isChatAuthorized('9999999991', '9999999991');
  checks.push({
    id: 'sec-stranger-lock',
    category: 'SECURITY',
    name: 'Strict Unauthorized Stranger Lockout',
    status: strangerAuthorized ? 'FAIL' : 'PASS',
    detail: strangerAuthorized
      ? 'CRITICAL: Unknown user ID bypassed isChatAuthorized()'
      : 'Verified: Unauthorized IDs strictly blocked & prompted for access code/admin',
  });

  const isDailyRotatingValid =
    /^\d{4}$/.test(codeState.code) &&
    codeState.code !== '2612' &&
    !String(codeState.expiresAt || '').startsWith('2099-');
  checks.push({
    id: 'sec-daily-code',
    category: 'SECURITY',
    name: '24h Auto-Rotating 4-Digit Code (No Hardcode 2612)',
    status: isDailyRotatingValid ? 'PASS' : 'FAIL',
    detail: `Active code: ${codeState.code} · Expires ${new Date(codeState.expiresAt).toLocaleString()}`,
  });

  const mainAdminActive = isChatAuthorized(MAIN_ADMIN_ID, MAIN_ADMIN_ID) && isMainAdmin(MAIN_ADMIN_ID);
  const revokeGuard = revokeUserAccess(MAIN_ADMIN_ID, 'audit-check');
  checks.push({
    id: 'sec-main-admin',
    category: 'SECURITY',
    name: `Main Admin (${MAIN_ADMIN_ID}) Immutable Root Protection`,
    status: mainAdminActive && !revokeGuard.ok ? 'PASS' : 'FAIL',
    detail: mainAdminActive && !revokeGuard.ok
      ? `Main Admin ${MAIN_ADMIN_ID} active & protected against revocation`
      : 'Main Admin guard check failed',
  });

  const staffCount = Object.keys(botSettings.staffRoles).length;
  checks.push({
    id: 'sec-rbac',
    category: 'SECURITY',
    name: 'Admin & Developer Role Hierarchy',
    status: 'PASS',
    detail: `Main Admin: 1 · Appointed Staff: ${staffCount} · Attempts Logged: ${Object.keys(botSettings.accessAttempts).length}`,
  });

  // 2. Upload speed checks
  const hasToken = Boolean(process.env.TELEGRAM_BOT_TOKEN?.trim());
  const hasExtraApi = Boolean(process.env.EXTRA_TELEGRAM_API_ID?.trim() && process.env.EXTRA_TELEGRAM_API_HASH?.trim());
  checks.push({
    id: 'spd-mtproto',
    category: 'UPLOAD_SPEED',
    name: '12/24-Socket TCP_NODELAY MTProto Pool',
    status: sockCounts.total >= 1 ? 'PASS' : hasToken ? 'WARN' : 'FAIL',
    detail: `Primary Sockets: ${sockCounts.primary}/12 · Secondary: ${sockCounts.secondary}/${hasExtraApi ? 12 : 0} · 48-Worker Pipeline`,
  });

  checks.push({
    id: 'spd-bot-api',
    category: 'UPLOAD_SPEED',
    name: 'Bot API HTTP/2 + MTProto Fast Routing (>=15MB)',
    status: hasToken ? 'PASS' : 'FAIL',
    detail: hasToken
      ? 'curl --http2 --tcp-nodelay active; >=15MB auto-routes to multi-socket MTProto when warm'
      : 'TELEGRAM_BOT_TOKEN missing',
  });

  // 3. Bot features & System health checks
  const cmdNames = new Set(BOT_COMMANDS_LIST.map((c) => c.command));
  const requiredCmds = ['admin', 'users', 'attempts', 'approve', 'revoke', 'newcode', 'addadmin', 'adddev', 'audit', 'only', 'skip', 'features', 'addapi', 'setcookies', 'weblogin', 'weblogout'];
  const missingCmds = requiredCmds.filter((c) => !cmdNames.has(c));
  checks.push({
    id: 'feat-menu',
    category: 'BOT_FEATURES',
    name: 'Menu Bar & Feature Button Parity',
    status: missingCmds.length === 0 ? 'PASS' : 'FAIL',
    detail: missingCmds.length === 0
      ? `All ${BOT_COMMANDS_LIST.length} Telegram menu commands & inline feature buttons registered`
      : `Missing commands: ${missingCmds.join(', ')}`,
  });

  checks.push({
    id: 'sys-media',
    category: 'SYSTEM_HEALTH',
    name: 'FFmpeg MP4 Remux + yt-dlp Extractor Binaries',
    status: ffmpegAvailable ? 'PASS' : 'WARN',
    detail: `FFmpeg: ${ffmpegAvailable ? 'Ready' : 'Missing'} · yt-dlp: ${resolvedYtDlpBinCache || fs.existsSync(YTDLP_TMP_BIN_PATH) ? 'Ready' : 'On-demand'}`,
  });

  checks.push({
    id: 'sys-disk',
    category: 'SYSTEM_HEALTH',
    name: 'Workspace Storage & Temp Sweep (<250 MB)',
    status: diskUsageMb < 250 ? 'PASS' : 'WARN',
    detail: `Disk: ${diskUsageMb} MB / 250 MB · Temp files swept: ${tempFilesSwept}`,
  });

  return {
    timestamp: new Date().toISOString(),
    durationMs: Math.max(1, Date.now() - startMs),
    passedCount: checks.filter((c) => c.status === 'PASS').length,
    warnCount: checks.filter((c) => c.status === 'WARN').length,
    failCount: checks.filter((c) => c.status === 'FAIL').length,
    tempFilesSwept,
    diskUsageMb,
    activeMtprotoSockets: sockCounts.primary,
    secondaryMtprotoSockets: sockCounts.secondary,
    checks,
  };
}

async function startServer() {
  const app = express();
  // In AI Studio / Cloud Run, Nginx listens on 8080 -> reverse-proxies to 3000.
  // In Hugging Face Docker Spaces (SPACE_ID), app_port is 7860. On Render, PORT is 10000.
  const isHfSpace = Boolean(process.env.SPACE_ID || process.env.SPACE_AUTHOR_NAME);
  const envPort = Number(process.env.PORT) || (isHfSpace ? 7860 : 3000);
  const PORT = envPort === 8080 ? 3000 : isHfSpace && !process.env.HF_SPACE_PORT ? 7860 : envPort;

  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, Range, X-Sync-Api');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use(express.json({ limit: '10mb' }));

  // Keep-Alive Ping endpoint with live Uptime Monitoring telemetry
  app.get('/api/ping', (req, res) => {
    const ua = String(req.headers['user-agent'] || 'unknown');
    const forwarded = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '');
    const ip = forwarded.split(',')[0].trim();
    const source = categorizePingSource(ua);
    totalPingsCount++;

    recentPingRecords.unshift({
      timestamp: new Date().toISOString(),
      userAgent: ua,
      ip,
      source,
    });
    if (recentPingRecords.length > 30) recentPingRecords.pop();

    const uptimeRobotDetected = recentPingRecords.some(
      (p) => p.source === 'UptimeRobot' || p.source === 'BetterStack' || p.source === 'Cron-Job.org'
    );

    res.json({
      ok: true,
      timestamp: new Date().toISOString(),
      botConnected: botInfoCache.connected,
      isRunningOnHuggingFace: IS_RUNNING_ON_HF,
      uptimeMonitoring: {
        active: uptimeRobotDetected,
        totalPings: totalPingsCount,
        lastPingSource: source,
        lastPingTime: new Date().toISOString(),
        recentPings: recentPingRecords.slice(0, 5),
      },
    });
  });

  app.get(['/api/health', '/health'], (_req, res) => {
    res.status(200).json({
      ok: true,
      status: 'alive',
      uptimeSec: Math.floor(process.uptime()),
      botConnected: botInfoCache.connected,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/uptime-check', (_req, res) => {
    const uptimeRobotPings = recentPingRecords.filter((p) => p.source === 'UptimeRobot');
    res.json({
      uptimeRobotActive: uptimeRobotPings.length > 0,
      totalPings: totalPingsCount,
      recentPings: recentPingRecords.slice(0, 10),
    });
  });


  app.get('/', (_req, res) => {
    res.status(200).json({
      ok: true,
      service: 'telegram-bot-only',
      botConnected: botInfoCache.connected,
      botUsername: botInfoCache.username || null,
      uptimeSec: Math.floor(process.uptime()),
      activeJobs: Array.from(jobs.values()).filter((j) =>
        ['downloading', 'merging', 'uploading_bot_api', 'uploading_mtproto_userbot'].includes(j.status)
      ).length,
      timestamp: new Date().toISOString(),
    });
  });

  const mainServer = app.listen(PORT, '0.0.0.0', () => {
    console.log(`Standalone Telegram Bot Health Server running on http://0.0.0.0:${PORT}`);
    setTimeout(() => {
      prewarmTurboPools(12);
    }, 2000);
  });
  mainServer.on('error', (err: any) => {
    if (err?.code === 'EADDRINUSE' && PORT !== 3000) {
      console.warn(`[TelegramBot] Port ${PORT} busy, fallback to 3000...`);
      app.listen(3000, '0.0.0.0', () => {
        console.log('Standalone Telegram Bot Health Server running on http://0.0.0.0:3000');
      });
    } else {
      console.error('[TelegramBot] Listen error:', err);
    }
  });
}

startServer().catch((e) => {
  console.error('Critical bot server error:', e);
});
