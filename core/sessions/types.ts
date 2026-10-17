export interface SessionDevice {
  id: string;
  deviceType: 'web' | 'mobile' | 'desktop' | 'tablet';
  deviceName: string;
  userAgent: string;
  lastActivity: Date;
  ipAddress: string;
  active: boolean;
  revoked?: boolean;
  revokedAt?: Date;
  revocationReason?: string;
}

export interface CrossDeviceSession {
  id: string;
  userId: string;
  createdAt: Date;
  devices: SessionDevice[];
  primaryDevice: string;
  state: Record<string, unknown>;
  conflicts: ConflictResolution[];
  syncToken: string;
  lastSync: Date;
  revoked?: boolean;
  revokedAt?: Date;
  revocationReason?: string;
}

export interface StateSync {
  deviceId: string;
  timestamp: Date;
  version: number;
  state: Record<string, unknown>;
  changes: StateChange[];
}

export interface StateChange {
  path: string;
  operation: 'set' | 'update' | 'delete';
  value?: unknown;
  oldValue?: unknown;
  timestamp: Date;
}

export interface ConflictResolution {
  id: string;
  timestamp: Date;
  field: string;
  deviceAValue: unknown;
  deviceBValue: unknown;
  resolution: unknown;
  strategy: 'last-write-wins' | 'manual' | 'device-priority' | 'merge';
  resolvedBy: string;
}

export interface SyncConflict {
  field: string;
  device1Id: string;
  device1Value: unknown;
  device2Id: string;
  device2Value: unknown;
  device1Timestamp: Date;
  device2Timestamp: Date;
}

export interface SessionConfig {
  conflictStrategy: 'last-write-wins' | 'manual' | 'device-priority';
  maxDevices: number;
  syncIntervalMs: number;
  timeoutMs: number;
  primaryDeviceStrategy: 'first-active' | 'most-recent' | 'manual';
  staleSessionTimeoutMs?: number;
}

export type SecurityEventType =
  | 'password_changed'
  | 'account_compromised'
  | 'suspicious_activity_detected'
  | 'role_downgraded'
  | 'manual_admin_revocation'
  | 'stale_session_timeout';

export interface SecurityEvent {
  type: SecurityEventType;
  userId: string;
  sessionId?: string;
  deviceId?: string;
  timestamp: Date;
  actor: { id: string; role: 'user' | 'maintainer' | 'system' };
  reason?: string;
}

export type SessionErrorCode =
  | 'session_not_found'
  | 'device_not_found'
  | 'session_revoked'
  | 'token_revoked'
  | 'unauthorized'
  | 'invalid_security_event'
  | 'revocation_failed'
  | 'revocation_retries_exhausted';

export interface RevocationReport {
  readonly success: boolean;
  readonly eventType: SecurityEventType;
  readonly userId: string;
  readonly revokedSessionIds: readonly string[];
  readonly revokedDeviceIds: readonly string[];
  readonly timestamp: Date;
  readonly reason?: string;
}

