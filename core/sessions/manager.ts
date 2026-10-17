import { err, ok, type Result } from '@/core/result/result';
import {
  CrossDeviceSession,
  SessionDevice,
  StateSync,
  StateChange,
  SyncConflict,
  ConflictResolution,
  SessionConfig,
  SecurityEvent,
  SessionErrorCode,
  RevocationReport,
} from './types';

class CrossDeviceSessionManager {
  private sessions: Map<string, CrossDeviceSession> = new Map();
  private stateSyncs: Map<string, StateSync[]> = new Map();
  private revokedTokens: Set<string> = new Set();
  private securityEvents: SecurityEvent[] = [];

  private defaultConfig: SessionConfig = {
    conflictStrategy: 'last-write-wins',
    maxDevices: 5,
    syncIntervalMs: 5000,
    timeoutMs: 30000,
    primaryDeviceStrategy: 'most-recent',
  };

  constructor(private config: Partial<SessionConfig> = {}) {
    this.config = { ...this.defaultConfig, ...config };
  }

  createSession(
    userId: string,
    device: Omit<SessionDevice, 'id' | 'active' | 'lastActivity'> & { lastActivity?: Date }
  ): CrossDeviceSession {
    const session: CrossDeviceSession = {
      id: `session-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      userId,
      createdAt: new Date(),
      devices: [
        {
          ...device,
          id: `device-${Date.now()}-${Math.random().toString(36).slice(2)}`,
          active: true,
          lastActivity: device.lastActivity || new Date(),
        },
      ],
      primaryDevice: '',
      state: {},
      conflicts: [],
      syncToken: this.generateSyncToken(),
      lastSync: new Date(),
    };

    session.primaryDevice = session.devices[0].id;
    this.sessions.set(session.id, session);
    this.stateSyncs.set(session.id, []);

    return session;
  }

  private generateSyncToken(): string {
    return `token-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  }

  addDevice(
    sessionId: string,
    device: Omit<SessionDevice, 'id' | 'active' | 'lastActivity'> & { lastActivity?: Date },
  ): SessionDevice | null {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    if (session.devices.length >= (this.config.maxDevices || 5)) {
      // Remove least active device
      const leastActive = session.devices.reduce((prev, curr) =>
        prev.lastActivity < curr.lastActivity ? prev : curr,
      );
      session.devices = session.devices.filter(d => d.id !== leastActive.id);
    }

    const newDevice: SessionDevice = {
      ...device,
      id: `device-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      active: true,
      lastActivity: new Date(),
    };

    session.devices.push(newDevice);

    // Update primary device based on strategy
    this.updatePrimaryDevice(session);

    return newDevice;
  }

  private updatePrimaryDevice(session: CrossDeviceSession): void {
    const strategy = this.config.primaryDeviceStrategy || 'most-recent';

    switch (strategy) {
      case 'first-active':
        const firstActive = session.devices.find(d => d.active);
        if (firstActive) session.primaryDevice = firstActive.id;
        break;

      case 'most-recent':
        const mostRecent = session.devices.reduce((prev, curr) =>
          prev.lastActivity > curr.lastActivity ? prev : curr,
        );
        session.primaryDevice = mostRecent.id;
        break;

      case 'manual':
        // Keep existing primary device
        break;
    }
  }

  syncState(
    sessionId: string,
    deviceId: string,
    state: Record<string, unknown>,
    syncToken?: string
  ): StateSync {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    if (session.revoked) {
      throw new Error(`Session ${sessionId} has been revoked: ${session.revocationReason || 'security_event'}`);
    }

    if (this.revokedTokens.has(session.syncToken)) {
      throw new Error(`Sync token for session ${sessionId} has been revoked`);
    }

    if (syncToken && (syncToken !== session.syncToken || this.revokedTokens.has(syncToken))) {
      throw new Error(`Provided sync token is invalid or revoked`);
    }

    const device = session.devices.find(d => d.id === deviceId);
    if (!device) throw new Error(`Device ${deviceId} not found in session`);

    if (device.revoked || !device.active) {
      throw new Error(`Device ${deviceId} is inactive or revoked`);
    }

    // Calculate changes
    const changes = this.calculateChanges(session.state, state);

    // Check for conflicts
    const conflicts = this.detectConflicts(session, deviceId, state);

    if (conflicts.length > 0) {
      const resolved = this.resolveConflicts(session, conflicts);

      for (const resolution of resolved) {
        session.conflicts.push(resolution);
        // Apply resolution to state
        const [obj, key] = this.navigateToPath(session.state, resolution.field);
        if (obj && key) {
          obj[key] = resolution.resolution;
        }
      }
    }

    // Update session state
    for (const change of changes) {
      const [obj, key] = this.navigateToPath(session.state, change.path);
      if (obj && key) {
        if (change.operation === 'delete') {
          delete obj[key];
        } else {
          obj[key] = change.value;
        }
      }
    }

    // Update device activity
    device.lastActivity = new Date();

    // Create sync record
    const sync: StateSync = {
      deviceId,
      timestamp: new Date(),
      version: (this.stateSyncs.get(sessionId) || []).length + 1,
      state: JSON.parse(JSON.stringify(session.state)),
      changes,
    };

    const syncs = this.stateSyncs.get(sessionId) || [];
    syncs.push(sync);
    this.stateSyncs.set(sessionId, syncs);

    session.lastSync = new Date();
    session.syncToken = this.generateSyncToken();

    return sync;
  }

  private calculateChanges(
    previousState: Record<string, unknown>,
    newState: Record<string, unknown>,
  ): StateChange[] {
    const changes: StateChange[] = [];

    // Find new or updated values
    for (const [key, value] of Object.entries(newState)) {
      if (JSON.stringify(previousState[key]) !== JSON.stringify(value)) {
        changes.push({
          path: key,
          operation: previousState[key] === undefined ? 'set' : 'update',
          value,
          oldValue: previousState[key],
          timestamp: new Date(),
        });
      }
    }

    // Find deleted values
    for (const key of Object.keys(previousState)) {
      if (!(key in newState)) {
        changes.push({
          path: key,
          operation: 'delete',
          oldValue: previousState[key],
          timestamp: new Date(),
        });
      }
    }

    return changes;
  }

  private detectConflicts(
    session: CrossDeviceSession,
    deviceId: string,
    newState: Record<string, unknown>,
  ): SyncConflict[] {
    const conflicts: SyncConflict[] = [];

    const syncs = this.stateSyncs.get(session.id) || [];
    if (syncs.length < 2) return conflicts;

    const lastOtherSync = [...syncs].reverse().find(s => s.deviceId !== deviceId);
    if (!lastOtherSync) return conflicts;

    for (const [key, value] of Object.entries(newState)) {
      if (
        lastOtherSync.state[key] !== undefined &&
        JSON.stringify(lastOtherSync.state[key]) !== JSON.stringify(value) &&
        JSON.stringify(session.state[key]) !== JSON.stringify(lastOtherSync.state[key])
      ) {
        conflicts.push({
          field: key,
          device1Id: deviceId,
          device1Value: value,
          device1Timestamp: new Date(),
          device2Id: lastOtherSync.deviceId,
          device2Value: lastOtherSync.state[key],
          device2Timestamp: lastOtherSync.timestamp,
        });
      }
    }

    return conflicts;
  }

  private resolveConflicts(session: CrossDeviceSession, conflicts: SyncConflict[]): ConflictResolution[] {
    const resolutions: ConflictResolution[] = [];
    const strategy = this.config.conflictStrategy || 'last-write-wins';

    for (const conflict of conflicts) {
      let resolution: unknown;
      let resolveStrategy = strategy;

      switch (strategy) {
        case 'last-write-wins':
          resolution =
            conflict.device1Timestamp > conflict.device2Timestamp
              ? conflict.device1Value
              : conflict.device2Value;
          break;

        case 'device-priority':
          resolution =
            conflict.device1Id === session.primaryDevice
              ? conflict.device1Value
              : conflict.device2Value;
          resolveStrategy = 'device-priority';
          break;

        case 'manual':
          // Return unresolved for manual review
          resolution = null;
          break;
      }

      resolutions.push({
        id: `resolution-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: new Date(),
        field: conflict.field,
        deviceAValue: conflict.device1Value,
        deviceBValue: conflict.device2Value,
        resolution,
        strategy: resolveStrategy as 'last-write-wins' | 'device-priority' | 'manual',
        resolvedBy: 'system',
      });
    }

    return resolutions;
  }

  private navigateToPath(obj: Record<string, unknown>, path: string): [Record<string, unknown>, string | null] {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      if (!(parts[i] in current)) {
        current[parts[i]] = {};
      }
      current = current[parts[i]] as Record<string, unknown>;
    }

    return [current, parts[parts.length - 1]];
  }

  getSession(sessionId: string): CrossDeviceSession | undefined {
    return this.sessions.get(sessionId);
  }

  getDeviceStatus(sessionId: string): Array<{
    id: string;
    name: string;
    active: boolean;
    lastActivity: Date;
    isPrimary: boolean;
  }> {
    const session = this.sessions.get(sessionId);
    if (!session) return [];

    return session.devices.map(d => ({
      id: d.id,
      name: d.deviceName,
      active: d.active,
      lastActivity: d.lastActivity,
      isPrimary: d.id === session.primaryDevice,
    }));
  }

  updateDeviceStatus(sessionId: string, deviceId: string, active: boolean): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    const device = session.devices.find(d => d.id === deviceId);
    if (!device) return false;

    device.active = active;
    device.lastActivity = new Date();

    if (active) {
      this.updatePrimaryDevice(session);
    }

    return true;
  }

  getConflictHistory(sessionId: string, limit: number = 50): ConflictResolution[] {
    const session = this.sessions.get(sessionId);
    if (!session) return [];

    return session.conflicts.slice(-limit);
  }

  getSyncHistory(sessionId: string, limit: number = 50): StateSync[] {
    const syncs = this.stateSyncs.get(sessionId) || [];
    return syncs.slice(-limit);
  }

  cleanup(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (!session) return false;

    // Mark all devices as inactive
    session.devices.forEach(d => (d.active = false));

    // Keep data for 30 days
    return true;
  }

  revokeSession(sessionId: string, event: SecurityEvent): Result<RevocationReport, SessionErrorCode> {
    const session = this.sessions.get(sessionId);
    if (!session) return err('session_not_found');

    if (!event || !event.type || !event.actor) {
      return err('invalid_security_event');
    }

    if (event.actor.role === 'user' && event.actor.id !== session.userId) {
      return err('unauthorized');
    }

    const timestamp = event.timestamp instanceof Date ? event.timestamp : new Date();
    session.revoked = true;
    session.revokedAt = timestamp;
    session.revocationReason = event.reason || event.type;

    this.revokedTokens.add(session.syncToken);

    const revokedDeviceIds: string[] = [];
    for (const device of session.devices) {
      device.active = false;
      device.revoked = true;
      device.revokedAt = timestamp;
      device.revocationReason = event.reason || event.type;
      revokedDeviceIds.push(device.id);
    }

    this.securityEvents.push(event);

    return ok({
      success: true,
      eventType: event.type,
      userId: session.userId,
      revokedSessionIds: [session.id],
      revokedDeviceIds,
      timestamp,
      reason: event.reason,
    });
  }

  revokeDevice(
    sessionId: string,
    deviceId: string,
    event: SecurityEvent
  ): Result<RevocationReport, SessionErrorCode> {
    const session = this.sessions.get(sessionId);
    if (!session) return err('session_not_found');

    if (!event || !event.type || !event.actor) {
      return err('invalid_security_event');
    }

    if (event.actor.role === 'user' && event.actor.id !== session.userId) {
      return err('unauthorized');
    }

    const device = session.devices.find(d => d.id === deviceId);
    if (!device) return err('device_not_found');

    const timestamp = event.timestamp instanceof Date ? event.timestamp : new Date();
    device.active = false;
    device.revoked = true;
    device.revokedAt = timestamp;
    device.revocationReason = event.reason || event.type;

    // Invalidate current sync token to disconnect compromised device
    this.revokedTokens.add(session.syncToken);
    session.syncToken = this.generateSyncToken();

    // Re-evaluate primary device
    const activeDevices = session.devices.filter(d => d.active && !d.revoked);
    if (activeDevices.length === 0) {
      session.revoked = true;
      session.revokedAt = timestamp;
      session.revocationReason = 'all_devices_revoked';
    } else if (session.primaryDevice === deviceId) {
      this.updatePrimaryDevice(session);
    }

    this.securityEvents.push(event);

    return ok({
      success: true,
      eventType: event.type,
      userId: session.userId,
      revokedSessionIds: session.revoked ? [session.id] : [],
      revokedDeviceIds: [deviceId],
      timestamp,
      reason: event.reason,
    });
  }

  revokeAllUserSessions(
    userId: string,
    event: SecurityEvent,
    exceptDeviceId?: string
  ): Result<RevocationReport, SessionErrorCode> {
    if (!userId || !event || !event.type || !event.actor) {
      return err('invalid_security_event');
    }

    if (event.actor.role === 'user' && event.actor.id !== userId) {
      return err('unauthorized');
    }

    const timestamp = event.timestamp instanceof Date ? event.timestamp : new Date();
    const revokedSessionIds: string[] = [];
    const revokedDeviceIds: string[] = [];

    for (const session of this.sessions.values()) {
      if (session.userId !== userId) continue;

      if (exceptDeviceId) {
        const hasExceptDevice = session.devices.some(d => d.id === exceptDeviceId);
        if (hasExceptDevice) {
          this.revokedTokens.add(session.syncToken);
          session.syncToken = this.generateSyncToken();

          for (const device of session.devices) {
            if (device.id !== exceptDeviceId) {
              device.active = false;
              device.revoked = true;
              device.revokedAt = timestamp;
              device.revocationReason = event.reason || event.type;
              revokedDeviceIds.push(device.id);
            }
          }
          session.primaryDevice = exceptDeviceId;
          continue;
        }
      }

      session.revoked = true;
      session.revokedAt = timestamp;
      session.revocationReason = event.reason || event.type;
      this.revokedTokens.add(session.syncToken);
      revokedSessionIds.push(session.id);

      for (const device of session.devices) {
        device.active = false;
        device.revoked = true;
        device.revokedAt = timestamp;
        device.revocationReason = event.reason || event.type;
        revokedDeviceIds.push(device.id);
      }
    }

    this.securityEvents.push(event);

    return ok({
      success: true,
      eventType: event.type,
      userId,
      revokedSessionIds,
      revokedDeviceIds,
      timestamp,
      reason: event.reason,
    });
  }

  pruneStaleSessions(options?: {
    staleThresholdMs?: number;
    actor?: { id: string; role: 'user' | 'maintainer' | 'system' };
    now?: Date;
  }): Result<RevocationReport, SessionErrorCode> {
    const actor = options?.actor ?? { id: 'system', role: 'system' };
    const now = options?.now ?? new Date();
    const thresholdMs = options?.staleThresholdMs ?? this.config.staleSessionTimeoutMs ?? 30 * 24 * 60 * 60 * 1000;

    const revokedSessionIds: string[] = [];
    const revokedDeviceIds: string[] = [];

    for (const session of this.sessions.values()) {
      if (actor.role === 'user' && session.userId !== actor.id) {
        continue;
      }

      let allDevicesStale = true;
      for (const device of session.devices) {
        const idleTime = now.getTime() - device.lastActivity.getTime();
        if (idleTime > thresholdMs && !device.revoked) {
          device.active = false;
          device.revoked = true;
          device.revokedAt = now;
          device.revocationReason = 'stale_session_timeout';
          revokedDeviceIds.push(device.id);
        } else if (!device.revoked && device.active) {
          allDevicesStale = false;
        }
      }

      if (allDevicesStale && !session.revoked) {
        session.revoked = true;
        session.revokedAt = now;
        session.revocationReason = 'stale_session_timeout';
        this.revokedTokens.add(session.syncToken);
        revokedSessionIds.push(session.id);
      }
    }

    return ok({
      success: true,
      eventType: 'stale_session_timeout',
      userId: actor.role === 'user' ? actor.id : 'global',
      revokedSessionIds,
      revokedDeviceIds,
      timestamp: now,
      reason: `Pruned devices/sessions inactive for over ${thresholdMs}ms`,
    });
  }

  isTokenRevoked(token: string): boolean {
    return this.revokedTokens.has(token);
  }

  isSessionRevoked(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    return Boolean(session?.revoked);
  }

  retryRevocation(
    fn: () => Result<RevocationReport, SessionErrorCode>,
    maxRetries = 3
  ): Result<RevocationReport, SessionErrorCode> {
    let attempts = 0;
    while (attempts <= maxRetries) {
      attempts += 1;
      const res = fn();
      if (res.ok) return res;
      if (attempts > maxRetries) {
        return err('revocation_retries_exhausted');
      }
    }
    return err('revocation_retries_exhausted');
  }

  reset(): void {
    this.sessions.clear();
    this.stateSyncs.clear();
    this.revokedTokens.clear();
    this.securityEvents = [];
  }
}


export const sessionManager = new CrossDeviceSessionManager();
