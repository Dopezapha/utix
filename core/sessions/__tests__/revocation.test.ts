import { describe, it, expect, beforeEach } from 'vitest';
import { sessionManager } from '../manager';
import type { SecurityEvent } from '../types';

describe('Stale Session and Token Revocation After Security Events (#261)', () => {
  beforeEach(() => {
    sessionManager.reset();
  });

  const createTestSession = (userId = 'user-123') => {
    return sessionManager.createSession(userId, {
      deviceType: 'web',
      deviceName: 'MacBook Pro',
      userAgent: 'Mozilla/5.0...',
      ipAddress: '192.168.1.1',
    });
  };

  describe('normal path', () => {
    it('revokes session and sync tokens after password_changed security event', () => {
      const session = createTestSession('alice');
      const deviceId = session.devices[0].id;
      const initialToken = session.syncToken;

      const event: SecurityEvent = {
        type: 'password_changed',
        userId: 'alice',
        sessionId: session.id,
        timestamp: new Date(),
        actor: { id: 'alice', role: 'user' },
        reason: 'User initiated password reset'
      };

      const result = sessionManager.revokeSession(session.id, event);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.revokedSessionIds).toContain(session.id);
      expect(result.value.revokedDeviceIds).toContain(deviceId);
      expect(sessionManager.isSessionRevoked(session.id)).toBe(true);
      expect(sessionManager.isTokenRevoked(initialToken)).toBe(true);

      // Subsequent syncState must be rejected
      expect(() => {
        sessionManager.syncState(session.id, deviceId, { key: 'value' });
      }).toThrow(/revoked/i);
    });

    it('revokes a specific compromised device and rotates the session syncToken', () => {
      const session = createTestSession('bob');
      const primaryDeviceId = session.devices[0].id;

      const mobileDevice = sessionManager.addDevice(session.id, {
        deviceType: 'mobile',
        deviceName: 'Pixel Phone',
        userAgent: 'Android...',
        ipAddress: '10.0.0.1',
      })!;

      const oldToken = session.syncToken;

      const event: SecurityEvent = {
        type: 'suspicious_activity_detected',
        userId: 'bob',
        sessionId: session.id,
        deviceId: mobileDevice.id,
        timestamp: new Date(),
        actor: { id: 'bob', role: 'user' },
        reason: 'Lost device report'
      };

      const result = sessionManager.revokeDevice(session.id, mobileDevice.id, event);
      expect(result.ok).toBe(true);

      const updated = sessionManager.getSession(session.id)!;
      expect(sessionManager.isTokenRevoked(oldToken)).toBe(true);
      expect(updated.syncToken).not.toBe(oldToken);

      // Compromised device cannot sync
      expect(() => {
        sessionManager.syncState(session.id, mobileDevice.id, { test: 1 });
      }).toThrow(/inactive or revoked/i);

      // Remaining valid device can continue syncing
      const sync = sessionManager.syncState(session.id, primaryDeviceId, { valid: true });
      expect(sync).toBeDefined();
    });

    it('revokes all sessions for a user on account_compromised event', () => {
      const session1 = createTestSession('charlie');
      const session2 = sessionManager.createSession('charlie', {
        deviceType: 'desktop',
        deviceName: 'Workstation',
        userAgent: 'Linux...',
        ipAddress: '10.0.0.2',
      });

      const event: SecurityEvent = {
        type: 'account_compromised',
        userId: 'charlie',
        timestamp: new Date(),
        actor: { id: 'admin-sec', role: 'maintainer' },
        reason: 'Credentials leak detected on paste site'
      };

      const result = sessionManager.revokeAllUserSessions('charlie', event);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.revokedSessionIds).toEqual(
        expect.arrayContaining([session1.id, session2.id])
      );
      expect(sessionManager.isSessionRevoked(session1.id)).toBe(true);
      expect(sessionManager.isSessionRevoked(session2.id)).toBe(true);
    });

    it('revokes all sessions except the current authenticated device', () => {
      const session = createTestSession('david');
      const currentDeviceId = session.devices[0].id;

      const otherDevice = sessionManager.addDevice(session.id, {
        deviceType: 'tablet',
        deviceName: 'Old iPad',
        userAgent: 'Safari...',
        ipAddress: '192.168.1.50',
      })!;

      const event: SecurityEvent = {
        type: 'password_changed',
        userId: 'david',
        timestamp: new Date(),
        actor: { id: 'david', role: 'user' },
      };

      const result = sessionManager.revokeAllUserSessions('david', event, currentDeviceId);
      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.revokedDeviceIds).toContain(otherDevice.id);
      expect(result.value.revokedDeviceIds).not.toContain(currentDeviceId);

      const updated = sessionManager.getSession(session.id)!;
      expect(updated.revoked).toBeFalsy();
      expect(sessionManager.syncState(session.id, currentDeviceId, { active: true })).toBeDefined();
    });

    it('prunes stale sessions based on max idle threshold', () => {
      const session = createTestSession('eve');
      const device = session.devices[0];

      // Simulate device inactive for 35 days
      const thirtyFiveDaysAgo = new Date(Date.now() - 35 * 24 * 60 * 60 * 1000);
      device.lastActivity = thirtyFiveDaysAgo;

      const pruneResult = sessionManager.pruneStaleSessions({
        staleThresholdMs: 30 * 24 * 60 * 60 * 1000,
        now: new Date(),
        actor: { id: 'cron-worker', role: 'system' }
      });

      expect(pruneResult.ok).toBe(true);
      if (!pruneResult.ok) return;

      expect(pruneResult.value.revokedDeviceIds).toContain(device.id);
      expect(pruneResult.value.revokedSessionIds).toContain(session.id);
      expect(sessionManager.isSessionRevoked(session.id)).toBe(true);
    });
  });

  describe('authorization path', () => {
    it('denies user revoking another user session', () => {
      const session = createTestSession('victim-user');

      const attackEvent: SecurityEvent = {
        type: 'manual_admin_revocation',
        userId: 'victim-user',
        sessionId: session.id,
        timestamp: new Date(),
        actor: { id: 'malicious-user', role: 'user' },
      };

      const result = sessionManager.revokeSession(session.id, attackEvent);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('unauthorized');
      }
      expect(sessionManager.isSessionRevoked(session.id)).toBe(false);
    });

    it('permits maintainer role to revoke any user session', () => {
      const session = createTestSession('target-user');

      const adminEvent: SecurityEvent = {
        type: 'manual_admin_revocation',
        userId: 'target-user',
        sessionId: session.id,
        timestamp: new Date(),
        actor: { id: 'admin-ada', role: 'maintainer' },
        reason: 'Security audit remediation'
      };

      const result = sessionManager.revokeSession(session.id, adminEvent);
      expect(result.ok).toBe(true);
      expect(sessionManager.isSessionRevoked(session.id)).toBe(true);
    });
  });

  describe('failure and retry paths', () => {
    it('returns session_not_found for non-existent session ID', () => {
      const event: SecurityEvent = {
        type: 'manual_admin_revocation',
        userId: 'any',
        timestamp: new Date(),
        actor: { id: 'admin', role: 'maintainer' }
      };

      const result = sessionManager.revokeSession('non-existent-session', event);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('session_not_found');
      }
    });

    it('returns invalid_security_event for malformed security event', () => {
      const session = createTestSession('frank');
      const malformed = {} as unknown as SecurityEvent;

      const result = sessionManager.revokeSession(session.id, malformed);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('invalid_security_event');
      }
    });

    it('retries revocation operation on transient error', () => {
      let callCount = 0;
      const transientFn = () => {
        callCount += 1;
        if (callCount < 2) {
          return { ok: false as const, code: 'revocation_failed' as const };
        }
        return {
          ok: true as const,
          value: {
            success: true,
            eventType: 'manual_admin_revocation' as const,
            userId: 'test',
            revokedSessionIds: ['s1'],
            revokedDeviceIds: [],
            timestamp: new Date()
          }
        };
      };

      const retryResult = sessionManager.retryRevocation(transientFn, 3);
      expect(retryResult.ok).toBe(true);
      expect(callCount).toBe(2);
    });
  });

  describe('operational edge cases', () => {
    it('re-elects primary device when current primary device is revoked', () => {
      const session = createTestSession('george');
      const primaryDevice = session.devices[0];

      const secondaryDevice = sessionManager.addDevice(session.id, {
        deviceType: 'mobile',
        deviceName: 'Android Mobile',
        userAgent: 'Mobile...',
        ipAddress: '10.0.0.5',
      })!;

      const event: SecurityEvent = {
        type: 'suspicious_activity_detected',
        userId: 'george',
        sessionId: session.id,
        deviceId: primaryDevice.id,
        timestamp: new Date(),
        actor: { id: 'george', role: 'user' }
      };

      const result = sessionManager.revokeDevice(session.id, primaryDevice.id, event);
      expect(result.ok).toBe(true);

      const updated = sessionManager.getSession(session.id)!;
      expect(updated.primaryDevice).toBe(secondaryDevice.id);
      expect(updated.revoked).toBeFalsy();
    });

    it('marks session revoked when all devices have been revoked', () => {
      const session = createTestSession('helen');
      const singleDevice = session.devices[0];

      const event: SecurityEvent = {
        type: 'manual_admin_revocation',
        userId: 'helen',
        sessionId: session.id,
        deviceId: singleDevice.id,
        timestamp: new Date(),
        actor: { id: 'helen', role: 'user' }
      };

      sessionManager.revokeDevice(session.id, singleDevice.id, event);
      const updated = sessionManager.getSession(session.id)!;
      expect(updated.revoked).toBe(true);
      expect(updated.revocationReason).toBe('all_devices_revoked');
    });
  });
});
