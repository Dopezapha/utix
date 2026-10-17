import { describe, expect, it } from 'vitest';
import {
  DeploymentRollbackVerifier,
  MigrationRunner
} from '../runner';
import type {
  DeploymentRollbackConfig,
  MigrationDefinition,
  RollbackVerificationCheck
} from '../types';

interface SampleAccountRecord {
  id: string;
  address: string;
  balanceStroops: number;
  subentryCount: number;
  version: number;
}

describe('Rollback Verification After Failed Migrations or Deployments (#265)', () => {
  const initialAccounts: SampleAccountRecord[] = [
    { id: 'acc_1', address: 'GBX...1', balanceStroops: 10_000_000, subentryCount: 2, version: 1 },
    { id: 'acc_2', address: 'GBX...2', balanceStroops: 50_000_000, subentryCount: 0, version: 1 },
    { id: 'acc_3', address: 'GBX...3', balanceStroops: 20_000_000, subentryCount: 1, version: 1 },
  ];

  const subentryInvarianceCheck: RollbackVerificationCheck<SampleAccountRecord> = {
    name: 'subentry_non_negative_check',
    description: 'Verifies that subentry count remains non-negative after rollback',
    validate: (restored) => {
      const invalid = restored.filter((r) => r.subentryCount < 0);
      return {
        checkName: 'subentry_non_negative_check',
        passed: invalid.length === 0,
        message: invalid.length > 0 ? 'Negative subentry count detected after rollback' : 'All subentries valid',
        violatingRecordIds: invalid.map((r) => r.id),
      };
    },
  };

  const createFailingMigration = (
    faultyRollback = false,
    corruptRollbackIds = false
  ): MigrationDefinition<SampleAccountRecord, SampleAccountRecord> => ({
    id: '20261017_account_v2_upgrade',
    name: 'Upgrade Account Schema to v2',
    description: 'Increments version and applies fee reserve calculation',
    fromVersion: 1,
    toVersion: 2,
    riskLevel: 'high',
    rollbackNotes: 'Restore version 1 and original balance',
    forwardFixNotes: 'Review failed accounts in staging before re-applying',
    dryRun: (records) => ({
      migrationId: '20261017_account_v2_upgrade',
      targetVersion: 2,
      totalRecords: records.length,
      affectedCount: records.length,
      unchangedCount: 0,
      sampleDiffs: [],
      riskLevel: 'high',
      rollbackNotes: 'Restore v1',
      forwardFixNotes: 'Fix bad records',
      estimatedDurationMs: 10,
    }),
    apply: (records) => {
      // Transformation deliberately introduces an invalid negative balance to trigger postCheck failure
      const transformed = records.map((r, i) => ({
        ...r,
        balanceStroops: i === 0 ? -100 : r.balanceStroops,
        version: 2,
      }));
      return { transformed, affectedCount: records.length };
    },
    rollback: (records) => {
      if (faultyRollback) {
        // Drop one record during rollback to simulate partial/faulty rollback
        const transformed = records.slice(0, records.length - 1).map((r) => ({
          ...r,
          balanceStroops: 10_000_000,
          version: 1,
        }));
        return { transformed, affectedCount: transformed.length };
      }

      if (corruptRollbackIds) {
        // Corrupt an ID during rollback
        const transformed = records.map((r, i) => ({
          ...r,
          id: i === 0 ? 'corrupted_id' : r.id,
          balanceStroops: 10_000_000,
          version: 1,
        }));
        return { transformed, affectedCount: transformed.length };
      }

      // Clean, correct rollback
      const transformed = records.map((r, i) => ({
        ...r,
        id: initialAccounts[i].id,
        balanceStroops: initialAccounts[i].balanceStroops,
        subentryCount: initialAccounts[i].subentryCount,
        version: 1,
      }));
      return { transformed, affectedCount: records.length };
    },
    postChecks: [
      {
        name: 'non_negative_balance',
        description: 'Ensures no negative balances',
        validate: (records) => {
          const invalid = records.filter((r) => r.balanceStroops < 0);
          return {
            checkName: 'non_negative_balance',
            passed: invalid.length === 0,
            message: invalid.length > 0 ? 'Negative balance found' : undefined,
            violatingRecordIds: invalid.map((r) => r.id),
          };
        },
      },
    ],
    rollbackChecks: [subentryInvarianceCheck],
  });

  describe('normal path', () => {
    it('executes rollback and verifies restored state when migration post-checks fail', async () => {
      const migration = createFailingMigration(false);
      const report = await MigrationRunner.execute(migration, initialAccounts, {
        autoRollbackOnFailure: true,
      });

      expect(report.success).toBe(false);
      expect(report.status).toBe('rolled_back');
      expect(report.rollbackExecuted).toBe(true);
      expect(report.rollbackVerification).toBeDefined();

      const verification = report.rollbackVerification!;
      expect(verification.verified).toBe(true);
      expect(verification.status).toBe('verified');
      expect(verification.restoredRecordCount).toBe(3);
      expect(verification.checkResults.every((c) => c.passed)).toBe(true);
      expect(verification.recoveryGuidance).toContain('Rollback successfully verified');
    });

    it('verifies deployment rollback health, version, and invariants', async () => {
      let healthCalled = false;
      let versionChecked = false;

      const deploymentConfig: DeploymentRollbackConfig = {
        deploymentId: 'deploy-20261017-v2',
        targetVersion: '2.0.0',
        previousVersion: '1.9.0',
        healthEndpointCheck: async () => {
          healthCalled = true;
          return true;
        },
        schemaVersionCheck: async () => {
          versionChecked = true;
          return '1.9.0';
        },
        invariants: [
          {
            name: 'database_connection_pool',
            check: async () => true,
          },
        ],
      };

      const result = await DeploymentRollbackVerifier.verifyDeploymentRollback(
        deploymentConfig,
        { role: 'maintainer', userId: 'maintainer-1' }
      );

      expect(result.success).toBe(true);
      expect(result.verified).toBe(true);
      expect(result.healthCheckPassed).toBe(true);
      expect(result.previousVersionRestored).toBe(true);
      expect(result.invariantResults[0].passed).toBe(true);
      expect(healthCalled).toBe(true);
      expect(versionChecked).toBe(true);
    });
  });

  describe('failure path', () => {
    it('detects record count discrepancy and flags rollback_verification_failed on partial rollback', async () => {
      const faultyMigration = createFailingMigration(true);
      const report = await MigrationRunner.execute(faultyMigration, initialAccounts, {
        autoRollbackOnFailure: true,
      });

      expect(report.success).toBe(false);
      expect(report.status).toBe('rollback_verification_failed');
      expect(report.rollbackExecuted).toBe(true);
      expect(report.rollbackVerification).toBeDefined();

      const verification = report.rollbackVerification!;
      expect(verification.verified).toBe(false);
      expect(verification.status).toBe('verification_failed');
      expect(verification.discrepancies).toBeDefined();
      expect(verification.discrepancies?.[0]).toContain('Record count discrepancy');
    });

    it('detects missing original record IDs after rollback', async () => {
      const corruptIdsMigration = createFailingMigration(false, true);
      const report = await MigrationRunner.execute(corruptIdsMigration, initialAccounts, {
        autoRollbackOnFailure: true,
      });

      expect(report.status).toBe('rollback_verification_failed');
      expect(report.rollbackVerification?.verified).toBe(false);
      const idCheck = report.rollbackVerification?.checkResults.find(
        (c) => c.checkName === 'record_id_parity'
      );
      expect(idCheck?.passed).toBe(false);
      expect(idCheck?.violatingRecordIds).toContain('acc_1');
    });

    it('flags deployment rollback failure when health check or version mismatch fails', async () => {
      const failingDeployConfig: DeploymentRollbackConfig = {
        deploymentId: 'deploy-bad',
        targetVersion: '2.0.0',
        previousVersion: '1.9.0',
        healthEndpointCheck: async () => false,
        schemaVersionCheck: async () => '2.0.0', // Failed to revert to 1.9.0
      };

      const result = await DeploymentRollbackVerifier.verifyDeploymentRollback(
        failingDeployConfig,
        { role: 'maintainer', userId: 'maintainer-1' }
      );

      expect(result.success).toBe(false);
      expect(result.verified).toBe(false);
      expect(result.healthCheckPassed).toBe(false);
      expect(result.previousVersionRestored).toBe(false);
      expect(result.discrepancies?.length).toBe(2);
    });
  });

  describe('retry path', () => {
    it('retries rollback verification on transient exceptions', async () => {
      let attempts = 0;
      const transientMigration: MigrationDefinition<SampleAccountRecord, SampleAccountRecord> = {
        ...createFailingMigration(false),
        rollback: () => {
          attempts += 1;
          if (attempts < 2) {
            throw new Error('Database transaction lock conflict during rollback');
          }
          return { transformed: [...initialAccounts], affectedCount: initialAccounts.length };
        },
      };

      const result = await MigrationRunner.retryRollback(
        transientMigration,
        initialAccounts,
        initialAccounts,
        {},
        3
      );

      expect(result.verified).toBe(true);
      expect(attempts).toBe(2);
    });

    it('exhausts retries and returns verification_failed when rollback persistently throws', async () => {
      const crashingRollbackMigration: MigrationDefinition<SampleAccountRecord, SampleAccountRecord> = {
        ...createFailingMigration(false),
        rollback: () => {
          throw new Error('Persistent storage corruption in rollback target');
        },
      };

      const result = await MigrationRunner.retryRollback(
        crashingRollbackMigration,
        initialAccounts,
        initialAccounts,
        {},
        2
      );

      expect(result.verified).toBe(false);
      expect(result.status).toBe('verification_failed');
      expect(result.discrepancies?.[0]).toContain('after 2 retries');
    });
  });

  describe('authorization path', () => {
    it('rejects deployment rollback verification for non-maintainer role', async () => {
      const deployConfig: DeploymentRollbackConfig = {
        deploymentId: 'deploy-auth-test',
        targetVersion: '2.0.0',
        previousVersion: '1.9.0',
      };

      const result = await DeploymentRollbackVerifier.verifyDeploymentRollback(
        deployConfig,
        { role: 'viewer', userId: 'viewer-1' }
      );

      expect(result.success).toBe(false);
      expect(result.verified).toBe(false);
      expect(result.discrepancies?.[0]).toContain('Unauthorized');
    });
  });

  describe('operational edge cases', () => {
    it('handles rollback verification check throwing an unexpected exception safely', async () => {
      const throwingCheck: RollbackVerificationCheck<SampleAccountRecord> = {
        name: 'exploding_check',
        description: 'Simulates unhandled error in custom rollback check',
        validate: () => {
          throw new Error('Unexpected undefined dereference in invariant');
        },
      };

      const migrationWithThrowingCheck: MigrationDefinition<SampleAccountRecord, SampleAccountRecord> = {
        ...createFailingMigration(false),
        rollbackChecks: [throwingCheck],
      };

      const report = await MigrationRunner.verifyRollback(
        migrationWithThrowingCheck,
        initialAccounts,
        initialAccounts
      );

      expect(report.verified).toBe(false);
      expect(report.discrepancies?.[0]).toContain('Check threw exception');
    });
  });
});
