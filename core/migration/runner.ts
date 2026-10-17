/**
 * Migration Runner Service (#79)
 *
 * Executes migrations with dry-run verification, atomic execution,
 * automated post-migration invariant checks, and automated rollback if needed.
 */

import {
  DeploymentRollbackConfig,
  DeploymentRollbackReport,
  MigrationContext,
  MigrationDefinition,
  MigrationExecutionReport,
  MigrationPreviewReport,
  PostMigrationCheckResult,
  RollbackVerificationReport
} from './types';

export class MigrationRunner {
  /**
   * Previews a migration via dryRun without making any modifications.
   * Time Complexity: O(N)
   * Space Complexity: O(1) beyond preview diff storage
   */
  public static preview<TInput, TOutput>(
    migration: MigrationDefinition<TInput, TOutput>,
    records: readonly TInput[],
    context?: MigrationContext
  ): MigrationPreviewReport {
    return migration.dryRun(records, context);
  }

  /**
   * Verifies that a rollback successfully restored records to valid pre-migration state.
   * Runs custom rollback checks if defined, and verifies structural record parity.
   *
   * Time Complexity: O(N) where N is record count.
   * Space Complexity: O(1) beyond check result allocations.
   */
  public static async verifyRollback<TInput, TOutput>(
    migration: MigrationDefinition<TInput, TOutput>,
    originalRecords: readonly TInput[],
    restoredRecords: readonly TInput[],
    context?: MigrationContext
  ): Promise<RollbackVerificationReport> {
    const startTime = Date.now();
    const checkResults: PostMigrationCheckResult[] = [];
    const discrepancies: string[] = [];

    // 1. Record Count Parity
    if (restoredRecords.length !== originalRecords.length) {
      discrepancies.push(
        `Record count discrepancy: expected ${originalRecords.length} records, got ${restoredRecords.length}`
      );
      checkResults.push({
        checkName: 'record_count_parity',
        passed: false,
        message: `Expected ${originalRecords.length} records after rollback, but found ${restoredRecords.length}`
      });
    } else {
      checkResults.push({
        checkName: 'record_count_parity',
        passed: true,
        message: `All ${originalRecords.length} records restored`
      });
    }

    // 2. ID Parity Check
    const originalIds = new Set<string>(
      originalRecords
        .map((r: unknown) => (r && typeof r === 'object' && 'id' in r ? String((r as { id: unknown }).id) : undefined))
        .filter((id): id is string => typeof id === 'string' && id.length > 0)
    );
    if (originalIds.size > 0) {
      const restoredIds = new Set<string>(
        restoredRecords
          .map((r: unknown) => (r && typeof r === 'object' && 'id' in r ? String((r as { id: unknown }).id) : undefined))
          .filter((id): id is string => typeof id === 'string' && id.length > 0)
      );
      const missingIds: string[] = [...originalIds].filter((id) => !restoredIds.has(id));
      if (missingIds.length > 0) {
        discrepancies.push(`Missing record IDs after rollback: ${missingIds.slice(0, 5).join(', ')}`);
        checkResults.push({
          checkName: 'record_id_parity',
          passed: false,
          violatingRecordIds: missingIds,
          message: `${missingIds.length} original records missing after rollback`
        });
      } else {
        checkResults.push({
          checkName: 'record_id_parity',
          passed: true,
          message: 'All original record IDs present after rollback'
        });
      }
    }

    // 3. Custom Rollback Invariant Checks
    if (migration.rollbackChecks && migration.rollbackChecks.length > 0) {
      for (const check of migration.rollbackChecks) {
        try {
          const res = await check.validate(restoredRecords, originalRecords, context);
          checkResults.push(res);
          if (!res.passed) {
            discrepancies.push(`[${check.name}] ${res.message || 'Rollback invariant failed'}`);
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          discrepancies.push(`[${check.name}] Check threw exception: ${msg}`);
          checkResults.push({
            checkName: check.name,
            passed: false,
            message: `Check threw exception: ${msg}`
          });
        }
      }
    }

    const verified = discrepancies.length === 0;
    const durationMs = Date.now() - startTime;

    return {
      verified,
      status: verified ? 'verified' : 'verification_failed',
      checkResults,
      discrepancies: discrepancies.length > 0 ? discrepancies : undefined,
      restoredRecordCount: restoredRecords.length,
      verificationDurationMs: durationMs,
      recoveryGuidance: verified
        ? 'Rollback successfully verified. System state restored.'
        : `Rollback verification failed: manual recovery intervention required. Refer to: ${migration.forwardFixNotes}`
    };
  }

  /**
   * Executes a migration safely.
   * If post-checks fail and `autoRollbackOnFailure` is true, rolls back to original state
   * and verifies that the rollback successfully restored integrity.
   *
   * Time Complexity: O(N)
   * Space Complexity: O(N) for transformed output
   */
  public static async execute<TInput, TOutput>(
    migration: MigrationDefinition<TInput, TOutput>,
    records: readonly TInput[],
    options?: MigrationContext
  ): Promise<MigrationExecutionReport<TOutput>> {
    const startTime = Date.now();
    const isDryRun = options?.dryRun ?? false;
    const autoRollback = options?.autoRollbackOnFailure ?? true;

    // 1. Dry Run Mode
    if (isDryRun) {
      const previewReport = migration.dryRun(records, options);
      const durationMs = Date.now() - startTime;
      return {
        migrationId: migration.id,
        success: true,
        status: 'dry_run',
        totalRecords: previewReport.totalRecords,
        affectedRecords: previewReport.affectedCount,
        postCheckResults: [],
        durationMs,
        rollbackNotes: migration.rollbackNotes,
        forwardFixNotes: migration.forwardFixNotes
      };
    }

    // 2. Apply Transformation
    let transformed: TOutput[];
    let affectedCount = 0;
    try {
      const applyResult = migration.apply(records, options);
      transformed = applyResult.transformed;
      affectedCount = applyResult.affectedCount;
    } catch (err: unknown) {
      const durationMs = Date.now() - startTime;
      const errMsg = err instanceof Error ? err.message : String(err);
      return {
        migrationId: migration.id,
        success: false,
        status: 'failed',
        totalRecords: records.length,
        affectedRecords: 0,
        postCheckResults: [],
        errors: [`Migration apply threw an unhandled exception: ${errMsg}`],
        durationMs,
        rollbackNotes: migration.rollbackNotes,
        forwardFixNotes: migration.forwardFixNotes
      };
    }

    // 3. Run Post-Migration Checks
    const postCheckResults: PostMigrationCheckResult[] = [];
    let allChecksPassed = true;

    for (const check of migration.postChecks) {
      try {
        const result = await check.validate(transformed, options);
        postCheckResults.push(result);
        if (!result.passed) {
          allChecksPassed = false;
        }
      } catch (checkErr: unknown) {
        allChecksPassed = false;
        const msg = checkErr instanceof Error ? checkErr.message : String(checkErr);
        postCheckResults.push({
          checkName: check.name,
          passed: false,
          message: `Post-check threw exception: ${msg}`
        });
      }
    }

    // 4. Handle Post-Check Failures with Verified Rollback
    if (!allChecksPassed) {
      const errors = postCheckResults
        .filter((c) => !c.passed)
        .map((c) => `[${c.checkName}] ${c.message || 'Validation failed'}`);

      // Attempt Rollback if requested
      if (autoRollback && migration.rollback) {
        try {
          const rollbackResult = migration.rollback(transformed, options);
          const restored = rollbackResult.transformed;
          const rollbackVerification = await this.verifyRollback(migration, records, restored, options);

          const durationMs = Date.now() - startTime;
          if (rollbackVerification.verified) {
            return {
              migrationId: migration.id,
              success: false,
              status: 'rolled_back',
              totalRecords: records.length,
              affectedRecords: affectedCount,
              postCheckResults,
              errors,
              durationMs,
              rollbackExecuted: true,
              rollbackVerification,
              rollbackNotes: migration.rollbackNotes,
              forwardFixNotes: migration.forwardFixNotes,
              rollbackOutputRecords: restored
            };
          } else {
            return {
              migrationId: migration.id,
              success: false,
              status: 'rollback_verification_failed',
              totalRecords: records.length,
              affectedRecords: affectedCount,
              postCheckResults,
              errors: [
                ...errors,
                `Rollback verification failed: ${rollbackVerification.discrepancies?.join(', ') || 'Invariants violated'}`
              ],
              durationMs,
              rollbackExecuted: true,
              rollbackVerification,
              rollbackNotes: migration.rollbackNotes,
              forwardFixNotes: migration.forwardFixNotes,
              rollbackOutputRecords: restored
            };
          }
        } catch (rbErr: unknown) {
          const rbMsg = rbErr instanceof Error ? rbErr.message : String(rbErr);
          errors.push(`Automated rollback failed: ${rbMsg}`);
        }
      }

      const durationMs = Date.now() - startTime;
      return {
        migrationId: migration.id,
        success: false,
        status: 'failed',
        totalRecords: records.length,
        affectedRecords: affectedCount,
        postCheckResults,
        errors,
        durationMs,
        rollbackExecuted: false,
        rollbackNotes: migration.rollbackNotes,
        forwardFixNotes: migration.forwardFixNotes
      };
    }

    // 5. Success
    const durationMs = Date.now() - startTime;
    return {
      migrationId: migration.id,
      success: true,
      status: 'applied',
      totalRecords: records.length,
      affectedRecords: affectedCount,
      postCheckResults,
      durationMs,
      rollbackNotes: migration.rollbackNotes,
      forwardFixNotes: migration.forwardFixNotes,
      outputRecords: transformed
    };
  }

  /**
   * Retries a rollback and verification operation up to maxRetries times.
   */
  public static async retryRollback<TInput, TOutput>(
    migration: MigrationDefinition<TInput, TOutput>,
    records: readonly TInput[],
    transformedRecords: readonly TOutput[],
    options?: MigrationContext,
    maxRetries = 3
  ): Promise<RollbackVerificationReport> {
    let attempts = 0;
    while (attempts <= maxRetries) {
      attempts += 1;
      if (!migration.rollback) {
        return {
          verified: false,
          status: 'verification_failed',
          checkResults: [{ checkName: 'rollback_handler_defined', passed: false, message: 'No rollback handler' }],
          discrepancies: ['No rollback handler defined on migration definition'],
          restoredRecordCount: 0,
          verificationDurationMs: 0
        };
      }
      try {
        const rollbackResult = migration.rollback(transformedRecords, options);
        const report = await this.verifyRollback(migration, records, rollbackResult.transformed, options);
        if (report.verified || attempts > maxRetries) {
          return report;
        }
      } catch (err: unknown) {
        if (attempts > maxRetries) {
          const msg = err instanceof Error ? err.message : String(err);
          return {
            verified: false,
            status: 'verification_failed',
            checkResults: [{ checkName: 'rollback_execution', passed: false, message: msg }],
            discrepancies: [`Rollback threw exception after ${maxRetries} retries: ${msg}`],
            restoredRecordCount: 0,
            verificationDurationMs: 0
          };
        }
      }
    }
    return {
      verified: false,
      status: 'verification_failed',
      checkResults: [],
      restoredRecordCount: 0,
      verificationDurationMs: 0
    };
  }
}

export class DeploymentRollbackVerifier {
  /**
   * Verifies health, schema version, and invariants after a deployment rollback.
   *
   * Time Complexity: O(1) / O(K) where K is number of deployment invariant checks.
   * Space Complexity: O(K)
   */
  public static async verifyDeploymentRollback(
    config: DeploymentRollbackConfig,
    actor?: { role: string; userId?: string }
  ): Promise<DeploymentRollbackReport> {
    const discrepancies: string[] = [];
    const invariantResults: { name: string; passed: boolean }[] = [];

    // Authorization check: only maintainers can verify deployment rollbacks
    if (actor && actor.role !== 'maintainer') {
      return {
        deploymentId: config.deploymentId,
        success: false,
        verified: false,
        previousVersionRestored: false,
        healthCheckPassed: false,
        invariantResults: [],
        discrepancies: ['Unauthorized: only maintainer can perform deployment rollback verification'],
        recoveryNotes: 'Authorization denied for non-maintainer role',
        timestamp: new Date()
      };
    }

    let healthCheckPassed = true;
    if (config.healthEndpointCheck) {
      try {
        healthCheckPassed = await config.healthEndpointCheck();
        if (!healthCheckPassed) {
          discrepancies.push('Health check endpoint failed after deployment rollback');
        }
      } catch (err: unknown) {
        healthCheckPassed = false;
        discrepancies.push(`Health check exception: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    let previousVersionRestored = true;
    if (config.schemaVersionCheck) {
      try {
        const currentVersion = await config.schemaVersionCheck();
        if (currentVersion !== config.previousVersion) {
          previousVersionRestored = false;
          discrepancies.push(
            `Schema version mismatch: expected ${config.previousVersion}, got ${currentVersion}`
          );
        }
      } catch (err: unknown) {
        previousVersionRestored = false;
        discrepancies.push(`Version check exception: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (config.invariants) {
      for (const inv of config.invariants) {
        try {
          const passed = await inv.check();
          invariantResults.push({ name: inv.name, passed });
          if (!passed) {
            discrepancies.push(`Deployment invariant failed: ${inv.name}`);
          }
        } catch {
          invariantResults.push({ name: inv.name, passed: false });
          discrepancies.push(`Deployment invariant exception: ${inv.name}`);
        }
      }
    }

    const verified = discrepancies.length === 0;

    return {
      deploymentId: config.deploymentId,
      success: verified,
      verified,
      previousVersionRestored,
      healthCheckPassed,
      invariantResults,
      discrepancies: discrepancies.length > 0 ? discrepancies : undefined,
      recoveryNotes: verified
        ? `Rollback to ${config.previousVersion} verified successfully.`
        : `Deployment rollback verification failed: ${discrepancies.join('; ')}`,
      timestamp: new Date()
    };
  }
}

