/**
 * Types and interfaces for Migration Safety Framework (#79)
 *
 * Provides dry-run previews, automated post-migration invariant checks,
 * rollback/forward-fix documentation, and safe execution with atomic rollback capabilities.
 */

export type MigrationRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface MigrationDiff<T = unknown> {
  readonly recordId: string;
  readonly before?: Partial<T> | Record<string, unknown>;
  readonly after?: Partial<T> | Record<string, unknown>;
  readonly action: 'update' | 'insert' | 'delete' | 'noop';
}

export interface MigrationPreviewReport {
  readonly migrationId: string;
  readonly targetVersion: number;
  readonly totalRecords: number;
  readonly affectedCount: number;
  readonly unchangedCount: number;
  readonly sampleDiffs: readonly MigrationDiff[];
  readonly riskLevel: MigrationRiskLevel;
  readonly rollbackNotes: string;
  readonly forwardFixNotes: string;
  readonly estimatedDurationMs: number;
}

export interface PostMigrationCheckResult {
  readonly checkName: string;
  readonly passed: boolean;
  readonly message?: string;
  readonly violatingRecordIds?: readonly string[];
}

export interface PostMigrationCheck<T> {
  readonly name: string;
  readonly description: string;
  readonly validate: (
    records: readonly T[],
    context?: MigrationContext
  ) => PostMigrationCheckResult | Promise<PostMigrationCheckResult>;
}

export interface MigrationContext {
  readonly dryRun?: boolean;
  readonly batchSize?: number;
  readonly autoRollbackOnFailure?: boolean;
  readonly now?: Date;
  readonly customParams?: Record<string, unknown>;
}

export interface MigrationDefinition<TInput, TOutput = TInput> {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly fromVersion: number;
  readonly toVersion: number;
  readonly riskLevel: MigrationRiskLevel;
  readonly rollbackNotes: string;
  readonly forwardFixNotes: string;

  /** Previews affected records, differences, and risk without mutating source data */
  readonly dryRun: (
    records: readonly TInput[],
    context?: MigrationContext
  ) => MigrationPreviewReport;

  /** Applies forward migration transformation */
  readonly apply: (
    records: readonly TInput[],
    context?: MigrationContext
  ) => { transformed: TOutput[]; affectedCount: number };

  /** Optional reverse migration handler to rollback changes */
  readonly rollback?: (
    records: readonly TOutput[],
    context?: MigrationContext
  ) => { transformed: TInput[]; affectedCount: number };

  /** Post-migration invariant checks that must all pass */
  readonly postChecks: readonly PostMigrationCheck<TOutput>[];

  /** Optional checks executed after rollback to verify successful state restoration */
  readonly rollbackChecks?: readonly RollbackVerificationCheck<TInput>[];
}

export interface RollbackVerificationCheck<T = unknown> {
  readonly name: string;
  readonly description: string;
  readonly validate: (
    restoredRecords: readonly T[],
    preMigrationRecords?: readonly unknown[],
    context?: MigrationContext
  ) => PostMigrationCheckResult | Promise<PostMigrationCheckResult>;
}

export interface RollbackVerificationReport {
  readonly verified: boolean;
  readonly status: 'verified' | 'verification_failed' | 'unverified';
  readonly checkResults: readonly PostMigrationCheckResult[];
  readonly discrepancies?: readonly string[];
  readonly restoredRecordCount: number;
  readonly verificationDurationMs: number;
  readonly recoveryGuidance?: string;
}

export interface DeploymentRollbackConfig {
  readonly deploymentId: string;
  readonly targetVersion: string;
  readonly previousVersion: string;
  readonly healthEndpointCheck?: () => Promise<boolean>;
  readonly schemaVersionCheck?: () => Promise<string>;
  readonly invariants?: readonly { name: string; check: () => Promise<boolean> }[];
}

export interface DeploymentRollbackReport {
  readonly deploymentId: string;
  readonly success: boolean;
  readonly verified: boolean;
  readonly previousVersionRestored: boolean;
  readonly healthCheckPassed: boolean;
  readonly invariantResults: readonly { name: string; passed: boolean }[];
  readonly discrepancies?: readonly string[];
  readonly recoveryNotes: string;
  readonly timestamp: Date;
}

export interface MigrationExecutionReport<TOutput = unknown> {
  readonly migrationId: string;
  readonly success: boolean;
  readonly status: 'applied' | 'dry_run' | 'rolled_back' | 'failed' | 'rollback_verification_failed';
  readonly totalRecords: number;
  readonly affectedRecords: number;
  readonly postCheckResults: readonly PostMigrationCheckResult[];
  readonly errors?: readonly string[];
  readonly durationMs: number;
  readonly rollbackExecuted?: boolean;
  readonly rollbackVerification?: RollbackVerificationReport;
  readonly rollbackNotes: string;
  readonly forwardFixNotes: string;
  readonly outputRecords?: readonly TOutput[];
  readonly rollbackOutputRecords?: readonly unknown[];
}

