import { describe, expect, it } from "vitest";
import {
  OperationalDataRetentionManager,
  scrubSensitiveValue,
  type DeletionOptions,
  type RetentionPolicy
} from "../retention";

describe("Operational Data Retention and Deletion (#259)", () => {
  const maintainerActor = { kind: "maintainer" as const, id: "admin-1" };
  const userActor = { kind: "user" as const, id: "user-123" };
  const systemActor = { kind: "system" as const };

  const sampleOperationalRecords = [
    {
      id: "op-1",
      at: "2026-01-01T00:00:00.000Z",
      action: "export.generated",
      details: "exported data for user-123",
      apiKey: "secret-key-value",
      nested: { bearerToken: "Bearer test-token-123" }
    },
    {
      id: "op-2",
      at: "2026-06-01T00:00:00.000Z",
      action: "record.state_changed",
      details: "transition to archived"
    },
    {
      id: "op-3",
      at: "2026-10-15T00:00:00.000Z",
      action: "notification.cleared",
      details: "cleared notifications"
    }
  ];

  describe("normal path", () => {
    it("enforces retention policy by removing records exceeding TTL", async () => {
      const fixedNow = Date.parse("2026-10-17T00:00:00.000Z");
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        ttlMs: 30 * 24 * 60 * 60 * 1000,
        scrubSensitiveFields: true
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "scheduled_retention_sweep",
        now: () => fixedNow
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.totalScanned).toBe(3);
      expect(result.value.retainedCount).toBe(1);
      expect(result.value.deletedCount).toBe(2);
      expect(result.value.retainedRecords[0].id).toBe("op-3");
      expect(result.value.dryRun).toBe(false);
    });

    it("enforces retention cap on maximum records", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 2,
        scrubSensitiveFields: false
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "capacity_cap_enforcement"
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.totalScanned).toBe(3);
      expect(result.value.retainedCount).toBe(2);
      expect(result.value.deletedCount).toBe(1);
      expect(result.value.retainedRecords.map((r) => r.id)).toEqual(["op-2", "op-3"]);
    });

    it("scrubs embedded Stellar secrets and authorization tokens during retention processing", async () => {
      const stellarSecret = "SCZANGBA5YHTNYVVV4C3U252E2B6P6IRKDIOHGZPFGDPGQVC4TUKWGLW";
      const recordWithSecret = {
        id: "op-secret",
        at: "2026-10-16T00:00:00.000Z",
        note: `Generated with seed ${stellarSecret} and auth Bearer abc123def456`,
        token: "raw-token-string"
      };

      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 10,
        scrubSensitiveFields: true
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "scrub_sensitive_operational_data"
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        [recordWithSecret],
        policy,
        options
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.scrubbedFieldsCount).toBe(1);
      const scrubbedRecord = result.value.retainedRecords[0] as typeof recordWithSecret;
      expect(scrubbedRecord.note).not.toContain(stellarSecret);
      expect(scrubbedRecord.note).toContain("[REDACTED]");
      expect(scrubbedRecord.token).toBe("[REDACTED]");
    });

    it("supports dryRun preview without deleting records", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 1
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "dry_run_retention_audit",
        dryRun: true
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.dryRun).toBe(true);
      expect(result.value.retainedCount).toBe(3);
      expect(result.value.deletedCount).toBe(2);
      expect(result.value.retainedRecords).toHaveLength(3);
    });

    it("permanently purges sensitive records matching predicate", () => {
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "targeted_sensitive_purge"
      };

      const purgeResult = OperationalDataRetentionManager.purgeSensitiveOperationalData(
        sampleOperationalRecords,
        (rec) => rec.action === "export.generated",
        options
      );

      expect(purgeResult.ok).toBe(true);
      if (!purgeResult.ok) return;

      expect(purgeResult.value.purgedCount).toBe(1);
      expect(purgeResult.value.remainingRecords).toHaveLength(2);
      expect(purgeResult.value.remainingRecords.some((r) => r.action === "export.generated")).toBe(false);
    });
  });

  describe("authorization path", () => {
    it("denies retention enforcement to standard user actors", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 10
      };
      const options: DeletionOptions = {
        actor: userActor,
        reason: "unauthorized_retention_attempt"
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("retention_denied");
      }
    });

    it("denies targeted purge to standard user actors", () => {
      const options: DeletionOptions = {
        actor: userActor,
        reason: "unauthorized_purge_attempt"
      };

      const result = OperationalDataRetentionManager.purgeSensitiveOperationalData(
        sampleOperationalRecords,
        () => true,
        options
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("retention_denied");
      }
    });

    it("allows system actor to perform retention sweeps", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 5
      };
      const options: DeletionOptions = {
        actor: systemActor,
        reason: "automated_cron_retention"
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(true);
    });
  });

  describe("failure and retry paths", () => {
    it("validates policy input and returns invalid_policy on empty record kind", async () => {
      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        { recordKind: "" },
        { actor: maintainerActor, reason: "check" }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("invalid_policy");
      }
    });

    it("validates deletion options and returns invalid_deletion_request on empty reason", async () => {
      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        { recordKind: "audit" },
        { actor: maintainerActor, reason: "   " }
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("invalid_deletion_request");
      }
    });

    it("recovers on retry when transient storage error occurs", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 10
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "retry_test",
        maxRetries: 3,
        simulateTransientFailures: 2,
        retryBackoffMs: 5
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(true);
    });

    it("exhausts retries and returns retention_retries_exhausted if errors persist", async () => {
      const policy: RetentionPolicy = {
        recordKind: "operational_log",
        maxRecords: 10
      };
      const options: DeletionOptions = {
        actor: maintainerActor,
        reason: "exhaust_retry_test",
        maxRetries: 1,
        simulateTransientFailures: 5,
        retryBackoffMs: 5
      };

      const result = await OperationalDataRetentionManager.enforceRetention(
        sampleOperationalRecords,
        policy,
        options
      );

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("retention_retries_exhausted");
      }
    });
  });

  describe("scrubSensitiveValue unit test", () => {
    it("scrubs deeply nested secrets in objects and arrays", () => {
      const input = {
        name: "test",
        auth: "bearer 123",
        credentials: "my-credentials",
        meta: {
          privateKey: "some-key",
          details: ["hello", "seed SBW... Bearer token-xyz"]
        }
      };

      const { scrubbed, modified } = scrubSensitiveValue(input);
      expect(modified).toBe(true);
      const res = scrubbed as typeof input;
      expect(res.auth).toBe("[REDACTED]");
      expect(res.credentials).toBe("[REDACTED]");
      expect(res.meta.privateKey).toBe("[REDACTED]");
    });
  });
});

