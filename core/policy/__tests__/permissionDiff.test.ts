import { describe, expect, it } from "vitest";
import { type Permission, type Role } from "@/core/auth/types";
import { PermissionDiffEngine } from "../permissionDiff";

describe("Permission-Diff Report Before Role and Policy Changes (#266)", () => {
  const maintainerContext = { role: "maintainer" as const, userId: "admin-ada" };
  const viewerContext = { role: "viewer" as const, userId: "viewer-guest" };

  const basePermissions: Record<Role, Permission[]> = {
    viewer: ["view:tools", "view:dashboard"],
    maintainer: [
      "view:tools",
      "view:dashboard",
      "admin:health",
      "admin:recovery",
      "admin:metrics",
      "admin:replay"
    ],
    service: ["admin:health", "admin:metrics"]
  };

  describe("normal path", () => {
    it("generates a clean diff report for benign permission adjustments", () => {
      const proposed: Record<Role, Permission[]> = {
        ...basePermissions,
        service: ["admin:health", "admin:metrics", "view:tools"]
      };

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, proposed, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const report = result.value;
      expect(report.overallRiskLevel).toBe("low");
      expect(report.totalAddedCount).toBe(1);
      expect(report.totalRemovedCount).toBe(0);
      expect(report.hasPrivilegeEscalation).toBe(true);
      expect(report.hasPrivilegeRevocation).toBe(false);
      expect(report.recommendedAction).toBe("proceed");
      expect(report.executionPlan.allowApply).toBe(true);

      const serviceDiff = report.roleDiffs.find((d) => d.role === "service");
      expect(serviceDiff?.addedPermissions).toEqual(["view:tools"]);
      expect(serviceDiff?.unchangedPermissions).toEqual(["admin:health", "admin:metrics"]);
      expect(serviceDiff?.removedPermissions).toEqual([]);
      expect(serviceDiff?.netChange).toBe(1);
    });

    it("creates rollback snapshot and applies changes successfully", () => {
      const proposed: Record<Role, Permission[]> = {
        ...basePermissions,
        service: ["admin:health"] // Removed admin:metrics
      };

      const result = PermissionDiffEngine.applyRolePolicyChange(basePermissions, proposed, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.newPermissions.service).toEqual(["admin:health"]);
      expect(result.value.rollbackSnapshot.service).toEqual(["admin:health", "admin:metrics"]);
      expect(result.value.report.hasPrivilegeRevocation).toBe(true);
    });

    it("handles zero diff (noop) cleanly", () => {
      const result = PermissionDiffEngine.generateDiffReport(basePermissions, basePermissions, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.value.totalAddedCount).toBe(0);
      expect(result.value.totalRemovedCount).toBe(0);
      expect(result.value.overallRiskLevel).toBe("low");
      expect(result.value.affectedRolesCount).toBe(0);
      expect(result.value.recommendedAction).toBe("proceed");
    });
  });

  describe("risk detection and lockout edge cases", () => {
    it("detects critical privilege escalation when admin permissions granted to viewer", () => {
      const dangerousProposed: Record<Role, Permission[]> = {
        ...basePermissions,
        viewer: ["view:tools", "view:dashboard", "admin:recovery"]
      };

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, dangerousProposed, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const report = result.value;
      expect(report.overallRiskLevel).toBe("critical");
      expect(report.recommendedAction).toBe("block");
      expect(report.executionPlan.allowApply).toBe(false);
      expect(report.warnings.some((w) => w.includes("CRITICAL ESCALATION"))).toBe(true);

      // Verify that applyRolePolicyChange blocks application
      const applyResult = PermissionDiffEngine.applyRolePolicyChange(basePermissions, dangerousProposed, {
        caller: maintainerContext
      });
      expect(applyResult.ok).toBe(false);
      if (!applyResult.ok) {
        expect(applyResult.code).toBe("critical_escalation_blocked");
      }
    });

    it("allows critical escalation only when explicitly allowed with override flag", () => {
      const dangerousProposed: Record<Role, Permission[]> = {
        ...basePermissions,
        viewer: ["view:tools", "view:dashboard", "admin:recovery"]
      };

      const applyResult = PermissionDiffEngine.applyRolePolicyChange(basePermissions, dangerousProposed, {
        caller: maintainerContext,
        allowCriticalEscalations: true
      });

      expect(applyResult.ok).toBe(true);
      if (!applyResult.ok) return;
      expect(applyResult.value.newPermissions.viewer).toContain("admin:recovery");
    });

    it("detects lockout risk when maintainer permissions are completely revoked", () => {
      const lockoutProposed: Record<Role, Permission[]> = {
        ...basePermissions,
        maintainer: []
      };

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, lockoutProposed, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      const report = result.value;
      expect(report.overallRiskLevel).toBe("critical");
      expect(report.recommendedAction).toBe("block");
      expect(report.warnings.some((w) => w.includes("LOCKOUT RISK"))).toBe(true);
      expect(report.executionPlan.gatingReasons).toContain("Lockout risk: Maintainer permissions emptied");
    });
  });

  describe("authorization path", () => {
    it("denies diff generation to non-maintainer caller", () => {
      const proposed = { ...basePermissions };
      const result = PermissionDiffEngine.generateDiffReport(basePermissions, proposed, {
        caller: viewerContext
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("unauthorized");
      }
    });

    it("denies applying changes to non-maintainer caller", () => {
      const proposed = { ...basePermissions };
      const result = PermissionDiffEngine.applyRolePolicyChange(basePermissions, proposed, {
        caller: viewerContext
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("unauthorized");
      }
    });
  });

  describe("failure and retry paths", () => {
    it("rejects unknown role with invalid_role_definition", () => {
      const invalidRoles = {
        ...basePermissions,
        super_admin: ["admin:recovery"]
      } as unknown as Record<Role, Permission[]>;

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, invalidRoles, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("invalid_role_definition");
      }
    });

    it("rejects invalid permission string with invalid_permission", () => {
      const invalidPerms = {
        ...basePermissions,
        viewer: ["view:tools", "admin:super_secret_unreal"]
      } as unknown as Record<Role, Permission[]>;

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, invalidPerms, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("invalid_permission");
      }
    });

    it("rejects empty role mapping with empty_permissions", () => {
      const empty = {} as Record<Role, Permission[]>;

      const result = PermissionDiffEngine.generateDiffReport(basePermissions, empty, {
        caller: maintainerContext
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe("empty_permissions");
      }
    });

    it("retries diff report operation on transient failures", () => {
      let attempts = 0;
      const transientFn = () => {
        attempts += 1;
        if (attempts < 2) {
          return { ok: false as const, code: "invalid_role_definition" as const };
        }
        return PermissionDiffEngine.generateDiffReport(basePermissions, basePermissions, {
          caller: maintainerContext
        });
      };

      const result = PermissionDiffEngine.retryDiffReport(transientFn, 3);
      expect(result.ok).toBe(true);
      expect(attempts).toBe(2);
    });
  });
});
