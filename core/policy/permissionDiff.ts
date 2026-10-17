/**
 * Permission Diff Engine for Role and Policy Changes (#266)
 *
 * Implements pre-flight permission-diff reports, privilege escalation detection,
 * lockout risk identification, and rollback snapshots before role and policy changes.
 */

import type { AuthContext } from "@/core/auth/middleware";
import type { Permission, Role } from "@/core/auth/types";
import { err, ok, type Result } from "@/core/result/result";

export type PermissionDiffSeverity = "low" | "medium" | "high" | "critical";

export interface RolePermissionDiff {
  readonly role: Role;
  readonly addedPermissions: readonly Permission[];
  readonly removedPermissions: readonly Permission[];
  readonly unchangedPermissions: readonly Permission[];
  readonly netChange: number;
  readonly severity: PermissionDiffSeverity;
  readonly isPrivilegeEscalation: boolean;
  readonly isPrivilegeRevocation: boolean;
}

export interface PermissionDiffReport {
  readonly reportId: string;
  readonly generatedAt: string;
  readonly roleDiffs: readonly RolePermissionDiff[];
  readonly overallRiskLevel: PermissionDiffSeverity;
  readonly hasPrivilegeEscalation: boolean;
  readonly hasPrivilegeRevocation: boolean;
  readonly warnings: readonly string[];
  readonly affectedRolesCount: number;
  readonly totalAddedCount: number;
  readonly totalRemovedCount: number;
  readonly rollbackSnapshot: Record<Role, Permission[]>;
  readonly recommendedAction: "proceed" | "proceed_with_caution" | "block";
  readonly executionPlan: {
    readonly allowApply: boolean;
    readonly gatingReasons: readonly string[];
  };
}

export interface PermissionDiffOptions {
  readonly caller?: AuthContext;
  readonly allowCriticalEscalations?: boolean;
  readonly now?: () => number;
  readonly simulateTransientFailures?: number;
}

export type PermissionDiffErrorCode =
  | "unauthorized"
  | "invalid_role_definition"
  | "invalid_permission"
  | "empty_permissions"
  | "critical_escalation_blocked"
  | "diff_retries_exhausted";

const VALID_ROLES = new Set<Role>(["viewer", "maintainer", "service"]);

const VALID_PERMISSIONS = new Set<Permission>([
  "view:tools",
  "view:dashboard",
  "admin:health",
  "admin:recovery",
  "admin:metrics",
  "admin:replay"
]);

const CRITICAL_PERMISSIONS = new Set<Permission>(["admin:recovery", "admin:replay"]);
const HIGH_PERMISSIONS = new Set<Permission>(["admin:health", "admin:metrics"]);

export class PermissionDiffEngine {
  /**
   * Generates a comprehensive permission diff report comparing current vs proposed
   * role-permission mappings.
   *
   * Time Complexity: O(R * P) where R is number of roles and P is permissions.
   * Space Complexity: O(R * P) for the diff structures.
   */
  public static generateDiffReport(
    current: Record<Role, Permission[]>,
    proposed: Record<Role, Permission[]>,
    options?: PermissionDiffOptions
  ): Result<PermissionDiffReport, PermissionDiffErrorCode> {
    // 1. Authorization check
    if (options?.caller && options.caller.role !== "maintainer") {
      return err("unauthorized");
    }

    // 2. Validation of proposed roles and permissions
    if (!proposed || typeof proposed !== "object") {
      return err("invalid_role_definition");
    }

    const proposedRoles = Object.keys(proposed) as Role[];
    if (proposedRoles.length === 0) {
      return err("empty_permissions");
    }

    for (const role of proposedRoles) {
      if (!VALID_ROLES.has(role)) {
        return err("invalid_role_definition");
      }
      const perms = proposed[role];
      if (!Array.isArray(perms)) {
        return err("invalid_role_definition");
      }
      for (const p of perms) {
        if (!VALID_PERMISSIONS.has(p)) {
          return err("invalid_permission");
        }
      }
    }

    const now = options?.now ? options.now() : Date.now();
    const timestamp = new Date(now).toISOString();
    const reportId = `pdiff-${now.toString(16)}-${Math.random().toString(36).slice(2, 8)}`;

    const roleDiffs: RolePermissionDiff[] = [];
    const warnings: string[] = [];
    const gatingReasons: string[] = [];

    let hasPrivilegeEscalation = false;
    let hasPrivilegeRevocation = false;
    let totalAddedCount = 0;
    let totalRemovedCount = 0;

    const allRoles = new Set<Role>([...(Object.keys(current) as Role[]), ...proposedRoles]);

    for (const role of allRoles) {
      const currentPerms = new Set(current[role] || []);
      const proposedPerms = new Set(proposed[role] || []);

      const added = [...proposedPerms].filter((p) => !currentPerms.has(p));
      const removed = [...currentPerms].filter((p) => !proposedPerms.has(p));
      const unchanged = [...currentPerms].filter((p) => proposedPerms.has(p));

      totalAddedCount += added.length;
      totalRemovedCount += removed.length;

      let severity: PermissionDiffSeverity = "low";
      let roleIsEscalation = false;
      let roleIsRevocation = false;

      if (added.length > 0) {
        roleIsEscalation = true;
        hasPrivilegeEscalation = true;

        for (const perm of added) {
          if (CRITICAL_PERMISSIONS.has(perm)) {
            severity = "critical";
            warnings.push(
              `CRITICAL ESCALATION: Role "${role}" granted sensitive permission "${perm}".`
            );
            if (role !== "maintainer") {
              gatingReasons.push(
                `Non-maintainer role "${role}" granted critical administrative permission "${perm}"`
              );
            }
          } else if (HIGH_PERMISSIONS.has(perm) && severity !== "critical") {
            severity = "high";
            warnings.push(`HIGH ESCALATION: Role "${role}" granted administrative permission "${perm}".`);
          } else if (perm.startsWith("view:") && severity === "low") {
            severity = "low";
          } else if (severity === "low") {
            severity = "medium";
          }
        }
      }

      if (removed.length > 0) {
        roleIsRevocation = true;
        hasPrivilegeRevocation = true;

        if (role === "maintainer" && proposedPerms.size === 0) {
          severity = "critical";
          warnings.push(
            `LOCKOUT RISK: Maintainer role permissions completely revoked. No administrator will remain.`
          );
          gatingReasons.push("Lockout risk: Maintainer permissions emptied");
        } else if (role === "maintainer" && removed.some((p) => CRITICAL_PERMISSIONS.has(p))) {
          if (severity !== "critical") severity = "high";
          warnings.push(`Maintainer role stripped of critical permission(s): ${removed.join(", ")}`);
        }
      }

      roleDiffs.push({
        role,
        addedPermissions: added,
        removedPermissions: removed,
        unchangedPermissions: unchanged,
        netChange: added.length - removed.length,
        severity,
        isPrivilegeEscalation: roleIsEscalation,
        isPrivilegeRevocation: roleIsRevocation
      });
    }

    // Overall Risk Calculation
    let overallRiskLevel: PermissionDiffSeverity = "low";
    if (roleDiffs.some((d) => d.severity === "critical") || gatingReasons.length > 0) {
      overallRiskLevel = "critical";
    } else if (roleDiffs.some((d) => d.severity === "high")) {
      overallRiskLevel = "high";
    } else if (roleDiffs.some((d) => d.severity === "medium")) {
      overallRiskLevel = "medium";
    }

    let recommendedAction: "proceed" | "proceed_with_caution" | "block" = "proceed";
    let allowApply = true;

    if (overallRiskLevel === "critical") {
      recommendedAction = "block";
      allowApply = Boolean(options?.allowCriticalEscalations);
    } else if (overallRiskLevel === "high") {
      recommendedAction = "proceed_with_caution";
    }

    const rollbackSnapshot: Record<Role, Permission[]> = {
      viewer: [...(current.viewer || [])],
      maintainer: [...(current.maintainer || [])],
      service: [...(current.service || [])]
    };

    return ok({
      reportId,
      generatedAt: timestamp,
      roleDiffs,
      overallRiskLevel,
      hasPrivilegeEscalation,
      hasPrivilegeRevocation,
      warnings,
      affectedRolesCount: roleDiffs.filter((d) => d.addedPermissions.length > 0 || d.removedPermissions.length > 0).length,
      totalAddedCount,
      totalRemovedCount,
      rollbackSnapshot,
      recommendedAction,
      executionPlan: {
        allowApply,
        gatingReasons
      }
    });
  }

  /**
   * Applies role and policy changes after computing diff report and enforcing risk guardrails.
   */
  public static applyRolePolicyChange(
    current: Record<Role, Permission[]>,
    proposed: Record<Role, Permission[]>,
    options?: PermissionDiffOptions
  ): Result<
    {
      newPermissions: Record<Role, Permission[]>;
      rollbackSnapshot: Record<Role, Permission[]>;
      report: PermissionDiffReport;
    },
    PermissionDiffErrorCode
  > {
    const reportResult = this.generateDiffReport(current, proposed, options);
    if (!reportResult.ok) return reportResult;

    const report = reportResult.value;
    if (!report.executionPlan.allowApply) {
      return err("critical_escalation_blocked");
    }

    const newPermissions: Record<Role, Permission[]> = {
      viewer: proposed.viewer ? [...proposed.viewer] : [...(current.viewer || [])],
      maintainer: proposed.maintainer ? [...proposed.maintainer] : [...(current.maintainer || [])],
      service: proposed.service ? [...proposed.service] : [...(current.service || [])]
    };

    return ok({
      newPermissions,
      rollbackSnapshot: report.rollbackSnapshot,
      report
    });
  }

  /**
   * Retries diff report generation on transient errors.
   */
  public static retryDiffReport(
    fn: () => Result<PermissionDiffReport, PermissionDiffErrorCode>,
    maxRetries = 3
  ): Result<PermissionDiffReport, PermissionDiffErrorCode> {
    let attempts = 0;
    while (attempts <= maxRetries) {
      attempts += 1;
      const res = fn();
      if (res.ok) return res;
      if (attempts > maxRetries) {
        return err("diff_retries_exhausted");
      }
    }
    return err("diff_retries_exhausted");
  }
}
