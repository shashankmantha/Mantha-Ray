// Pure artifact risk and analyzer-coverage calculations.
// This module must not read or mutate the DOM.

import type {
  AnalyzerName,
  ArtifactDisplay,
  ArtifactRecord,
  ArtifactRisk,
  ArtifactRiskSource,
  CoverageStatus,
  JsonObject,
  ScanResult,
} from "./types";

export function objectValue(value: unknown): JsonObject | null {
  if (
    typeof value === "object"
    && value !== null
    && !Array.isArray(value)
  ) {
    return value as JsonObject;
  }
  return null;
}

export function analyzer(
  report: JsonObject,
  name: string,
): JsonObject | null {
  const direct = objectValue(report[name]);
  if (direct) {
    return direct;
  }
  for (const groupName of [
    "analysis",
    "analyses",
    "analyzers",
  ]) {
    const group = objectValue(report[groupName]);
    const match = group ? objectValue(group[name]) : null;
    if (match) {
      return match;
    }
  }
  return null;
}

function analyzerResultMap(
  data: JsonObject | null,
): Map<string, JsonObject> {
  const results = data?.results;
  const mapped = new Map<string, JsonObject>();

  if (!Array.isArray(results)) {
    return mapped;
  }

  for (const value of results) {
    const result = objectValue(value);

    if (
      !result
      || typeof result.relative_path !== "string"
    ) {
      continue;
    }

    mapped.set(
      result.relative_path,
      result,
    );

    if (Array.isArray(result.reused_for)) {
      for (const reusedPath of result.reused_for) {
        if (typeof reusedPath === "string") {
          mapped.set(
            reusedPath,
            result,
          );
        }
      }
    }
  }

  return mapped;
}
function pathMatches(
  candidate: string,
  relativePath: string,
): boolean {
  const normalized = candidate.replaceAll("\\\\", "/");
  return (
    normalized === relativePath
    || normalized.endsWith(`/${relativePath}`)
    || normalized.startsWith(`${relativePath}:`)
    || normalized.includes(`/${relativePath}:`)
  );
}

function clamavHasFinding(
  data: JsonObject | null,
  relativePath: string,
): boolean {
  const findings = data?.findings;
  if (!Array.isArray(findings)) {
    return false;
  }
  for (const finding of findings) {
    if (
      typeof finding === "string"
      && pathMatches(finding, relativePath)
    ) {
      return true;
    }
    const object = objectValue(finding);
    if (!object) {
      continue;
    }
    for (const key of [
      "relative_path",
      "path",
      "file",
      "filename",
    ]) {
      const candidate = object[key];
      if (
        typeof candidate === "string"
        && pathMatches(candidate, relativePath)
      ) {
        return true;
      }
    }
  }
  return false;
}

function analyzerCoverage(
  analyzerData: JsonObject | null,
  fileResult: JsonObject | null,
  eligible: boolean,
): CoverageStatus {
  if (!eligible) {
    return "not-applicable";
  }
  if (!analyzerData) {
    return "unavailable";
  }
  if (analyzerData.status === "not_run") {
    return "unavailable";
  }
  if (analyzerData.status === "error") {
    return "error";
  }
  if (fileResult) {
    if (fileResult.status === "error") {
      return "error";
    }
    return fileResult.complete === true
      ? "completed"
      : "incomplete";
  }
  return analyzerData.complete === true
    ? "incomplete"
    : "incomplete";
}

function coverageHasGap(
  coverage: Record<AnalyzerName, CoverageStatus>,
): boolean {
  return Object.values(coverage).some((status) =>
    status === "incomplete"
    || status === "unavailable"
    || status === "error",
  );
}

function completedCoverageSource(
  coverage: Record<AnalyzerName, CoverageStatus>,
): ArtifactRiskSource {
  const completed = (
    Object.entries(coverage) as Array<
      [AnalyzerName, CoverageStatus]
    >
  ).filter(([, status]) => status === "completed");
  if (completed.length > 1) {
    return "all-tools";
  }
  return completed[0]?.[0] ?? "coverage";
}

function artifactAssessment(
  artifact: ArtifactRecord,
  clamavFinding: boolean,
  capaResult: JsonObject | null,
  coverage: Record<AnalyzerName, CoverageStatus>,
): {
  risk: ArtifactRisk;
  source: ArtifactRiskSource;
} {
  if (clamavFinding) {
    return {
      risk: "high",
      source: "clamav",
    };
  }
  if (
    artifact.error
    || artifact.review_flags > 0
  ) {
    return {
      risk: "medium",
      source: "inventory",
    };
  }
  const risk = objectValue(capaResult?.risk);
  if (risk) {
    const level = typeof risk.level === "string"
      ? risk.level.toLowerCase()
      : "";
    if (
      risk.high_concern === true
      || level.includes("high")
    ) {
      return {
        risk: "high",
        source: "capa",
      };
    }
    if (
      risk.review_required === true
      || level === "medium"
      || level === "review"
    ) {
      return {
        risk: "medium",
        source: "capa",
      };
    }
    if (
      typeof risk.score === "number"
      && risk.score > 0
    ) {
      return {
        risk: "low",
        source: "capa",
      };
    }
  }
  if (
    typeof capaResult?.capability_count === "number"
    && capaResult.capability_count > 0
  ) {
    return {
      risk: "low",
      source: "capa",
    };
  }
  if (coverageHasGap(coverage)) {
    return {
      risk: "unknown",
      source: "coverage",
    };
  }
  return {
    risk: "clean",
    source: completedCoverageSource(coverage),
  };
}

export function artifactDisplayRecords(
  result: ScanResult,
): ArtifactDisplay[] {
  const artifacts = result.artifacts ?? [];
  const report = result.report;
  const clamav = analyzer(report, "clamav");
  const capa = analyzer(report, "capa");
  const floss = analyzer(report, "floss");
  const capaResults = analyzerResultMap(capa);
  const flossResults = analyzerResultMap(floss);
  return artifacts.map((artifact) => {
    const relativePath = artifact.relative_path;
    const capaResult =
      capaResults.get(relativePath) ?? null;
    const flossResult =
      flossResults.get(relativePath) ?? null;
    const hasClamavFinding = clamavHasFinding(
      clamav,
      relativePath,
    );
    const routingClass =
      artifact.routing_class?.toLowerCase() ?? "";
    const regularFile =
      artifact.kind === "regular_file";
    const capaEligible = (
      capaResult !== null
      || ["pe", "elf", "dotnet"].includes(
        routingClass,
      )
    );
    const flossEligible = (
      flossResult !== null
      || ["pe", "dotnet"].includes(
        routingClass,
      )
    );
    let clamavCoverage: CoverageStatus;
    if (!regularFile) {
      clamavCoverage = "not-applicable";
    } else if (hasClamavFinding) {
      clamavCoverage = "finding";
    } else if (!clamav) {
      clamavCoverage = "unavailable";
    } else if (clamav.status === "error") {
      clamavCoverage = "error";
    } else if (clamav.complete === true) {
      clamavCoverage = "completed";
    } else {
      clamavCoverage = "incomplete";
    }
    const coverage: Record<AnalyzerName, CoverageStatus> = {
      clamav: clamavCoverage,
      capa: analyzerCoverage(
        capa,
        capaResult,
        regularFile && capaEligible,
      ),
      floss: analyzerCoverage(
        floss,
        flossResult,
        regularFile && flossEligible,
      ),
    };
    const assessment = artifactAssessment(
      artifact,
      hasClamavFinding,
      capaResult,
      coverage,
    );
    return {
      artifact,
      risk: assessment.risk,
      riskSource: assessment.source,
      coverage,
      capaResult,
    };
  });
}

const riskRanks: Record<ArtifactRisk, number> = {
  unknown: -1,
  clean: 0,
  low: 1,
  medium: 2,
  high: 3,
};

export function highestRisk(
  first: ArtifactRisk,
  second: ArtifactRisk,
): ArtifactRisk {
  return riskRanks[second] > riskRanks[first]
    ? second
    : first;
}