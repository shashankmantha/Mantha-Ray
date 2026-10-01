

export type JsonObject = Record<string, unknown>;

export type StageName =
  | "inventory"
  | "clamav"
  | "capa"
  | "floss"
  | "report";

export type StageStatus =
  | "waiting"
  | "running"
  | "completed"
  | "incomplete"
  | "unavailable"
  | "error"
  | "cancelled";

export interface ScanEvent {
  time: string;
  message: string;
}

export type ArtifactRisk =
  | "high"
  | "medium"
  | "low"
  | "clean"
  | "unknown";

export type CoverageStatus =
  | "completed"
  | "finding"
  | "incomplete"
  | "unavailable"
  | "not-applicable"
  | "error";

export type AnalyzerName =
  | "clamav"
  | "capa"
  | "floss";

export type ArtifactRiskSource =
  | AnalyzerName
  | "inventory"
  | "coverage"
  | "all-tools"
  | "child"
  | null;

export interface ArtifactRecord {
  relative_path: string;
  kind: string;
  detected_type: string | null;
  routing_class: string | null;
  state: string | null;
  mode: string | null;
  size_bytes: number | null;
  sha256: string | null;
  review_flags: number;
  error: string | null;
}

export interface ArtifactDisplay {
  artifact: ArtifactRecord;
  risk: ArtifactRisk;
  riskSource: ArtifactRiskSource;
  coverage: Record<AnalyzerName, CoverageStatus>;
  capaResult: JsonObject | null;
}

export interface ArtifactTreeNode {
  name: string;
  path: string;
  directory: boolean;
  children: Map<string, ArtifactTreeNode>;
  artifact: ArtifactDisplay | null;
  fileCount: number;
  risk: ArtifactRisk;
  riskSource: ArtifactRiskSource;
}

export interface ScanResult {
  case_id: string;
  status: string;
  case_directory: string;
  report_path: string;
  report: JsonObject;
  report_markdown: string;
  artifacts?: ArtifactRecord[];
}

export interface ScanState {
  scan_id: string;
  state: string;
  message: string;
  events: ScanEvent[];
  stages?: Partial<Record<StageName, StageStatus>>;
  result: ScanResult | null;
  error: string | null;
}

export interface CaseHistoryEntry {
  case_id: string;
  status: string;
  created_at: string;
  source_directory: string | null;
  label: string;
}

export interface CaseHistoryResponse {
  cases: CaseHistoryEntry[];
  truncated: boolean;
}

export interface ScanSession {
  id: string;
  label: string;
  sourcePath: string;
  startedAt: Date;
  state: ScanState;
  historical: boolean;
  loaded: boolean;
  caseId: string | null;
  resultsDirectory: string;
  persistedStatus: string | null;
}