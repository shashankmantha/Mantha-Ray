export type JsonObject = Record<string, unknown>;

export type StageName =
  | "inventory"
  | "clamav"
  | "yara"
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
  | "yara"
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
  yaraResult: JsonObject | null;
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

export interface QueueItem {
  position: number;
  path: string;
  size: string;
  copies: number;
  mode: string;
  status: string;
  detail: string;
}

export interface StageQueue {
  total: number;
  items: Array<QueueItem | null>;
}

export interface ScanState {
  scan_id: string;
  state: string;
  message: string;
  events: ScanEvent[];
  queues?: Record<string, StageQueue>;
  stages?: Partial<Record<StageName, StageStatus>>;
  result: ScanResult | null;
  error: string | null;
  resource_profile?: ResourceProfileSummary | null;
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

export type ResourceValues = Record<string, number>;

export interface ResourceFieldSpec {
  label: string;
  kind: "int" | "cpus";
  minimum: number;
  maximum: number;
}

export interface ResourceCatalog {
  schema_version: number;
  default: string;
  presets: Record<string, ResourceValues>;
  fields: Record<string, ResourceFieldSpec>;
  host_timeout_margin_seconds: number;
}

export interface DockerCapacity {
  cpus: number;
  memory_bytes: number;
}

export interface ResourceOptions {
  catalog: ResourceCatalog;
  capacity: DockerCapacity | null;
}

export interface ResourceProfileSummary {
  name: string;
  base: string;
  values: ResourceValues;
  changed: ResourceValues;
}

export interface ResourceSelection {
  resource_profile?: string;
  resource_overrides?: ResourceValues | null;
}

export interface ResourceProblem {
  field: string | null;
  message: string;
}

export interface ResourceValidation {
  ok: boolean;
  profile: ResourceProfileSummary | null;
  problems: ResourceProblem[];
  warnings: string[];
}