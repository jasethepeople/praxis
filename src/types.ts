export type RiskTier = 0 | 1 | 2;
export type ContractState = "draft" | "validated" | "canonical" | "deprecated" | "quarantined";
export type Outcome = "success" | "failure" | "partial" | "blocked" | "unverified";
export type VerificationMethod = "output_spec" | "eval_replay" | "human" | "self_report";

export interface SkillStep {
  tool_id: string;
  action: string;
  failure_policy?: string;
  input?: Record<string, unknown>;
}

export interface SkillContract {
  id: string;
  schema_version: "skill-contract-v1";
  agentbook_state: ContractState;
  risk_tier: RiskTier;
  domain: string;
  name: string;
  description: string;
  trigger: {
    description: string;
    lexical_hints: string[];
    embedding?: { model: string; model_sha: string; dims: number; vector?: number[] };
  };
  workflow: SkillStep[];
  constraints: string[];
  forbidden_actions: string[];
  output_spec: Record<string, unknown>;
  provenance: {
    trajectory_hashes: string[];
    extraction_model_sha: string;
    sanitizer_version: string;
    evidence_refs: Array<Record<string, unknown>>;
    eval_suites: string[];
    human_approvers: string[];
  };
  supersedes?: string;
  molts_event_hash?: string;
}

export interface SignedEvent {
  event_type: string;
  event_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
  signature: string;
  signer?: string;
  prev_hash?: string;
  event_hash?: string;
}

export interface SearchResult {
  skill: SkillContract;
  score: number;
  relevance: number;
  sampled_success: number;
  stats: { alpha: number; beta: number; uses: number; blocked: number; unverified: number };
  retrieval_mode: "hybrid" | "lexical";
}

export interface IntelEvidence {
  source: "openalex" | "crossref" | "unpaywall" | "arxiv" | "github" | "nvd" | "exploit_db" | "annas_metadata" | "local";
  access: "oa_pdf" | "preprint" | "abstract_only" | "metadata_only" | "no_access" | "local";
  title?: string;
  doi?: string;
  url?: string;
  retrieved_at: string;
  metadata: Record<string, unknown>;
}

export interface ToolPolicy {
  tool_id: string;
  risk_tier: RiskTier;
  enabled: boolean;
}
