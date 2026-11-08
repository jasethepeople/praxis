import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import skillContractSchema from "../schemas/skill-contract-v1.json";
import type { RiskTier, SkillContract, SkillStep } from "./types";
import { canonicalJson } from "./canonical";

const skillIdPattern = /^skill_[0-9A-HJKMNP-TV-Z]{26}$/;
const sha256Pattern = /^sha256:[0-9a-f]{64}$/i;
const modelShaPattern = /^[0-9a-f]{40}$/i;
const evidenceSources = new Set(["openalex", "crossref", "unpaywall", "arxiv", "github", "nvd", "exploit_db", "annas_metadata", "local"]);
const evidenceAccess = new Set(["oa_pdf", "preprint", "abstract_only", "metadata_only", "no_access", "local"]);
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);
const validateSchema = ajv.compile(skillContractSchema);


export interface ToolPolicy {
  risk_tier: RiskTier;
  enabled: boolean;
}

export interface WorkflowLint {
  valid: boolean;
  riskTier: RiskTier;
  errors: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function string(value: unknown, min = 1, max = 4096): value is string {
  return typeof value === "string" && value.length >= min && value.length <= max;
}

function strings(value: unknown, maxItems = 128): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => string(item, 1, 1000));
}

function validateValueComplexity(value: unknown, maxDepth = 32, maxNodes = 20_000, maxStringChars = 65_536): string | undefined {
  let nodes = 0;
  const visit = (item: unknown, depth: number): boolean => {
    nodes++;
    if (nodes > maxNodes || depth > maxDepth) return false;
    if (Array.isArray(item)) return item.every((child) => visit(child, depth + 1));
    if (isRecord(item)) return Object.entries(item).every(([key, child]) => key.length <= 1024 && visit(child, depth + 1));
    return typeof item !== "string" || item.length <= maxStringChars;
  };
  return visit(value, 0) ? undefined : "contract exceeds structural complexity limits";
}


export function validateInputComplexity(value: unknown, maxStringLength = 1_048_576): boolean {
  const maxNodes = 20_000;
  const maxDepth = 32;
  let nodes = 0;
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > maxNodes || depth > maxDepth) return false;
    if (Array.isArray(item)) return item.every((child) => visit(child, depth + 1));
    if (isRecord(item)) return Object.entries(item).every(([key, child]) => key.length <= 1024 && visit(child, depth + 1));
    return typeof item !== "string" || item.length <= maxStringLength;
  };
  return visit(value, 0);
}

export function validateContract(value: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!isRecord(value)) return { valid: false, errors: ["contract must be an object"] };
  if (!validateSchema(value)) errors.push(...(validateSchema.errors ?? []).map((error) => `${error.instancePath || "/"} ${error.message ?? "is invalid"}`));
  const complexity = validateValueComplexity(value);
  if (complexity) errors.push(complexity);
  const v = value;
  if (typeof v.id !== "string" || !skillIdPattern.test(v.id)) errors.push("id must be a prefixed ULID");
  if (v.schema_version !== "skill-contract-v1") errors.push("schema_version must be skill-contract-v1");
  if (!new Set(["draft", "validated", "canonical", "deprecated", "quarantined"]).has(String(v.agentbook_state))) errors.push("agentbook_state is invalid");
  if (![0, 1, 2].includes(Number(v.risk_tier))) errors.push("risk_tier must be 0, 1, or 2");
  if (!string(v.domain, 1, 120)) errors.push("domain must be a non-empty string of at most 120 characters");
  if (!string(v.name, 1, 120)) errors.push("name must be a non-empty string of at most 120 characters");
  if (!string(v.description, 1, 2000)) errors.push("description must be a non-empty string of at most 2000 characters");

  if (!isRecord(v.trigger)) errors.push("trigger must be an object");
  else {
    if (!string(v.trigger.description, 1, 1000)) errors.push("trigger.description is required");
    if (!strings(v.trigger.lexical_hints, 64)) errors.push("trigger.lexical_hints must be an array of at most 64 strings");
    if (v.trigger.embedding !== undefined) {
      const e = v.trigger.embedding;
      if (!isRecord(e) || !string(e.model, 1, 200) || typeof e.model_sha !== "string" || !modelShaPattern.test(e.model_sha) || !Number.isInteger(e.dims) || Number(e.dims) < 1 || Number(e.dims) > 8192 || (e.vector !== undefined && (!Array.isArray(e.vector) || e.vector.length !== e.dims || !e.vector.every((n) => typeof n === "number" && Number.isFinite(n))))) errors.push("trigger.embedding is invalid");
    }
  }

  if (!Array.isArray(v.workflow) || v.workflow.length < 1 || v.workflow.length > 64 || !v.workflow.every((step) => isRecord(step) && string(step.tool_id, 1, 160) && string(step.action, 1, 2000) && (step.failure_policy === undefined || string(step.failure_policy, 1, 1000)) && (step.input === undefined || isRecord(step.input)))) errors.push("workflow must contain 1–64 valid steps");
  if (!strings(v.constraints, 128)) errors.push("constraints must be an array of strings");
  if (!strings(v.forbidden_actions, 128)) errors.push("forbidden_actions must be an array of strings");
  if (!isRecord(v.output_spec)) errors.push("output_spec must be an object");
  else {
    if (!Array.isArray(v.output_spec.assertions ?? [])) errors.push("output_spec.assertions must be an array");
    if (!Array.isArray(v.output_spec.required_artifacts ?? [])) errors.push("output_spec.required_artifacts must be an array");
    if (v.output_spec.schema !== undefined && !isRecord(v.output_spec.schema)) errors.push("output_spec.schema must be an object");
    else if (isRecord(v.output_spec.schema)) validateOutputSchema(v.output_spec.schema, errors);
  }

  if (!isRecord(v.provenance)) errors.push("provenance must be an object");
  else {
    if (!Array.isArray(v.provenance.trajectory_hashes) || !v.provenance.trajectory_hashes.every((x) => typeof x === "string" && sha256Pattern.test(x))) errors.push("provenance.trajectory_hashes must contain sha256 hashes");
    if (typeof v.provenance.extraction_model_sha !== "string" || !modelShaPattern.test(v.provenance.extraction_model_sha)) errors.push("provenance.extraction_model_sha must be a 40-character SHA");
    if (!string(v.provenance.sanitizer_version, 1, 100)) errors.push("provenance.sanitizer_version is required");
    if (!Array.isArray(v.provenance.evidence_refs) || v.provenance.evidence_refs.length > 256) errors.push("provenance.evidence_refs must be an array");
    else for (const [index, ref] of v.provenance.evidence_refs.entries()) {
      if (!isRecord(ref) || typeof ref.source !== "string" || !evidenceSources.has(ref.source) || typeof ref.access !== "string" || !evidenceAccess.has(ref.access) || (ref.doi !== undefined && !string(ref.doi, 3, 300)) || (ref.retrieved_at !== undefined && !string(ref.retrieved_at, 1, 100))) errors.push(`provenance.evidence_refs[${index}] is invalid`);
    }
    if (!strings(v.provenance.eval_suites, 128) || !strings(v.provenance.human_approvers, 32)) errors.push("provenance eval_suites and human_approvers must be arrays of strings");
  }
  if (v.supersedes !== undefined && (typeof v.supersedes !== "string" || !skillIdPattern.test(v.supersedes))) errors.push("supersedes must be a skill id");
  if (v.molts_event_hash !== undefined && (typeof v.molts_event_hash !== "string" || !sha256Pattern.test(v.molts_event_hash))) errors.push("molts_event_hash must be a sha256 hash");
  return { valid: errors.length === 0, errors };
}

const dangerousAction = /\b(?:eval|exec|dynamic code|download and run|fetch and execute|curl\s+[^\n]{0,120}\|\s*(?:sh|bash)|wget\s+[^\n]{0,120}\|\s*(?:sh|bash))\b/i;
const protectedTarget = /(?:foundry(?:\/|\b)|molt(?:s)?[ _-]?ledger|praxis[ _-]?(?:bank|db|store)|\.git(?:\/|\b)|credentials?|private key)/i;

export function lintWorkflow(workflow: SkillStep[], tools: Map<string, ToolPolicy>, forbidden: string[] = []): WorkflowLint {
  const errors: string[] = [];
  let riskTier: RiskTier = 0;
  for (const [i, step] of workflow.entries()) {
    const policy = tools.get(step.tool_id);
    if (!policy || !policy.enabled) errors.push(`workflow[${i}] uses an unknown or disabled tool: ${step.tool_id}`);
    else riskTier = Math.max(riskTier, policy.risk_tier) as RiskTier;
    if (dangerousAction.test(step.action)) errors.push(`workflow[${i}] contains dynamic code execution or code-fetching behavior`);
    if (protectedTarget.test(`${step.action} ${JSON.stringify(step.input ?? {})}`)) errors.push(`workflow[${i}] targets protected system state`);
    for (const phrase of forbidden) if (phrase && `${step.action} ${JSON.stringify(step.input ?? {})}`.toLowerCase().includes(phrase.toLowerCase())) errors.push(`workflow[${i}] matches forbidden action: ${phrase}`);
  }
  return { valid: errors.length === 0, riskTier, errors: [...new Set(errors)] };
}

function getPath(root: unknown, path: string): unknown {
  if (path === "$" || path === "") return root;
  return path.replace(/^\$\.?/, "").split(".").filter(Boolean).reduce<unknown>((value, key) => {
    if (Array.isArray(value) && /^\d+$/.test(key)) return value[Number(key)];
    return isRecord(value) && Object.hasOwn(value, key) ? value[key] : undefined;
  }, root);
}

const outputSchemaKeywords = new Set(["type", "properties", "required", "additionalProperties", "items", "enum", "const", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "minProperties", "maxProperties", "uniqueItems"]);

function validateOutputSchema(schema: Record<string, unknown>, errors: string[], path = "output_spec.schema", depth = 0): void {
  if (depth > 16) { errors.push(`${path} exceeds schema depth limits`); return; }
  if (!Object.keys(schema).length) { errors.push(`${path} must constrain output`); return; }
  for (const keyword of Object.keys(schema)) if (!outputSchemaKeywords.has(keyword)) errors.push(`${path}.${keyword} is not a supported output-schema keyword`);
  const type = schema.type;
  const types = new Set(["object", "array", "string", "number", "integer", "boolean", "null"]);
  if (type !== undefined && (typeof type !== "string" || !types.has(type))) errors.push(`${path}.type is unsupported`);
  const objectKeywords = ["properties", "required", "additionalProperties", "minProperties", "maxProperties"];
  const arrayKeywords = ["items", "minItems", "maxItems", "uniqueItems"];
  if (objectKeywords.some((key) => Object.hasOwn(schema, key)) && type !== "object") errors.push(`${path} requires type=object for object keywords`);
  if (arrayKeywords.some((key) => Object.hasOwn(schema, key)) && type !== "array") errors.push(`${path} requires type=array for array keywords`);
  if (schema.properties !== undefined) {
    if (!isRecord(schema.properties) || Object.keys(schema.properties).length > 128) errors.push(`${path}.properties must contain at most 128 schemas`);
    else for (const [key, child] of Object.entries(schema.properties)) {
      if (!key || key.length > 256 || !isRecord(child)) errors.push(`${path}.properties contains an invalid schema`);
      else validateOutputSchema(child, errors, `${path}.properties.${key}`, depth + 1);
    }
  }
  if (schema.items !== undefined) {
    if (!isRecord(schema.items)) errors.push(`${path}.items must be a schema object`);
    else validateOutputSchema(schema.items, errors, `${path}.items`, depth + 1);
  }
  if (schema.required !== undefined && (!Array.isArray(schema.required) || schema.required.length > 128 || !schema.required.every((key) => typeof key === "string" && key.length <= 256) || new Set(schema.required).size !== schema.required.length)) errors.push(`${path}.required must contain unique property names`);
  if (schema.enum !== undefined && (!Array.isArray(schema.enum) || schema.enum.length < 1 || schema.enum.length > 128)) errors.push(`${path}.enum must contain 1–128 values`);
  if (schema.additionalProperties !== undefined && typeof schema.additionalProperties !== "boolean") errors.push(`${path}.additionalProperties must be boolean`);
  for (const [minKey, maxKey, limit] of [["minLength", "maxLength", 65_536], ["minItems", "maxItems", 8192], ["minProperties", "maxProperties", 8192]] as const) {
    const min = schema[minKey];
    const max = schema[maxKey];
    if (min !== undefined && (!Number.isInteger(min) || Number(min) < 0 || Number(min) > limit)) errors.push(`${path}.${minKey} is out of range`);
    if (max !== undefined && (!Number.isInteger(max) || Number(max) < 0 || Number(max) > limit)) errors.push(`${path}.${maxKey} is out of range`);
    if (typeof min === "number" && typeof max === "number" && min > max) errors.push(`${path} has inconsistent ${minKey}/${maxKey}`);
  }
  for (const key of ["minimum", "maximum"]) if (schema[key] !== undefined && (typeof schema[key] !== "number" || !Number.isFinite(schema[key]))) errors.push(`${path}.${key} must be finite`);
  if (typeof schema.minimum === "number" && typeof schema.maximum === "number" && schema.minimum > schema.maximum) errors.push(`${path} has inconsistent minimum/maximum`);
  if (schema.uniqueItems !== undefined && typeof schema.uniqueItems !== "boolean") errors.push(`${path}.uniqueItems must be boolean`);
}

function sameJson(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function validateJsonShape(schema: Record<string, unknown>, value: unknown, path = "$", errors: string[] = [], depth = 0, budget = { nodes: 0 }): string[] {
  if (++budget.nodes > 20_000 || depth > 32) {
    errors.push(`${path} exceeds output complexity limits`);
    return errors;
  }
  const type = schema.type;
  const actual = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
  if (typeof type === "string" && type !== actual && !(type === "integer" && typeof value === "number" && Number.isInteger(value))) {
    errors.push(`${path} must be ${type}`);
    return errors;
  }
  if (Object.hasOwn(schema, "const") && !sameJson(schema.const, value)) errors.push(`${path} does not match the required constant`);
  if (Array.isArray(schema.enum) && !schema.enum.some((item) => sameJson(item, value))) errors.push(`${path} is not an allowed value`);
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) errors.push(`${path} is too short`);
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) errors.push(`${path} is too long`);
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) errors.push(`${path} is below minimum`);
    if (typeof schema.maximum === "number" && value > schema.maximum) errors.push(`${path} is above maximum`);
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) errors.push(`${path} has too few items`);
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) errors.push(`${path} has too many items`);
    if (schema.uniqueItems === true && new Set(value.map((item) => canonicalJson(item))).size !== value.length) errors.push(`${path} contains duplicate items`);
    if (isRecord(schema.items)) value.forEach((item, index) => validateJsonShape(schema.items as Record<string, unknown>, item, `${path}[${index}]`, errors, depth + 1, budget));
  }
  if (isRecord(value)) {
    const required = Array.isArray(schema.required) ? schema.required.filter((item): item is string => typeof item === "string") : [];
    for (const key of required) if (!Object.hasOwn(value, key)) errors.push(`${path}.${key} is required`);
    if (typeof schema.minProperties === "number" && Object.keys(value).length < schema.minProperties) errors.push(`${path} has too few properties`);
    if (typeof schema.maxProperties === "number" && Object.keys(value).length > schema.maxProperties) errors.push(`${path} has too many properties`);
    const properties = isRecord(schema.properties) ? schema.properties : {};
    for (const [key, propSchema] of Object.entries(properties)) if (Object.hasOwn(value, key) && isRecord(propSchema)) validateJsonShape(propSchema, value[key], `${path}.${key}`, errors, depth + 1, budget);
    if (schema.additionalProperties === false) for (const key of Object.keys(value)) if (!Object.hasOwn(properties, key)) errors.push(`${path}.${key} is not allowed`);
  }
  return errors;
}

export function verifyOutputSpec(spec: Record<string, unknown>, output: unknown, artifacts: string[] = []): { passed: boolean; checks_passed: number; checks_total: number; errors: string[] } {
  const errors: string[] = [];
  let total = 0;
  let passed = 0;
  if (isRecord(spec.schema)) {
    total++;
    const schemaErrors = validateJsonShape(spec.schema, output);
    errors.push(...schemaErrors);
    if (!schemaErrors.length) passed++;
  }
  const assertions = Array.isArray(spec.assertions) ? spec.assertions : [];
  for (const raw of assertions) {
    total++;
    if (!isRecord(raw) || typeof raw.path !== "string" || typeof raw.op !== "string") {
      errors.push("output_spec contains an invalid assertion");
      continue;
    }
    const actual = getPath(output, raw.path);
    const ok = raw.op === "exists" ? actual !== undefined && actual !== null
      : raw.op === "equals" ? sameJson(actual, raw.expected)
      : raw.op === "contains" ? (typeof actual === "string" && typeof raw.expected === "string" && actual.includes(raw.expected)) || (Array.isArray(actual) && actual.some((x) => sameJson(x, raw.expected)))
      : raw.op === "gte" ? typeof actual === "number" && typeof raw.expected === "number" && actual >= raw.expected
      : raw.op === "lte" ? typeof actual === "number" && typeof raw.expected === "number" && actual <= raw.expected
      : false;
    if (ok) passed++;
    else errors.push(`assertion failed: ${raw.path} ${raw.op}`);
  }
  const required = Array.isArray(spec.required_artifacts) ? spec.required_artifacts.filter((x): x is string => typeof x === "string") : [];
  for (const item of required) {
    total++;
    if (artifacts.includes(item)) passed++;
    else errors.push(`required artifact missing: ${item}`);
  }
  return { passed: errors.length === 0, checks_passed: passed, checks_total: total, errors };
}
