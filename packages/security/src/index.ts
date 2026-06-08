import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join as joinPath, relative as relativePath } from "node:path";
import { spawnSync } from "node:child_process";
import { newId, nowIso, type FindingSeverity, type SecurityAsset, type SecurityAuthContext, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityPhase, type SecurityTechnology, type SecurityToolFailureCategory, type SecurityToolRun, type SecurityToolRunStatus, type SecurityValidationAttempt, type SecurityValidationCheck, type SecurityWorkflow, type SecurityWorkflowTask, type SubAgentRecord, type SubAgentRole, type TargetInput } from "@aegisprobe/shared";
import type { SkillDefinition, SkillRegistry } from "@aegisprobe/skills";

// ── Types ──
import type { SecurityWorkflowPlan, SkillExecutionPlan, PentestIntensity, PentestScanProfile, PentestScope, SecurityToolCapability, SecurityToolAdapter, SecurityToolInventoryItem, SecurityToolDiscovery, SecurityToolHealth, PentestPipelineStep, PentestPipeline, NormalizedSecurityObservation, SecurityToolOutputClassification, SecurityAssetGraphNode, SecurityAssetGraphEdge, SecurityAssetGraph, SecurityDecisionQueueItem, SecurityDecisionQueue, SecurityDecisionSupervision, SecurityObjectiveId, SecurityObjectiveStatus, SecurityObjectiveAssessment, SecurityAttackPathStage, SecurityAttackPathModel, SecurityObjectiveModel, BusinessWorkflowCategory, BusinessWorkflowGraphNode, BusinessWorkflowGraphEdge, BusinessWorkflowGraph, ValidationClosureCandidate, ValidationClosurePlan, BrowserInteractionPlan, AuthorizedValidationStepKind, AuthorizedValidationStep, AuthorizedValidationPlaybook, SubAgentOperatingModel, SecurityClosureModel, CveReconciliationPlan, SubAgentCoordinationPlanItem, SubAgentCoordinationPlan, AdaptiveSecurityAction, OwaspValidationItem, SecurityReportFinding, NucleiTemplateKnowledge, SecurityKnowledgeIndex, FrameworkKnowledgeProfile, FrameworkKnowledgeIndex, BusinessLogicKnowledgeItem, BusinessLogicTestCase, BusinessLogicTestPlan, SecurityKnowledgeSyncResult, SecurityKnowledgeSearchResult, FrameworkKnowledgeSeed, LocalAdvisoryRule, PayloadCandidate, PayloadCandidateSet, PayloadCandidateRisk, PayloadInsertionHint, PayloadDraftExecutionGate, PayloadRequestDraft, PayloadRequestDraftSet, AccessExposureState, AccessExposureItem, AccessExposureMap } from "./types.js";
export type { SecurityWorkflowPlan, SkillExecutionPlan, PentestIntensity, PentestScanProfile, PentestScope, SecurityToolCapability, SecurityToolAdapter, SecurityToolDiscovery, SecurityToolInventoryItem, SecurityToolHealth, PentestPipelineStep, PentestPipeline, NormalizedSecurityObservation, SecurityToolOutputClassification, SecurityAssetGraphNode, SecurityAssetGraphEdge, SecurityAssetGraph, SecurityDecisionQueueItem, SecurityDecisionQueue, SecurityDecisionSupervision, SecurityObjectiveId, SecurityObjectiveStatus, SecurityObjectiveAssessment, SecurityAttackPathStage, SecurityAttackPathModel, SecurityObjectiveModel, BusinessWorkflowCategory, BusinessWorkflowGraphNode, BusinessWorkflowGraphEdge, BusinessWorkflowGraph, ValidationClosureCandidate, ValidationClosurePlan, BrowserInteractionPlan, AuthorizedValidationStepKind, AuthorizedValidationStep, AuthorizedValidationPlaybook, SubAgentOperatingModel, SecurityClosureModel, CveReconciliationPlan, SubAgentCoordinationPlanItem, SubAgentCoordinationPlan, AdaptiveSecurityAction, OwaspValidationItem, SecurityReportFinding, NucleiTemplateKnowledge, SecurityKnowledgeIndex, FrameworkKnowledgeProfile, FrameworkKnowledgeIndex, BusinessLogicKnowledgeItem, BusinessLogicTestCase, BusinessLogicTestPlan, SecurityKnowledgeSyncResult, SecurityKnowledgeSearchResult, FrameworkKnowledgeSeed, LocalAdvisoryRule, PayloadCandidate, PayloadCandidateSet, PayloadCandidateRisk, PayloadInsertionHint, PayloadDraftExecutionGate, PayloadRequestDraft, PayloadRequestDraftSet, AccessExposureState, AccessExposureItem, AccessExposureMap } from "./types.js";

// ── Knowledge Base ──
export { securityKnowledgeRoot, nucleiTemplatesRoot, wappalyzerRoot, wappalyzerTechnologiesRoot, securityKnowledgeIndexPath, frameworkKnowledgeIndexPath, businessLogicKnowledgePath, syncSecurityKnowledge, loadSecurityKnowledgeIndex, loadFrameworkKnowledgeIndex, loadBusinessLogicKnowledge, searchSecurityKnowledge, buildNucleiKnowledgeIndex, buildFrameworkKnowledgeIndex, buildBusinessLogicKnowledgeBase } from "./knowledge-base.js";

// ── Adapters ──
export { shellQuote, executableName, localToolBinPath, defaultDirsearchWordlistPath, defaultServicePortSet, resolveSecurityToolBinary, toolBinary, preferredPathSecurityTool, isOnPath, hostnameForTarget, urlForTarget, supportsHostnameEnumeration, isDomainEnumerationAdapter, inferIpv4Cidr, createDefaultPentestScope, defaultSecurityToolAdapters, getSecurityToolInventory, checkSecurityToolHealth, scanPathForSecurityTools, renderToolDiscoverySummary, versionArgsFor, installCommandFor, buildPentestPipeline, buildSecurityToolCommandForInputFile, buildAdaptiveSecurityActions, pushAdaptiveAction, limitInputs, serviceToHttpCandidate } from "./adapters.js";

// ── Decision Models & Workflow ──
export { buildSecurityAssetGraph, buildSecurityDecisionQueue, buildSecurityDecisionSupervision, buildSecurityObjectiveModel, buildBusinessWorkflowGraph, buildBrowserInteractionPlan, buildValidationClosurePlan, buildAuthorizedValidationPlaybook, buildCveReconciliationPlan, buildSubAgentOperatingModel, buildSecurityClosureModel, buildSubAgentCoordinationPlan, buildBusinessLogicTestPlan, renderPentestPipelineMarkdown, buildSecurityWorkflowPlan, buildSkillExecutionPlan, renderSecurityWorkflowPrompt } from "./decision-models.js";

// ── Normalizer ──
export { normalizeSecurityToolOutput, classifySecurityToolOutput, matchLocalCveKnowledge, matchNucleiKnowledgeForTechnologies, buildOwaspValidationMatrix, buildSecurityValidationChecks } from "./normalizer.js";
export { normalizeApiInventory } from "./api-inventory.js";
export { buildAuthSurfaceAssessment } from "./auth-surface.js";
export { analyzeJavaScriptAsset, buildJavaScriptBundleAnalysis, sourceMapUrlForScript, type JavaScriptAssetAnalysis, type JavaScriptBundleAnalysis } from "./js-analyzer.js";

// ── Pipeline Support ──
export { versionMatches, compareVersions, inferPhase, roleForPhase, buildPipelinePreflight, renderPipelinePreflight, curatedFrameworkSeeds, localAdvisories } from "./pipeline-support.js";
export type { PipelinePreflightReport } from "./pipeline-support.js";

// ── OWASP Validator ──
export { OWASP_CHECK_MAPPINGS, buildOwaspValidationPlan, buildOwaspTestCommand, parseOwaspTestOutput, buildOwaspCoverageReport, buildOwaspValidationPrompt, buildOwaspJobPipeline, computeOwaspExitCode, type OwaspCheckMapping, type OwaspValidationPlan, type OwaspValidationResult, type OwaspJobStep } from "./owasp-validator.js";

// ── Exploit Engine ──
export { ExploitManager, type ExploitPlatform, type ExploitTarget, type ExploitCandidate, type ExploitOption, type ExploitResult, type PostModuleResult, type ExploitManagerConfig } from "./exploit-engine.js";

// ── Exploitation Support ──
export { generatePayload, renderPayloadLibrary, syncCveExploitIndex, searchCveExploitIndex, renderCveExploitStats, type PayloadType, type PayloadOptions, type CveExploitIndex, type CveExploitEntry } from "./exploits.js";
export { buildPayloadCandidateSet, renderPayloadCandidateSet, type PayloadCandidateInput } from "./payload-candidates.js";
export { buildPayloadRequestDraftSet, renderPayloadRequestDraftSet, type PayloadRequestDraftInput } from "./payload-request-drafts.js";
export { buildAccessExposureMap, renderAccessExposureMap, type AccessExposureMapInput } from "./access-exposure-map.js";

// ── FOFA ──
export { fofaSearch, fofaSearchSubdomains, fofaSearchByIp, fofaSearchByCert, fofaExportCsv, renderFofaResults, type FofaConfig, type FofaHost, type FofaSearchResult } from "./fofa.js";

// ── CVE Chain (Fingerprint → CVE → Payload → Exploit) ──
export { CveMatchEngine, cveMatchEngine, buildCveChainContext, type CveExploitChain, type CveExploitOption, type GeneratedPayload, type CveChainResult, type CveChainSummary } from "./cve-chain.js";

// ── CVSS Calculator ──
export { calculateCvss, parseCvssVector, cvssScore, severityFromScore, type CvssMetrics, type CvssResult, type CvssSeverity } from "./cvss.js";

// ── CPE 2.3 Matcher ──
export { parseCpe23, normalizeCpeName, matchCpeAgainstTechnology, batchMatchCpe, templateMatchesTechnologyCpe, cpeMatchConfidence, formatCpeMatch, type CpeUri, type CpePart, type CpeMatchResult } from "./cpe-matcher.js";

// ── Semantic Version Matcher ──
export { parseSemver, parseSemverLenient, compareSemver, parseVersionRange, versionInRange, matchesVersionRange, matchesCpeVersion, type Semver, type VersionRange } from "./semver.js";

// ── NVD API Client ──
export { fetchCveDetails, fetchCveDetailsBatch, getOfflineCvss, type NvdCveItem, type NvdConfig } from "./nvd.js";

// ── Graph Scheduler ──
export { createSchedulerState, tickScheduler, consumeAnalysisTrigger, applyAnalysisResult, dispatchInvestigation, buildAnalysisPrompt, buildInvestigationPrompt, type SchedulerState } from "./graph-scheduler.js";

// ── Goal Satisfaction Model (PTT + Coverage) ──
export { assessGoalSatisfaction, createDefaultPtt, updatePttFromGraph, renderPttContext, type GoalAssessment, type DimensionScore, type CoverageDimension, type PttNode } from "./goal-model.js";

// ── Graph Engine ──
export { createPenetrationGraph, addEvidence, getEvidence, getEvidenceByKind, getRecentEvidence, proposeHypothesis, claimHypothesis, concludeHypothesis, failHypothesis, blockHypothesis, getHypothesis, getOpenHypotheses, getClaimedHypotheses, getUnclaimedHypothesis, addOverride, completeGraph, isGraphCompleted, createGraphCheckpoint, hasGraphChanged, describeChange, createGraphSnapshot, buildGraphContextPrompt, extractTechnologiesFromGraph, buildGraphSearchQuery } from "./graph.js";
export type { EvidenceNode, EvidenceKind, EvidenceConfidence, EvidenceSource, EvidencePayload, HypothesisNode, HypothesisCategory, HypothesisPriority, HypothesisStatus, OverrideNode, OverrideKind, PenetrationGraph, GraphStatus, GraphEvent, GraphSnapshot, GraphCheckpoint, ReasonResult } from "./graph-types.js";

// ── Self-Learning Feedback ──
export { saveAttackPathRecord, loadFeedbackIndex, loadAllFeedbackRecords, searchFeedback, buildAttackPathRecord, extractTagsFromRecord, buildFeedbackContext, feedbackRoot, feedbackIndexPath, type AttackPathRecord, type AttackPathFinding, type AttackPathCveReference, type FeedbackSearchResult, type FeedbackIndex } from "./feedback.js";

// ── EPSS + KEV ──
export { fetchEpssScore, fetchEpssScores, fetchKevCatalog, getKevCatalog, loadKevCatalogCache, saveKevCatalogCache, isKevCacheExpired, isInKevCatalog, getKevEntry, computeCvePriorityScore, buildCvePriorityContext, priorityTier, formatPriorityContext, type EpssResult, type KevEntry, type KevCatalog, type CvePriorityContext, type EpssKevConfig } from "./epss-kev.js";

// ── Pentest Workflow (Device Profiles / JS Analyzer / Rate Control) ──
export { DEVICE_PROFILES, matchDeviceProfile, buildDefaultCredentialTests, type DeviceProfile } from "./pentest-workflow.js";
export { analyzeJsContent, buildJsAnalysisSummary, type JsFinding } from "./pentest-workflow.js";
export { getRateConfig, recommendRateProfile, buildRateLimitedCommand, detectWafBan, type RateProfile, type RateConfig } from "./pentest-workflow.js";

// ── Attack Chains ──
export { ATTACK_CHAINS_V2, ATTACK_CHAINS, matchAttackChainsV2, matchAttackChains, buildChainContextPrompt, type AttackChainV2, type ChainCondition, type ChainMatch } from "./attack-chains.js";

// ── Exploit Knowledge Base ──
export { loadExploitMethodology, loadExploitKnowledge, matchExploitTypes, matchExploitCandidates, buildRunnerCommand, buildExploitPrompt, buildFullExploitPrompt, hasExploitMatches, type ExploitTypeId, type ExploitMethodology, type ExploitMethodologyKB, type TechHints } from "./exploit-knowledge.js";

// ── Wappalyzer Fingerprinting ──
export { fingerprint, loadWappalyzerTechnologies, type DetectedTechnology, type FingerprintInput, type FingerprintResult, type WappalyzerTechnology } from "./wappalyzer.js";
