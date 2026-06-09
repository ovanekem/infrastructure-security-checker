export type Severity = 'PASS' | 'WARN' | 'FAIL';

export type ProtocolStatus = 'validated' | 'deprecated';
export type CipherRecommendation = 'Y' | 'D' | 'N';
export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered' | 'inconclusive';

export interface ProtocolPolicyEntry {
  name: string;
  status: ProtocolStatus;
}

export interface ProtocolPolicyFile {
  protocols: ProtocolPolicyEntry[];
}

export type TransportProtocol = 'tcp' | 'udp';

export interface PortPolicyEntry {
  port: number;
  transport: TransportProtocol;
  service: string;
  protocol: string;
  policy?: 'open' | 'closed';
  notes?: string;
}

export interface IcmpCheckResult {
  reachable: boolean;
  status: Severity;
  evidence: string;
}

export interface PortsPolicyFile {
  ports: PortPolicyEntry[];
}

export interface CipherEntry {
  name: string;
  recommended: CipherRecommendation;
  value?: string;
  references?: string[];
}

export interface CipherListFile {
  metadata: {
    sourceUrl: string;
    fetchedAt: string;
    registryId: 'tls-parameters-4';
  };
  ciphers: CipherEntry[];
}

export interface PolicyCheckResult {
  name: string;
  policy: ProtocolStatus | 'validated' | 'deprecated';
  supported: boolean | null;
  success: boolean;
  evidence: string;
}

export interface VulnerabilityResult {
  name: string;
  status: Severity;
  evidence: string;
  remediation: string;
}

export interface ClientSimulationResult {
  client: string;
  protocol: string | null;
  cipher: string | null;
  forwardSecrecy: boolean | null;
  status: 'PASS' | 'FAIL' | 'WARN';
  evidence: string;
}

export interface PortProbeResult {
  status: Severity;
  evidence: string;
}

export interface PortScanResult {
  port: number;
  transport: TransportProtocol;
  service: string;
  protocol: string;
  state: PortState;
  evidence: string;
  probe?: PortProbeResult;
}

export interface CertificateInfo {
  validFrom?: string;
  validTo?: string;
  trustValid: boolean;
  authorizationError?: string;
  hostnameMatches: boolean;
}

export interface InfrastructureCheck {
  name: string;
  status: Severity;
  evidence: string;
  remediation: string;
}

export interface WebServerEntry {
  name: string;
  pattern: string;
  minimumSecureVersion: string;
  notes?: string;
}

export interface WebServersFile {
  webServers: WebServerEntry[];
}

export interface AnalysisResult {
  targetUrl: string;
  startedAt: Date;
  finishedAt: Date;
  durationMs: number;
  webServer: string;
  certificate: CertificateInfo;
  negotiatedProtocol: string;
  negotiatedProtocolStatus: ProtocolStatus | 'UNKNOWN';
  negotiatedCipher: string;
  negotiatedCipherStatus: CipherRecommendation | 'UNKNOWN';
  protocolResults: PolicyCheckResult[];
  cipherResults: PolicyCheckResult[];
  infrastructureChecks: InfrastructureCheck[];
  portResults: PortScanResult[];
  icmpCheck: IcmpCheckResult;
  vulnerabilityResults: VulnerabilityResult[];
  clientSimulations: ClientSimulationResult[];
  globalStatus: Severity;
  exitCode: number;
}
