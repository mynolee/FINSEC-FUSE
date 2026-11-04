/** Closed metadata for the explicit synthetic fixture registry. No historical fixtures are inferred. */
export interface RegisteredSimulationFixture {
  readonly fixtureSetId: string;
  readonly caseIds: readonly string[];
  readonly modelModes: readonly ['REPLAY'];
  readonly resultsSource: 'VIRTUAL_SIMULATION';
}
export interface SimulationFixtureRegistry {
  readonly fixtureSets: readonly RegisteredSimulationFixture[];
  readonly executionMode: 'VIRTUAL_NON_DURABLE';
}
export class SimulationRegistryProtocolError extends Error {
  constructor() {
    super('등록된 합성 데이터 응답을 확인하지 못했어요.');
    this.name = 'SimulationRegistryProtocolError';
  }
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function closed(value: Record<string, unknown>, keys: readonly string[]) {
  return keys.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => keys.includes(key));
}
function identifier(value: unknown): value is string {
  // Mirrors the synthetic identity contract; never invent or normalize registry identifiers.
  return typeof value === 'string' && value.startsWith('synthetic-') && value.length <= 64;
}
export function parseSimulationFixtureRegistry(value: unknown): SimulationFixtureRegistry {
  if (!record(value) || !closed(value, ['fixtureSets', 'executionMode']) ||
      value.executionMode !== 'VIRTUAL_NON_DURABLE' || !Array.isArray(value.fixtureSets))
    throw new SimulationRegistryProtocolError();
  const fixtureIds = new Set<string>();
  const fixtureSets = value.fixtureSets.map((raw): RegisteredSimulationFixture => {
    if (!record(raw) || !closed(raw, ['fixtureSetId', 'caseIds', 'modelModes', 'resultsSource']) ||
        !identifier(raw.fixtureSetId) || fixtureIds.has(raw.fixtureSetId) ||
        !Array.isArray(raw.caseIds) || raw.caseIds.length < 1 || raw.caseIds.length > 100 ||
        !raw.caseIds.every(identifier) || new Set(raw.caseIds).size !== raw.caseIds.length ||
        !Array.isArray(raw.modelModes) || raw.modelModes.length !== 1 || raw.modelModes[0] !== 'REPLAY' ||
        raw.resultsSource !== 'VIRTUAL_SIMULATION')
      throw new SimulationRegistryProtocolError();
    fixtureIds.add(raw.fixtureSetId);
    return Object.freeze({
      fixtureSetId: raw.fixtureSetId,
      caseIds: Object.freeze([...raw.caseIds]) as readonly string[],
      modelModes: Object.freeze(['REPLAY'] as const),
      resultsSource: 'VIRTUAL_SIMULATION',
    });
  });
  // An empty registry is valid metadata but offers no selectable or submittable plan.
  return Object.freeze({ fixtureSets: Object.freeze(fixtureSets), executionMode: 'VIRTUAL_NON_DURABLE' });
}
