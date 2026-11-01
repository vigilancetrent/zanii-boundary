import { AppError, exactObject, positiveInteger } from '../protocol.mjs';
import { hashCanonical } from './policy.mjs';

/** @type {ReadonlyArray<readonly [string, RegExp]>} */
const SIGNALS = Object.freeze([
  ['instruction-override', /\b(?:ignore|disregard|override)\b.{0,80}\b(?:previous|prior|system|instructions?|polic(?:y|ies))\b/is],
  ['authority-spoofing', /\b(?:system message|developer message|administrator override|new system prompt|you are now root)\b/i],
  ['credential-request', /\b(?:reveal|print|extract|return|show)\b.{0,60}\b(?:passwords?|credentials?|api[ _-]?keys?|private[ _-]?keys?|access[ _-]?tokens?)\b/is],
  ['external-disclosure', /\b(?:send|upload|transmit|exfiltrate)\b.{0,100}\b(?:secrets?|payroll|credentials?|confidential)\b.{0,100}\b(?:external|outside|attacker|https?:\/\/)\b/is],
  ['memory-policy-poisoning', /\b(?:remember|store|memorize)\b.{0,80}\b(?:ignore|override|always approve|new policy|trusted instruction)\b/is],
]);

export function boundedText(text) {
  if (typeof text !== 'string' || !text.trim() || Buffer.byteLength(text) > 16_384) throw new AppError(400, 'INVALID_CONTENT');
  return text;
}

export function normalizeExample(text) {
  return boundedText(text).normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim();
}

function tokens(text) {
  return new Set(normalizeExample(text).match(/[\p{L}\p{N}_-]+/gu)?.slice(0, 2_048) ?? []);
}

function similarity(left, right) {
  if (!left.size || !right.size) return 0;
  const common = [...left].filter((token) => right.has(token)).length;
  return common / Math.sqrt(left.size * right.size);
}

export function validateDetectorModel(value) {
  exactObject(value, ['version', 'examples', 'threshold']);
  if (value.version !== 1 || !Array.isArray(value.examples) || value.examples.length < 2 || value.examples.length > 128
      || typeof value.threshold !== 'number' || !Number.isFinite(value.threshold)
      || value.threshold < 0.5 || value.threshold > 0.95) throw new AppError(400, 'INVALID_MODEL');
  const examples = value.examples.map((example) => {
    exactObject(example, ['text', 'label']);
    if (!['attack', 'benign'].includes(example.label)) throw new AppError(400, 'INVALID_MODEL');
    return Object.freeze({ text: boundedText(example.text), label: example.label });
  });
  if (!examples.some((example) => example.label === 'attack') || !examples.some((example) => example.label === 'benign')) throw new AppError(400, 'INVALID_MODEL');
  return Object.freeze({ version: 1, threshold: value.threshold, examples: Object.freeze(examples) });
}

/** Bounded local warning detector; it never authorizes an action or infers hidden model intent.
 * @param {string} textValue
 * @param {{source?:string,task?:{documentIds:string[],recipients:string[]},
 * proposedAction?:{kind:string,documentId:string,recipient?:string},model?:object}} options
 */
export function detectContent(textValue, { source = 'document', task, proposedAction, model } = {}) {
  const text = boundedText(textValue);
  if (!['document', 'tool', 'memory', 'owner'].includes(source)) throw new AppError(400, 'INVALID_SOURCE');
  const reasons = SIGNALS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
  if (task && proposedAction) {
    if (!task.documentIds?.includes(proposedAction.documentId)) reasons.push('task-resource-deviation');
    if (proposedAction.kind === 'share' && !task.recipients?.includes(proposedAction.recipient)) reasons.push('task-destination-deviation');
  }
  let learnedScore = 0; let modelDigest = null;
  if (model) {
    const valid = validateDetectorModel(model);
    const input = tokens(text);
    let attack = 0; let benign = 0;
    for (const example of valid.examples) {
      const score = similarity(input, tokens(example.text));
      if (example.label === 'attack') attack = Math.max(attack, score);
      else benign = Math.max(benign, score);
    }
    learnedScore = attack;
    if (attack >= valid.threshold && attack > benign + 0.05) reasons.push('approved-attack-similarity');
    modelDigest = hashCanonical(valid);
  }
  return Object.freeze({ suspicious: reasons.length > 0, reasons: Object.freeze([...new Set(reasons)]),
    learnedScore, modelDigest, source, grantsAuthority: false });
}

export function evaluateDetector(modelValue, examples) {
  const model = validateDetectorModel(modelValue);
  if (!Array.isArray(examples) || examples.length < 4 || examples.length > 128) throw new AppError(400, 'INVALID_EVALUATION');
  let truePositive = 0; let trueNegative = 0; let falsePositive = 0; let falseNegative = 0;
  const normalizedTraining = new Set(model.examples.map((example) => normalizeExample(example.text)));
  const seen = new Set();
  for (const example of examples) {
    exactObject(example, ['text', 'label']);
    if (!['attack', 'benign'].includes(example.label)) throw new AppError(400, 'INVALID_EVALUATION');
    const normalized = normalizeExample(example.text);
    if (normalizedTraining.has(normalized) || seen.has(normalized)) throw new AppError(400, 'EVALUATION_CONTAMINATED');
    seen.add(normalized);
    const prediction = detectContent(example.text, { model }).suspicious;
    if (example.label === 'attack') { if (prediction) truePositive += 1; else falseNegative += 1; }
    else if (prediction) falsePositive += 1; else trueNegative += 1;
  }
  const attackCount = truePositive + falseNegative; const benignCount = trueNegative + falsePositive;
  positiveInteger(attackCount); positiveInteger(benignCount);
  return Object.freeze({ examples: examples.length, attackCount, benignCount, truePositive, trueNegative, falsePositive, falseNegative,
    precision: truePositive / Math.max(1, truePositive + falsePositive),
    recall: truePositive / attackCount, falsePositiveRate: falsePositive / benignCount,
    corpusDigest: hashCanonical(examples), modelDigest: hashCanonical(model) });
}
