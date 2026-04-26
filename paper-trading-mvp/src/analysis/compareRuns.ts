import path from 'node:path';
import { defaultConfig, mergeConfig } from '../config/defaultConfig';
import { loadMarkets } from '../data/marketSource';
import { loadTradeHistory } from '../data/polymarketTradeHistorySource';
import { runBacktest } from '../backtest/engine';
import { readJson, writeJson } from '../utils/io';

interface RunMetrics {
  roi: number;
  winRate: number;
  maxDrawdown: number;
  tradeCount: number;
  rejectionRate: number;
}

const summarize = (artifactsDir: string, backtest: ReturnType<typeof runBacktest>): RunMetrics => {
  const rejections = readJson(path.resolve(process.cwd(), artifactsDir, 'guardrail_rejections.json')) as Array<{ marketId: string }>;
  const rejectedCount = rejections.length;
  const acceptedCount = backtest.tradeResults.length;
  const totalReviewed = Math.max(1, rejectedCount + acceptedCount);

  return {
    roi: backtest.summary.roi,
    winRate: backtest.summary.winRate,
    maxDrawdown: backtest.summary.maxDrawdown,
    tradeCount: acceptedCount,
    rejectionRate: rejectedCount / totalReviewed
  };
};

const main = () => {
  const sampleConfig = mergeConfig(defaultConfig, { engine: { ...defaultConfig.engine, artifactsDir: 'artifacts/sample_run' } });
  const realConfig = mergeConfig(defaultConfig, { engine: { ...defaultConfig.engine, artifactsDir: 'artifacts/real_run' } });

  const sampleResult = runBacktest(loadMarkets('./data/sample_markets.json'), loadTradeHistory('json', './data/sample_trades.json', sampleConfig), sampleConfig);
  const realResult = runBacktest(loadMarkets('./data/real_markets.json'), loadTradeHistory('json', './data/real_trades.json', realConfig), realConfig);

  const sample = summarize(sampleConfig.engine.artifactsDir, sampleResult);
  const real = summarize(realConfig.engine.artifactsDir, realResult);

  const reasons: string[] = [];
  if (real.roi < sample.roi * 0.5) reasons.push('real ROI is materially below sample ROI');
  if (realResult.testSummary.roi < 0) reasons.push('test ROI is negative on real data');
  if (real.rejectionRate > 0.8) reasons.push('guardrail rejection rate is above 80% on real data');
  if (real.tradeCount === 0) reasons.push('no executable trades on real data');

  const verdict = reasons.length === 0 ? (real.roi > 0 ? 'YES' : 'WEAK') : 'NO';
  const noSignalDetected = verdict === 'NO';

  if (noSignalDetected) {
    console.warn(`NO SIGNAL DETECTED: ${reasons.join('; ')}`);
  }

  const comparison = {
    generatedAt: new Date().toISOString(),
    sample,
    real,
    delta: {
      roi: real.roi - sample.roi,
      winRate: real.winRate - sample.winRate,
      maxDrawdown: real.maxDrawdown - sample.maxDrawdown,
      tradeCount: real.tradeCount - sample.tradeCount,
      rejectionRate: real.rejectionRate - sample.rejectionRate
    },
    verdict,
    noSignalDetected,
    reasons
  };

  writeJson(path.resolve(process.cwd(), 'artifacts', 'comparison_summary.json'), comparison);
  console.log('Wrote artifacts/comparison_summary.json');
};

main();
