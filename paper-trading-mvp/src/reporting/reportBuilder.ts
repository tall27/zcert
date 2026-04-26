import fs from 'node:fs';
import path from 'node:path';

interface BuildReportInput {
  mode: 'paper' | 'backtest';
  artifactsDir: string;
}

const safeRead = <T>(filePath: string, fallback: T): T => {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as T;
  } catch {
    return fallback;
  }
};

const toPct = (n: number): string => `${(n * 100).toFixed(2)}%`;

export const buildReportArtifacts = ({ mode, artifactsDir }: BuildReportInput): { mdPath: string; htmlPath: string } => {
  const dir = path.resolve(process.cwd(), artifactsDir);
  const runSummary = safeRead<Record<string, unknown>>(path.join(dir, 'run_summary.json'), {});
  const backtestSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_summary.json'), {});
  const trainSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_train_summary.json'), {});
  const testSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_test_summary.json'), {});
  const guardRejections = safeRead<Array<{ marketId: string; reasons: string[] }>>(path.join(dir, 'guardrail_rejections.json'), []);
  const llmResearch = safeRead<Array<Record<string, unknown>>>(path.join(dir, 'llm_research.json'), []);
  const ledger = safeRead<{ trades?: Array<Record<string, unknown>>; bankroll?: number }>(path.join(dir, 'paper_ledger.json'), {});
  const dataQuality = safeRead<{ criticalIssues?: string[]; warnings?: string[] }>(path.join(dir, 'data_quality_report.json'), {});
  const comparison = safeRead<{ verdict?: string; reasons?: string[]; sample?: Record<string, number>; real?: Record<string, number> }>(
    path.join(dir, 'comparison_summary.json'),
    {}
  );
  const pipelineDiagnostics = safeRead<{
    funnel?: Record<string, number>;
    topBlockers?: Array<{ stage: string; reason: string; count: number }>;
    nearMissCandidates?: Array<Record<string, unknown>>;
  }>(path.join(dir, 'pipeline_diagnostics.json'), {});

  const topAcceptedTrades =
    mode === 'backtest'
      ? (backtestSummary.tradeResults as Array<Record<string, unknown>> | undefined)?.slice(0, 5) ?? []
      : (ledger.trades ?? []).slice(0, 5);

  const finalBankroll =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.endingBankroll ?? 0)
      : Number(runSummary.final_bankroll ?? ledger.bankroll ?? 0);

  const roi =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.roi ?? 0)
      : finalBankroll > 0 ? (finalBankroll - 10000) / 10000 : 0;

  const winRate =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.winRate ?? 0)
      : Number(runSummary.win_rate ?? 0);

  const maxDrawdown =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.maxDrawdown ?? 0)
      : Number(runSummary.drawdown ?? 0);

  const profitFactor =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.profitFactor ?? 0)
      : 0;

  const sharpeLike =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.sharpeLike ?? 0)
      : Number(runSummary.sharpe_like ?? 0);

  const source = String(runSummary.source ?? backtestSummary.source ?? 'unknown');

  const rejectionByReason = guardRejections.reduce<Record<string, number>>((acc, row) => {
    row.reasons.forEach((r) => {
      acc[r] = (acc[r] ?? 0) + 1;
    });
    return acc;
  }, {});

  const trainVsTest = {
    trainRoi: Number(trainSummary.roi ?? 0),
    testRoi: Number(testSummary.roi ?? 0),
    trainWinRate: Number(trainSummary.winRate ?? 0),
    testWinRate: Number(testSummary.winRate ?? 0)
  };

  const md = `# Run Report

- **Run mode:** ${mode}
- **Source:** ${source}
- **Final bankroll:** ${finalBankroll.toFixed(2)}
- **ROI:** ${toPct(roi)}
- **Win rate:** ${toPct(winRate)}
- **Max drawdown:** ${maxDrawdown.toFixed(2)}
- **Profit factor:** ${profitFactor.toFixed(4)}
- **Sharpe-like score:** ${sharpeLike.toFixed(4)}

## Top accepted trades

${topAcceptedTrades.map((t) => `- ${JSON.stringify(t)}`).join('\n') || '- none'}

## Rejected trades by guardrail reason

${Object.entries(rejectionByReason).map(([k, v]) => `- ${k}: ${v}`).join('\n') || '- none'}

## Train vs Test comparison

- train ROI: ${toPct(trainVsTest.trainRoi)}
- test ROI: ${toPct(trainVsTest.testRoi)}
- train win rate: ${toPct(trainVsTest.trainWinRate)}
- test win rate: ${toPct(trainVsTest.testWinRate)}

## LLM research summary

- enabled: ${String(runSummary.llm_enabled ?? false)}
- llm reports generated: ${llmResearch.length}

## Data quality diagnostics

- critical issues: ${(dataQuality.criticalIssues ?? []).join(', ') || 'none'}
- warnings: ${(dataQuality.warnings ?? []).join(', ') || 'none'}

## Reality Check

- sample ROI: ${comparison.sample ? toPct(Number(comparison.sample.roi ?? 0)) : 'N/A'}
- real ROI: ${comparison.real ? toPct(Number(comparison.real.roi ?? 0)) : 'N/A'}
- sample win rate: ${comparison.sample ? toPct(Number(comparison.sample.winRate ?? 0)) : 'N/A'}
- real win rate: ${comparison.real ? toPct(Number(comparison.real.winRate ?? 0)) : 'N/A'}
- sample drawdown: ${comparison.sample ? Number(comparison.sample.maxDrawdown ?? 0).toFixed(2) : 'N/A'}
- real drawdown: ${comparison.real ? Number(comparison.real.maxDrawdown ?? 0).toFixed(2) : 'N/A'}
- sample trade count: ${comparison.sample ? Number(comparison.sample.tradeCount ?? 0) : 'N/A'}
- real trade count: ${comparison.real ? Number(comparison.real.tradeCount ?? 0) : 'N/A'}
- sample rejection rate: ${comparison.sample ? toPct(Number(comparison.sample.rejectionRate ?? 0)) : 'N/A'}
- real rejection rate: ${comparison.real ? toPct(Number(comparison.real.rejectionRate ?? 0)) : 'N/A'}
- signal verdict: ${String(comparison.verdict ?? 'N/A')}
- no signal reasons: ${(comparison.reasons ?? []).join('; ') || 'none'}

## Pipeline Diagnostics

| Stage | Count |
| --- | ---: |
| markets loaded | ${Number(pipelineDiagnostics.funnel?.marketsLoaded ?? 0)} |
| scanner passed | ${Number(pipelineDiagnostics.funnel?.scannerPassed ?? 0)} |
| research passed | ${Number(pipelineDiagnostics.funnel?.researchPassed ?? 0)} |
| wallet signals available | ${Number(pipelineDiagnostics.funnel?.walletSignalsAvailable ?? 0)} |
| strategy candidates | ${Number(pipelineDiagnostics.funnel?.strategyCandidates ?? 0)} |
| risk-approved trades | ${Number(pipelineDiagnostics.funnel?.riskApproved ?? 0)} |
| guardrail-approved trades | ${Number(pipelineDiagnostics.funnel?.guardrailApproved ?? 0)} |
| final executed trades | ${Number(pipelineDiagnostics.funnel?.executedTrades ?? 0)} |

### Biggest blockers

${(pipelineDiagnostics.topBlockers ?? []).map((b) => `- ${b.stage}: ${b.reason} (${b.count})`).join('\n') || '- none'}

### Near-miss opportunities

${(pipelineDiagnostics.nearMissCandidates ?? []).slice(0, 20).map((n) => `- ${String(n.marketId ?? '')}: stage=${String(n.failedStage ?? '')}, reason=${String(n.failedReason ?? '')}, edge=${Number(n.edge ?? 0).toFixed(4)}, edgeAfterSlippage=${Number(n.edgeAfterSlippage ?? 0).toFixed(4)}, liquidity=${Number(n.liquidity ?? 0)}, spread=${Number(n.spread ?? 0).toFixed(4)}, timeToResolution=${Number(n.timeToResolutionHours ?? 0).toFixed(2)}h, walletSignal=${Number(n.walletSignal ?? 0).toFixed(2)}`).join('\n') || '- none'}
`;

  const htmlRows = topAcceptedTrades
    .map((t) => `<tr><td>${String(t.marketId ?? t.id ?? '')}</td><td>${String(t.pnl ?? '')}</td><td>${String(t.roi ?? '')}</td></tr>`)
    .join('');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Run Report</title></head><body>
<h1>Run Report</h1>
<table border="1"><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Run mode</td><td>${mode}</td></tr>
<tr><td>Source</td><td>${source}</td></tr>
<tr><td>Final bankroll</td><td>${finalBankroll.toFixed(2)}</td></tr>
<tr><td>ROI</td><td>${toPct(roi)}</td></tr>
<tr><td>Win rate</td><td>${toPct(winRate)}</td></tr>
<tr><td>Max drawdown</td><td>${maxDrawdown.toFixed(2)}</td></tr>
<tr><td>Profit factor</td><td>${profitFactor.toFixed(4)}</td></tr>
<tr><td>Sharpe-like</td><td>${sharpeLike.toFixed(4)}</td></tr>
</table>
<h2>Top accepted trades</h2>
<table border="1"><tr><th>Market</th><th>PnL</th><th>ROI</th></tr>${htmlRows}</table>
<h2>Rejected by guardrail</h2>
<ul>${Object.entries(rejectionByReason).map(([k, v]) => `<li>${k}: ${v}</li>`).join('') || '<li>none</li>'}</ul>
<h2>Train vs Test</h2>
<table border="1"><tr><th>Split</th><th>ROI</th><th>Win Rate</th></tr>
<tr><td>Train</td><td>${toPct(trainVsTest.trainRoi)}</td><td>${toPct(trainVsTest.trainWinRate)}</td></tr>
<tr><td>Test</td><td>${toPct(trainVsTest.testRoi)}</td><td>${toPct(trainVsTest.testWinRate)}</td></tr>
</table>
<h2>LLM Summary</h2><p>Enabled: ${String(runSummary.llm_enabled ?? false)}, Reports: ${llmResearch.length}</p>
<h2>Data Quality</h2><p>Critical: ${(dataQuality.criticalIssues ?? []).join(', ') || 'none'}</p><p>Warnings: ${(dataQuality.warnings ?? []).join(', ') || 'none'}</p>
<h2>Reality Check</h2>
<table border="1"><tr><th>Metric</th><th>Sample</th><th>Real</th></tr>
<tr><td>ROI</td><td>${comparison.sample ? toPct(Number(comparison.sample.roi ?? 0)) : 'N/A'}</td><td>${comparison.real ? toPct(Number(comparison.real.roi ?? 0)) : 'N/A'}</td></tr>
<tr><td>Win rate</td><td>${comparison.sample ? toPct(Number(comparison.sample.winRate ?? 0)) : 'N/A'}</td><td>${comparison.real ? toPct(Number(comparison.real.winRate ?? 0)) : 'N/A'}</td></tr>
<tr><td>Drawdown</td><td>${comparison.sample ? Number(comparison.sample.maxDrawdown ?? 0).toFixed(2) : 'N/A'}</td><td>${comparison.real ? Number(comparison.real.maxDrawdown ?? 0).toFixed(2) : 'N/A'}</td></tr>
<tr><td>Trade count</td><td>${comparison.sample ? Number(comparison.sample.tradeCount ?? 0) : 'N/A'}</td><td>${comparison.real ? Number(comparison.real.tradeCount ?? 0) : 'N/A'}</td></tr>
<tr><td>Rejection rate</td><td>${comparison.sample ? toPct(Number(comparison.sample.rejectionRate ?? 0)) : 'N/A'}</td><td>${comparison.real ? toPct(Number(comparison.real.rejectionRate ?? 0)) : 'N/A'}</td></tr>
</table>
<p><strong>Signal verdict:</strong> ${String(comparison.verdict ?? 'N/A')}</p>
<p><strong>No-signal reasons:</strong> ${(comparison.reasons ?? []).join('; ') || 'none'}</p>
<h2>Pipeline Diagnostics</h2>
<table border="1"><tr><th>Stage</th><th>Count</th></tr>
<tr><td>Markets loaded</td><td>${Number(pipelineDiagnostics.funnel?.marketsLoaded ?? 0)}</td></tr>
<tr><td>Scanner passed</td><td>${Number(pipelineDiagnostics.funnel?.scannerPassed ?? 0)}</td></tr>
<tr><td>Research passed</td><td>${Number(pipelineDiagnostics.funnel?.researchPassed ?? 0)}</td></tr>
<tr><td>Wallet signals available</td><td>${Number(pipelineDiagnostics.funnel?.walletSignalsAvailable ?? 0)}</td></tr>
<tr><td>Strategy candidates</td><td>${Number(pipelineDiagnostics.funnel?.strategyCandidates ?? 0)}</td></tr>
<tr><td>Risk-approved trades</td><td>${Number(pipelineDiagnostics.funnel?.riskApproved ?? 0)}</td></tr>
<tr><td>Guardrail-approved trades</td><td>${Number(pipelineDiagnostics.funnel?.guardrailApproved ?? 0)}</td></tr>
<tr><td>Final executed trades</td><td>${Number(pipelineDiagnostics.funnel?.executedTrades ?? 0)}</td></tr>
</table>
<h3>Biggest blockers</h3>
<ul>${(pipelineDiagnostics.topBlockers ?? []).map((b) => `<li>${b.stage}: ${b.reason} (${b.count})</li>`).join('') || '<li>none</li>'}</ul>
<h3>Near-miss opportunities</h3>
<ul>${(pipelineDiagnostics.nearMissCandidates ?? []).slice(0, 20).map((n) => `<li>${String(n.marketId ?? '')}: stage=${String(n.failedStage ?? '')}, reason=${String(n.failedReason ?? '')}, edge=${Number(n.edge ?? 0).toFixed(4)}, edgeAfterSlippage=${Number(n.edgeAfterSlippage ?? 0).toFixed(4)}, liquidity=${Number(n.liquidity ?? 0)}, spread=${Number(n.spread ?? 0).toFixed(4)}, timeToResolution=${Number(n.timeToResolutionHours ?? 0).toFixed(2)}h, walletSignal=${Number(n.walletSignal ?? 0).toFixed(2)}</li>`).join('') || '<li>none</li>'}</ul>
</body></html>`;

  const mdPath = path.join(dir, 'report.md');
  const htmlPath = path.join(dir, 'report.html');
  fs.writeFileSync(mdPath, md);
  fs.writeFileSync(htmlPath, html);

  return { mdPath, htmlPath };
};
