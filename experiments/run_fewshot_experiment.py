import asyncio, json
from app.core.retriever import FewShotRetriever
from app.core.evaluator import Evaluator, CVSS_V31_METRICS
from app.core.llm_enhancer import LLMEnhancer
from app.prompts.cvss_v40_fvp import build_v40_fvp_prompt, parse_v40_output

SHOTS_LIST = [1, 4, 8, 16, 24, 32]
SCENARIOS = ["STD", "DTD"]
SORT_STRATEGIES = ["similarity", "diversity"]
THRESHOLDS = [0.3, 0.5, 0.7]


async def run_experiment(test_set, vector_db, api_key):
    evaluator = Evaluator(CVSS_V31_METRICS)
    enhancer = LLMEnhancer(api_key=api_key, model="deepseek-chat",
                           log_file="perf_log.jsonl")
    all_results = {}

    for scenario in SCENARIOS:
        for shots in SHOTS_LIST:
            for strategy in SORT_STRATEGIES:
                for thr in THRESHOLDS:
                    retriever = FewShotRetriever(vector_db, similarity_threshold=thr)
                    y_true, y_pred = [], []
                    for item in test_set[scenario]:
                        examples = retriever.retrieve(item["description"], k=shots,
                                                      sort_strategy=strategy)
                        prompt = build_v40_fvp_prompt(item["description"], examples)
                        resp = await enhancer.complete(prompt, shots=shots,
                                                       scenario=scenario)
                        pred = parse_v40_output(resp["content"])
                        y_true.append(item["cvss_vector"])
                        y_pred.append(pred)

                    key = f"{scenario}_s{shots}_{strategy}_t{thr}"
                    metrics = evaluator.evaluate(y_true, y_pred)
                    metrics["avg_latency"] = resp["latency_ms"]
                    metrics["avg_tokens"] = resp["usage"].total_tokens
                    all_results[key] = metrics
                    print(f"[{key}] Acc={metrics['Accuracy']} QSRS={metrics['QSRS']}")

    # 生成报告
    report_md = evaluator.compare_report(all_results)
    with open("fewshot_report.md", "w", encoding="utf-8") as f:
        f.write("# 少样本策略对比报告\n\n" + report_md)

    cost_md = LLMEnhancer.cost_effect_report(
        "perf_log.jsonl",
        pricing={"deepseek-chat": {"input": 0.14, "output": 0.28}}
    )
    with open("cost_effect_report.md", "w", encoding="utf-8") as f:
        f.write("# 成本-效果分析\n\n" + cost_md)

    # 推荐最佳配置
    best = max(all_results.items(), key=lambda kv: kv[1]["QSRS"])
    print(f"\n推荐配置: {best[0]}, QSRS={best[1]['QSRS']}")
    return all_results


if __name__ == "__main__":
    # test_set = load_test_set(); vector_db = build_vector_db()
    # asyncio.run(run_experiment(test_set, vector_db, "your-api-key"))
    pass