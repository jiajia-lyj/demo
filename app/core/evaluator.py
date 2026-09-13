from __future__ import annotations

CVSS_V31_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
CVSS_V40_METRICS = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

_NUMERIC_MAPPING: dict[str, dict[str | None, float]] = {
    "AV": {"N": 0.0, "A": 0.33, "L": 0.67, "P": 1.0},
    "AC": {"L": 0.0, "H": 1.0},
    "PR": {"N": 0.0, "L": 0.5, "H": 1.0},
    "UI": {"N": 0.0, "R": 1.0},
    "S":  {"U": 0.0, "C": 1.0},
    "C":  {"N": 0.0, "L": 0.5, "H": 1.0},
    "I":  {"N": 0.0, "L": 0.5, "H": 1.0},
    "A":  {"N": 0.0, "L": 0.5, "H": 1.0},
    "AT": {"N": 0.0, "P": 1.0},
    "VC": {"N": 0.0, "L": 0.5, "H": 1.0},
    "VI": {"N": 0.0, "L": 0.5, "H": 1.0},
    "VA": {"N": 0.0, "L": 0.5, "H": 1.0},
    "SC": {"N": 0.0, "L": 0.5, "H": 1.0},
    "SI": {"N": 0.0, "L": 0.5, "H": 1.0},
    "SA": {"N": 0.0, "L": 0.5, "H": 1.0},
}


class Evaluator:
    """多维度评估：Accuracy / wF1 / MF1 / MAE / MSE / QSRS"""

    def __init__(self, metrics: list[str] | None = None):
        self.metrics = metrics or CVSS_V31_METRICS

    # ---------- 基础指标 ----------
    def accuracy(self, y_true: list[dict], y_pred: list[dict]) -> float:
        """样本级完全匹配准确率（所有指标全对才算对）"""
        correct = sum(1 for t, p in zip(y_true, y_pred) if self._all_match(t, p))
        return correct / len(y_true) if y_true else 0.0

    def per_metric_accuracy(self, y_true, y_pred) -> dict[str, float]:
        """每个指标的准确率"""
        result = {}
        for m in self.metrics:
            hit = sum(1 for t, p in zip(y_true, y_pred) if t.get(m) == p.get(m))
            result[m] = hit / len(y_true) if y_true else 0.0
        return result

    def macro_f1(self, y_true, y_pred) -> float:
        """宏平均 F1：每个指标各类别 F1 的均值"""
        f1_list = []
        for m in self.metrics:
            labels = sorted({t[m] for t in y_true if m in t})
            f1s = [self._f1_single(y_true, y_pred, m, lbl) for lbl in labels]
            f1_list.append(sum(f1s) / len(f1s) if f1s else 0.0)
        return sum(f1_list) / len(f1_list) if f1_list else 0.0

    def weighted_f1(self, y_true, y_pred) -> float:
        """加权 F1：以各类别支持度为权重"""
        total_support, weighted_sum = 0, 0.0
        for m in self.metrics:
            labels = sorted({t[m] for t in y_true if m in t})
            for lbl in labels:
                support = sum(1 for t in y_true if t.get(m) == lbl)
                f1 = self._f1_single(y_true, y_pred, m, lbl)
                weighted_sum += f1 * support
                total_support += support
        return weighted_sum / total_support if total_support else 0.0

    def mae(self, y_true, y_pred) -> float:
        """平均绝对误差：基于指标数值化映射"""
        errors = []
        for t, p in zip(y_true, y_pred):
            for m in self.metrics:
                errors.append(abs(self._to_numeric(m, t.get(m)) - self._to_numeric(m, p.get(m))))
        return sum(errors) / len(errors) if errors else 0.0

    def mse(self, y_true, y_pred) -> float:
        errors = []
        for t, p in zip(y_true, y_pred):
            for m in self.metrics:
                diff = self._to_numeric(m, t.get(m)) - self._to_numeric(m, p.get(m))
                errors.append(diff ** 2)
        return sum(errors) / len(errors) if errors else 0.0

    def qsrs(self, y_true, y_pred) -> float:
        """
        Query-Sample Reliability Score：
        综合完全匹配 + 单指标准确率 + 结构合法性的复合指标
        """
        if not y_true:
            return 0.0
        exact = self.accuracy(y_true, y_pred)
        avg_metric = sum(self.per_metric_accuracy(y_true, y_pred).values()) / len(self.metrics)
        structural = sum(1 for p in y_pred if self._is_valid_structure(p)) / len(y_pred)
        return 0.4 * exact + 0.4 * avg_metric + 0.2 * structural

    # ---------- 综合评估与报表 ----------
    def evaluate(self, y_true, y_pred) -> dict:
        return {
            "Accuracy": round(self.accuracy(y_true, y_pred), 4),
            "wF1": round(self.weighted_f1(y_true, y_pred), 4),
            "MF1": round(self.macro_f1(y_true, y_pred), 4),
            "MAE": round(self.mae(y_true, y_pred), 4),
            "MSE": round(self.mse(y_true, y_pred), 4),
            "QSRS": round(self.qsrs(y_true, y_pred), 4),
            "per_metric_acc": self.per_metric_accuracy(y_true, y_pred),
        }

    def compare_report(self, results: dict[str, dict]) -> str:
        """
        results: {"config_name": {"Accuracy":..., "wF1":..., ..., "tokens":..., "latency":...}}
        生成 Markdown 对比表
        """
        metrics = ["Accuracy", "wF1", "MF1", "MAE", "MSE", "QSRS", "tokens", "latency"]
        header = "| 配置 | " + " | ".join(metrics) + " |"
        sep = "|" + "---|" * (len(metrics) + 1)
        rows = [header, sep]
        for name, r in results.items():
            row = f"| {name} | " + " | ".join(
                f"{r.get(m, '-'):.4f}" if isinstance(r.get(m), float) else str(r.get(m, '-'))
                for m in metrics
            ) + " |"
            rows.append(row)
        return "\n".join(rows)

    # ---------- 内部工具 ----------
    def _all_match(self, t, p) -> bool:
        return all(t.get(m) == p.get(m) for m in self.metrics)

    def _is_valid_structure(self, pred: dict) -> bool:
        return all(m in pred for m in self.metrics)

    def _f1_single(self, y_true, y_pred, metric, label) -> float:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t.get(metric) == label and p.get(metric) == label)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t.get(metric) != label and p.get(metric) == label)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t.get(metric) == label and p.get(metric) != label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    @staticmethod
    def _to_numeric(metric: str, value: str | None) -> float:
        """CVSS 指标 -> 数值映射，用于 MAE/MSE 计算"""
        return _NUMERIC_MAPPING.get(metric, {}).get(value, 0.0)
