from __future__ import annotations


class FewShotRetriever:
    """少样本示例检索器：支持相似度阈值过滤与多种排序策略"""

    def __init__(self, vector_db, similarity_threshold: float = 0.5):
        self.vector_db = vector_db
        self.similarity_threshold = similarity_threshold

    def retrieve(self,
                 query: str,
                 k: int,
                 sort_strategy: str = "similarity",
                 threshold: float | None = None) -> list[dict]:
        """
        检索 top-k 少样本示例
        :param k: shots 数量
        :param sort_strategy: "similarity" 按相似度降序 | "diversity" 按标签多样性
        :param threshold: 相似度阈值，覆盖默认值
        """
        thr = threshold if threshold is not None else self.similarity_threshold
        raw = self.vector_db.search_with_scores(query, top_k=k * 3)

        filtered = [r for r in raw if r["score"] >= thr]
        if len(filtered) < k:
            filtered = raw

        if sort_strategy == "similarity":
            sorted_items = sorted(filtered, key=lambda x: x["score"], reverse=True)
        elif sort_strategy == "diversity":
            sorted_items = self._diversity_sort(filtered, k)
        else:
            raise ValueError(f"Unknown sort_strategy: {sort_strategy}")

        return sorted_items[:k]

    def _diversity_sort(self, candidates: list[dict], k: int) -> list[dict]:
        """按标签多样性排序：贪心选择与已选标签差异最大的样本"""
        if not candidates:
            return []
        selected = [max(candidates, key=lambda x: x["score"])]
        remaining = [c for c in candidates if c is not selected[0]]

        while len(selected) < k and remaining:
            best, best_score = None, -1
            for cand in remaining:
                diff = self._label_diff(cand, selected)
                combined = cand["score"] * (1 + diff)
                if combined > best_score:
                    best, best_score = cand, combined
            selected.append(best)
            remaining.remove(best)
        return selected

    @staticmethod
    def _label_diff(cand: dict, selected: list[dict]) -> float:
        """计算候选样本与已选样本在 CVSS 标签上的差异度"""
        cand_labels = set(cand["cvss_vector"].values())
        diff_sum = 0
        for s in selected:
            sel_labels = set(s["cvss_vector"].values())
            total = len(cand_labels | sel_labels)
            diff_sum += len(cand_labels ^ sel_labels) / total if total else 0
        return diff_sum / len(selected)
