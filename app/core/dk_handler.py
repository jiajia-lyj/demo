from typing import Dict, Any
from app.schemas import (
    AVEnum, ACEnum, PREnum, UIEnum, SEnum, CEnum, IEnum, AEnum,
    CvssAllPrediction
)

# Worst Case 保守映射表（需求指定映射关系）
WORST_CASE_MAP: Dict[str, Any] = {
    "av": AVEnum.NETWORK,
    "ac": ACEnum.LOW,
    "pr": PREnum.NONE,
    "ui": UIEnum.NONE,
    "s": SEnum.CHANGED,
    "c": CEnum.HIGH,
    "i": IEnum.HIGH,
    "a": AEnum.HIGH,
}


def handle_dk_output(prediction: CvssAllPrediction) -> CvssAllPrediction:
    """
    DK后处理中间件：检测字段为DONT_KNOW时替换为Worst‑Case保守取值
    :param prediction: LLM原始输出CvssAllPrediction对象，可能包含DONT_KNOW
    :return: 替换DONT_KNOW之后的新预测对象
    """
    raw_dict = prediction.model_dump()

    for field_name, worst_val in WORST_CASE_MAP.items():
        field_value = raw_dict.get(field_name)
        if field_value == "DONT_KNOW" or getattr(field_value, "value", None) == "DONT_KNOW":
            raw_dict[field_name] = worst_val

    return CvssAllPrediction(**raw_dict)
