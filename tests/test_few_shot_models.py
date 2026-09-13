import pytest
from app.core.llm import LLMManager
from app.core.prompt import build_few_shot_prompt

@pytest.mark.parametrize("shots", [0, 1, 3, 5])
@pytest.mark.parametrize("model_name", ["gpt-4o-mini", "deepseek-chat", "deepseek-coder"])
def test_few_shot_std_dtd_integration(shots, model_name):
    """
    Test STD/DTD prompt integration across various shot counts and model backends (including DeepSeek).
    """
    cve_input = "An unauthenticated remote attacker can execute arbitrary code via SQL injection in /api/v1/login."
    #Build Prompt
    prompt = build_few_shot_prompt(cve_input, shots=shots, strategy="STD_DTD")
    assert prompt is not None
    
    #Call Model
    llm = LLMManager(model=model_name)
    response = llm.generate(prompt)
    
    assert response is not None
    assert len(response.text) > 0