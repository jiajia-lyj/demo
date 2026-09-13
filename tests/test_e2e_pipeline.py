import pytest
from app.core.rag import RAGRetriever
from app.core.prompt import build_few_shot_prompt
from app.core.llm import LLMManager
from app.core.cvss import CVSSv4Calculator
from app.schemas import CVSSv4Prediction

def test_e2e_cve_to_cvss_pipeline():
    """
    Pipeline Test: CVE Input -> RAG Retrieval -> Prompt Building -> 
    LLM Call -> Pydantic Parsing -> DK Fallback -> CVSS v4 Score Calculation
    """
    cve_text = "Out-of-bounds write in Google Chrome prior to 120.0.6099.129 allowed remote attacker to execute arbitrary code."
    
    retriever = RAGRetriever()
    retrieved_examples = retriever.search(cve_text, top_k=3)
    
    prompt = build_few_shot_prompt(cve_text, examples=retrieved_examples)
    
    llm = LLMManager(model="deepseek-chat")
    prediction = llm.generate_structured(prompt, schema=CVSSv4Prediction)
    
    validated_prediction = prediction.apply_dk_fallback_if_needed()
    
    calculator = CVSSv4Calculator()
    score_result = calculator.calculate_v4(validated_prediction.metrics)
    
    assert 0.0 <= score_result.score <= 10.0
    assert score_result.vector.startswith("CVSS:4.0/")