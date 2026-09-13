import pytest
from app.core.rag import RAGRetriever

@pytest.fixture
def retriever():
    return RAGRetriever(collection_name="cve_test_db")

def test_rag_semantic_retrieval(retriever):
    """
    Verify that a given CVE description returns semantically similar historical samples.
    """
    query_text = "Buffer overflow in heap memory allowing remote code execution via malformed HTTP request."
    results = retriever.search(query=query_text, top_k=3)
    
    assert len(results) > 0, "Retrieval should return at least 1 document"
    assert "buffer overflow" in results[0].metadata["vulnerability_type"].lower() or results[0].score > 0.70
    assert "cve_id" in results[0].metadata