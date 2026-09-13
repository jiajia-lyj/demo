from app.core.rag_retriever import RAGRetriever


def test_embed_is_deterministic_and_normalized():
    retriever = RAGRetriever.__new__(RAGRetriever)
    retriever.embedding_dimensions = 256

    first = retriever.embed("Remote unauthenticated code execution")
    second = retriever.embed("Remote unauthenticated code execution")

    assert first == second
    assert len(first) == 256
    assert abs(sum(value * value for value in first) - 1.0) < 1e-9


def test_embed_empty_text_returns_zero_vector():
    retriever = RAGRetriever.__new__(RAGRetriever)
    retriever.embedding_dimensions = 256

    assert retriever.embed("") == [0.0] * 256