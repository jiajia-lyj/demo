import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.rag_retriever import RAGRetriever


def main() -> None:
    retriever = RAGRetriever()

    result = retriever.get("CVE-2024-0001")
    print(result or "CVE not found in local RAG index")


if __name__ == "__main__":
    main()