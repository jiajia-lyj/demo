import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.rag_retriever import RAGRetriever


def main() -> None:
    retriever = RAGRetriever()

    description = (
        "A local account remains active after initial system configuration, "
        "allowing an attacker to gain elevated privileges."
    )

    results = retriever.retrieve_similar_cves(
        description=description,
        top_k=5,
        cvss_version="3.1",
    )

    print(f"Results found: {len(results)}")
    print()

    for index, result in enumerate(results, 1):
        print(f"{index}. {result['cve_id']}")
        print(f"   Distance: {result['distance']:.4f}")
        print(f"   CVSS: {result['metadata'].get('cvss_vector', 'N/A')}")
        print(f"   Score: {result['metadata'].get('cvss_base_score', 'N/A')}")
        print(f"   Severity: {result['metadata'].get('cvss_severity', 'N/A')}")
        print(f"   Description: {result['description']}")
        print()


if __name__ == "__main__":
    main()