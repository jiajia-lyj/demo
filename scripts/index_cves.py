import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.rag_retriever import RAGRetriever
from app.services.database import Database


def main() -> None:
    database = Database()
    records = database.list_cves()

    print(f"CVE records found: {len(records)}")

    if not records:
        print("No CVE records found in the database.")
        return

    retriever = RAGRetriever()

    existing_ids = {item["id"] for item in retriever.all()}

    records_to_index = [
        record
        for record in records
        if record.get("cve_id") not in existing_ids
    ]

    print(f"CVE records already indexed: {len(existing_ids)}")
    print(f"CVE records remaining: {len(records_to_index)}")

    if not records_to_index:
        print("All CVE records are already indexed.")
        return

    indexed = retriever.index_cves(records_to_index)
    stored = len(retriever.all())

    print(f"CVE records indexed this run: {indexed}")
    print(f"CVE records stored in local RAG index: {stored}")


if __name__ == "__main__":
    main()