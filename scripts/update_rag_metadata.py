import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.rag_retriever import RAGRetriever
from app.services.database import Database


BATCH_SIZE = 5000


def main() -> None:
    database = Database()
    retriever = RAGRetriever()

    records = database.list_cves()

    print(f"CVE records found in database: {len(records)}")

    updated = 0

    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start:start + BATCH_SIZE]

            updated_batch = []

        for record in batch:
            cve_id = record.get("cve_id")

            if not cve_id:
                continue

            metadata = {
                "cve_id": cve_id,
            }

            if record.get("published_date"):
                metadata["published_date"] = str(record["published_date"])

            if record.get("updated_date"):
                metadata["updated_date"] = str(record["updated_date"])

            metadata.update(
                retriever._extract_cvss_metadata(record)
            )

            if retriever.update_metadata(cve_id, metadata):
                updated_batch.append(cve_id)

        if updated_batch:
            retriever.save()
            updated += len(updated_batch)

        print(
            f"Metadata updated: {updated}/{len(records)}"
        )

    print(f"Finished. Total records updated: {updated}")


if __name__ == "__main__":
    main()