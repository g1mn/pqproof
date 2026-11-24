import json
import re
import unittest
from pathlib import Path


class TestMappingsReadmeCounts(unittest.TestCase):
    def test_readme_item_counts_match_json_files(self):
        mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
        readme_text = (mappings_dir / "README.md").read_text(encoding="utf-8")

        # Match markdown table rows referencing a .json file and a numeric count
        rows = re.findall(r"`([a-zA-Z0-9_.-]+\.json)`[^|\n]*\|[^|\n]*\|\s*(\d+)", readme_text)
        self.assertTrue(rows, "No mapping rows found in mappings/README.md")

        for filename, count_str in rows:
            json_path = mappings_dir / filename
            self.assertTrue(json_path.exists(), f"Missing mapping file: {filename}")
            data = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "items" in data:
                actual = len(data["items"])
            elif isinstance(data, list):
                actual = len(data)
            else:
                actual = len(data)
            self.assertEqual(actual, int(count_str), f"Count mismatch for {filename}")


if __name__ == "__main__":
    unittest.main()
