import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class EntrypointNamingTests(unittest.TestCase):
    def test_documentation_uses_the_wpsplinter_entrypoint_name(self):
        for filename in ("README.md", "QUICKREF.md", "OUTSTANDING.md"):
            content = (PROJECT_ROOT / filename).read_text(encoding="utf-8")
            self.assertNotIn("wpslinter.py", content, filename)


if __name__ == "__main__":
    unittest.main()
