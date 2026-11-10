import unittest

from bitcoin_puzzle_research import (
    RANGE_END, RANGE_START, TARGET_ADDRESS, decode_p2pkh_address, normalize_ranges, summarize
)


class PuzzleResearchTests(unittest.TestCase):
    def test_target_address_and_hash160(self):
        decoded = decode_p2pkh_address(TARGET_ADDRESS)
        self.assertEqual(decoded["version"], "00")
        self.assertEqual(decoded["hash160"], "f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8")

    def test_rejects_bad_checksum(self):
        with self.assertRaises(ValueError):
            decode_p2pkh_address(TARGET_ADDRESS[:-1] + "Y")

    def test_merges_overlap_and_adjacent_ranges(self):
        merged = normalize_ranges([
            {"start": f"{RANGE_START:x}", "end": f"{RANGE_START + 10:x}"},
            {"start": f"{RANGE_START + 8:x}", "end": f"{RANGE_START + 20:x}"},
            {"start": f"{RANGE_START + 21:x}", "end": f"{RANGE_START + 25:x}"},
        ])
        self.assertEqual(merged, [(RANGE_START, RANGE_START + 25)])

    def test_coverage_and_gap_accounting(self):
        result = summarize([
            {"start": f"{RANGE_START:x}", "end": f"{RANGE_START + 2:x}"},
            {"start": f"{RANGE_END - 1:x}", "end": f"{RANGE_END:x}"},
        ])
        self.assertEqual(result["reported_covered_candidates"], 5)
        self.assertEqual(len(result["unreported_ranges"]), 1)

    def test_rejects_out_of_bounds_range(self):
        with self.assertRaises(ValueError):
            normalize_ranges([{"start": f"{RANGE_START - 1:x}", "end": f"{RANGE_START:x}"}])


if __name__ == "__main__":
    unittest.main()
