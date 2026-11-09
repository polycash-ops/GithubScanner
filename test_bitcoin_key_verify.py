import unittest

from bitcoin_key_verify import decode_wif, derive_addresses

SECRET_ONE = (1).to_bytes(32, "big")


class BitcoinKeyVerifierTests(unittest.TestCase):
    def test_compressed_mainnet_p2pkh(self):
        addresses = derive_addresses(SECRET_ONE, "mainnet", True)
        self.assertEqual(
            addresses["P2PKH"],
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        )
        self.assertIn("P2WPKH", addresses)
        self.assertIn("P2SH-P2WPKH", addresses)

    def test_uncompressed_mainnet_p2pkh(self):
        addresses = derive_addresses(SECRET_ONE, "mainnet", False)
        self.assertEqual(
            addresses["P2PKH"],
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        )
        self.assertEqual(set(addresses), {"P2PKH"})

    def test_compressed_wif_flag(self):
        secret, compressed = decode_wif(
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            "mainnet",
        )
        self.assertEqual(secret, SECRET_ONE)
        self.assertTrue(compressed)

    def test_uncompressed_wif_flag(self):
        secret, compressed = decode_wif(
            "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
            "mainnet",
        )
        self.assertEqual(secret, SECRET_ONE)
        self.assertFalse(compressed)


if __name__ == "__main__":
    unittest.main()
