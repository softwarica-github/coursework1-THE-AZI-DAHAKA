import unittest
import hashlib

# Function to be tested
def hashpassword(input):
    hash = hashlib.sha256(input.encode())
    hash = hash.hexdigest()
    return hash

class TestHashPassword(unittest.TestCase):
    def test_hashpassword(self):
        # Test with a known input and expected output
        input_text = "password123"
        expected_hash = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
        result = hashpassword(input_text)

        # Assertion
        self.assertEqual(result, expected_hash)
        print("Test Hash Password: PASSED")

if __name__ == '__main__':
    unittest.main()