import string
import secrets
import unittest

# Function to be tested
def generate_password(length):
    if length < 1:
        raise ValueError("Password length must be at least 1.")
    
    alphabet = string.ascii_letters + string.digits + string.punctuation
    suggested_password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return suggested_password

class TestGeneratePassword(unittest.TestCase):
    def test_generate_password_valid_length(self):
        length = 12
        password = generate_password(length)

        # Assertion
        self.assertEqual(len(password), length)
        print("Test Generate Password - Valid Length: PASSED")

    def test_generate_password_invalid_length(self):
        length = 0

        # Assertion
        with self.assertRaises(ValueError):
            generate_password(length)
        print("Test Generate Password - Invalid Length: PASSED")

if __name__ == '__main__':
    unittest.main()