import sqlite3
import unittest

def create_test_database():
    # Create a new database in memory for testing
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.executescript(""" 
    CREATE TABLE IF NOT EXISTS vault(
        id INTEGER PRIMARY KEY,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL);
    """)
    return conn, cursor

def insert_into_vault(website, username, password, cursor):
    cursor.execute("INSERT INTO vault (website, username, password) VALUES (?, ?, ?)",
                   (website, username, password))

class TestInsertIntoVault(unittest.TestCase):
    def test_insert_into_vault(self):
        # Test data
        website = "example.com"
        username = "testuser"
        password = "testpassword"

        # Create a temporary database and cursor
        conn, cursor = create_test_database()

        # Call the function
        insert_into_vault(website, username, password, cursor)

        # Check if the data was inserted correctly
        cursor.execute("SELECT * FROM vault WHERE website=?", (website,))
        result = cursor.fetchone()

        # Assertions
        self.assertIsNotNone(result)
        self.assertEqual(result[1], website)
        self.assertEqual(result[2], username)
        self.assertEqual(result[3], password)
        print("Test Insert Into Vault: PASSED")

        # Close the temporary database connection
        conn.close()

if __name__ == '__main__':
    unittest.main()