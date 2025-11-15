import unittest
from unittest.mock import patch, MagicMock
import sys
import hashlib
from io import StringIO

import checkmypass


class TestRequestApiData(unittest.TestCase):
    """Test cases for request_api_data function"""

    @patch('checkmypass.requests.get')
    def test_request_api_data_success(self, mock_get):
        """Test successful API request"""
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = checkmypass.request_api_data('ABCDE')
        
        mock_get.assert_called_once_with('https://api.pwnedpasswords.com/range/ABCDE')
        self.assertEqual(result, mock_response)

    @patch('checkmypass.requests.get')
    def test_request_api_data_error(self, mock_get):
        """Test API request with error status code"""
        # Mock response with error
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            checkmypass.request_api_data('ABCDE')
        
        self.assertIn('Error Fectching: 404', str(context.exception))

    @patch('checkmypass.requests.get')
    def test_request_api_data_500_error(self, mock_get):
        """Test API request with 500 error"""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        with self.assertRaises(RuntimeError) as context:
            checkmypass.request_api_data('12345')
        
        self.assertIn('Error Fectching: 500', str(context.exception))


class TestGetPasswordLeaksCount(unittest.TestCase):
    """Test cases for get_password_leaks_count function"""

    def test_password_found_in_breaches(self):
        """Test when password hash is found in the response"""
        mock_response = MagicMock()
        mock_response.text = "ABCDEF1234567890ABCDEF1234567890ABCDEF:12345\n" \
                            "FEDCBA0987654321FEDCBA0987654321FEDCBA:67890\n" \
                            "11111111111111111111111111111111111111:999"
        
        hash_to_check = "FEDCBA0987654321FEDCBA0987654321FEDCBA"
        result = checkmypass.get_password_leaks_count(mock_response, hash_to_check)
        
        self.assertEqual(result, "67890")

    def test_password_not_found(self):
        """Test when password hash is not found in the response"""
        mock_response = MagicMock()
        mock_response.text = "ABCDEF1234567890ABCDEF1234567890ABCDEF:12345\n" \
                            "FEDCBA0987654321FEDCBA0987654321FEDCBA:67890"
        
        hash_to_check = "NOTFOUND1234567890123456789012345678901234"
        result = checkmypass.get_password_leaks_count(mock_response, hash_to_check)
        
        self.assertEqual(result, 0)

    def test_empty_response(self):
        """Test with empty API response"""
        mock_response = MagicMock()
        mock_response.text = ""
        
        hash_to_check = "ABCDEF1234567890ABCDEF1234567890ABCDEF"
        result = checkmypass.get_password_leaks_count(mock_response, hash_to_check)
        
        self.assertEqual(result, 0)

    def test_multiple_matches_first_one_returned(self):
        """Test that first match is returned if multiple exist (edge case)"""
        mock_response = MagicMock()
        mock_response.text = "ABCDEF1234567890ABCDEF1234567890ABCDEF:111\n" \
                            "ABCDEF1234567890ABCDEF1234567890ABCDEF:222"
        
        hash_to_check = "ABCDEF1234567890ABCDEF1234567890ABCDEF"
        result = checkmypass.get_password_leaks_count(mock_response, hash_to_check)
        
        self.assertEqual(result, "111")


class TestPwnedApiCheck(unittest.TestCase):
    """Test cases for pwned_api_check function"""

    @patch('checkmypass.request_api_data')
    @patch('checkmypass.get_password_leaks_count')
    def test_pwned_api_check_password_found(self, mock_get_count, mock_request):
        """Test pwned_api_check when password is found"""
        password = "testpassword123"
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5 = sha1_hash[:5]
        tail = sha1_hash[5:]
        
        mock_response = MagicMock()
        mock_request.return_value = mock_response
        mock_get_count.return_value = "12345"
        
        result = checkmypass.pwned_api_check(password)
        
        mock_request.assert_called_once_with(first5)
        mock_get_count.assert_called_once_with(mock_response, tail)
        self.assertEqual(result, "12345")

    @patch('checkmypass.request_api_data')
    @patch('checkmypass.get_password_leaks_count')
    def test_pwned_api_check_password_not_found(self, mock_get_count, mock_request):
        """Test pwned_api_check when password is not found"""
        password = "verySecurePassword123!@#"
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5 = sha1_hash[:5]
        tail = sha1_hash[5:]
        
        mock_response = MagicMock()
        mock_request.return_value = mock_response
        mock_get_count.return_value = 0
        
        result = checkmypass.pwned_api_check(password)
        
        mock_request.assert_called_once_with(first5)
        mock_get_count.assert_called_once_with(mock_response, tail)
        self.assertEqual(result, 0)

    @patch('checkmypass.request_api_data')
    def test_pwned_api_check_hash_generation(self, mock_request):
        """Test that SHA-1 hash is generated correctly"""
        password = "test"
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        first5 = sha1_hash[:5]
        tail = sha1_hash[5:]
        
        mock_response = MagicMock()
        mock_response.text = f"{tail}:999"
        mock_request.return_value = mock_response
        
        result = checkmypass.pwned_api_check(password)
        
        # Verify the correct first 5 characters were used
        mock_request.assert_called_once_with(first5)
        self.assertEqual(result, "999")


class TestMain(unittest.TestCase):
    """Test cases for main function"""

    @patch('checkmypass.pwned_api_check')
    @patch('sys.stdout', new_callable=StringIO)
    def test_main_password_found(self, mock_stdout, mock_pwned_check):
        """Test main function when password is found"""
        mock_pwned_check.return_value = "12345"
        
        result = checkmypass.main(["testpassword"])
        
        mock_pwned_check.assert_called_once_with("testpassword")
        output = mock_stdout.getvalue()
        self.assertIn("testpassword was found 12345 times", output)
        self.assertIn("You should change your password!", output)
        self.assertEqual(result, 'Done!')

    @patch('checkmypass.pwned_api_check')
    @patch('sys.stdout', new_callable=StringIO)
    def test_main_password_not_found(self, mock_stdout, mock_pwned_check):
        """Test main function when password is not found"""
        mock_pwned_check.return_value = 0
        
        result = checkmypass.main(["securepassword"])
        
        mock_pwned_check.assert_called_once_with("securepassword")
        output = mock_stdout.getvalue()
        self.assertIn("securepassword was not found", output)
        self.assertIn("Carry On!", output)
        self.assertEqual(result, 'Done!')

    @patch('checkmypass.pwned_api_check')
    @patch('sys.stdout', new_callable=StringIO)
    def test_main_multiple_passwords(self, mock_stdout, mock_pwned_check):
        """Test main function with multiple passwords"""
        # Note: Due to the return statement in the loop, only first password is processed
        mock_pwned_check.return_value = "5000"
        
        result = checkmypass.main(["password1", "password2", "password3"])
        
        # Only first password should be checked due to return in loop
        mock_pwned_check.assert_called_once_with("password1")
        output = mock_stdout.getvalue()
        self.assertIn("password1 was found 5000 times", output)
        self.assertEqual(result, 'Done!')

    @patch('checkmypass.pwned_api_check')
    @patch('sys.stdout', new_callable=StringIO)
    def test_main_empty_args(self, mock_stdout, mock_pwned_check):
        """Test main function with no arguments"""
        result = checkmypass.main([])
        
        mock_pwned_check.assert_not_called()
        output = mock_stdout.getvalue()
        self.assertEqual(output, "")
        # When args is empty, the loop doesn't execute, so function returns None
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()

