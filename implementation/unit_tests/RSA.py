import unittest
from implementation.encryption.rsa import *
class TestIsPrime(unittest.TestCase):
    def test_prime(self):
        # Small composite numbers
        self.assertFalse(is_prime(4))
        self.assertFalse(is_prime(15))
        self.assertFalse(is_prime(21))
        self.assertFalse(is_prime(33))
        self.assertFalse(is_prime(45))
        self.assertFalse(is_prime(49))
        self.assertFalse(is_prime(55))
        self.assertFalse(is_prime(65))
        self.assertFalse(is_prime(77))
        self.assertFalse(is_prime(85))
        self.assertFalse(is_prime(91))
        self.assertFalse(is_prime(95))
        self.assertFalse(is_prime(99))
        self.assertFalse(is_prime(105))
        self.assertFalse(is_prime(111))

        # Small prime numbers
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(3))
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(7))
        self.assertTrue(is_prime(11))
        self.assertTrue(is_prime(17))
        self.assertTrue(is_prime(23))
        self.assertTrue(is_prime(29))
        self.assertTrue(is_prime(31))
        self.assertTrue(is_prime(37))
        self.assertTrue(is_prime(41))
        self.assertTrue(is_prime(43))
        self.assertTrue(is_prime(47))
        self.assertTrue(is_prime(53))
        self.assertTrue(is_prime(59))
        self.assertTrue(is_prime(61))
        self.assertTrue(is_prime(67))
        self.assertTrue(is_prime(71))
        self.assertTrue(is_prime(73))
        self.assertTrue(is_prime(79))
        self.assertTrue(is_prime(83))
        self.assertTrue(is_prime(89))
        self.assertTrue(is_prime(97))
        self.assertTrue(is_prime(101))
        self.assertTrue(is_prime(103))

        # Medium-sized prime numbers
        self.assertTrue(is_prime(101))
        self.assertTrue(is_prime(103))
        self.assertTrue(is_prime(107))
        self.assertTrue(is_prime(109))
        self.assertTrue(is_prime(113))
        self.assertTrue(is_prime(127))
        self.assertTrue(is_prime(131))
        self.assertTrue(is_prime(137))
        self.assertTrue(is_prime(139))
        self.assertTrue(is_prime(149))
        self.assertTrue(is_prime(151))
        self.assertTrue(is_prime(157))
        self.assertTrue(is_prime(163))
        self.assertTrue(is_prime(167))
        self.assertTrue(is_prime(173))
        self.assertTrue(is_prime(179))

        # Large prime numbers
        self.assertTrue(is_prime(6700417))  # Fermat prime
        self.assertTrue(is_prime(2147483647))  # Mersenne prime
        self.assertTrue(is_prime(982451653))  # Large known prime
        self.assertTrue(is_prime(32416190071))  # Large known prime
        self.assertTrue(is_prime(2305843009213693951))  # Mersenne prime
        self.assertTrue(is_prime(999999000001))  # Carmichael prime
        self.assertTrue(is_prime(4256233))  # Random large prime

        # Very large prime numbers
        self.assertTrue(is_prime(67280421310721))  # 2^56 - 15, known prime
        self.assertTrue(is_prime(1000000000000037))

        # Large composite numbers
        self.assertFalse(is_prime(1000000000000))  # Even number
        self.assertFalse(is_prime(999999000000))  # Large composite
        self.assertFalse(is_prime(2147483646))  # Mersenne composite
        self.assertFalse(is_prime(999981))  # Composite close to a large prime
        self.assertFalse(is_prime(32416190070))  # Close to a large prime
        self.assertFalse(is_prime(2305843009213693952))  # Even Mersenne composite

        # Very large composite numbers
        self.assertFalse(is_prime(67280421310720))  # 2^56 - 16, even composite
        self.assertFalse(is_prime(1099726899285418))  # Close to a very large prime

        # Edge cases
        self.assertFalse(is_prime(0))  # Non-prime
        self.assertFalse(is_prime(1))  # Non-prime
        self.assertTrue(is_prime(2))  # Smallest prime
        self.assertFalse(is_prime(-7))  # Negative numbers are not prime
        self.assertFalse(is_prime(-2147483647))  # Negative large composite

    def test_gcd(self):
        # Coprime numbers (no common divisor other than 1)
        self.assertEqual(euclidean_algorithm(20, 7), 1)
        self.assertEqual(euclidean_algorithm(35, 64), 1)
        self.assertEqual(euclidean_algorithm(101, 10), 1)

        # One number is zero
        self.assertEqual(euclidean_algorithm(0, 5), 5)
        self.assertEqual(euclidean_algorithm(5, 0), 5)
        self.assertEqual(euclidean_algorithm(0, 0), 0)  # Special case: gcd(0, 0) is 0

        # Both numbers are the same
        self.assertEqual(euclidean_algorithm(7, 7), 7)
        self.assertEqual(euclidean_algorithm(100, 100), 100)

        # One number is a multiple of the other
        self.assertEqual(euclidean_algorithm(12, 4), 4)
        self.assertEqual(euclidean_algorithm(4, 12), 4)
        self.assertEqual(euclidean_algorithm(100, 25), 25)

        # General cases
        self.assertEqual(euclidean_algorithm(56, 98), 14)  # gcd(56, 98) = 14
        self.assertEqual(euclidean_algorithm(48, 18), 6)  # gcd(48, 18) = 6
        self.assertEqual(euclidean_algorithm(270, 192), 6)  # gcd(270, 192) = 6

        # Negative inputs
        self.assertEqual(euclidean_algorithm(-20, 7), 1)
        self.assertEqual(euclidean_algorithm(20, -7), 1)
        self.assertEqual(euclidean_algorithm(-20, -7), 1)
        self.assertEqual(euclidean_algorithm(-100, -25), 25)
        self.assertEqual(euclidean_algorithm(-100, 25), 25)
        self.assertEqual(euclidean_algorithm(100, -25), 25)


    def test_generate_prime(self):
        test_bit_first = 1024
        for _ in range(10):
            p = get_prime_number(test_bit_first//2)
            q = get_prime_number(test_bit_first//2)
            self.assertTrue(is_prime(p))
            self.assertTrue(is_prime(q))

        # grotere bits duren echt lang
        test_bit_second = 2048
        for _ in range(5):
            p = get_prime_number(test_bit_second//2)
            q = get_prime_number(test_bit_second//2)
            self.assertTrue(is_prime(p))
            self.assertTrue(is_prime(q))

    def test_get_n(self):
        self.assertEqual(get_n(3, 7), 7 * 3)
        self.assertEqual(get_n(5, 12), 5 * 12)
        self.assertEqual(get_n(7, 20), 20 * 7)
        self.assertEqual(get_n(17, 3120), 3120 * 17)
        self.assertEqual(get_n(65537, 3120),65537* 3120)
        self.assertEqual(get_n(35, 48), 35 * 48)
        self.assertEqual(get_n(240, 509), 240 * 509)
        self.assertEqual(get_n(41, 77), 41 * 77)
        self.assertEqual(get_n(1, 7), 7)
        self.assertEqual(get_n(6, 7), 6* 7)

    def test_get_phi_n(self):
        self.assertEqual(get_totient(3, 7), (3 - 1) * (7 - 1))
        self.assertEqual(get_totient(5, 12), (5 - 1) * (12 - 1))
        self.assertEqual(get_totient(7, 20), (7 - 1) * (20 - 1))
        self.assertEqual(get_totient(17, 3120), (17 - 1) * (3120 - 1))
        self.assertEqual(get_totient(65537, 3120), (65537 - 1) * (3120 - 1))
        self.assertEqual(get_totient(35, 48), (35 - 1) * (48 - 1))
        self.assertEqual(get_totient(240, 509), (240 - 1) * (509 - 1))
        self.assertEqual(get_totient(41, 77), (41 - 1) * (77 - 1))
        self.assertEqual(get_totient(1, 7), (1-1) * (7-1))
        self.assertEqual(get_totient(6, 7),(6-1) * (7-1))
        self.assertEqual(get_totient(4, 8), (4-1) * (8-1))
        self.assertEqual(get_totient(6, 9), (6-1) * (9-1))
        self.assertEqual(get_totient(41, 77), (41-1) * (77-1))


    def test_get_d(self):
        # Basic cases
        self.assertEqual(get_d(3, 7), 5)  # 3 * 5 % 7 == 1
        self.assertEqual(get_d(5, 12), 5)  # 5 * 5 % 12 == 1
        self.assertEqual(get_d(7,20),3) # zie yt van codetheorie

        # Cryptographic examples
        self.assertEqual(get_d(17, 3120), 2753)  # Example RSA values
        self.assertEqual(get_d(65537, 3120), 2753)  # Common RSA e = 65537

        # Larger values
        self.assertEqual(get_d(35, 48), 11)  # 35 * 11 % 48 == 1
        self.assertEqual(get_d(240, 509), 193)  # 240 * 193 % 509 == 1

        # Modular inverse when e is close to phi(n)
        self.assertEqual(get_d(41, 77), 62)  # 41 * 4 % 77 == 1

        # EDGE CASES
        # Modular inverse of 1 is always 1
        self.assertEqual(get_d(1, 7), 1)

        # Modular inverse of e = phi(n) - 1
        self.assertEqual(get_d(6, 7), 6)  # 6 * 6 % 7 == 1

        # Non-coprime inputs should raise an exception
        with self.assertRaises(ValueError):
            get_d(4, 8)  # gcd(4, 8) != 1
        with self.assertRaises(ValueError):
            get_d(6, 9)  # gcd(6, 9) != 1

if __name__ == '__main__':
    unittest.main()
