#!/bin/bash
# ==============================================================================
# AUTOMATED CURL TEST RUNNER FOR NTAG 424 DNA SERVER BACKEND
# Progetto: Ntag424SdmFeature
# Usage: ./server/tests/run_curl_tests.sh [TARGET_URL]
# ==============================================================================

SERVER_URL="${1:-https://logicarts.altervista.org/verify.php}"

echo "=========================================================================="
echo "RUNNING AUTOMATED CURL TESTS AGAINST: ${SERVER_URL}"
echo "=========================================================================="

echo -e "\n[TEST 1] Missing Parameters Test..."
curl -s -X GET "${SERVER_URL}?json=1" -H "Accept: application/json"

echo -e "\n\n[TEST 2] Corrupt / Invalid CMAC Test..."
curl -s -X GET "${SERVER_URL}?picc_data=00112233445566778899aabbccddeeff&cmac=0011223344556677&json=1" -H "Accept: application/json"

echo -e "\n\n[TEST 3] Execute Full PHP Test Suite Runner..."
php "$(dirname "$0")/run_tests.php" --url="${SERVER_URL}"

echo -e "\n=========================================================================="
echo "TEST SUITE COMPLETE."
echo "=========================================================================="
