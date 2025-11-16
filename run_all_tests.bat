@echo off
echo ========================================
echo Running All Automated Tests
echo ========================================
echo.
echo Make sure server is running first!
echo Press any key to continue...
pause

cd /d "%~dp0"

echo.
echo Test 1: Invalid Certificate Test
echo ========================================
python test_invalid_cert.py
echo.
echo Press any key to continue to next test...
pause

echo.
echo Test 2: Tampering Test
echo ========================================
python test_tampering_client.py
echo.
echo Press any key to continue to next test...
pause

echo.
echo Test 3: Replay Test
echo ========================================
python test_replay_client.py
echo.
echo All automated tests completed!
pause


