@echo off
echo ====================================================
echo   CONFIGURING WINDOWS VM FIREWALL FOR PORT 9999
echo ====================================================
echo.
echo Running firewall configuration...
netsh advfirewall firewall add rule name="Allow Client Port 9999" dir=in action=allow protocol=TCP localport=9999
echo.
echo Firewall rule added successfully! Port 9999 is now open.
echo.
pause
