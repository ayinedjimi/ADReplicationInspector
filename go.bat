@echo off
echo ========================================
echo AD Replication Inspector - Compilation
echo Ayi NEDJIMI Consultants
echo ========================================
echo.

cl.exe /EHsc /std:c++17 /W4 /Fe:ADReplicationInspector.exe ADReplicationInspector.cpp ^
    activeds.lib adsiid.lib netapi32.lib wevtapi.lib comctl32.lib ole32.lib oleaut32.lib user32.lib gdi32.lib /link /SUBSYSTEM:WINDOWS

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation reussie!
    echo Executable: ADReplicationInspector.exe
    echo.
    echo Lancement...
    ADReplicationInspector.exe
) else (
    echo.
    echo Erreur de compilation!
    pause
)
