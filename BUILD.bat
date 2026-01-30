@echo off
title NetWatch Pro - EXE Builder

echo.
echo ============================================================
echo   NetWatch Pro - Automatischer EXE Builder
echo ============================================================
echo.

REM Pruefe ob Python installiert ist
python --version >nul 2>&1
if errorlevel 1 (
    echo [FEHLER] Python wurde nicht gefunden!
    echo.
    echo Bitte installiere Python 3.8+ von: https://www.python.org/downloads/
    echo WICHTIG: Bei Installation "Add Python to PATH" aktivieren!
    echo.
    pause
    exit /b 1
)

echo [OK] Python gefunden
echo.

REM Installiere PyInstaller
echo [INFO] Installiere PyInstaller...
python -m pip install --upgrade pip --quiet
python -m pip install pyinstaller --quiet

if errorlevel 1 (
    echo [FEHLER] Konnte PyInstaller nicht installieren
    pause
    exit /b 1
)

echo [OK] PyInstaller installiert
echo.

REM Baue die EXE
echo [INFO] Baue NetWatchPro.exe...
echo [INFO] Dies kann 1-2 Minuten dauern...
echo.

python -m PyInstaller --onefile --windowed --name=NetWatchPro --clean netwatch_pro.py

if errorlevel 1 (
    echo.
    echo [FEHLER] Build fehlgeschlagen!
    pause
    exit /b 1
)

REM Aufraeumen
echo.
echo [INFO] Raeume auf...
rmdir /s /q build 2>nul
del NetWatchPro.spec 2>nul

REM Pruefe ob EXE erstellt wurde
if exist "dist\NetWatchPro.exe" (
    echo.
    echo ============================================================
    echo   BUILD ERFOLGREICH!
    echo ============================================================
    echo.
    echo [OK] NetWatchPro.exe wurde erstellt!
    echo [INFO] Pfad: %CD%\dist\NetWatchPro.exe
    echo.
    echo Du kannst die EXE jetzt auf andere PCs kopieren
    echo und dort ohne Python-Installation starten!
    echo.
    echo WICHTIG: Nur im eigenen Netzwerk verwenden!
    echo.
    echo ============================================================
) else (
    echo [FEHLER] NetWatchPro.exe wurde nicht gefunden!
)

echo.
pause
