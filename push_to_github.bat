@echo off
cd /d "%~dp0"
echo ========================================================
echo  Pushing WebTrust to https://github.com/vishnub-lab/webtrust
echo ========================================================
echo.
git push -u origin main
echo.
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] WebTrust was successfully pushed to GitHub!
) else (
    echo.
    echo [ERROR] Push failed. 
    echo If you haven't created the repository on GitHub yet, please create it at:
    echo https://github.com/new (Repository name: webtrust)
    echo.
)
echo.
pause
