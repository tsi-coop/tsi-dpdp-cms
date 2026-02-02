@echo off
setlocal

title TSI DPDP CMS
:: Check if .env file exists
if not exist ".env" (
    echo Error: .env file not found. Please create it.
    exit /b 1
)

:: Parse .env file line by line
:: /F "tokens=1* delims==" means:
:: - read each line
:: - "tokens=1*" splits the line at the first '='
::   - token 1 gets the part before '=' (the variable name)
::   - token * gets all the rest of the line (the value), including spaces
:: - "delims==" specifies that '=' is the delimiter
for /f "tokens=1* delims==" %%A in (.env) do (
    :: Check if the line is not empty and not a comment (starts with #)
    if not "%%A"=="" (
        if not "%%A"=="::" (
            if not "%%A"=="#" (
                :: Set the environment variable
                set "%%A=%%B"
            )
        )
    )
)

set JAVA_HOME=%JAVA_HOME%
set TSI_DPDP_CMS_ENV=%TSI_DPDP_CMS_ENV%
set TSI_DPDP_CMS_HOME=%TSI_DPDP_CMS_HOME%
set POSTGRES_HOST=%POSTGRES_HOST%
set POSTGRES_DB=%POSTGRES_DB%
set POSTGRES_USER=%POSTGRES_USER%
set POSTGRES_PASSWD=%POSTGRES_PASSWD%
set JETTY_HOME=%JETTY_HOME%
set JETTY_BASE=%JETTY_BASE%
set TSI_EXPORT_PATH=%TSI_EXPORT_PATH%
copy %TSI_DPDP_CMS_HOME%\target\tsi_dpdp_cms.war %JETTY_BASE%\webapps\ROOT.war >NUL
java -jar %JETTY_HOME%/start.jar
