@echo off
IF "%SDKROOT%"=="" ( 
	ECHO SDKROOT is not defined. Please set it to the root directory of the IDA SDK.
	exit /b
)

PUSHD win32
msbuild
POPD
