@call ..\..\bin\jython_coll_253.bat %~n0.py %*
REM
REM To launch the TADDM jython environment, the first line should point to the 
REM jython_coll script in the $COLLATION_HOME/bin directory. 
REM Use the relative location of the directory to initialize the environment.
REM
REM If for example, the script is stored in %COLLATION_HOME%\custom\bin
REM use the following path to launch the jython interpreter and initiate the TADDM environment
REM	../../dist/bin/jython_coll_253.bat 
REM
REM If the script is stored in %COLLATION_HOME%/bin
REM use the following path to launch the jython interpreter and initiate the TADDM environment
REM	.\jython_coll_253

