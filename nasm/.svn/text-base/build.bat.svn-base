@echo off

set NAME=Rosetta

if exist %NAME%.obj del %NAME%.obj
if exist %NAME%.exe del %NAME%.exe
if exist copy.exe del copy.exe
if exist hello.exe del hello.exe

\masm32\bin\ml /c /coff /nologo %NAME%.asm
\masm32\bin\link /SUBSYSTEM:WINDOWS /SUBSYSTEM:CONSOLE %NAME%.obj > nul

copy safe\hello.exe hello.exe

dir %NAME%.*

pause
