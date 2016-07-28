@echo off
if exist loli.exe del loli.exe
copy safe\hello.exe loli.exe

if exist victim.exe del victim.exe
copy	victim\victim.exe victim.exe