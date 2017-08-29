@echo off
schtasks /create /sc minute /mo 30 /tn "´úÀíIP³Ø" /tr "F:\Tests\ipproxy\IP_Proxy_Spider.py"
pause