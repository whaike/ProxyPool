@echo off
set /p s="请输入要结束的任务计划名称:"
SCHTASKS /Delete /TN %s%
echo "任务计划结束成功!"
pause