#!/bin/sh

echo "Starting sandbox test..."

# Static-analysis test data
# URL: http://example.com/test
# IP: 192.168.1.100
# Suspicious keyword: wget

echo "Testing child process execution..."

sh -c 'echo "Child process started" && sh -c "echo Grandchild process started && sleep 1"'

echo "Sandbox test complete."
