#!/bin/bash
LOG_FILE="/var/log/auth.log"
THRESHOLD=3
ALERT_EMAIL="your_email@example.com"
FAILED_COUNT=$(grep "User authentication failed" $LOG_FILE | tail -n 10 | wc -l)
if [ "$FAILED_COUNT" -ge "$THRESHOLD" ]; then
echo "Multiple authentication failures detected!" | mail -s "Authentication Alert" "$ALERT_EMAIL"
fi
