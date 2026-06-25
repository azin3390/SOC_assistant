#!/bin/bash
kill -9 $(lsof -ti:5002) 2>/dev/null
sleep 1
cd /Users/aziniftikhar/soc_assistant/backend
python3 app.py &
sleep 12
open -a "Google Chrome" /Users/aziniftikhar/soc_assistant/frontend/index.html
