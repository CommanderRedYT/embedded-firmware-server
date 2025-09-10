#!/bin/bash
ARGS=$@

# check that arguments are provided
if [ -z "$ARGS" ]; then
  echo "No arguments provided. Usage: ./run.sh <arguments>"
  exit 1
fi

docker-compose -f docker-compose.yml exec firmware-server /bin/sh -c "cd /app && yarn start $ARGS"
