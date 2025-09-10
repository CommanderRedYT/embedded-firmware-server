#!/bin/bash
ARGS=$@

# if no args, default to "--help"
if [ -z "$ARGS" ]; then
  ARGS="--help"
fi

docker-compose -f docker-compose.yml exec firmware-server /bin/sh -c "cd /app && node_modules/.bin/tsx src/index.ts $ARGS"
