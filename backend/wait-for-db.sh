#!/bin/bash

host="$1"
port="$2"
shift 2
cmd="$@"

until nc -z "$host" "$port"; do
  echo "Database not ready yet, waiting..."
  sleep 1
done

echo "Database is ready! Starting application..."
exec $cmd
