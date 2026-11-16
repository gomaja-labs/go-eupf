#!/bin/env sh

# No filesystem mounts are needed; maps live for the lifetime of their owners.
# Replace the shell to preserve signal handling and forward arguments.
exec /app/bin/eupf "$@"
