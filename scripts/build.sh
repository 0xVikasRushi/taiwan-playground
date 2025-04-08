#!/bin/bash

set -e

run_circom_pipeline() {
  local circuit=$1
  echo "🚀 Processing circuit: $circuit"
  npx circomkit compile "$circuit"
  npx circomkit setup "$circuit"
  npx circomkit prove "$circuit" default
  npx circomkit verify "$circuit" default
  echo "✅ Done with $circuit"
  echo ""
}

if [ $# -eq 0 ]; then
  echo "Usage: bash build <matcher|es256|jwt|all>"
  exit 1
fi

case "$1" in
  matcher)
    run_circom_pipeline matcher
    ;;
  es256)
    run_circom_pipeline es256
    ;;
  jwt)
    run_circom_pipeline jwt
    ;;
  all)
    run_circom_pipeline matcher
    run_circom_pipeline es256
    run_circom_pipeline jwt
    ;;
  *)
    echo "❌ Unknown option: $1"
    echo "Usage: bash build <matcher|es256|jwt|all>"
    exit 1
    ;;
esac
