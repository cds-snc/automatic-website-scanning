#!/bin/bash

set -e pipefail

if [ ! -f "catalog-info.yaml" ]; then
  echo "Error: catalog-info.yaml not found"
  exit 1
fi

# Parse catalog-info.yaml
KIND=$(grep '^kind:' catalog-info.yaml | cut -d':' -f2 | sed 's/ //g')
NAME=$(grep '^  name:' catalog-info.yaml | cut -d':' -f2 | sed 's/ //g')
NAMESPACE=$(grep '^  namespace:' catalog-info.yaml | cut -d':' -f2 | sed 's/ //g')

# Use default namespace if not specified
if [ -z "$NAMESPACE" ]; then
  NAMESPACE="default"
fi

# return the kind, name and namespace in a format <Namespace/Kind/Name>
echo "$NAMESPACE/$KIND/$NAME"
