#!/bin/bash
# コンテナ内の az CLI をサービスプリンシパルでログインさせる。
# 値は ar.ps1 が .env から渡す ARM_* 環境変数。ログイン情報はボリューム aar-azure に残る。
#   .\ar.ps1 bash /work/docker/sp-login.sh
set -euo pipefail

for v in ARM_CLIENT_ID ARM_CLIENT_SECRET ARM_TENANT_ID ARM_SUBSCRIPTION_ID; do
  if [ -z "${!v:-}" ]; then
    echo "ERROR: $v is empty. Check .env at the repo root." >&2
    exit 1
  fi
done

# --password= 形式にするのは、シークレットが '-' で始まるとオプション扱いされるため（az の公式注意書き）
az login --service-principal \
  --username "$ARM_CLIENT_ID" \
  --password="$ARM_CLIENT_SECRET" \
  --tenant "$ARM_TENANT_ID" \
  --output none
az account set --subscription "$ARM_SUBSCRIPTION_ID"
az account show --query "{subscription:name, id:id, user:user.name, type:user.type}" -o table
