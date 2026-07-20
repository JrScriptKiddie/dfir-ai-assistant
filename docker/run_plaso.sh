#!/bin/bash
# Скрипт запуска plaso-пайплайна внутри контейнера
# Аргументы: $1 = case_id
# Монтирование (снаружи):
#   /evidence -> data/triage/<case_id> (read-only)
#   /output   -> data/timelines/<case_id> (read-write)

set -euo pipefail

CASE_ID="${1:?case_id required}"
EVIDENCE_DIR="/evidence"
OUTPUT_DIR="/output"
PLASO_FILE="${OUTPUT_DIR}/${CASE_ID}.plaso"
TIMELINE_JSONL="${OUTPUT_DIR}/${CASE_ID}.timeline.jsonl"
STATS_FILE="${OUTPUT_DIR}/${CASE_ID}.pinfo.txt"

PARSERS="${PLASO_PARSERS:-winevtx,winreg,prefetch,filestat}"
VSS="${PLASO_VSS:-none}"

echo "[plaso] case_id=${CASE_ID}"
echo "[plaso] evidence=${EVIDENCE_DIR}"
echo "[plaso] output=${OUTPUT_DIR}"
echo "[plaso] parsers=${PARSERS} vss=${VSS}"

# 1. log2timeline
LOG2TL_ARGS="--storage-file ${PLASO_FILE} --parsers ${PARSERS}"
if [ "${VSS}" != "none" ]; then
  LOG2TL_ARGS="${LOG2TL_ARGS} --vss_stores ${VSS}"
fi
LOG2TL_ARGS="${LOG2TL_ARGS} ${EVIDENCE_DIR}"

echo "[plaso] running log2timeline.py ${LOG2TL_ARGS}"
log2timeline.py ${LOG2TL_ARGS}

# 2. pinfo (статистика)
echo "[plaso] running pinfo.py"
pinfo.py ${PLASO_FILE} > "${STATS_FILE}"

# 3. psort -> JSONL
echo "[plaso] running psort.py -> JSON line"
psort.py -o json_line -w "${TIMELINE_JSONL}" ${PLASO_FILE}

# 4. Контрольная сумма выхода
echo "[plaso] computing sha256 of timeline"
sha256sum "${TIMELINE_JSONL}" > "${TIMELINE_JSONL}.sha256"

echo "[plaso] done. timeline: ${TIMELINE_JSONL}"
ls -lh "${OUTPUT_DIR}"