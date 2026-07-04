#!/usr/bin/env bash
# Manage the SOAR platform compose stacks by component.
#
# Examples:
#   scripts/soarctl.sh start thehive
#   scripts/soarctl.sh recreate misp --service db --service misp-core
#   scripts/soarctl.sh destroy all --yes
#   scripts/soarctl.sh destroy all --volumes --yes
#   scripts/soarctl.sh logs shuffle --tail 200 --follow
#   scripts/soarctl.sh doctor all
#
# All actions are best-effort across multiple targets: if one stack fails
# (missing directory, missing .env, docker error, declined confirmation),
# soarctl reports it and keeps going with the remaining targets, then exits
# non-zero with a summary at the end.

set -uo pipefail

ROOT="${SOAR_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
DEPLOY_DIR="${SOAR_DEPLOY_DIR:-$ROOT/deploy/soar}"
THEHIVE_DIR="${SOAR_THEHIVE_DIR:-$DEPLOY_DIR/thehive/testing}"
MISP_DIR="${SOAR_MISP_DIR:-$DEPLOY_DIR/misp}"
SHUFFLE_DIR="${SOAR_SHUFFLE_DIR:-$DEPLOY_DIR/shuffle}"
WAZUH_MODE="${SOAR_WAZUH_MODE:-single-node}"
WAZUH_DIR="${SOAR_WAZUH_DIR:-$DEPLOY_DIR/wazuh/$WAZUH_MODE}"
ORCHESTRATOR_DIR="${SOAR_ORCHESTRATOR_DIR:-$DEPLOY_DIR/orchestrator}"
WAZUH_MANAGER_DIR="${SOAR_WAZUH_MANAGER_DIR:-$DEPLOY_DIR/wazuh-manager}"

USE_SUDO="${SOAR_USE_SUDO:-1}"
SKIP_ENV_CHECK="${SOAR_SKIP_ENV_CHECK:-0}"
MANAGE_SWAP="${SOAR_SHUFFLE_MANAGE_SWAP:-1}"
# Filter the benign "<VAR> is not set. Defaulting to a blank string." noise the
# vendored MISP/TheHive compose files emit. Set 0 to see everything.
QUIET_COMPOSE_WARNINGS="${SOAR_QUIET_COMPOSE_WARNINGS:-1}"

# misp's stack predates the deploy/soar/ reorg and was originally brought up
# from a directory literally named misp-docker, so its already-running
# containers/volumes/networks carry project label "misp-docker". Compose's
# default project name is the basename of --project-directory ("misp" here),
# so without this override every compose call against misp silently targets
# an empty, never-created "misp" project while the real stack runs
# untouched. Override it explicitly so soarctl attaches to what's actually
# deployed instead of a phantom project of the same name as the directory.
MISP_PROJECT_NAME="${SOAR_MISP_PROJECT_NAME:-misp-docker}"

ACTION=""
TARGETS=()
SERVICES=()
DRY_RUN=0
YES=0
INCLUDE_RUNNING=0
WITH_VOLUMES=0
WITH_BUILD=0
WITH_PULL=0
WITH_MISP_GUARD=0
FOLLOW=0
TAIL=100

usage() {
  cat <<'EOF'
Usage:
  scripts/soarctl.sh ACTION TARGET... [options]

Actions:
  start       sudo docker compose up -d
  stop        sudo docker compose stop
  restart     sudo docker compose restart
  recreate    sudo docker compose up -d --force-recreate
  destroy     sudo docker compose down --remove-orphans
  cleanup     Remove stopped/stale containers for the selected target
  status      sudo docker compose ps
  logs        sudo docker compose logs
  config      sudo docker compose config --quiet
  doctor      Check each target's directory/compose file/.env without touching docker

Targets:
  thehive       deploy/soar/thehive/testing
  misp          deploy/soar/misp
  shuffle       deploy/soar/shuffle
  wazuh-manager deploy/soar/wazuh-manager (manager-ONLY; the on-demand
                Active-Response enforcement channel — this is the one you want)
  orchestrator  deploy/soar/orchestrator (SOAR orchestrator; reads the
                detection Postgres alerts contract cross-machine)
  wazuh         deploy/soar/wazuh/<mode> — FULL Wazuh SIEM (manager + indexer +
                dashboard). HEAVY (indexer wants 2-4GB) and OPTIONAL: only for a
                future log/event-context (SIEM) role. NOT in `all`; start it
                explicitly and only if the host has the memory. For enforcement
                use `wazuh-manager`, not this.
  core          thehive + misp + shuffle
  all           thehive + misp + shuffle + wazuh-manager
                (orchestrator and the full `wazuh` SIEM are intentionally NOT in
                core/all — start those explicitly)

Options:
  --service NAME       Limit the action to one compose service. Repeatable.
  --services "A B"     Limit the action to several compose services.
  --wazuh-mode MODE    Wazuh compose directory: single-node, multi-node, wazuh-agent.
  --with-misp-guard    Include the MISP misp-guard compose profile.
  --build              Add --build to start/recreate.
  --pull               Run docker compose pull before start/recreate.
  --include-running    With cleanup shuffle, also remove running Shuffle app/worker containers.
  --volumes            With destroy, remove named volumes too.
  -y, --yes            Do not prompt before destroy/cleanup.
  -n, --dry-run         Print commands without running them (validation still runs).
  --tail N             Log lines for logs action. Default: 100.
  -f, --follow         Follow logs.
  -h, --help           Show this help.

Environment overrides:
  SOAR_ROOT                  repo root (default: parent of scripts/)
  SOAR_DEPLOY_DIR            vendored stacks root (default: $SOAR_ROOT/deploy/soar)
  SOAR_THEHIVE_DIR           override TheHive compose dir
  SOAR_MISP_DIR               override MISP compose dir
  SOAR_SHUFFLE_DIR            override Shuffle compose dir
  SOAR_WAZUH_DIR              override Wazuh compose dir
  SOAR_WAZUH_MODE             single-node | multi-node | wazuh-agent (default: single-node)
  SOAR_ORCHESTRATOR_DIR       override orchestrator compose dir
  SOAR_USE_SUDO               1 to prefix docker commands with sudo (default: 1; ignored if already root)
  SOAR_QUIET_COMPOSE_WARNINGS  1 to hide the benign "<VAR> is not set" compose noise (default: 1; set 0 to show)
  SOAR_SKIP_ENV_CHECK         1 to proceed even if a stack's required .env is missing (default: 0)
  SOAR_SHUFFLE_MANAGE_SWAP    1 to let soarctl swapoff before starting Shuffle (default: 1)

Multiple targets are best-effort: a failure on one target is reported and the
remaining targets still run. soarctl exits non-zero if any target failed.

Examples:
  scripts/soarctl.sh start core
  scripts/soarctl.sh start all --with-misp-guard
  scripts/soarctl.sh recreate thehive --service cassandra --service elasticsearch
  scripts/soarctl.sh recreate misp --services "db misp-core misp-modules"
  scripts/soarctl.sh cleanup shuffle --yes
  scripts/soarctl.sh cleanup shuffle --include-running --yes
  scripts/soarctl.sh destroy shuffle --yes
  scripts/soarctl.sh destroy all --volumes --yes
  scripts/soarctl.sh doctor all
EOF
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

fail() {
  echo "ERROR: $*" >&2
  return 1
}

log() {
  echo
  echo "=== $* ==="
}

run() {
  echo "+ $*"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    "$@"
  fi
}

sdo() {
  if [[ "$USE_SUDO" -eq 1 && "$(id -u)" -ne 0 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

stack_dir() {
  case "$1" in
    thehive) printf '%s\n' "$THEHIVE_DIR" ;;
    misp) printf '%s\n' "$MISP_DIR" ;;
    shuffle) printf '%s\n' "$SHUFFLE_DIR" ;;
    wazuh) printf '%s\n' "$WAZUH_DIR" ;;
    orchestrator) printf '%s\n' "$ORCHESTRATOR_DIR" ;;
    wazuh-manager) printf '%s\n' "$WAZUH_MANAGER_DIR" ;;
    *) die "Unknown target: $1" ;;
  esac
}

# Both of these write to the global EXPANDED_TARGETS array directly instead
# of printing to stdout for `mapfile < <(...)` to capture: a process
# substitution runs in its own subshell, so a `die` (exit) inside it would
# only kill that subshell — mapfile would still report success and the
# script would carry on with an empty/partial target list instead of
# actually stopping on an invalid target.
expand_targets() {
  local target
  local expanded=()
  for target in "$@"; do
    case "$target" in
      # `all` brings up the lean enforcement manager (wazuh-manager), NOT the
      # heavy full Wazuh SIEM stack (`wazuh`), which would OOM a memory-tight host.
      all) expanded+=(thehive misp shuffle wazuh-manager) ;;
      core) expanded+=(thehive misp shuffle) ;;
      thehive|misp|shuffle|wazuh|wazuh-manager|orchestrator) expanded+=("$target") ;;
      *) die "Unknown target: $target" ;;
    esac
  done

  local seen=" "
  local unique=()
  for target in "${expanded[@]}"; do
    if [[ "$seen" != *" $target "* ]]; then
      unique+=("$target")
      seen+="$target "
    fi
  done

  EXPANDED_TARGETS=("${unique[@]}")
}

reverse_targets() {
  local -a items=("$@")
  EXPANDED_TARGETS=()
  local i
  for ((i=${#items[@]}-1; i>=0; i--)); do
    EXPANDED_TARGETS+=("${items[$i]}")
  done
}

# ── Preflight: catch missing dirs/compose files/.env before docker compose ──

detect_compose_file() {
  local dir="$1"
  local f
  for f in docker-compose.yml compose.yml compose.yaml; do
    if [[ -f "$dir/$f" ]]; then
      printf '%s\n' "$f"
      return 0
    fi
  done
  return 1
}

find_env_template() {
  local dir="$1"
  local f
  for f in .env.example .env.template dot.env.template template.env env.template example.env; do
    if [[ -f "$dir/$f" ]]; then
      printf '%s\n' "$f"
      return 0
    fi
  done
  return 1
}

# True if the compose file has at least one ${VAR} interpolation with no
# default (${VAR:-x}) — i.e. docker compose needs a real value from somewhere,
# normally the stack's own .env. This is how we catch a missing .env before
# docker compose silently substitutes blank strings and fails on a cryptic
# "invalid spec" volume error.
stack_requires_env_file() {
  grep -qE '\$\{[A-Za-z_][A-Za-z0-9_]*\}' "$1"
}

preflight_stack() {
  local stack="$1"
  local dir="$2"
  local compose_file

  if [[ ! -d "$dir" ]]; then
    fail "$stack: directory does not exist: $dir"
    return 1
  fi

  if ! compose_file="$(detect_compose_file "$dir")"; then
    fail "$stack: no compose file (docker-compose.yml/compose.yml/compose.yaml) in $dir"
    return 1
  fi

  if [[ ! -f "$dir/.env" ]] && stack_requires_env_file "$dir/$compose_file"; then
    if [[ "$SKIP_ENV_CHECK" -eq 1 ]]; then
      echo "WARNING: $stack: $dir/.env is missing but SOAR_SKIP_ENV_CHECK=1; proceeding anyway." >&2
    else
      local template=""
      template="$(find_env_template "$dir" || true)"
      {
        echo "$stack requires $dir/.env but it does not exist."
        echo "Without it, docker compose substitutes blank values for every variable"
        echo "the file would normally provide, and the command fails unpredictably."
        if [[ -n "$template" ]]; then
          echo "A template is available: cp $dir/$template $dir/.env   (then edit the values)"
        else
          echo "No template found in $dir; check its README for how to generate .env."
        fi
        echo "To proceed anyway: SOAR_SKIP_ENV_CHECK=1 scripts/soarctl.sh ..."
      } >&2
      fail "$stack: missing required .env"
      return 1
    fi
  fi

  printf '%s\n' "$compose_file"
}

compose() {
  local stack="$1"
  shift

  local dir
  dir="$(stack_dir "$stack")" || return 1

  local compose_file
  compose_file="$(preflight_stack "$stack" "$dir")" || return 1

  local -a cmd=()
  if [[ "$USE_SUDO" -eq 1 && "$(id -u)" -ne 0 ]]; then
    # `sudo` strips PWD; pass it through so compose files that reference ${PWD}
    # (e.g. TheHive's cortex_docker_job_directory=${PWD}/...) resolve correctly
    # instead of warning + defaulting to a blank/wrong path.
    cmd+=(sudo env "PWD=$dir")
  fi
  # --progress plain: the stderr filter below pipes compose's output, which
  # breaks its TTY progress renderer into staircase garbage; plain mode emits
  # clean one-line-per-event output that survives the pipe.
  cmd+=(docker compose --progress plain -f "$dir/$compose_file" --project-directory "$dir" -p "$(compose_project_name "$stack")")
  if [[ "$stack" == "misp" && "$WITH_MISP_GUARD" -eq 1 ]]; then
    cmd+=(--profile misp-guard)
  fi

  log "$stack ($dir)"
  (
    cd "$dir" || exit 1
    if [[ "$QUIET_COMPOSE_WARNINGS" -eq 1 ]]; then
      # Drop only the benign "variable is not set. Defaulting to a blank string."
      # noise (vendored MISP/TheHive compose files reference many optional vars).
      # All other stderr (real warnings/errors) passes through unchanged.
      run "${cmd[@]}" "$@" 2> >(grep -vE 'variable is not set\. Defaulting to a blank string\.' >&2)
    else
      run "${cmd[@]}" "$@"
    fi
  ) || { fail "$stack: command failed"; return 1; }
}

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    local secret=""
    while [[ "${#secret}" -lt 48 ]]; do
      secret+="$(tr -dc A-Za-z0-9 </dev/urandom | head -c $((48 - ${#secret})) || true)"
    done
    printf '%s\n' "$secret"
  fi
}

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  local secret="${4:-0}"
  local display="$value"
  [[ "$secret" -eq 1 ]] && display="<redacted>"

  echo "+ set $key=$display in $file"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if grep -q "^${key}=" "$file"; then
      sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
      printf "\n%s=%s\n" "$key" "$value" >> "$file"
    fi
  fi
}

shuffle_prepare_env() {
  local env_file="$SHUFFLE_DIR/.env"
  [[ -f "$env_file" ]] || return 0

  local replicas=""
  replicas="$(grep -E "^SHUFFLE_APP_REPLICAS=" "$env_file" | tail -1 | cut -d= -f2- || true)"
  replicas="${replicas//\"/}"
  replicas="${replicas// /}"
  if [[ -z "$replicas" || "$replicas" != "1" ]]; then
    set_env_value "$env_file" SHUFFLE_APP_REPLICAS 1 0
  fi

  local modifier=""
  modifier="$(grep -E "^SHUFFLE_ENCRYPTION_MODIFIER=" "$env_file" | tail -1 | cut -d= -f2- || true)"
  modifier="${modifier//\"/}"
  modifier="${modifier// /}"
  if [[ -z "$modifier" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      set_env_value "$env_file" SHUFFLE_ENCRYPTION_MODIFIER "<generated>" 1
    else
      set_env_value "$env_file" SHUFFLE_ENCRYPTION_MODIFIER "$(random_secret)" 1
    fi
  fi
}

shuffle_pre_start() {
  log "shuffle pre-start maintenance"

  preflight_stack shuffle "$SHUFFLE_DIR" >/dev/null || return 1
  shuffle_prepare_env || return 1

  run mkdir -p "$SHUFFLE_DIR/shuffle-database"
  run sdo chown -R 1000:1000 "$SHUFFLE_DIR/shuffle-database" || return 1

  if [[ "$MANAGE_SWAP" -eq 1 ]]; then
    if [[ "$DRY_RUN" -eq 1 || -n "$(sdo swapon --show 2>/dev/null || true)" ]]; then
      echo "Swap is enabled; OpenSearch's bootstrap check requires it off."
      echo "Disabling now (set SOAR_SHUFFLE_MANAGE_SWAP=0 to manage swap yourself)."
      run sdo swapoff -a || return 1
    fi
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    run sdo docker restart shuffle-opensearch
  elif sdo docker ps -a --format "{{.Names}}" | grep -Fxq shuffle-opensearch; then
    run sdo docker restart shuffle-opensearch || return 1
  else
    echo "shuffle-opensearch does not exist yet; skipping restart before first start."
  fi
}

shuffle_container_health() {
  local name="$1"
  sdo docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" "$name" 2>/dev/null || true
}

shuffle_wait_healthy() {
  local name="$1"
  local timeout="${2:-420}"
  local elapsed=0
  local status=""

  echo "+ wait for $name to become healthy (timeout ${timeout}s)"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    return 0
  fi

  while [[ "$elapsed" -lt "$timeout" ]]; do
    status="$(shuffle_container_health "$name")"
    if [[ "$status" == "healthy" ]]; then
      echo "$name is healthy."
      return 0
    fi
    if [[ "$status" == "exited" || "$status" == "dead" ]]; then
      sdo docker logs --tail 80 "$name" || true
      fail "$name is $status while waiting for health"
      return 1
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done

  sdo docker logs --tail 120 "$name" || true
  fail "$name did not become healthy within ${timeout}s; last status: ${status:-unknown}"
  return 1
}

shuffle_start_stack() {
  local force_recreate="${1:-0}"
  local -a opensearch_args=(up -d --force-recreate)
  local -a backend_args=(up -d --no-deps)
  local -a app_args=(up -d --no-deps)

  [[ "$force_recreate" -eq 1 ]] && backend_args+=(--force-recreate)
  [[ "$force_recreate" -eq 1 ]] && app_args+=(--force-recreate)
  [[ "$WITH_BUILD" -eq 1 ]] && backend_args+=(--build)
  [[ "$WITH_BUILD" -eq 1 ]] && app_args+=(--build)

  shuffle_pre_start || return 1
  compose shuffle "${opensearch_args[@]}" opensearch || return 1
  shuffle_wait_healthy shuffle-opensearch 420 || return 1
  compose shuffle "${backend_args[@]}" backend || return 1
  shuffle_wait_healthy shuffle-backend 420 || return 1
  compose shuffle "${app_args[@]}" frontend orborus || return 1
}

compose_project_name() {
  local stack="$1"
  if [[ "$stack" == "misp" ]]; then
    printf '%s\n' "$MISP_PROJECT_NAME"
    return 0
  fi
  basename "$(stack_dir "$stack")"
}

stopped_container_ids() {
  local status
  for status in created exited dead; do
    sdo docker ps -aq --filter "status=$status" "$@"
  done | sort -u
}

shuffle_app_container_ids() {
  local include_running="${1:-0}"

  sdo docker ps -a \
    --filter label=com.docker.swarm.service.name \
    --format '{{.ID}}\t{{.State}}\t{{.Image}}\t{{.Names}}' | \
    awk -F '\t' -v include_running="$include_running" '
      function is_shuffle_app(name, image) {
        if (name ~ /^(shuffle-frontend|shuffle-backend|shuffle-opensearch|shuffle-orborus)$/) return 0
        if (name ~ /^(shufflehealthcheck_|shuffle-ai_|shuffle-tools_|shuffle-subflow_|shuffle-workers\.|http_[0-9]|email_[0-9]|wazuh_[0-9])/) return 1
        if (image ~ /^frikky\/shuffle:/) return 1
        if (image == "ghcr.io/shuffle/shuffle-worker:latest" && name ~ /^shuffle-workers\./) return 1
        return 0
      }
      is_shuffle_app($4, $3) {
        if (include_running == 1 || $2 != "running") print $1
      }
    ' | sort -u
}

shuffle_swarm_service_ids() {
  sdo docker service ls --format '{{.ID}}\t{{.Name}}\t{{.Image}}' | \
    awk -F '\t' '
      function is_shuffle_app(name, image) {
        if (name ~ /^(shufflehealthcheck_|shuffle-ai_|shuffle-tools_|shuffle-subflow_|shuffle-workers$|http_[0-9]|email_[0-9]|wazuh_[0-9])/) return 1
        if (image ~ /^frikky\/shuffle:/) return 1
        if (image ~ /^ghcr\.io\/shuffle\/shuffle-worker/) return 1
        return 0
      }
      is_shuffle_app($2, $3) { print $1 }
    ' | sort -u
}

# Shuffle's app/worker containers are backed by Docker Swarm services that
# orborus creates via the Docker API (they carry a
# com.docker.swarm.service.name label) — `docker rm -f`/`docker stop` on the
# task containers is a no-op against the swarm scheduler: it just reschedules
# a replacement task within seconds to satisfy the service's replica count.
# They have to be stopped/removed at the service level instead.
shuffle_stop_swarm_services() {
  local -a ids=()
  mapfile -t ids < <(shuffle_swarm_service_ids)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No Shuffle swarm services found."
    return 0
  fi
  echo "Scaling ${#ids[@]} Shuffle swarm services to 0 replicas..."
  local id
  for id in "${ids[@]}"; do
    run sdo docker service scale "${id}=0" || return 1
  done
}

shuffle_remove_swarm_services() {
  local -a ids=()
  mapfile -t ids < <(shuffle_swarm_service_ids)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No Shuffle swarm services found."
    return 0
  fi
  echo "Removing ${#ids[@]} Shuffle swarm services..."
  run sdo docker service rm "${ids[@]}" || return 1
}

# Fallback for any Shuffle app/worker container that, unlike the swarm-backed
# ones above, isn't tied to a service (e.g. left behind by an older Shuffle
# version) — carries no com.docker.compose.project label, so
# `docker compose stop|down` never touches it either.
shuffle_stop_app_containers() {
  local -a ids=()
  mapfile -t ids < <(shuffle_app_container_ids 1)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No Shuffle app/worker containers found."
    return 0
  fi
  echo "Stopping ${#ids[@]} Shuffle app/worker containers (not managed by compose)..."
  run sdo docker stop "${ids[@]}" || return 1
}

shuffle_remove_app_containers() {
  local -a ids=()
  mapfile -t ids < <(shuffle_app_container_ids 1)
  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No Shuffle app/worker containers found."
    return 0
  fi
  echo "Removing ${#ids[@]} Shuffle app/worker containers (not managed by compose)..."
  run sdo docker rm -f "${ids[@]}" || return 1
}

remove_containers() {
  local description="$1"
  local force="$2"
  shift 2
  local -a ids=("$@")

  if [[ "${#ids[@]}" -eq 0 ]]; then
    echo "No $description found."
    return 0
  fi

  echo "Found ${#ids[@]} $description:"
  sdo docker inspect \
    --format '  {{.Name}} {{.State.Status}} {{.Config.Image}}' \
    "${ids[@]}" || true

  if [[ "$DRY_RUN" -eq 0 && "$YES" -ne 1 ]]; then
    local action="remove"
    [[ "$force" -eq 1 ]] && action="force-remove"
    local reply=""
    read -r -p "$action ${#ids[@]} $description? Type yes to continue: " reply
    if [[ "$reply" != "yes" ]]; then
      echo "Skipped: $description not confirmed."
      return 1
    fi
  fi

  if [[ "$force" -eq 1 ]]; then
    run sdo docker rm -f "${ids[@]}" || return 1
  else
    run sdo docker rm "${ids[@]}" || return 1
  fi
}

cleanup_stack() {
  local stack="$1"
  local project=""
  local -a ids=()
  local status=0

  if [[ "$stack" == "shuffle" ]]; then
    mapfile -t ids < <(shuffle_app_container_ids "$INCLUDE_RUNNING")
    remove_containers "Shuffle app/worker containers" "$INCLUDE_RUNNING" "${ids[@]}" || status=1
  fi

  project="$(compose_project_name "$stack")"
  mapfile -t ids < <(stopped_container_ids --filter "label=com.docker.compose.project=$project")
  remove_containers "$stack stopped compose containers" 0 "${ids[@]}" || status=1

  return "$status"
}

confirm_destroy() {
  local stack="$1"
  [[ "$YES" -eq 1 ]] && return 0

  local volume_msg="keeping volumes"
  [[ "$WITH_VOLUMES" -eq 1 ]] && volume_msg="REMOVING volumes"

  local reply=""
  read -r -p "Destroy $stack containers/networks ($volume_msg)? Type yes to continue: " reply
  if [[ "$reply" != "yes" ]]; then
    echo "Skipped: $stack destroy not confirmed."
    return 1
  fi
}

doctor_stack() {
  local stack="$1"
  local dir compose_file ok=0

  dir="$(stack_dir "$stack")" || return 1
  log "$stack ($dir)"

  if [[ -d "$dir" ]]; then
    echo "  [ok]   directory exists"
  else
    echo "  [FAIL] directory missing: $dir"
    return 1
  fi

  if compose_file="$(detect_compose_file "$dir")"; then
    echo "  [ok]   compose file: $compose_file"
  else
    echo "  [FAIL] no compose file (docker-compose.yml/compose.yml/compose.yaml)"
    ok=1
  fi

  if [[ -n "${compose_file:-}" ]]; then
    if [[ -f "$dir/.env" ]]; then
      echo "  [ok]   .env present"
    elif stack_requires_env_file "$dir/$compose_file"; then
      local template
      template="$(find_env_template "$dir" || true)"
      if [[ -n "$template" ]]; then
        echo "  [FAIL] .env missing (compose file needs it) - template found: $template"
      else
        echo "  [FAIL] .env missing (compose file needs it) - no template found, see README"
      fi
      ok=1
    else
      echo "  [ok]   .env not required by this compose file"
    fi
  fi

  return "$ok"
}

do_stack() {
  local stack="$1"
  local -a svc=("${SERVICES[@]}")

  case "$ACTION" in
    start)
      if [[ "$WITH_PULL" -eq 1 ]]; then
        compose "$stack" pull "${svc[@]}" || return 1
      fi
      if [[ "$stack" == "shuffle" && "${#svc[@]}" -eq 0 ]]; then
        shuffle_start_stack 0 || return 1
        return 0
      fi
      if [[ "$stack" == "shuffle" ]]; then
        shuffle_pre_start || return 1
      fi
      local -a up_args=(up -d)
      [[ "$WITH_BUILD" -eq 1 ]] && up_args+=(--build)
      compose "$stack" "${up_args[@]}" "${svc[@]}" || return 1
      ;;
    stop)
      compose "$stack" stop "${svc[@]}" || return 1
      if [[ "$stack" == "shuffle" && "${#svc[@]}" -eq 0 ]]; then
        shuffle_stop_swarm_services || return 1
        shuffle_stop_app_containers || return 1
      fi
      ;;
    restart)
      compose "$stack" restart "${svc[@]}" || return 1
      ;;
    recreate)
      if [[ "$WITH_PULL" -eq 1 ]]; then
        compose "$stack" pull "${svc[@]}" || return 1
      fi
      if [[ "$stack" == "shuffle" && "${#svc[@]}" -eq 0 ]]; then
        shuffle_start_stack 1 || return 1
        return 0
      fi
      if [[ "$stack" == "shuffle" ]]; then
        shuffle_pre_start || return 1
      fi
      local -a recreate_args=(up -d --force-recreate)
      [[ "${#svc[@]}" -gt 0 ]] && recreate_args+=(--no-deps)
      [[ "$WITH_BUILD" -eq 1 ]] && recreate_args+=(--build)
      compose "$stack" "${recreate_args[@]}" "${svc[@]}" || return 1
      ;;
    cleanup)
      cleanup_stack "$stack" || return 1
      ;;
    destroy)
      confirm_destroy "$stack" || return 1
      local -a down_args=(down --remove-orphans)
      [[ "$WITH_VOLUMES" -eq 1 ]] && down_args+=(-v)
      compose "$stack" "${down_args[@]}" || return 1
      if [[ "$stack" == "shuffle" ]]; then
        shuffle_remove_swarm_services || return 1
        shuffle_remove_app_containers || return 1
      fi
      ;;
    status)
      compose "$stack" ps "${svc[@]}" || return 1
      ;;
    logs)
      local -a log_args=(logs --tail "$TAIL")
      [[ "$FOLLOW" -eq 1 ]] && log_args+=(-f)
      compose "$stack" "${log_args[@]}" "${svc[@]}" || return 1
      ;;
    config)
      compose "$stack" config --quiet || return 1
      ;;
    doctor)
      doctor_stack "$stack" || return 1
      ;;
    *)
      die "Unknown action: $ACTION"
      ;;
  esac
}

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    start|stop|restart|recreate|destroy|cleanup|status|logs|config|doctor)
      [[ -z "$ACTION" ]] || die "Action already set to '$ACTION'"
      ACTION="$1"
      shift
      ;;
    --service)
      [[ $# -ge 2 ]] || die "--service requires a value"
      SERVICES+=("$2")
      shift 2
      ;;
    --services)
      [[ $# -ge 2 ]] || die "--services requires a value"
      read -r -a parsed_services <<< "$2"
      SERVICES+=("${parsed_services[@]}")
      shift 2
      ;;
    --wazuh-mode)
      [[ $# -ge 2 ]] || die "--wazuh-mode requires a value"
      WAZUH_MODE="$2"
      WAZUH_DIR="${SOAR_WAZUH_DIR:-$DEPLOY_DIR/wazuh/$WAZUH_MODE}"
      shift 2
      ;;
    --with-misp-guard)
      WITH_MISP_GUARD=1
      shift
      ;;
    --build)
      WITH_BUILD=1
      shift
      ;;
    --pull)
      WITH_PULL=1
      shift
      ;;
    --include-running)
      INCLUDE_RUNNING=1
      shift
      ;;
    --volumes)
      WITH_VOLUMES=1
      shift
      ;;
    -y|--yes)
      YES=1
      shift
      ;;
    -n|--dry-run)
      DRY_RUN=1
      shift
      ;;
    --tail)
      [[ $# -ge 2 ]] || die "--tail requires a value"
      TAIL="$2"
      [[ "$TAIL" =~ ^[0-9]+$ ]] || die "--tail must be a number"
      shift 2
      ;;
    -f|--follow)
      FOLLOW=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        TARGETS+=("$1")
        shift
      done
      ;;
    -*)
      die "Unknown option: $1"
      ;;
    *)
      TARGETS+=("$1")
      shift
      ;;
  esac
done

[[ -n "$ACTION" ]] || die "Missing action"
[[ "${#TARGETS[@]}" -gt 0 ]] || die "Missing target. Use one of: thehive, misp, shuffle, wazuh, core, all"

case "$WAZUH_MODE" in
  single-node|multi-node|wazuh-agent) ;;
  *) die "Invalid wazuh mode '$WAZUH_MODE' (expected: single-node, multi-node, wazuh-agent)" ;;
esac

if [[ "$INCLUDE_RUNNING" -eq 1 && "$ACTION" != "cleanup" ]]; then
  die "--include-running can only be used with cleanup"
fi

if [[ "$ACTION" == "cleanup" && "${#SERVICES[@]}" -gt 0 ]]; then
  die "--service/--services is not supported with cleanup"
fi

if [[ "${#SERVICES[@]}" -gt 0 && "${#TARGETS[@]}" -ne 1 ]]; then
  die "--service/--services can be used with exactly one target"
fi

if [[ "$ACTION" != "doctor" ]]; then
  command -v docker >/dev/null 2>&1 || die "docker is not installed or not on PATH"
fi

EXPANDED_TARGETS=()
expand_targets "${TARGETS[@]}"

if [[ "$ACTION" == "destroy" || "$ACTION" == "stop" ]]; then
  reverse_targets "${EXPANDED_TARGETS[@]}"
fi

FAILED_TARGETS=()
for target in "${EXPANDED_TARGETS[@]}"; do
  if ! do_stack "$target"; then
    FAILED_TARGETS+=("$target")
    echo "WARNING: $ACTION failed for '$target'; continuing with remaining targets." >&2
  fi
done

if [[ "${#FAILED_TARGETS[@]}" -gt 0 ]]; then
  echo >&2
  echo "soarctl: $ACTION completed with failures for: ${FAILED_TARGETS[*]}" >&2
  exit 1
fi
