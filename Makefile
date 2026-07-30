.PHONY: test unit e2e e2e-one llm-e2e smoke preflight launch final lab-up lab-down

test:
	pytest -q

# Every offline suite. This deliberately lists all non-gated directories rather
# than three of them: an earlier version ran only unit/agent_tests/
# orchestration_tests, so a breaking change to the report adapter shipped green
# because tests/reporting_tests was never executed. tests/e2e_tests is the only
# excluded directory (it is Docker/model gated — see `make e2e` / `make llm-e2e`).
unit:
	pytest tests/unit tests/agent_tests tests/orchestration_tests tests/parser_tests \
		tests/tools_tests tests/reporting_tests tests/model_tests tests/storage_tests \
		tests/integration -q --tb=short -x

e2e:
	SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests -q --tb=short -x

e2e-one:
	SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_planner_orchestrator_report_e2e.py -q --tb=short

# Gated live-model acceptance tests: needs a live model (SABER_MODEL /
# SABER_MODEL_API_KEY) AND Docker. Makes real API calls; skipped in CI.
llm-e2e:
	SABER_RUN_LLM_E2E=1 SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_mission_loop_live_llm_e2e.py -q --tb=short

smoke:
	python -m py_compile scripts/launch_saber.py saber/core/runtime.py saber/core/docker_runner.py saber/orchestration/mission_orchestrator.py saber/agents/planner_agent.py saber/reporting/finalizer.py
	pytest tests/unit/test_planner_execution_plan.py tests/unit/test_report_finalizer.py tests/unit/test_approval_gates.py -q --tb=short -x

preflight:
	git diff --check
	git status --short
	python scripts/preflight_secrets.py

launch:
	./run_saber

final:
	$(MAKE) smoke
	$(MAKE) unit
	$(MAKE) e2e
	$(MAKE) preflight

lab-up:
	docker network inspect saber-lab >/dev/null 2>&1 || docker network create saber-lab
	docker compose -f docker/lab/docker-compose.yml up -d --build
	python3 scripts/lab_scope.py
	@echo "Lab up. Set SABER_DOCKER_NETWORK=saber-lab in .env, then run missions with --scope runs/lab_scope.yaml"

lab-down:
	docker compose -f docker/lab/docker-compose.yml down -v
	-docker network rm saber-lab
