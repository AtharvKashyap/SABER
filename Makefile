.PHONY: test unit e2e e2e-one smoke preflight launch final

test:
	pytest -q

unit:
	pytest tests/unit tests/agent_tests tests/orchestration_tests -q --tb=short -x

e2e:
	SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests -q --tb=short -x

e2e-one:
	SABER_RUN_DOCKER_E2E=1 pytest tests/e2e_tests/test_planner_orchestrator_report_e2e.py -q --tb=short

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
