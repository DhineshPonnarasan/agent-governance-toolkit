# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for folder-level governance policy discovery and merge."""

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from agent_os.policies.discovery import discover_policies, filter_by_scope
from agent_os.policies.evaluator import PolicyDecision, PolicyEvaluator
from agent_os.policies.merge import merge_policies
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDefaults,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


def _write_policy(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f)


def _make_policy(name: str, rules: list[dict], **kwargs) -> dict:
    return {
        "name": name,
        "version": "1.0",
        "rules": rules,
        "defaults": {"action": "allow"},
        **kwargs,
    }


def _make_rule(name: str, tool: str, action: str = "deny", priority: int = 100, **kwargs) -> dict:
    return {
        "name": name,
        "condition": {"field": "tool_name", "operator": "eq", "value": tool},
        "action": action,
        "priority": priority,
        **kwargs,
    }


# =============================================================================
# Discovery tests
# =============================================================================


class TestDiscoverPolicies:
    def test_single_root_policy(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 1
        assert result[0].name == "governance.yaml"

    def test_nested_policies_root_first(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        _write_policy(tmp_path / "services" / "billing" / "governance.yaml", _make_policy("billing", []))
        action = tmp_path / "services" / "billing" / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 2
        assert "governance.yaml" in str(result[0])
        assert "billing" in str(result[1])

    def test_no_policies_found(self, tmp_path):
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()

        result = discover_policies(action, tmp_path)
        assert result == []

    def test_inherit_false_stops_chain(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        _write_policy(
            tmp_path / "services" / "governance.yaml",
            _make_policy("services", [], inherit=False),
        )
        _write_policy(
            tmp_path / "services" / "billing" / "governance.yaml",
            _make_policy("billing", []),
        )
        action = tmp_path / "services" / "billing" / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        # Should NOT include root — services has inherit: false
        assert len(result) == 2
        names = [str(p) for p in result]
        assert not any("governance.yaml" == Path(n).name and Path(n).parent == tmp_path for n in names[:1])

    def test_yml_extension(self, tmp_path):
        _write_policy(tmp_path / "governance.yml", _make_policy("root", []))
        action = tmp_path / "agent.py"
        action.touch()

        result = discover_policies(action, tmp_path)
        assert len(result) == 1

    def test_directory_as_action_path(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action_dir = tmp_path / "src"
        action_dir.mkdir()

        result = discover_policies(action_dir, tmp_path)
        assert len(result) == 1

    # -- Path-traversal hardening ------------------------------------------

    def test_action_path_outside_root_returns_empty(self, tmp_path):
        """If ``action_path`` resolves outside ``root`` the walk must NOT
        traverse upward to the filesystem root, picking up
        ``governance.yaml`` files from arbitrary locations on disk.
        """
        root = tmp_path / "workspace"
        root.mkdir()
        _write_policy(root / "governance.yaml", _make_policy("root", []))

        # Plant a "hostile" governance.yaml above the workspace.
        hostile_dir = tmp_path / "outside"
        hostile_dir.mkdir()
        _write_policy(hostile_dir / "governance.yaml", _make_policy("hostile", []))

        action = hostile_dir / "evil.py"
        action.touch()

        result = discover_policies(action, root)
        assert result == [], (
            "discover_policies must refuse to load policies for an action "
            "outside the configured root; otherwise an attacker who can "
            "influence the action path can plant a governance.yaml anywhere "
            "above their target and have it loaded."
        )

    def test_symlink_escape_does_not_load_outside_root(self, tmp_path):
        """A symlink inside ``root`` that points outside resolves outside
        and must be rejected.
        """
        root = tmp_path / "workspace"
        root.mkdir()
        _write_policy(root / "governance.yaml", _make_policy("root", []))

        outside = tmp_path / "outside"
        outside.mkdir()
        _write_policy(outside / "governance.yaml", _make_policy("hostile", []))

        link = root / "escape"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation not supported on this platform")

        action = link / "evil.py"
        # File doesn't exist through the symlink, but resolve() still works
        # to compute the resolved target directory.
        result = discover_policies(action, root)
        assert result == []

    def test_relative_dot_dot_in_action_path_is_resolved_and_checked(self, tmp_path):
        """``..`` segments are resolved, and an action_path that resolves
        outside root via ``..`` is rejected.
        """
        root = tmp_path / "workspace"
        root.mkdir()
        _write_policy(root / "governance.yaml", _make_policy("root", []))

        outside = tmp_path / "outside"
        outside.mkdir()
        _write_policy(outside / "governance.yaml", _make_policy("hostile", []))

        # action_path uses .. to escape the workspace.
        action = root / ".." / "outside" / "evil.py"
        result = discover_policies(action, root)
        assert result == []


# =============================================================================
# Merge tests
# =============================================================================


class TestMergePolicies:
    def test_single_policy(self):
        doc = PolicyDocument(
            name="root",
            rules=[
                PolicyRule(name="r1", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=100),
            ],
        )
        result = merge_policies([doc])
        assert len(result) == 1
        assert result[0].name == "r1"

    def test_additive_rules(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=100),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="r2", condition=PolicyCondition(field="y", operator=PolicyOperator.EQ, value=2), action=PolicyAction.DENY, priority=200),
        ])
        result = merge_policies([root, child])
        assert len(result) == 2
        assert result[0].name == "r2"  # Higher priority first
        assert result[1].name == "r1"

    def test_override_replaces_parent(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.AUDIT, priority=50),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=50, override=True, message="Stricter in child"),
        ])
        result = merge_policies([root, child])
        assert len(result) == 1
        assert result[0].action == PolicyAction.DENY
        assert result[0].message == "Stricter in child"

    def test_deny_cannot_be_overridden(self):
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=1000),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.ALLOW, priority=1000, override=True),
        ])
        result = merge_policies([root, child])
        # Child override is dropped entirely — only the parent deny remains.
        assert len(result) == 1
        assert result[0].action == PolicyAction.DENY
        assert result[0].name == "block-shell"

    def test_higher_priority_child_cannot_defeat_parent_deny(self):
        # Regression: previously the child rule was appended despite the
        # "ignored" warning, so a higher-priority child ALLOW would sort
        # above the parent DENY and win at evaluation time.
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.DENY, priority=100),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="block-shell", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.ALLOW, priority=9999, override=True),
        ])
        result = merge_policies([root, child])
        assert len(result) == 1
        assert result[0].action == PolicyAction.DENY
        assert all(r.action != PolicyAction.ALLOW for r in result)

    def test_same_name_without_override_does_not_accumulate(self):
        """Regression for #2276: same-name child rule without override=True
        should NOT be appended — otherwise its higher priority defeats the
        parent deny at evaluation time."""
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="block-exec", condition=PolicyCondition(field="tool", operator=PolicyOperator.EQ, value="shell"), action=PolicyAction.DENY, priority=100),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="block-exec", condition=PolicyCondition(field="tool", operator=PolicyOperator.EQ, value="shell"), action=PolicyAction.ALLOW, priority=9999, override=False),
        ])
        result = merge_policies([root, child])
        # Child is dropped — only the parent deny remains.
        assert len(result) == 1
        assert result[0].action == PolicyAction.DENY
        assert result[0].name == "block-exec"

    def test_same_name_without_override_non_deny_parent_keeps_parent(self):
        """When parent is non-deny, same-name child without override still
        keeps only the parent version (no accumulation)."""
        root = PolicyDocument(name="root", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.AUDIT, priority=50),
        ])
        child = PolicyDocument(name="child", rules=[
            PolicyRule(name="audit-rule", condition=PolicyCondition(field="x", operator=PolicyOperator.EQ, value=1), action=PolicyAction.ALLOW, priority=200, override=False),
        ])
        result = merge_policies([root, child])
        assert len(result) == 1
        assert result[0].action == PolicyAction.AUDIT

    def test_empty_chain(self):
        assert merge_policies([]) == []


# =============================================================================
# Scope filter tests
# =============================================================================


class TestFilterByScope:
    def test_no_scope_always_matches(self, tmp_path):
        assert filter_by_scope(tmp_path / "governance.yaml", None, tmp_path / "src" / "x.py", tmp_path)

    def test_matching_scope(self, tmp_path):
        action = tmp_path / "services" / "billing" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()
        assert filter_by_scope(tmp_path / "governance.yaml", "services/billing/**", action, tmp_path)

    def test_non_matching_scope(self, tmp_path):
        action = tmp_path / "services" / "docs" / "agent.py"
        action.parent.mkdir(parents=True)
        action.touch()
        assert not filter_by_scope(tmp_path / "governance.yaml", "services/billing/**", action, tmp_path)


# =============================================================================
# End-to-end evaluator tests
# =============================================================================


class TestFolderScopedEvaluator:
    def test_scoped_evaluation(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", [
            _make_rule("block-shell", "shell_exec", priority=1000),
        ]))
        _write_policy(tmp_path / "services" / "billing" / "governance.yaml", _make_policy("billing", [
            _make_rule("block-pii", "export_pii", priority=900),
        ]))

        action = tmp_path / "services" / "billing" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)

        # Parent deny still works
        result = evaluator.evaluate({"tool_name": "shell_exec", "path": str(action)})
        assert not result.allowed
        assert result.matched_rule == "block-shell"

        # Child rule works
        result = evaluator.evaluate({"tool_name": "export_pii", "path": str(action)})
        assert not result.allowed
        assert result.matched_rule == "block-pii"

        # Allowed tool
        result = evaluator.evaluate({"tool_name": "web_search", "path": str(action)})
        assert result.allowed

    def test_flat_fallback_without_root_dir(self):
        doc = PolicyDocument(name="flat", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="tool_name", operator=PolicyOperator.EQ, value="x"), action=PolicyAction.DENY, priority=100),
        ])
        evaluator = PolicyEvaluator(policies=[doc])
        result = evaluator.evaluate({"tool_name": "x"})
        assert not result.allowed

    def test_flat_fallback_without_path_in_context(self, tmp_path):
        doc = PolicyDocument(name="flat", rules=[
            PolicyRule(name="r1", condition=PolicyCondition(field="tool_name", operator=PolicyOperator.EQ, value="x"), action=PolicyAction.DENY, priority=100),
        ])
        evaluator = PolicyEvaluator(policies=[doc], root_dir=tmp_path)
        # No 'path' in context — falls back to flat
        result = evaluator.evaluate({"tool_name": "x"})
        assert not result.allowed


# =============================================================================
# Regression tests for #2861 — folder-scoped backend decisions must produce
# the same audit_entry schema as the flat-path backend branch.
# =============================================================================


class TestFolderScopedBackendAudit:
    """#2861 — folder-scoped backend decisions must include backend
    metadata, evaluation_ms, and context_snapshot in audit_entry, matching
    the flat-path backend branch."""

    OPA_ALLOW_REGO = """
package agentos
default allow = false
allow { input.tool_name == "web_search" }
"""

    OPA_DENY_REGO = """
package agentos
default allow = false
"""

    CEDAR_PERMIT = """
permit(principal, action == Action::"WebSearch", resource);
"""

    CEDAR_FORBID = """
forbid(principal, action == Action::"WebSearch", resource);
"""

    def test_scoped_opa_backend_allow_audit_entry(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", [
            _make_rule("block-shell", "shell_exec", priority=1000),
        ]))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_rego(rego_content=self.OPA_ALLOW_REGO, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "web_search", "path": str(action)}
        )
        assert decision.allowed is True
        ae = decision.audit_entry
        assert ae, "Backend-originated scoped decision must include audit_entry"
        assert ae["policy"] == "external:opa"
        assert ae["rule"] is None
        assert ae["action"] == "allow"
        assert ae["backend"] == "opa"
        assert "evaluation_ms" in ae
        assert ae["context_snapshot"] == {
            "tool_name": "web_search",
            "path": str(action),
        }
        assert "timestamp" in ae

    def test_scoped_opa_backend_deny_audit_entry(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_rego(rego_content=self.OPA_DENY_REGO, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "file_read", "path": str(action)}
        )
        assert decision.allowed is False
        ae = decision.audit_entry
        assert ae["policy"] == "external:opa"
        assert ae["backend"] == "opa"
        assert ae["action"] == "deny"
        assert "evaluation_ms" in ae
        assert "context_snapshot" in ae
        assert "timestamp" in ae

    def test_scoped_cedar_backend_audit_entry(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_cedar(policy_content=self.CEDAR_PERMIT, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "web_search", "path": str(action)}
        )
        assert decision.allowed is True
        ae = decision.audit_entry
        assert ae["policy"] == "external:cedar"
        assert ae["backend"] == "cedar"
        assert ae["action"] == "allow"
        assert "evaluation_ms" in ae

    def test_scoped_cedar_backend_forbid_audit_entry(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_cedar(policy_content=self.CEDAR_FORBID, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "web_search", "path": str(action)}
        )
        assert decision.allowed is False
        ae = decision.audit_entry
        assert ae["policy"] == "external:cedar"
        assert ae["backend"] == "cedar"
        assert ae["action"] == "deny"
        assert "evaluation_ms" in ae
        assert "context_snapshot" in ae
        assert "timestamp" in ae

    def test_scoped_backend_evaluation_timing_present(self, tmp_path):
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_rego(rego_content=self.OPA_ALLOW_REGO, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "web_search", "path": str(action)}
        )
        # evaluation_ms is a non-negative number (BackendDecision field).
        assert isinstance(decision.audit_entry["evaluation_ms"], (int, float))
        assert decision.audit_entry["evaluation_ms"] >= 0

    def test_flat_vs_scoped_backend_audit_entry_key_parity(self, tmp_path):
        """Equivalent backend-originated decisions must produce equivalent
        audit_entry key sets regardless of evaluation path."""
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        # Flat path — no root_dir, no 'path' in context.
        flat_evaluator = PolicyEvaluator()
        flat_evaluator.load_rego(rego_content=self.OPA_ALLOW_REGO, mode="builtin")
        flat_decision = flat_evaluator.evaluate({"tool_name": "web_search"})

        # Scoped path — root_dir set, 'path' in context.
        scoped_evaluator = PolicyEvaluator(root_dir=tmp_path)
        scoped_evaluator.load_rego(rego_content=self.OPA_ALLOW_REGO, mode="builtin")
        scoped_decision = scoped_evaluator.evaluate(
            {"tool_name": "web_search", "path": str(action)}
        )

        # The audit_entry key set must be identical between the two paths
        # for the same logical backend decision.
        assert set(flat_decision.audit_entry) == set(scoped_decision.audit_entry)

    def test_scoped_backend_decision_preserves_allowed_and_action(self, tmp_path):
        """The fix must not change authorization semantics: allowed, action,
        matched_rule, and reason must be set correctly on scoped backend
        decisions, identical to the pre-fix behavior."""
        _write_policy(tmp_path / "governance.yaml", _make_policy("root", []))
        action = tmp_path / "src" / "agent.py"
        action.parent.mkdir(parents=True, exist_ok=True)
        action.touch()

        evaluator = PolicyEvaluator(root_dir=tmp_path)
        evaluator.load_rego(rego_content=self.OPA_DENY_REGO, mode="builtin")
        decision = evaluator.evaluate(
            {"tool_name": "anything", "path": str(action)}
        )
        assert decision.allowed is False
        assert decision.matched_rule is None
        assert decision.action == "deny"
        # The reason field is propagated from the BackendDecision.
        assert decision.reason  # non-empty
        # And audit_entry is now non-empty (the fix).
        assert decision.audit_entry
