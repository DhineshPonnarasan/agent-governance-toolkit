# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""cedarling-agentmesh: Cedarling policy backend for AGT.

Community integration package — connects Cedarling to AGT's
ExternalPolicyBackend contract without modifying AGT core.

Usage::

    from agent_os.policies import PolicyEvaluator
    from cedarling_agentmesh import CedarlingBackend

    evaluator = PolicyEvaluator()
    evaluator.add_backend(CedarlingBackend(
        bootstrap_config={"policy_store_uri": "https://..."},
    ))
    decision = evaluator.evaluate({"tool_name": "read_data", "agent_id": "a1"})
"""

from cedarling_agentmesh.backend import CedarlingBackend

__all__ = ["CedarlingBackend"]

__version__ = "3.5.0"
